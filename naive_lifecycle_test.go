package cronet

import (
	"context"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
)

// Tests for the client lifecycle state machine.
//
// Start and Close are a CAS state machine over clientStateCreated -> Starting ->
// Running -> Closing -> Closed, and Close must be safe to call from any state,
// concurrently, and more than once. The failure modes are the kind that only appear
// in a long-running client: a Close that blocks forever waiting on a goroutine that
// will never finish, a double Close that panics on a closed channel, or a leaked
// goroutine per restart.
//
// These tests build the client through newNaiveClientWithoutLibraryCheck so they run
// on any machine. The native library is needed to actually start an engine, so the
// transitions that require one are exercised for their ERROR and CLEANUP behaviour
// rather than for a successful start: that is still where the interesting bugs are,
// because a failed start must leave the client closed and its channel closed exactly
// once.

// newTestClient builds a client that never touches the native library.
func newTestClient(t *testing.T, ctx context.Context) *NaiveClient {
	t.Helper()
	if ctx == nil {
		ctx = context.Background()
	}
	client, err := newNaiveClientWithoutLibraryCheck(NaiveClientOptions{
		Context:       ctx,
		ServerAddress: M.ParseSocksaddrHostPort("127.0.0.1", 443),
		DNSResolver:   proxyDNSResolver,
	})
	if err != nil {
		t.Fatalf("construct a client for testing: %v", err)
	}
	return client
}

// proxyDNSResolver is a no-op resolver satisfying the constructor's requirement.
// The constructor only checks that it is non-nil; no query is issued by these tests.
func proxyDNSResolver(ctx context.Context, request *mDNS.Msg) *mDNS.Msg { return nil }

// TestConstructedClientReportsTheCreatedState pins the starting state.
func TestConstructedClientReportsTheCreatedState(t *testing.T) {
	client := newTestClient(t, nil)
	if state := clientState(client.state.Load()); state != clientStateCreated {
		t.Fatalf("a freshly constructed client must be in clientStateCreated, got %d", state)
	}
}

// TestCloseOnANeverStartedClientIsClean covers the common shutdown path where a
// client is created and then discarded without ever starting.
//
// Close on clientStateCreated must close the started channel so that a concurrent
// Start waiting on it is released, and it must NOT go through the engine teardown
// path, which would dereference engines that were never created.
func TestCloseOnANeverStartedClientIsClean(t *testing.T) {
	client := newTestClient(t, nil)

	if err := client.Close(); err != nil {
		t.Fatalf("closing a never-started client must succeed, got %v", err)
	}
	if state := clientState(client.state.Load()); state != clientStateClosed {
		t.Fatalf("the client must end up closed, got state %d", state)
	}
	select {
	case <-client.started:
	default:
		t.Fatal("Close must close the started channel, or a concurrent Start blocks " +
			"on it forever")
	}
}

// TestDoubleCloseDoesNotPanic is the property that matters most in practice: deferred
// cleanup plus an explicit Close is a normal pattern, and a second close of a channel
// panics.
func TestDoubleCloseDoesNotPanic(t *testing.T) {
	client := newTestClient(t, nil)

	if err := client.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// The second Close must be an error or a no-op, never a panic. net.ErrClosed is
	// the documented signal; doClose is idempotent for the Running path.
	err := client.Close()
	if err != nil && !errorIs(err, net.ErrClosed) {
		t.Fatalf("a second Close must return nil or net.ErrClosed, got %v", err)
	}

	// And many more, because teardown helpers are often called more than twice.
	for i := 0; i < 5; i++ {
		_ = client.Close()
	}
}

// TestConcurrentCloseIsSafe runs Close from many goroutines at once.
//
// This is where a non-atomic implementation fails: two goroutines can both observe
// clientStateCreated and both call close(c.started), which panics. Run under -race.
func TestConcurrentCloseIsSafe(t *testing.T) {
	client := newTestClient(t, nil)

	const goroutines = 32
	var waitGroup sync.WaitGroup
	waitGroup.Add(goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			defer waitGroup.Done()
			<-start
			_ = client.Close()
		}()
	}
	close(start)

	done := make(chan struct{})
	go func() {
		waitGroup.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent Close calls did not all return; one is blocked")
	}

	if state := clientState(client.state.Load()); state != clientStateClosed {
		t.Fatalf("the client must be closed after all Close calls, got state %d", state)
	}
}

// TestCloseRespectsContextCancellation proves a Close that cannot proceed returns
// rather than hanging, which matters when the parent context is already dead.
func TestCloseRespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	client := newTestClient(t, ctx)
	done := make(chan error, 1)
	go func() { done <- client.Close() }()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close must not block when the client's context is already cancelled")
	}
}

// TestStartFailsCleanlyWithoutTheNativeLibrary drives the failure path of Start.
//
// The cleanup contract is the interesting part: a failed Start must close the started
// channel exactly once, leave the state closed, and release the proxy context. Before
// the deferred cleanup was written carefully, a failed start left the channel unclosed
// and every subsequent Start blocked forever on it.
func TestStartFailsCleanlyWithoutTheNativeLibrary(t *testing.T) {
	client := newTestClient(t, nil)

	err := client.Start()
	if err == nil {
		// The native library happens to be available; Start may have succeeded.
		// Tear down and assert only the invariants that hold either way.
		t.Log("Start succeeded, so the native library is loadable; checking teardown only")
		if closeErr := client.Close(); closeErr != nil && !errorIs(closeErr, net.ErrClosed) {
			t.Fatalf("Close after a successful Start: %v", closeErr)
		}
		return
	}

	if state := clientState(client.state.Load()); state != clientStateClosed {
		t.Fatalf("a failed Start must leave the client closed, got state %d", state)
	}
	select {
	case <-client.started:
	case <-time.After(5 * time.Second):
		t.Fatal("a failed Start must close the started channel, or every later Start " +
			"and Close blocks on it forever")
	}
	// A second Start after a failure must report the closed state rather than retry.
	if secondErr := client.Start(); secondErr == nil {
		t.Fatal("Start must not succeed after a failed Start")
	}
	// Close after a failed Start must not panic on the already-closed channel.
	if closeErr := client.Close(); closeErr != nil && !errorIs(closeErr, net.ErrClosed) {
		t.Fatalf("Close after a failed Start: %v", closeErr)
	}
}

// TestStartIsNotReentrant checks the state machine's guard against a second Start.
func TestStartIsNotReentrant(t *testing.T) {
	client := newTestClient(t, nil)
	// Force the running state, since reaching it for real needs the native library.
	client.state.Store(uint32(clientStateRunning))

	err := client.Start()
	if err == nil {
		t.Fatal("Start must refuse to restart a running client")
	}
	if errorIs(err, net.ErrClosed) {
		t.Fatalf("a running client must be reported as already started, not closed; got %v", err)
	}
}

// TestCloseWhileRunningIsIdempotent checks the Running -> Closing -> Closed path,
// which is the one a real client takes.
func TestCloseWhileRunningIsIdempotent(t *testing.T) {
	client := newTestClient(t, nil)
	client.state.Store(uint32(clientStateRunning))

	if err := client.Close(); err != nil {
		t.Fatalf("Close from the running state: %v", err)
	}
	if state := clientState(client.state.Load()); state != clientStateClosed {
		t.Fatalf("the client must be closed, got state %d", state)
	}
	// Repeated closes must be safe; doClose has already run.
	for i := 0; i < 3; i++ {
		_ = client.Close()
	}
}

// failingDialer is a Dialer that always fails, used to prove the dial path reports
// errors rather than hanging.
type failingDialer struct{ err error }

// TestDialAfterCloseIsRefused checks that a closed client does not attempt a dial.
func TestDialAfterCloseIsRefused(t *testing.T) {
	client := newTestClient(t, nil)
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	destination := M.ParseSocksaddrHostPort("example.com", 443)
	if _, err := client.DialEarly(context.Background(), destination); err == nil {
		t.Fatal("DialEarly on a closed client must fail")
	}
	if _, err := client.DialContext(context.Background(), "tcp", destination); err == nil {
		t.Fatal("DialContext on a closed client must fail")
	}
}

// TestCloseAllConnectionsIsSafeAtAnyState guards the exported helper that callers
// invoke without checking the state first.
func TestCloseAllConnectionsIsSafeAtAnyState(t *testing.T) {
	client := newTestClient(t, nil)
	// No engines yet: must not panic.
	client.CloseAllConnections()
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	client.CloseAllConnections()
}

// TestLifecycleLeavesNoGoroutines is the leak check.
//
// It creates and closes many clients and confirms the goroutine count returns to its
// baseline. A per-client goroutine that Close forgets to stop is invisible in a
// single test run and fatal in a client that reconnects repeatedly.
func TestLifecycleLeavesNoGoroutines(t *testing.T) {
	// Let any prior goroutines settle first.
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	for i := 0; i < 50; i++ {
		client := newTestClient(t, nil)
		_ = client.Start() // fails without the library, exercising the cleanup path
		_ = client.Close()
	}

	// Allow the runtime to reap anything that is finishing.
	deadline := time.Now().Add(5 * time.Second)
	var final int
	for time.Now().Before(deadline) {
		runtime.GC()
		final = runtime.NumGoroutine()
		if final <= baseline+2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if final > baseline+2 {
		t.Fatalf("goroutine count grew from %d to %d over 50 create/start/close "+
			"cycles; the lifecycle leaks a goroutine per client", baseline, final)
	}
}

// errorIs is errors.Is, named locally to keep the import list short.
func errorIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}
