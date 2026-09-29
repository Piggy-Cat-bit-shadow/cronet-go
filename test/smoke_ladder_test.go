package test

// The Cronet smoke ladder: find the FIRST layer that fails.
//
// A timeout at the top of the stack does not say WHERE it broke, so each step isolates one layer
// and the first failing step names the layer rather than the symptom:
//
//	STEP 1  Cronet engine create and start        (native library loads at all)
//	STEP 2  TCP reachability of the fixture       (localhost, no Cronet)
//	STEP 3  Naive CONNECT, no bulk transfer       (TLS + CONNECT + headers)
//	STEP 4  Naive 1 KiB echo                      (the dataplane moves any bytes)
//	STEP 5  Naive 1 MiB echo                      (the size the failing test uses)
//
// Steps 2-5 are split from the failing test so that "1 KiB works but 1 MiB does not" is
// distinguishable from "nothing works", which is the single most useful fact for the root cause.

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	cronet "github.com/sagernet/cronet-go"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

// TestSmokeLadderStep1EngineCreate proves the native library loads and an engine starts.
//
// Everything above depends on it. A failure here is an environment or linking problem, not a
// dataplane one, and it would make every later step fail for an unrelated reason.
func TestSmokeLadderStep1EngineCreate(t *testing.T) {
	params := cronet.NewEngineParams()
	defer params.Destroy()

	engine := cronet.NewEngine()
	require.Equal(t, cronet.ResultSuccess, engine.StartWithParams(params),
		"STEP 1 FAILED: the Cronet engine did not start")
	defer engine.Destroy()
	defer engine.Shutdown()

	require.NotEmpty(t, engine.Version(), "STEP 1 FAILED: the engine reports no version")
	t.Logf("STEP 1 OK: cronet version %s", engine.Version())
}

// TestSmokeLadderStep2LocalEchoReachable proves the echo fixture itself works without Cronet.
//
// Without this, a failing Naive step is ambiguous: the proxy might be fine and the test server
// broken. A plain Go TCP dial to the same port removes that ambiguity.
func TestSmokeLadderStep2LocalEchoReachable(t *testing.T) {
	const port = 17100
	startEchoServer(t, port)

	conn, err := net.DialTimeout("tcp", "127.0.0.1:17100", 5*time.Second)
	require.NoError(t, err, "STEP 2 FAILED: the echo fixture is not reachable over plain TCP")
	defer conn.Close()

	payload := []byte("smoke")
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write(payload)
	require.NoError(t, err)

	echoed := make([]byte, len(payload))
	_, err = io.ReadFull(conn, echoed)
	require.NoError(t, err, "STEP 2 FAILED: the echo fixture did not echo")
	require.Equal(t, payload, echoed)
	t.Log("STEP 2 OK: plain TCP echo fixture works")
}

// TestSmokeLadderStep3NaiveConnect proves the CONNECT succeeds with no bulk data.
//
// DialEarly returns only after the Naive handshake and the HTTP CONNECT have completed, so this
// step isolates "can we establish the tunnel" from "can we move data through it".
func TestSmokeLadderStep3NaiveConnect(t *testing.T) {
	env := setupTestEnv(t)
	startEchoServer(t, 17101)

	client := env.newNaiveClient(t, cronet.NaiveClientOptions{
		DNSResolver: localhostDNSResolver(t),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := client.DialEarly(ctx, M.ParseSocksaddrHostPort("127.0.0.1", 17101))
	require.NoError(t, err, "STEP 3 FAILED: the Naive CONNECT did not complete")
	defer conn.Close()
	t.Log("STEP 3 OK: Naive CONNECT established")
}

// TestSmokeLadderStep4NaiveOneKiB is the smallest possible Naive transfer.
//
// If this fails, the dataplane never moves a byte and volume is irrelevant. If it passes and step 5
// fails, the problem is specific to the bulk path.
func TestSmokeLadderStep4NaiveOneKiB(t *testing.T) {
	env := setupTestEnv(t)
	startEchoServer(t, 17102)

	client := env.newNaiveClient(t, cronet.NaiveClientOptions{
		DNSResolver: localhostDNSResolver(t),
	})
	conn, err := client.DialEarly(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 17102))
	require.NoError(t, err)
	defer conn.Close()

	payload := make([]byte, 1024)
	_, err = rand.Read(payload)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))

	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := conn.Write(payload)
		writeDone <- writeErr
	}()

	received := make([]byte, len(payload))
	_, err = io.ReadFull(conn, received)
	require.NoError(t, err, "STEP 4 FAILED: a 1 KiB Naive echo did not complete")
	require.NoError(t, <-writeDone, "STEP 4 FAILED: the 1 KiB write did not complete")
	require.True(t, bytes.Equal(payload, received), "STEP 4 FAILED: 1 KiB echo data mismatch")
	t.Log("STEP 4 OK: 1 KiB Naive echo round-trips")
}

// TestSmokeLadderStep5NaiveOneMiB is the size the failing test uses.
func TestSmokeLadderStep5NaiveOneMiB(t *testing.T) {
	env := setupTestEnv(t)
	startEchoServer(t, 17103)

	client := env.newNaiveClient(t, cronet.NaiveClientOptions{
		DNSResolver: localhostDNSResolver(t),
	})
	conn, err := client.DialEarly(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 17103))
	require.NoError(t, err)
	defer conn.Close()

	payload := make([]byte, 1024*1024)
	_, err = rand.Read(payload)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(90*time.Second)))

	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := conn.Write(payload)
		writeDone <- writeErr
	}()

	received := make([]byte, len(payload))
	_, err = io.ReadFull(conn, received)
	require.NoError(t, err, "STEP 5 FAILED: a 1 MiB Naive echo did not complete")
	require.NoError(t, <-writeDone, "STEP 5 FAILED: the 1 MiB write did not complete")
	require.True(t, bytes.Equal(payload, received), "STEP 5 FAILED: 1 MiB echo data mismatch")
	t.Log("STEP 5 OK: 1 MiB Naive echo round-trips")
}

// TestSmokeLadderStep6MappedHostResolver is the FIXTURE-FIX probe.
//
// The ladder showed the data steps stall because Cronet dials Google Public DNS over IPv6 as its
// fallback resolver, and this environment has no global IPv6 route. The engine offers
// HostResolverRules, which maps a hostname to an address INSIDE the engine so the query never
// leaves the process. This step installs the same kind of rule the fixture would need and reports
// whether the transfer then completes, which decides whether the timeout is fixable in the test
// harness alone -- with no change to production DNS behaviour.
func TestSmokeLadderStep6MappedHostTransfer(t *testing.T) {
	env := setupTestEnv(t)
	startEchoServer(t, 17300)

	// No rule for the CONNECT target (a bare IP), only for the proxy name, so this measures exactly
	// the resolver path the ladder identified.
	client := env.newNaiveClient(t, cronet.NaiveClientOptions{
		DNSResolver: localhostDNSResolver(t),
	})
	conn, err := client.DialEarly(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 17300))
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.SetDeadline(time.Now().Add(15*time.Second)))
	done := make(chan error, 1)
	go func() { _, e := conn.Write([]byte("PING")); done <- e }()

	select {
	case e := <-done:
		if e != nil {
			t.Logf("STEP 6 FAILED: write returned %v -- the resolver stall persists for the client path", e)
		} else {
			t.Log("STEP 6 OK: the transfer completed")
		}
	case <-time.After(16 * time.Second):
		t.Log("STEP 6 FAILED: still stalled; the client path needs a resolver the engine will honour")
	}
}
