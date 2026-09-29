package test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestEveryTerminalCallbackReachesTerminate pins the premise the terminate safety-net rests on.
//
// # What is being protected
//
// terminate() unpins anything still outstanding, which is only safe because it is entered from a
// point after which native code is guaranteed not to touch a pinned buffer. That guarantee comes
// from the C header, which states "Once invoked, no further callback methods will be invoked" on
// ALL THREE terminal callbacks -- on_succeded, on_failed and on_canceled -- not on on_canceled
// alone. ASYNC_BUFFER_LIFETIME.md records this; an earlier revision of that document claimed
// on_canceled was the only one, which would have made the safety-net unsound on the success and
// failure paths.
//
// # Why it is checked here, at the source
//
// The property is a pairing between a C contract and three Go methods, and there is no runtime
// observable for "the last callback has fired". What CAN be checked is that all three terminal
// callbacks still route through terminate, so a future edit that gives one of them its own teardown
// -- or adds a fourth terminal outcome without one -- is caught here rather than in production as a
// use-after-free.
func TestEveryTerminalCallbackReachesTerminate(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test source file")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "../bidirectional_conn.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(source)

	// The three terminal callbacks the header documents, and the Go methods that implement them.
	for _, terminal := range []struct {
		method string
		calls  string
	}{
		{"OnSucceeded", "c.terminate(io.EOF)"},
		{"OnFailed", "c.terminate(NetError(netError))"},
		{"OnCanceled", "c.terminate(context.Canceled)"},
	} {
		marker := "func (c *bidirectionalHandler) " + terminal.method + "("
		start := strings.Index(src, marker)
		if start < 0 {
			t.Fatalf("%s must exist", terminal.method)
		}

		body := src[start:]
		if end := strings.Index(body, "\n}\n"); end >= 0 {
			body = body[:end]
		}
		if !strings.Contains(body, "c.terminate(") {
			t.Fatalf("%s is a TERMINAL callback per the C header, so it must reach terminate: the "+
				"pinning safety-net unpins there on the guarantee that no further callback follows",
				terminal.method)
		}
	}

	// And terminate must actually drop the pin, or reaching it would prove nothing.
	start := strings.Index(src, "func (c *BidirectionalConn) terminate(")
	if start < 0 {
		t.Fatal("terminate must exist")
	}
	body := src[start:]
	if end := strings.Index(body, "\n}\n"); end >= 0 {
		body = body[:end]
	}
	if !strings.Contains(body, "readPinned.release()") {
		t.Fatal("terminate must unpin the read buffer")
	}
	if !strings.Contains(body, "writePinned.release()") {
		t.Fatal("terminate must unpin the write buffer")
	}
}
