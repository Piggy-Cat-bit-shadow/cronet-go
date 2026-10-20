package cronet

import (
	"context"
	"testing"

	mDNS "github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
)

// The per-dial transport choice is one header: `-force-quic`.
//
// These tests exercise the header builder directly, because the alternative -
// starting a Cronet engine - needs a native library and a live server, and the
// rule being pinned is a pure function of (client option, per-dial flag).
//
// The contract they protect:
//
//	DialEarly           -> the client-level QUIC option, unchanged behaviour
//	DialEarlyWithQUIC   -> the caller's choice, independent of that option
//
// and the reserved-header rule still wins over a user-supplied extra header.

func newPerDialTestClient(t *testing.T, quic bool, extraHeaders map[string]string) *NaiveClient {
	t.Helper()
	client, err := newNaiveClientWithoutLibraryCheck(NaiveClientOptions{
		Context:             context.Background(),
		ServerAddress:       M.ParseSocksaddr("127.0.0.1:443"),
		Username:            "user",
		Password:            "pass",
		DNSResolver:         func(context.Context, *mDNS.Msg) *mDNS.Msg { return nil },
		QUIC:                quic,
		ExtraHeaders:        extraHeaders,
		InsecureConcurrency: 1,
	})
	if err != nil {
		t.Fatalf("newNaiveClientWithoutLibraryCheck: %v", err)
	}
	return client
}

// TestDialHeadersFollowsTheClientOption is the old behaviour: DialEarly still
// takes the engine-level option.
func TestDialHeadersFollowsTheClientOption(t *testing.T) {
	destination := M.ParseSocksaddr("example.com:443")
	for _, quic := range []bool{true, false} {
		client := newPerDialTestClient(t, quic, nil)
		headers := client.dialHeaders(destination, client.quicEnabled)
		_, forced := headers["-force-quic"]
		if forced != quic {
			t.Fatalf("client QUIC=%v produced -force-quic=%v", quic, forced)
		}
		if got := headers["-connect-authority"]; got != destination.String() {
			t.Fatalf("connect authority = %q, want %q", got, destination.String())
		}
		if _, ok := headers["Padding"]; !ok {
			t.Fatal("the Padding header must always be sent")
		}
		if got := headers["proxy-authorization"]; got == "" {
			t.Fatal("the credentials header must be sent when configured")
		}
	}
}

// TestDialHeadersAllowsPerDialOverride is the new capability: one client can
// issue an H3-forced CONNECT and an H2 CONNECT.
func TestDialHeadersAllowsPerDialOverride(t *testing.T) {
	destination := M.ParseSocksaddr("example.com:443")
	for _, clientQUIC := range []bool{true, false} {
		client := newPerDialTestClient(t, clientQUIC, nil)
		for _, force := range []bool{true, false} {
			headers := client.dialHeaders(destination, force)
			_, got := headers["-force-quic"]
			if got != force {
				t.Fatalf("client QUIC=%v, per-dial force=%v: -force-quic=%v",
					clientQUIC, force, got)
			}
		}
	}
}

// TestDialHeadersKeepsReservedHeadersOut proves a user header set cannot smuggle
// a control header in, which is what makes the per-dial choice authoritative.
func TestDialHeadersKeepsReservedHeadersOut(t *testing.T) {
	// The constructor rejects these outright, so the defensive path in the
	// builder is tested through a client built without that check.
	client := newPerDialTestClient(t, false, nil)
	client.extraHeaders = map[string]string{
		"paddingd":    "x", // not reserved
		"-force-quic": "true",
		"Padding":     "",
	}
	headers := client.dialHeaders(M.ParseSocksaddr("example.com:443"), false)
	if _, ok := headers["-force-quic"]; ok {
		t.Fatal("a user extra header must not be able to force QUIC")
	}
	if headers["Padding"] == "" {
		t.Fatal("a user extra header must not be able to disable padding")
	}
	if headers["paddingd"] != "x" {
		t.Fatal("an ordinary extra header must still be forwarded")
	}
}
