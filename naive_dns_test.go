package cronet

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
)

// Tests for the in-process DNS server that Chromium's resolver is pointed at.
//
// The chain is:
//
//	Chromium resolver
//	  -> virtual 127.0.0.1:53
//	     -> socket pair
//	        -> serveDNSPacketConn / serveDNSStreamConn
//	           -> sing-box dnsRouter

// ---------------------------------------------------------------------------
// Buffer sizing and truncation are two different roles
// ---------------------------------------------------------------------------

// TestQueryBufferIsLargerThanAnyQueryChromiumSends pins the receive buffer against
// real query sizes.
//
// The buffer and the truncation threshold used to be the SAME constant, which
// conflated two requirements that pull in opposite directions: the receive buffer
// must be big enough not to truncate a query, while the response threshold must
// stay at 512 so oversized answers set TC=1 and move Chromium to TCP. Oversizing a
// UDP read is worse than it looks, because a truncated read is SILENT: ReadFrom
// returns only what fit, Unpack fails, and the loop moves on without answering, so
// Chromium waits for a timeout instead of getting TC=1.
func TestQueryBufferIsLargerThanAnyQueryChromiumSends(t *testing.T) {
	longName := ""
	for len(longName) < 250 {
		longName += "abcdefghij."
	}
	longName = longName[:253] // DNS's maximum name length

	queries := []struct {
		name string
		msg  *mDNS.Msg
	}{
		{"plain A", func() *mDNS.Msg {
			m := new(mDNS.Msg)
			m.SetQuestion("example.com.", mDNS.TypeA)
			return m
		}()},
		{"EDNS0 4096", func() *mDNS.Msg {
			m := new(mDNS.Msg)
			m.SetQuestion("example.com.", mDNS.TypeA)
			m.SetEdns0(4096, false)
			return m
		}()},
		{"HTTPS/SVCB", func() *mDNS.Msg {
			m := new(mDNS.Msg)
			m.SetQuestion("example.com.", mDNS.TypeHTTPS)
			m.SetEdns0(1232, false)
			return m
		}()},
		{"ECS", func() *mDNS.Msg {
			m := new(mDNS.Msg)
			m.SetQuestion("example.com.", mDNS.TypeA)
			option := new(mDNS.OPT)
			option.Hdr.Name = "."
			option.Hdr.Rrtype = mDNS.TypeOPT
			subnet := new(mDNS.EDNS0_SUBNET)
			subnet.Code = mDNS.EDNS0SUBNET
			subnet.Family = 1
			subnet.SourceNetmask = 24
			subnet.Address = []byte{203, 0, 113, 0}
			option.Option = append(option.Option, subnet)
			m.Extra = append(m.Extra, option)
			return m
		}()},
		{"253-char QNAME + EDNS0", func() *mDNS.Msg {
			m := new(mDNS.Msg)
			m.SetQuestion(longName, mDNS.TypeA)
			m.SetEdns0(4096, false)
			return m
		}()},
	}

	for _, query := range queries {
		packed, err := query.msg.Pack()
		if err != nil {
			t.Fatalf("%s: pack: %v", query.name, err)
		}
		if len(packed) > chromiumDNSQueryBufferSize {
			t.Errorf("%s packs to %d bytes, which exceeds the %d-byte receive buffer; "+
				"a truncated read fails silently and Chromium times out",
				query.name, len(packed), chromiumDNSQueryBufferSize)
		}
	}
}

// TestResponseThresholdStaysAt512 is the other half. Raising this would stop
// oversized responses from setting TC=1, so Chromium would never retry over TCP
// and would silently receive a clipped answer.
func TestResponseThresholdStaysAt512(t *testing.T) {
	if chromiumDNSResponseMaxSize != 512 {
		t.Fatalf("the response truncation threshold is %d; it must stay 512 so that "+
			"oversized responses set TC=1 and Chromium retries over TCP",
			chromiumDNSResponseMaxSize)
	}
	if chromiumDNSQueryBufferSize <= chromiumDNSResponseMaxSize {
		t.Fatalf("the receive buffer (%d) must be larger than the response threshold "+
			"(%d)", chromiumDNSQueryBufferSize, chromiumDNSResponseMaxSize)
	}
}

// TestOversizedResponseIsTruncatedNotDropped checks the TC=1 behaviour directly.
func TestOversizedResponseIsTruncatedNotDropped(t *testing.T) {
	request := new(mDNS.Msg)
	request.SetQuestion("example.com.", mDNS.TypeA)

	truncated := truncatedDNSResponse(request, mDNS.RcodeSuccess)
	packed, err := truncated.Pack()
	if err != nil {
		t.Fatalf("pack truncated response: %v", err)
	}
	if !truncated.Truncated {
		t.Fatal("the truncated response must set TC=1, which is what tells Chromium to " +
			"retry over TCP")
	}
	if len(packed) > chromiumDNSResponseMaxSize {
		t.Fatalf("the truncated response is %d bytes, still over the %d threshold",
			len(packed), chromiumDNSResponseMaxSize)
	}
	if truncated.Id != request.Id {
		t.Fatal("the truncated response must echo the request ID")
	}
}

// ---------------------------------------------------------------------------
// Failure reporting: SERVFAIL, not silence
// ---------------------------------------------------------------------------

// TestMinimalSERVFAILIsAValidResponse proves the fallback is well-formed, since its
// whole purpose is to be accepted by Chromium as a definitive answer.
func TestMinimalSERVFAILIsAValidResponse(t *testing.T) {
	request := new(mDNS.Msg)
	request.SetQuestion("example.com.", mDNS.TypeA)
	request.Id = 0x1234

	packed, err := minimalSERVFAIL(request, mDNS.RcodeSuccess)
	if err != nil {
		t.Fatalf("minimalSERVFAIL: %v", err)
	}
	var decoded mDNS.Msg
	if err := decoded.Unpack(packed); err != nil {
		t.Fatalf("the SERVFAIL fallback must be parseable: %v", err)
	}
	if decoded.Id != request.Id {
		t.Fatalf("SERVFAIL must echo the request ID: got %d, want %d",
			decoded.Id, request.Id)
	}
	if !decoded.Response {
		t.Fatal("SERVFAIL must have QR set")
	}
	// RcodeSuccess must be upgraded: a pack failure on a "successful" answer is
	// still a failure, and replying NOERROR would be a lie.
	if decoded.Rcode != mDNS.RcodeServerFailure {
		t.Fatalf("a pack failure must be reported as SERVFAIL, got rcode %d (%s)",
			decoded.Rcode, mDNS.RcodeToString[decoded.Rcode])
	}
	if len(decoded.Question) != 1 {
		t.Fatal("SERVFAIL should echo the question so the response is matchable")
	}
}

// TestSERVFAILPreservesARealErrorRcode checks the rcode is not blindly overwritten
// when the resolver already reported a specific failure.
func TestSERVFAILPreservesARealErrorRcode(t *testing.T) {
	request := new(mDNS.Msg)
	request.SetQuestion("example.com.", mDNS.TypeA)

	packed, err := minimalSERVFAIL(request, mDNS.RcodeNameError)
	if err != nil {
		t.Fatal(err)
	}
	var decoded mDNS.Msg
	if err := decoded.Unpack(packed); err != nil {
		t.Fatal(err)
	}
	if decoded.Rcode != mDNS.RcodeNameError {
		t.Fatalf("NXDOMAIN must be preserved, got %s", mDNS.RcodeToString[decoded.Rcode])
	}
}

// ---------------------------------------------------------------------------
// Stream framing: complete writes
// ---------------------------------------------------------------------------

// shortNetConn is a net.Conn whose Write can return fewer bytes than requested with
// a NIL error, which io.Writer permits.
type shortNetConn struct {
	net.Conn
	shortBy int
	writes  [][]byte
}

func (c *shortNetConn) Write(p []byte) (int, error) {
	if c.shortBy > 0 {
		n := len(p) - c.shortBy
		if n < 0 {
			n = 0
		}
		copied := make([]byte, n)
		copy(copied, p)
		c.writes = append(c.writes, copied)
		return n, nil
	}
	copied := make([]byte, len(p))
	copy(copied, p)
	c.writes = append(c.writes, copied)
	return len(p), nil
}

// TestStreamWriteDetectsAShortWrite pins the DNS stream framing contract.
//
// The stream is a 2-byte big-endian length prefix followed by the message. A
// partial write of either leaves the peer parsing garbage, and the previous code
// called conn.Write twice without checking the byte count.
func TestStreamWriteDetectsAShortWrite(t *testing.T) {
	conn := &shortNetConn{shortBy: 1}
	if _, err := writeFullDNS(conn, []byte("abc")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("a short write must return io.ErrShortWrite, got %v", err)
	}

	// A complete write must succeed.
	full := &shortNetConn{}
	if n, err := writeFullDNS(full, []byte("abc")); err != nil || n != 3 {
		t.Fatalf("a complete write must succeed: n=%d err=%v", n, err)
	}
}

// failingNetConn always fails its writes.
type failingNetConn struct {
	net.Conn
	err error
}

func (c *failingNetConn) Write(p []byte) (int, error) { return 0, c.err }

// TestStreamWritePropagatesErrors covers the write-error path.
func TestStreamWritePropagatesErrors(t *testing.T) {
	sentinel := errors.New("write failed")
	conn := &failingNetConn{err: sentinel}
	if _, err := writeFullDNS(conn, []byte("abc")); !errors.Is(err, sentinel) {
		t.Fatalf("the writer's error must be propagated, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// The UDP server loop end-to-end
// ---------------------------------------------------------------------------

// TestUDPBridgeAnswersAndTruncates drives serveDNSPacketConn with a real two-ended
// UDP loopback pair, so the loop's addressing, resolver call and truncation are
// exercised together rather than in isolation.
//
// It uses its own pair rather than createPacketSocketPair because that helper
// returns the Chromium-side fd and the proxy-side conn - the two ends of the SAME
// connection - whereas this test needs a server socket and a separate client
// socket.
func TestUDPBridgeAnswersAndTruncates(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot listen on UDP loopback in this environment: %v", err)
	}
	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		server.Close()
		t.Skipf("cannot dial UDP loopback in this environment: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A resolver that returns a response with a large answer, forcing truncation.
	resolver := func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg {
		response := new(mDNS.Msg)
		response.SetReply(request)
		for i := 0; i < 40; i++ {
			record, rrErr := mDNS.NewRR("example.com. 300 IN A 93.184.216.34")
			if rrErr == nil && record != nil {
				response.Answer = append(response.Answer, record)
			}
		}
		return response
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = serveDNSPacketConn(ctx, server, resolver)
	}()

	query := new(mDNS.Msg)
	query.SetQuestion("example.com.", mDNS.TypeA)
	packedQuery, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Write(packedQuery); err != nil {
		t.Fatalf("send query: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 65536)
	n, err := client.Read(buffer)
	if err != nil {
		t.Fatalf("the DNS bridge must answer rather than stay silent: %v", err)
	}

	var response mDNS.Msg
	if err := response.Unpack(buffer[:n]); err != nil {
		t.Fatalf("the reply must be a valid DNS message: %v", err)
	}
	if !response.Truncated {
		t.Fatalf("an oversized response must set TC=1 so Chromium retries over TCP "+
			"(reply was %d bytes)", n)
	}
	if response.Id != query.Id {
		t.Fatal("the reply must echo the query ID")
	}
	cancel()
	<-done
}

// TestBridgeNeverDropsSilentlyForAValidQuery is the property the SERVFAIL fallback
// exists to preserve: for any query it accepts, the bridge sends SOMETHING back.
//
// A resolver that returns nil is the reachable "cannot answer" case - normalizeDNSResponse
// turns it into SERVFAIL - and the bridge must put that on the wire rather than stay
// silent, because silence makes Chromium wait out its full resolver timeout while an
// immediate SERVFAIL fails fast.
func TestBridgeNeverDropsSilentlyForAValidQuery(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot listen on UDP loopback in this environment: %v", err)
	}
	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		server.Close()
		t.Skipf("cannot dial UDP loopback in this environment: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A resolver that cannot answer at all.
	resolver := func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg { return nil }

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = serveDNSPacketConn(ctx, server, resolver)
	}()

	query := new(mDNS.Msg)
	query.SetQuestion("example.com.", mDNS.TypeA)
	packedQuery, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(packedQuery); err != nil {
		t.Fatalf("send query: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 4096)
	n, err := client.Read(buffer)
	if err != nil {
		// The timeout message names the failure mode directly.
		t.Fatalf("a resolver that cannot answer must still produce a SERVFAIL reply, "+
			"not silence: %v", err)
	}
	var response mDNS.Msg
	if err := response.Unpack(buffer[:n]); err != nil {
		t.Fatalf("the SERVFAIL reply must be parseable: %v", err)
	}
	if response.Rcode != mDNS.RcodeServerFailure {
		t.Fatalf("want SERVFAIL, got %s", mDNS.RcodeToString[response.Rcode])
	}
	if response.Id != query.Id {
		t.Fatal("the SERVFAIL reply must echo the query ID")
	}
	cancel()
	<-done
}
