//go:build unix

package cronet

import (
	"context"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
)

// TestDNSPacketConnAnswersOnAnonymousSocketpair is the Linux regression for the DNS
// bridge.
//
// The client hands serveDNSPacketConn the proxy end of an anonymous AF_UNIX
// SOCK_DGRAM socketpair, whose peer has no name. A reply sent through a bound
// WriteTo cannot be delivered there - UnixConn rejects the nil address with EINVAL -
// so the bridge stayed silent, Chromium fell back to the system resolver, and the
// client dialled the system-resolved address (172.66.157.237:10443 in the failing
// log) instead of the configured server, ending in a connect timeout.
//
// The test drives the same helper the client uses, so it fails on the old reply path
// and passes on the address-aware one.
func TestDNSPacketConnAnswersOnAnonymousSocketpair(t *testing.T) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		t.Skip("the client uses a connected UDP loopback pair on these platforms; TestUDPBridgeAnswersAndTruncates covers that shape")
	}

	fd, proxyConn, err := createPacketSocketPair(false)
	if err != nil {
		t.Fatalf("create the datagram socketpair: %v", err)
	}
	defer proxyConn.Close()

	clientFile := os.NewFile(uintptr(fd), "dns-bridge-client")
	clientConn, err := net.FilePacketConn(clientFile)
	_ = clientFile.Close()
	if err != nil {
		t.Fatalf("wrap the client end: %v", err)
	}
	defer clientConn.Close()
	clientUnix, isUnix := clientConn.(*net.UnixConn)
	if !isUnix {
		t.Skipf("the platform handed out %T instead of an anonymous socketpair", clientConn)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = serveDNSPacketConn(ctx, proxyConn, func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg {
			response := new(mDNS.Msg)
			response.SetReply(request)
			record, recordErr := mDNS.NewRR("example.org. 60 IN A 192.0.2.1")
			if recordErr == nil {
				response.Answer = append(response.Answer, record)
			}
			return response
		})
	}()

	query := new(mDNS.Msg)
	query.SetQuestion("example.org.", mDNS.TypeA)
	packedQuery, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}

	before := dnsReplyFailures.Load()
	if err = clientUnix.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set the client deadline: %v", err)
	}
	if _, err = clientUnix.Write(packedQuery); err != nil {
		t.Fatalf("send the query on the client end: %v", err)
	}
	buffer := make([]byte, 4096)
	read, readErr := clientUnix.Read(buffer)
	cancel()
	<-done
	if readErr != nil {
		t.Fatalf("the bridge must answer on the anonymous socketpair "+
			"(failed replies during this query: %d): %v", dnsReplyFailures.Load()-before, readErr)
	}

	var response mDNS.Msg
	if err = response.Unpack(buffer[:read]); err != nil {
		t.Fatalf("the reply must be a DNS message: %v", err)
	}
	if response.Id != query.Id || !response.Response {
		t.Fatalf("reply id=%d response=%v, want the query id %d and a response", response.Id, response.Response, query.Id)
	}
	if failed := dnsReplyFailures.Load() - before; failed != 0 {
		t.Fatalf("a delivered reply must not be counted as a failure, got %d", failed)
	}
}
