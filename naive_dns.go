package cronet

// DNS Hijacking Logic for ServerName Resolution
//
// Priority: serverName (SNI) = ServerName config > ServerAddress
//
// HTTPS queries for serverName (ECH):
//   - If fixed ECHConfigList exists: return synthetic response immediately
//   - Otherwise: forward query (priority: ECHQueryServerName > serverName)
//   - Always filter ipv4hint/ipv6hint to prevent incorrect IP usage

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"

	mDNS "github.com/miekg/dns"
)

// DNSResolverFunc resolves a DNS request into a DNS response.
//
// The resolver is used by NaiveClient's optional in-process DNS server. The
// returned message should be a response to the request; the implementation
// will normalize the ID and question section as needed.
type DNSResolverFunc func(ctx context.Context, request *mDNS.Msg) (response *mDNS.Msg)

// chromiumDNSUDPMaxSize is the UDP receive buffer for the in-process DNS server
// that Chromium's resolver is pointed at, and the threshold above which a response
// is truncated (TC=1) so Chromium retries over TCP.
//
// These are two DIFFERENT roles and the constant is used for both:
//
//   - as a RECEIVE buffer it must be large enough for any query Chromium sends.
//     Measured against the queries this path actually carries, the largest is a
//     253-character QNAME with EDNS0 at 281 bytes; plain A is 29, EDNS0 4096 is 40,
//     HTTPS/SVCB is 40, and ECS is 51. 512 therefore has headroom, and a truncated
//     read would be worse than an oversized buffer because it fails silently:
//     ReadFrom returns the bytes that fit, Msg.Unpack then fails, and the loop
//     continues WITHOUT answering, leaving Chromium to time out instead of getting
//     an error.
//
//   - as a RESPONSE threshold the 512 default is correct and must NOT be raised:
//     it is what produces TC=1, which is the protocol's signal for Chromium to
//     retry over TCP and get the full answer. Raising it would let oversized
//     responses go out over UDP instead.
//
// Because the two roles want different values, the receive buffer is now sized
// separately and deliberately, while the truncation threshold keeps the classic
// 512. See chromiumDNSResponseMaxSize.
const (
	// chromiumDNSQueryBufferSize sizes the UDP receive buffer. DNS's own maximum
	// UDP payload is 65535, but a query is bounded far below that: a 253-byte
	// QNAME plus EDNS0 plus one ECS option measured 281 bytes. 4096 is the
	// conventional EDNS0 buffer size and leaves a wide margin over anything
	// Chromium sends, without inviting a large allocation per packet.
	chromiumDNSQueryBufferSize = 4096

	// chromiumDNSResponseMaxSize is the truncation threshold for responses. This
	// is the classic DNS UDP limit and must stay 512: exceeding it is what sets
	// TC=1 and moves Chromium to TCP.
	chromiumDNSResponseMaxSize = 512

	// maxDNSMessageSize bounds a message accepted from a peer on the TCP path. It
	// is checked BEFORE the body is read, so an overlong prefix is rejected
	// immediately instead of leaving io.ReadFull blocked until the read deadline.
	//
	// 65535 would be no limit at all, since that is exactly what a 16-bit prefix
	// can express: the check would never fire. A DNS message is capped at 65535
	// bytes by its own protocol, and the 2-byte prefix here occupies part of that
	// budget, so the largest message this framing can carry is 65535 - 2.
	maxDNSMessageSize = 65535 - 2
)

// fakeServerAddress is the address returned for the server name's A query. It is
// never dialled: the TCP/UDP dialer callbacks map it back to the configured
// server address and let that dialer resolve the name with the host's DNS policy.
var fakeServerAddress = netip.AddrFrom4([4]byte{192, 0, 2, 1})

// dnsReplyFailures counts replies the packet bridge could not put on the wire.
//
// The loop deliberately does not log per query (see the write-error comment below),
// so this counter is how a failure stays observable rather than silent: tests assert
// it, and a future periodic summary can read it.
var dnsReplyFailures atomic.Uint64

// writePacketConnWithoutAddress replies on a datagram connection that reports no peer
// address: the anonymous AF_UNIX SOCK_DGRAM socketpair the Linux client uses, whose
// two ends are already connected and whose peer has no name to WriteTo.
//
// The connection still has to be a net.Conn for the write to have a destination at
// all. The check is on the address, not on "implements net.Conn", because an
// unconnected *net.UDPConn implements net.Conn too and would fail here with
// "destination address required".
func writePacketConnWithoutAddress(conn net.PacketConn, payload []byte) error {
	writer, isConn := conn.(net.Conn)
	if !isConn {
		return E.New("dns bridge: packet connection reported no peer address and is not writable without one")
	}
	_, err := writer.Write(payload)
	return err
}

func serveDNSPacketConn(ctx context.Context, conn net.PacketConn, resolver DNSResolverFunc) error {
	defer conn.Close()

	if ctx.Done() != nil {
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-ctx.Done():
				conn.Close()
			case <-done:
			}
		}()
	}

	buffer := make([]byte, chromiumDNSQueryBufferSize)
	for {
		conn.SetReadDeadline(time.Now().Add(15 * time.Second))

		n, remoteAddress, err := conn.ReadFrom(buffer)
		if err != nil {
			return err
		}

		var request mDNS.Msg
		err = request.Unpack(buffer[:n])
		if err != nil {
			// A malformed request cannot be answered: there is no reliable ID or
			// question to reply to. Dropping it is correct - the sender either
			// retries or times out, and Chromium does not send malformed queries.
			continue
		}

		response := resolver(ctx, &request)
		response = normalizeDNSResponse(&request, response)

		packed, err := response.Pack()
		if err != nil {
			// The resolver returned something unpackable. Answer SERVFAIL rather
			// than dropping: dropping makes Chromium wait for the full resolver
			// timeout, whereas SERVFAIL fails fast and is what a broken upstream
			// should produce.
			//
			// "Do not drop silently" here means "do not drop the QUERY", not "log
			// it". There is still no log line, for the reason given at the write
			// error above.
			if servfail, servfailErr := minimalSERVFAIL(&request, response.Rcode); servfailErr == nil {
				packed = servfail
			} else {
				continue
			}
		}
		if len(packed) > chromiumDNSResponseMaxSize {
			truncated := truncatedDNSResponse(&request, response.Rcode)
			packed, err = truncated.Pack()
			if err != nil {
				if servfail, servfailErr := minimalSERVFAIL(&request, mDNS.RcodeServerFailure); servfailErr == nil {
					packed = servfail
				} else {
					continue
				}
			}
		}

		// Reply to the address the query came from.
		//
		// Three shapes reach this loop, and the address ReadFrom reports is what
		// tells them apart:
		//
		//   - an unconnected UDP listener: the reply must name its destination, so
		//     it goes through a bound PacketConn.
		//   - a connected UDP socket (the Windows pair, and the Linux loopback
		//     pair): ReadFrom reports the peer, and a bound WriteTo that names it is
		//     what this code has always done on those platforms.
		//   - an anonymous AF_UNIX SOCK_DGRAM socketpair, which is the Linux
		//     default: the two ends are already connected and the peer has no name
		//     at all, so ReadFrom reports a nil address. There is nothing to
		//     WriteTo, and UnixConn rejects a nil (or foreign) address with EINVAL,
		//     so the reply has to go out on the connected endpoint with Write.
		//
		// The distinction cannot be "does this conn implement net.Conn": an
		// unconnected *net.UDPConn implements it too, and Write on that socket
		// fails with "destination address required". It is the peer address that
		// decides.
		var writeErr error
		if remoteAddress == nil {
			writeErr = writePacketConnWithoutAddress(conn, packed)
		} else {
			writeConn := bufio.NewBindPacketConn(conn, remoteAddress)
			_, writeErr = writeConn.Write(packed)
		}
		if writeErr != nil {
			// Keep serving: a transient send error must not kill the bridge.
			//
			// The error is deliberately NOT logged. This is the per-query path and
			// Chromium's resolver issues queries continuously, so a condition that
			// persists - the peer gone, the socket buffer full - would produce one
			// log line per query indefinitely. The loop takes no logger argument for
			// this reason. The counter is what keeps the failure visible without that
			// spam: it is what a test asserts on, and what a future summary can read.
			dnsReplyFailures.Add(1)
			continue
		}
	}
}

func serveDNSStreamConn(ctx context.Context, conn net.Conn, resolver DNSResolverFunc) error {
	defer conn.Close()

	if ctx.Done() != nil {
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-ctx.Done():
				conn.Close()
			case <-done:
			}
		}()
	}

	for {
		conn.SetReadDeadline(time.Now().Add(15 * time.Second))

		var queryLength uint16
		err := binary.Read(conn, binary.BigEndian, &queryLength)
		if err != nil {
			return err
		}
		if queryLength == 0 {
			return nil
		}
		// Cap the declared length before allocating.
		//
		// The prefix is 16 bits, so a peer can ask the bridge to reserve 65535 bytes
		// per connection. More importantly, a length that the peer never follows
		// with data leaves io.ReadFull blocked until the 15-second deadline, and the
		// caller discards that error, so the failure is invisible. A DNS message
		// cannot legitimately exceed 65535 bytes on the wire, but for a QUERY - which
		// is all this loop carries - the real bound is far lower. Reject anything
		// above the same ceiling the UDP path uses so the two paths agree on what a
		// message can be.
		if int(queryLength) > maxDNSMessageSize {
			return E.New("DNS message of ", queryLength, " bytes exceeds the ",
				maxDNSMessageSize, "-byte limit")
		}

		query := make([]byte, int(queryLength))
		_, err = io.ReadFull(conn, query)
		if err != nil {
			return err
		}

		var request mDNS.Msg
		err = request.Unpack(query)
		if err != nil {
			// Malformed request: as on the UDP path, there is nothing reliable to
			// answer, so drop it and keep the connection usable.
			continue
		}

		response := resolver(ctx, &request)
		response = normalizeDNSResponse(&request, response)

		packed, err := response.Pack()
		if err != nil {
			// Fail fast with SERVFAIL rather than leaving Chromium to time out.
			if servfail, servfailErr := minimalSERVFAIL(&request, response.Rcode); servfailErr == nil {
				packed = servfail
			} else {
				continue
			}
		}

		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		// The 2-byte length prefix and the message are a single logical frame: a
		// partial write of either corrupts the stream, so both must complete.
		// net.Conn normally reports a short write with an error, but the io.Writer
		// contract permits n < len(p) with a nil error, and a net.Conn is an
		// io.Writer.
		var lengthPrefix [2]byte
		binary.BigEndian.PutUint16(lengthPrefix[:], uint16(len(packed)))
		if _, err := writeFullDNS(conn, lengthPrefix[:]); err != nil {
			return err
		}
		if _, err := writeFullDNS(conn, packed); err != nil {
			return err
		}
	}
}

func normalizeDNSResponse(request *mDNS.Msg, response *mDNS.Msg) *mDNS.Msg {
	if response == nil {
		fallback := new(mDNS.Msg)
		fallback.SetReply(request)
		fallback.Rcode = mDNS.RcodeServerFailure
		return fallback
	}

	response.Id = request.Id
	response.Response = true
	if len(response.Question) == 0 {
		response.Question = request.Question
	}
	return response
}

func truncatedDNSResponse(request *mDNS.Msg, rcode int) *mDNS.Msg {
	response := new(mDNS.Msg)
	response.SetReply(request)
	response.Truncated = true
	response.Rcode = rcode
	return response
}

func wrapDNSResolverWithECH(
	resolver DNSResolverFunc,
	serverName string,
	echQueryServerName string,
	echConfigGetter func() []byte,
	quicEnabled bool,
	l logger.ContextLogger,
) DNSResolverFunc {
	return func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg {
		if len(request.Question) > 0 {
			question := request.Question[0]
			if question.Qtype == mDNS.TypeHTTPS && matchesServerName(question.Name, serverName) {
				echConfig := echConfigGetter()
				if len(echConfig) > 0 {
					var alpn []string
					if quicEnabled {
						alpn = []string{"h3"}
					} else {
						alpn = []string{"h2"}
					}
					l.DebugContext(ctx, "ech config injected, length: ", len(echConfig))
					return injectECHConfig(request, nil, echConfig, alpn)
				}

				var response *mDNS.Msg
				if echQueryServerName != serverName {
					redirectedRequest := request.Copy()
					redirectedRequest.Question[0].Name = rewriteHTTPSQueryName(question.Name, serverName, echQueryServerName)
					response = resolver(ctx, redirectedRequest)
					if response != nil {
						response = response.Copy()
						response.Question = request.Question
						rewriteHTTPSAnswerNames(response, echQueryServerName, serverName)
					}
				} else {
					response = resolver(ctx, request)
					if response != nil {
						response = response.Copy()
					}
				}

				filterIPHintsFromHTTPS(response)
				return response
			}
		}
		return resolver(ctx, request)
	}
}

func rewriteHTTPSQueryName(queryName, fromServer, toServer string) string {
	queryName = strings.TrimSuffix(queryName, ".")
	fromServer = strings.TrimSuffix(fromServer, ".")
	toServer = strings.TrimSuffix(toServer, ".")

	if strings.HasPrefix(queryName, "_") {
		parts := strings.SplitN(queryName, "._https.", 2)
		if len(parts) == 2 && strings.EqualFold(parts[1], fromServer) {
			return parts[0] + "._https." + toServer + "."
		}
	}

	if strings.EqualFold(queryName, fromServer) {
		return toServer + "."
	}

	return queryName + "."
}

func rewriteHTTPSAnswerNames(response *mDNS.Msg, fromServer, toServer string) {
	fromServer = strings.TrimSuffix(fromServer, ".")
	toServer = strings.TrimSuffix(toServer, ".")

	for _, rr := range response.Answer {
		if https, ok := rr.(*mDNS.HTTPS); ok {
			hdrName := strings.TrimSuffix(https.Hdr.Name, ".")
			if strings.EqualFold(hdrName, fromServer) {
				https.Hdr.Name = toServer + "."
			} else if strings.HasPrefix(hdrName, "_") {
				parts := strings.SplitN(hdrName, "._https.", 2)
				if len(parts) == 2 && strings.EqualFold(parts[1], fromServer) {
					https.Hdr.Name = parts[0] + "._https." + toServer + "."
				}
			}
			targetName := strings.TrimSuffix(https.Target, ".")
			if strings.EqualFold(targetName, fromServer) {
				https.Target = toServer + "."
			}
		}
	}
}

func matchesServerName(queryName, serverName string) bool {
	queryName = strings.TrimSuffix(queryName, ".")
	serverName = strings.TrimSuffix(serverName, ".")

	if strings.EqualFold(queryName, serverName) {
		return true
	}

	if strings.HasPrefix(queryName, "_") {
		parts := strings.SplitN(queryName, "._https.", 2)
		if len(parts) == 2 {
			return strings.EqualFold(parts[1], serverName)
		}
	}

	return false
}

func injectECHConfig(request *mDNS.Msg, response *mDNS.Msg, echConfig []byte, alpn []string) *mDNS.Msg {
	if response == nil {
		response = new(mDNS.Msg)
		response.SetReply(request)
	}

	var servicePort uint16
	var hasServicePort bool
	if len(request.Question) > 0 {
		servicePort, hasServicePort = parseHTTPSServicePort(request.Question[0].Name)
	}

	hasHTTPS := false
	for _, rr := range response.Answer {
		if https, ok := rr.(*mDNS.HTTPS); ok {
			hasHTTPS = true
			updateECHInSVCB(&https.SVCB, echConfig)
			if hasServicePort {
				updatePortInSVCB(&https.SVCB, servicePort)
			}
		}
	}

	if !hasHTTPS && len(request.Question) > 0 {
		queryName := request.Question[0].Name
		targetName := queryName
		if strings.HasPrefix(queryName, "_") {
			parts := strings.SplitN(queryName, "._https.", 2)
			if len(parts) == 2 {
				targetName = parts[1]
			}
		}

		https := &mDNS.HTTPS{
			SVCB: mDNS.SVCB{
				Hdr: mDNS.RR_Header{
					Name:   queryName,
					Rrtype: mDNS.TypeHTTPS,
					Class:  mDNS.ClassINET,
					Ttl:    300,
				},
				Priority: 1,
				Target:   targetName,
			},
		}
		if hasServicePort {
			https.Value = append(https.Value, &mDNS.SVCBPort{Port: servicePort})
		}
		https.Value = append(https.Value, &mDNS.SVCBAlpn{Alpn: alpn})
		https.Value = append(https.Value, &mDNS.SVCBECHConfig{ECH: echConfig})
		response.Answer = append(response.Answer, https)
	}

	return response
}

func updateECHInSVCB(svcb *mDNS.SVCB, echConfig []byte) {
	for i, kv := range svcb.Value {
		if _, ok := kv.(*mDNS.SVCBECHConfig); ok {
			svcb.Value[i] = &mDNS.SVCBECHConfig{ECH: echConfig}
			return
		}
	}
	svcb.Value = append(svcb.Value, &mDNS.SVCBECHConfig{ECH: echConfig})
}

func updatePortInSVCB(svcb *mDNS.SVCB, port uint16) {
	for i, kv := range svcb.Value {
		if _, ok := kv.(*mDNS.SVCBPort); ok {
			svcb.Value[i] = &mDNS.SVCBPort{Port: port}
			return
		}
	}
	svcb.Value = append(svcb.Value, &mDNS.SVCBPort{Port: port})
}

func parseHTTPSServicePort(queryName string) (uint16, bool) {
	trimmedName := strings.TrimSuffix(queryName, ".")
	if !strings.HasPrefix(trimmedName, "_") {
		return 0, false
	}
	parts := strings.SplitN(trimmedName, "._https.", 2)
	if len(parts) != 2 {
		return 0, false
	}
	portValue, err := strconv.Atoi(strings.TrimPrefix(parts[0], "_"))
	if err != nil || portValue <= 0 || portValue > 65535 {
		return 0, false
	}
	return uint16(portValue), true
}

func filterIPHintsFromHTTPS(response *mDNS.Msg) {
	if response == nil {
		return
	}
	for _, rr := range response.Answer {
		if https, ok := rr.(*mDNS.HTTPS); ok {
			filterIPHintsFromSVCB(&https.SVCB)
		}
	}
}

func filterIPHintsFromSVCB(svcb *mDNS.SVCB) {
	filtered := svcb.Value[:0]
	for _, kv := range svcb.Value {
		switch kv.(type) {
		case *mDNS.SVCBIPv4Hint, *mDNS.SVCBIPv6Hint:
		default:
			filtered = append(filtered, kv)
		}
	}
	svcb.Value = filtered
}

func wrapDNSResolverWithFakeServerAddress(resolver DNSResolverFunc, serverName string) DNSResolverFunc {
	serverFQDN := mDNS.Fqdn(serverName)
	return func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg {
		if len(request.Question) == 0 {
			return resolver(ctx, request)
		}
		question := request.Question[0]
		if question.Qtype != mDNS.TypeA && question.Qtype != mDNS.TypeAAAA || !strings.EqualFold(question.Name, serverFQDN) {
			return resolver(ctx, request)
		}
		response := new(mDNS.Msg)
		response.SetReply(request)
		if question.Qtype == mDNS.TypeA {
			response.Answer = append(response.Answer, &mDNS.A{
				Hdr: mDNS.RR_Header{
					Name:   question.Name,
					Rrtype: mDNS.TypeA,
					Class:  mDNS.ClassINET,
					Ttl:    300,
				},
				A: fakeServerAddress.AsSlice(),
			})
		}
		return response
	}
}

// minimalSERVFAIL builds the smallest valid SERVFAIL reply to request.
//
// Used when the resolver's answer cannot be packed, so the failure is reported to
// Chromium immediately instead of leaving it to wait out a resolver timeout. The
// reply echoes the request's ID and question, which is what makes it a valid
// response rather than a stray packet.
func minimalSERVFAIL(request *mDNS.Msg, rcode int) ([]byte, error) {
	response := new(mDNS.Msg)
	response.SetReply(request)
	if rcode == mDNS.RcodeSuccess {
		// A pack failure on a successful rcode still has to be reported as a
		// failure; keeping RcodeSuccess would be a lie.
		rcode = mDNS.RcodeServerFailure
	}
	response.Rcode = rcode
	response.Answer = nil
	response.Ns = nil
	response.Extra = nil
	return response.Pack()
}

// writeFullDNS writes all of data, converting a short write into io.ErrShortWrite.
//
// The DNS stream framing is a 2-byte length prefix followed by the message; a
// partial write of either leaves the peer parsing garbage, so both must complete.
func writeFullDNS(writer io.Writer, data []byte) (int, error) {
	written, err := writer.Write(data)
	if err != nil {
		return written, err
	}
	if written != len(data) {
		return written, io.ErrShortWrite
	}
	return written, nil
}
