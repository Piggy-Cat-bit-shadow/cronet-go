package cronet

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ N.Dialer = (*NaiveClient)(nil)

type QUICCongestionControl string

const (
	QUICCongestionControlDefault QUICCongestionControl = ""
	QUICCongestionControlBBR     QUICCongestionControl = "TBBR"
	QUICCongestionControlBBRv2   QUICCongestionControl = "B2ON"
	// QUICHE selects Cubic on the QBIC tag only when the quic_default_to_bbr
	// reloadable flag is set, and Chromium builds it with that flag false; CQBC
	// is the client-only tag QuicSentPacketManager honors unconditionally.
	QUICCongestionControlCubic QUICCongestionControl = "CQBC"
	QUICCongestionControlReno  QUICCongestionControl = "RENO"
)

type clientState uint32

const (
	clientStateCreated clientState = iota
	clientStateStarting
	clientStateRunning
	clientStateClosing
	clientStateClosed
)

// Naive control headers.
//
// These are consumed by the Naive implementation rather than forwarded as
// ordinary request headers, and overriding them changes protocol behaviour:
//
//	Padding                 enables the padded framing on the SERVER side. An empty
//	                        value turns framing off at the server while this client
//	                        keeps framing, so every byte after CONNECT is
//	                        misinterpreted - a guaranteed stream corruption.
//	Proxy-Authorization     the credentials. Overriding it contradicts an explicit
//	                        username/password configuration and yields an
//	                        unexplained 407.
//	-connect-authority      the CONNECT target. Overriding it can make the tunnel
//	                        reach a host the user never configured, which is a
//	                        routing-integrity failure.
//	-force-quic              selects the QUIC path.
//	-network-isolation-key  the connection-pool isolation key. This one is written
//	                        AFTER the extraHeaders loop, so it was never
//	                        overridable, but it is listed for completeness so the
//	                        set stays honest as the implementation changes.
//
// HTTP header names are case-insensitive, so "Padding", "padding" and "PADDING"
// are the same header and must all collide. The dashes-prefixed entries are
// Cronet-internal pseudo-controls; they are matched case-insensitively too, which
// is strictly safer than matching them exactly.
var reservedNaiveHeaders = []string{
	"Padding",
	"Proxy-Authorization",
	"-connect-authority",
	"-force-quic",
	"-network-isolation-key",
}

// IsReservedNaiveHeader reports whether name collides with a Naive control header.
//
// The comparison is case-insensitive, because that is how HTTP treats header
// names: a case-sensitive check would let "padding" through and corrupt the
// stream.
func IsReservedNaiveHeader(name string) bool {
	for _, reserved := range reservedNaiveHeaders {
		if strings.EqualFold(name, reserved) {
			return true
		}
	}
	return false
}

// ValidateExtraHeaders rejects a user header set that would override a control
// header, so the misconfiguration surfaces as a configuration error instead of a
// stream corruption, an unexplained 407, or a tunnel to the wrong host.
func ValidateExtraHeaders(extraHeaders map[string]string) error {
	for key := range extraHeaders {
		if IsReservedNaiveHeader(key) {
			return E.New("extra_headers must not override the reserved Naive control header ", key)
		}
	}
	return nil
}

type NaiveClient struct {
	state                    atomic.Uint32
	ctx                      context.Context
	dialer                   N.Dialer
	logger                   logger.ContextLogger
	serverAddress            M.Socksaddr
	serverName               string
	serverURL                string
	authorization            string
	concurrency              int
	extraHeaders             map[string]string
	receiveWindow            uint64
	trustedRootCertificates  string
	dnsResolver              DNSResolverFunc
	echEnabled               bool
	echConfigList            []byte
	echQueryServerName       string
	echMutex                 sync.RWMutex
	testForceUDPLoopback     bool
	quicEnabled              bool
	quicCongestionControl    QUICCongestionControl
	quicSessionReceiveWindow uint64
	counter                  atomic.Uint64
	started                  chan struct{}
	singleEngine             bool
	engines                  []Engine
	streamEngines            []StreamEngine
	activeConnections        sync.WaitGroup
	proxyWaitGroup           sync.WaitGroup
	proxyCancel              context.CancelFunc
}

type NaiveClientOptions struct {
	Context                  context.Context
	ServerAddress            M.Socksaddr
	ServerName               string
	Username                 string
	Password                 string
	InsecureConcurrency      int
	ReceiveWindow            uint64
	ExtraHeaders             map[string]string
	TrustedRootCertificates  string
	DNSResolver              DNSResolverFunc
	Logger                   logger.ContextLogger
	Dialer                   N.Dialer
	ECHEnabled               bool
	ECHConfigList            []byte
	ECHQueryServerName       string
	TestForceUDPLoopback     bool
	TestForceSingleEngine    bool
	QUIC                     bool
	QUICCongestionControl    QUICCongestionControl
	QUICSessionReceiveWindow uint64
}

func NewNaiveClient(config NaiveClientOptions) (*NaiveClient, error) {
	// Reject a reserved-header collision BEFORE anything else, so the
	// misconfiguration is reported as a configuration error and does not depend
	// on the native library being loadable.
	if err := ValidateExtraHeaders(config.ExtraHeaders); err != nil {
		return nil, err
	}
	err := checkLibrary()
	if err != nil {
		return nil, err
	}
	return newNaiveClientWithoutLibraryCheck(config)
}

// newNaiveClientWithoutLibraryCheck builds the client without requiring the native
// library to be loadable.
//
// It exists so the lifecycle state machine - the CAS transitions in Start and Close,
// and the cleanup they promise - can be tested on any machine, including CI runners
// with no Cronet build. That logic is pure Go and its failure modes (a leaked
// goroutine, a Close that never completes, a second Close that panics) are exactly
// the ones that only show up under -race or in a long-running client, so it should
// not be reachable only through a test that needs native binaries.
//
// It is unexported and performs no I/O, so it cannot be used to skip the library
// check in production: NewNaiveClient always calls checkLibrary first.
func newNaiveClientWithoutLibraryCheck(config NaiveClientOptions) (*NaiveClient, error) {
	if !config.ServerAddress.IsValid() {
		return nil, E.New("invalid server address")
	}
	if config.DNSResolver == nil {
		return nil, E.New("DNSResolver is required")
	}

	serverName := config.ServerName
	if serverName == "" {
		serverName = config.ServerAddress.AddrString()
	}

	serverURL := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(serverName, F.ToString(config.ServerAddress.Port)),
	}

	var authorization string
	if config.Username != "" {
		authorization = "Basic " + base64.StdEncoding.EncodeToString(
			[]byte(config.Username+":"+config.Password))
	}

	concurrency := config.InsecureConcurrency
	if concurrency < 1 {
		concurrency = 1
	}

	ctx := config.Context
	if ctx == nil {
		ctx = context.Background()
	}

	dialer := config.Dialer
	if dialer == nil {
		dialer = N.SystemDialer
	}

	l := config.Logger
	if l == nil {
		l = logger.NOP()
	}

	return &NaiveClient{
		ctx:                      ctx,
		dialer:                   dialer,
		logger:                   l,
		serverAddress:            config.ServerAddress,
		serverName:               serverName,
		serverURL:                serverURL.String(),
		authorization:            authorization,
		extraHeaders:             config.ExtraHeaders,
		concurrency:              concurrency,
		trustedRootCertificates:  config.TrustedRootCertificates,
		dnsResolver:              config.DNSResolver,
		echEnabled:               config.ECHEnabled,
		echConfigList:            config.ECHConfigList,
		echQueryServerName:       config.ECHQueryServerName,
		testForceUDPLoopback:     config.TestForceUDPLoopback,
		singleEngine:             config.TestForceSingleEngine || runtime.GOOS == "ios",
		quicEnabled:              config.QUIC,
		quicCongestionControl:    config.QUICCongestionControl,
		receiveWindow:            config.ReceiveWindow,
		quicSessionReceiveWindow: config.QUICSessionReceiveWindow,
		started:                  make(chan struct{}),
	}, nil
}

func (c *NaiveClient) Start() error {
	if !c.state.CompareAndSwap(uint32(clientStateCreated), uint32(clientStateStarting)) {
		state := clientState(c.state.Load())
		switch state {
		case clientStateStarting:
			return errors.New("start already in progress")
		case clientStateRunning:
			return errors.New("already started")
		default:
			return net.ErrClosed
		}
	}

	var startError error
	var engines []Engine

	// The engine creation path panics rather than returning an error when the native
	// library cannot be loaded (internal/cronet.ensureLoaded calls panic(err), reached
	// through NewEngine). Convert that into an ordinary error.
	//
	// Without this, Start panics and the deferred cleanup below NEVER RUNS, because a
	// panic unwinds past it. The result was that a failed start left the state at
	// clientStateStarting, never closed the started channel, and leaked any engines
	// already created - so every later Start returned "start already in progress" and
	// every Close blocked forever waiting on that channel.
	defer func() {
		if recovered := recover(); recovered != nil {
			startError = E.Cause(panicError(recovered), "start cronet engine")
			if c.proxyCancel != nil {
				c.proxyCancel()
			}
			for _, engine := range engines {
				engine.Shutdown()
				engine.Destroy()
			}
			c.state.Store(uint32(clientStateClosed))
			close(c.started)
		}
	}()

	defer func() {
		if startError != nil {
			if c.proxyCancel != nil {
				c.proxyCancel()
			}
			for _, engine := range engines {
				engine.Shutdown()
				engine.Destroy()
			}
			c.state.Store(uint32(clientStateClosed))
			close(c.started)
		}
	}()

	proxyContext, proxyCancel := context.WithCancel(c.ctx)
	c.proxyCancel = proxyCancel

	dnsServerAddress := M.ParseSocksaddrHostPort("127.0.0.1", 53)
	dnsResolver := c.dnsResolver

	if c.serverName != c.serverAddress.AddrString() {
		dnsResolver = wrapDNSResolverForServerRedirect(dnsResolver, c.serverName, c.serverAddress)
	}

	if c.echEnabled {
		echQueryServerName := c.echQueryServerName
		if echQueryServerName == "" {
			echQueryServerName = c.serverName
		}
		dnsResolver = wrapDNSResolverWithECH(dnsResolver, c.serverName, echQueryServerName, c.getECHConfigList, c.quicEnabled, c.logger)
	}

	tcpDialer := Dialer(func(address string, port uint16) int {
		if address == dnsServerAddress.AddrString() && port == dnsServerAddress.Port {
			fd, conn, err := createSocketPair()
			if err != nil {
				c.logger.ErrorContext(c.ctx, "socket pair failed: ", err)
				return NetErrorConnectionFailed.Code()
			}

			go func() {
				_ = serveDNSStreamConn(proxyContext, conn, dnsResolver)
			}()

			return fd
		}

		destination := M.ParseSocksaddrHostPort(address, port)
		c.logger.DebugContext(c.ctx, "open TCP connection to ", destination)
		conn, err := c.dialer.DialContext(proxyContext, N.NetworkTCP, destination)
		if err != nil {
			c.logger.ErrorContext(c.ctx, "open TCP connection to ", destination, ": ", err)
			return toNetError(err).Code()
		}

		if tcpConn, ok := N.CastReader[*net.TCPConn](conn); ok {
			fd, duplicateError := dupSocketFD(tcpConn)
			if duplicateError == nil {
				conn.Close()
				return fd
			}
		}

		c.logger.DebugContext(c.ctx, "relaying TCP connection to ", destination)
		fd, pipeConn, err := createSocketPair()
		if err != nil {
			c.logger.ErrorContext(c.ctx, "socket pair failed: ", err)
			conn.Close()
			return NetErrorConnectionFailed.Code()
		}

		c.proxyWaitGroup.Add(1)
		go func() {
			defer c.proxyWaitGroup.Done()
			bufio.CopyConn(proxyContext, conn, pipeConn)
			conn.Close()
			pipeConn.Close()
		}()

		return fd
	})

	udpDialer := UDPDialer(func(address string, port uint16) (fd int, localAddress string, localPort uint16, onClose func()) {
		if address == dnsServerAddress.AddrString() && port == dnsServerAddress.Port {
			fd, conn, err := createPacketSocketPair(c.testForceUDPLoopback)
			if err != nil {
				c.logger.ErrorContext(c.ctx, "socket pair failed: ", err)
				return NetErrorConnectionFailed.Code(), "", 0, nil
			}
			localAddr := M.SocksaddrFromNet(conn.LocalAddr())
			if localAddr.IsValid() {
				localAddress = localAddr.AddrString()
				localPort = localAddr.Port
			}

			dnsContext, dnsCancel := context.WithCancel(proxyContext)
			go func() {
				defer dnsCancel()
				_ = serveDNSPacketConn(dnsContext, conn, dnsResolver)
			}()

			return fd, localAddress, localPort, dnsCancel
		}

		destination := M.ParseSocksaddrHostPort(address, port)
		c.logger.DebugContext(c.ctx, "open UDP connection to ", destination)
		conn, err := c.dialer.DialContext(proxyContext, N.NetworkUDP, destination)
		if err != nil {
			c.logger.ErrorContext(c.ctx, "open UDP connection to ", destination, ": ", err)
			return toNetError(err).Code(), "", 0, nil
		}

		localAddr := M.SocksaddrFromNet(conn.LocalAddr())
		if localAddr.IsValid() {
			localAddress = localAddr.AddrString()
			localPort = localAddr.Port
		}

		if udpConn, ok := N.CastReader[*net.UDPConn](conn); ok {
			fd, duplicateError := dupSocketFD(udpConn)
			if duplicateError == nil {
				conn.Close()
				return fd, localAddress, localPort, nil
			}
		}

		c.logger.DebugContext(c.ctx, "relaying UDP connection to ", destination)
		fd, pipeConn, err := createPacketSocketPair(c.testForceUDPLoopback)
		if err != nil {
			c.logger.ErrorContext(c.ctx, "socket pair failed: ", err)
			conn.Close()
			return NetErrorConnectionFailed.Code(), "", 0, nil
		}

		remoteAddress := M.SocksaddrFromNet(conn.RemoteAddr())
		packetConn := bufio.NewUnbindPacketConn(conn)
		pipePacketConn := bufio.NewUnbindPacketConnWithAddr(pipeConn.(net.Conn), remoteAddress)

		relayContext, relayCancel := context.WithCancel(proxyContext)
		c.proxyWaitGroup.Add(1)
		go func() {
			defer c.proxyWaitGroup.Done()
			defer relayCancel()
			_ = bufio.CopyPacketConn(relayContext, packetConn, pipePacketConn)
		}()

		return fd, localAddress, localPort, relayCancel
	})

	engineCount := 1
	if c.concurrency > 1 && !c.singleEngine {
		engineCount = c.concurrency
	}
	for i := 0; i < engineCount; i++ {
		var engine Engine
		engine, startError = c.startEngine(tcpDialer, udpDialer, dnsServerAddress)
		if startError != nil {
			return startError
		}
		engines = append(engines, engine)
	}

	c.engines = engines
	c.streamEngines = common.Map(engines, Engine.StreamEngine)

	c.state.Store(uint32(clientStateRunning))
	close(c.started)
	return nil
}

func (c *NaiveClient) startEngine(tcpDialer Dialer, udpDialer UDPDialer, dnsServerAddress M.Socksaddr) (Engine, error) {
	engine := NewEngine()
	destroyEngine := func() {
		engine.Shutdown()
		engine.Destroy()
	}

	if c.trustedRootCertificates != "" {
		if !engine.SetTrustedRootCertificates(c.trustedRootCertificates) {
			destroyEngine()
			return Engine{}, E.New("failed to set trusted CA certificates")
		}
	}

	engine.SetDialer(tcpDialer)
	engine.SetUDPDialer(udpDialer)

	params := NewEngineParams()
	if c.quicEnabled {
		params.SetEnableQuic(true)
	} else {
		params.SetEnableQuic(false)
		params.SetEnableHTTP2(true)
	}

	paramsError := params.SetAsyncDNS(true)
	if paramsError == nil {
		paramsError = params.SetDNSServerOverride([]string{dnsServerAddress.String()})
	}
	if paramsError == nil {
		paramsError = params.SetUseDnsHttpsSvcb(c.echEnabled)
	}
	if paramsError == nil {
		if c.quicEnabled {
			streamReceiveWindow := c.receiveWindow
			if streamReceiveWindow == 0 {
				streamReceiveWindow = 6 * 1024 * 1024
			}
			sessionReceiveWindow := c.quicSessionReceiveWindow
			if sessionReceiveWindow == 0 {
				sessionReceiveWindow = 15 * 1024 * 1024
			}
			paramsError = params.SetQUICOptions("", string(c.quicCongestionControl), streamReceiveWindow, sessionReceiveWindow)
		} else {
			receiveWindow := c.receiveWindow
			if receiveWindow == 0 {
				if runtime.GOOS == "ios" {
					receiveWindow = 4 * 1024 * 1024
				} else {
					receiveWindow = 128 * 1024 * 1024
				}
			}
			paramsError = params.SetHTTP2Options(receiveWindow, receiveWindow/2)
		}
	}
	if paramsError == nil {
		paramsError = params.SetSocketPoolOptions(2048, 2048, 2040)
	}
	if paramsError != nil {
		params.Destroy()
		destroyEngine()
		return Engine{}, paramsError
	}

	result := engine.StartWithParams(params)
	params.Destroy()
	if result != ResultSuccess {
		destroyEngine()
		return Engine{}, E.New("failed to start engine: ", int(result))
	}
	return engine, nil
}

func (c *NaiveClient) Engine() Engine {
	if clientState(c.state.Load()) != clientStateRunning {
		return Engine{}
	}
	return c.engines[0]
}

func (c *NaiveClient) CloseAllConnections() {
	if clientState(c.state.Load()) != clientStateRunning {
		return
	}
	for _, engine := range c.engines {
		engine.CloseAllConnections()
	}
}

func (c *NaiveClient) DialEarly(ctx context.Context, destination M.Socksaddr) (NaiveConn, error) {
	state := clientState(c.state.Load())
	switch state {
	case clientStateRunning:
	case clientStateClosed, clientStateClosing:
		return nil, net.ErrClosed
	default:
		select {
		case <-c.started:
			if clientState(c.state.Load()) != clientStateRunning {
				return nil, net.ErrClosed
			}
		case <-c.ctx.Done():
			return nil, c.ctx.Err()
		}
	}
	headers := map[string]string{
		"-connect-authority": destination.String(),
		"Padding":            generatePaddingHeader(),
	}
	if c.authorization != "" {
		headers["proxy-authorization"] = c.authorization
	}
	if c.quicEnabled {
		headers["-force-quic"] = "true"
	}
	// extraHeaders are user-supplied and must not override the control headers
	// above. NewNaiveClient rejects a colliding configuration up front, so this
	// loop cannot displace a control value; the guard here is defensive in case a
	// caller constructs the client without going through the constructor.
	for key, value := range c.extraHeaders {
		if IsReservedNaiveHeader(key) {
			continue
		}
		headers[key] = value
	}

	streamEngine := c.streamEngines[0]
	if c.concurrency > 1 {
		concurrencyIndex := int(c.counter.Add(1) % uint64(c.concurrency))
		if len(c.streamEngines) > 1 {
			streamEngine = c.streamEngines[concurrencyIndex]
		} else {
			headers["-network-isolation-key"] = F.ToString("https://pool-", concurrencyIndex, ":443")
		}
	}
	conn := streamEngine.CreateConn(ctx, c.logger, true, false)
	err := conn.Start("CONNECT", c.serverURL, headers, 0, false)
	if err != nil {
		return nil, err
	}
	trackedConn := &trackedNaiveConn{
		NaiveConn: NewNaiveConn(ctx, conn, c.logger),
		client:    c,
	}
	c.activeConnections.Add(1)
	conn.setOnTerminate(trackedConn.release)
	return trackedConn, nil
}

func (c *NaiveClient) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, os.ErrInvalid
	}
	conn, err := c.DialEarly(ctx, destination)
	if err != nil {
		return nil, err
	}
	err = conn.HandshakeContext(ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *NaiveClient) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (c *NaiveClient) Close() error {
	for {
		state := clientState(c.state.Load())
		switch state {
		case clientStateCreated:
			if c.state.CompareAndSwap(uint32(clientStateCreated), uint32(clientStateClosed)) {
				close(c.started)
				return nil
			}

		case clientStateStarting:
			select {
			case <-c.started:
				continue
			case <-c.ctx.Done():
				return c.ctx.Err()
			}

		case clientStateRunning:
			if !c.state.CompareAndSwap(uint32(clientStateRunning), uint32(clientStateClosing)) {
				continue
			}
			return c.doClose()

		case clientStateClosing:
			return nil

		case clientStateClosed:
			return net.ErrClosed
		}
	}
}

func (c *NaiveClient) doClose() error {
	if c.proxyCancel != nil {
		c.proxyCancel()
	}

	for _, engine := range c.engines {
		engine.CloseAllConnections()
	}
	c.proxyWaitGroup.Wait()
	c.activeConnections.Wait()
	for _, engine := range c.engines {
		engine.Shutdown()
		engine.Destroy()
	}

	c.state.Store(uint32(clientStateClosed))
	return nil
}

func (c *NaiveClient) getECHConfigList() []byte {
	c.echMutex.RLock()
	defer c.echMutex.RUnlock()
	return c.echConfigList
}

type trackedNaiveConn struct {
	NaiveConn
	client    *NaiveClient
	closeOnce sync.Once
}

func (c *trackedNaiveConn) release() {
	c.closeOnce.Do(func() {
		c.client.activeConnections.Done()
	})
}

func (c *trackedNaiveConn) Close() error {
	c.release()
	return c.NaiveConn.Close()
}

func (c *trackedNaiveConn) Upstream() any {
	return c.NaiveConn
}

func (c *trackedNaiveConn) ReaderReplaceable() bool {
	return true
}

func (c *trackedNaiveConn) WriterReplaceable() bool {
	return true
}

// panicError converts a recovered panic value into an error.
func panicError(recovered any) error {
	if err, isError := recovered.(error); isError {
		return err
	}
	return E.New(F.ToString(recovered))
}
