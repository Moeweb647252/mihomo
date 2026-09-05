package wtp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/quic-go/quicvarint"
	"github.com/metacubex/tls"
)

const (
	webTransportSetting            uint64 = 0x2b603742
	webTransportFingerprintSetting uint64 = 0x2c7cf000
	webTransportStream             uint64 = 0x41

	setupTimeout = 10 * time.Second

	maxTCPStreams     = 100
	maxIdleTCPSession = 64
	idleSession       = 60 * time.Second
	maxUDPSessions    = 64
	packetQueueSize   = 256
)

func webTransportSettings() map[uint64]uint64 {
	return map[uint64]uint64{
		0x8:                            1, // SETTINGS_ENABLE_CONNECT_PROTOCOL
		webTransportSetting:            1,
		webTransportFingerprintSetting: 1, // WTP-SW compatibility fingerprint
	}
}

var (
	errClientClosed      = errors.New("wtp: client is closed")
	errSessionClosed     = errors.New("wtp: session is closed")
	errServerUnsupported = errors.New("wtp: server does not support WebTransport")
	errUDPSessionLimit   = errors.New("wtp: UDP target session limit reached")
)

// ClientOption configures a WTP client. The transport intentionally keeps the
// WebTransport wire format private; callers only provide the proxy endpoint,
// TLS, and QUIC settings.
type ClientOption struct {
	Address     string
	Authority   string
	Path        string
	TLSConfig   *tls.Config
	QUICConfig  *quic.Config
	Dialer      common.PacketDialer
	DialOptions []dialer.Option

	CongestionController string
	CWND                 int
	BBRProfile           string
}

type requestStream interface {
	SendRequestHeader(*http.Request) error
	ReadResponse() (*http.Response, error)
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
}

// Client is a WTP outbound client. TCP sessions are pooled per logical target;
// UDP sessions are owned by the PacketConn that created them.
type Client struct {
	option ClientOption

	pool *tcpPool

	udpMu      sync.Mutex
	udpSession map[*session]struct{}

	closeOnce sync.Once
	closeErr  error
	closed    atomic.Bool
	janitor   chan struct{}
	janitorWG sync.WaitGroup
}

// NewClient creates a WTP client. The returned client does not perform network
// I/O until DialContext or ListenPacket is called.
func NewClient(option ClientOption) (*Client, error) {
	if option.Address == "" {
		return nil, errors.New("wtp: missing server address")
	}
	if option.Authority == "" {
		return nil, errors.New("wtp: missing HTTP authority")
	}
	if option.Path == "" || option.Path[0] != '/' {
		return nil, errors.New("wtp: path must start with '/'")
	}
	if option.TLSConfig == nil {
		return nil, errors.New("wtp: missing TLS configuration")
	}
	if option.QUICConfig == nil {
		return nil, errors.New("wtp: missing QUIC configuration")
	}
	if option.Dialer == nil {
		return nil, errors.New("wtp: missing packet dialer")
	}

	c := &Client{
		option:     option,
		pool:       newTCPPool(),
		udpSession: make(map[*session]struct{}),
		janitor:    make(chan struct{}),
	}
	c.janitorWG.Add(1)
	go c.runJanitor()
	return c, nil
}

// DialContext opens one TCP stream to endpoint. The endpoint is sent to the
// WTP server as-is, so domain names remain domain names for server-side DNS.
func (c *Client) DialContext(ctx context.Context, endpoint string) (net.Conn, error) {
	if endpoint == "" {
		return nil, errors.New("wtp: missing target endpoint")
	}
	if c.closed.Load() {
		return nil, errClientClosed
	}

	for attempt := 0; attempt < 2; attempt++ {
		s, err := c.pool.acquire(ctx, endpoint, func(ctx context.Context) (*session, error) {
			return c.newSession(ctx, "tcp", endpoint, func(s *session) {
				c.pool.remove(s)
			})
		})
		if err != nil {
			return nil, err
		}
		conn, err := s.openTCP(ctx, endpoint)
		if err == nil {
			return conn, nil
		}
		if isStreamLimitError(err) {
			continue
		}
		if !errors.Is(err, errSessionClosed) {
			return nil, err
		}
		c.pool.remove(s)
		_ = s.Close()
	}
	return nil, errors.New("wtp: unable to open TCP stream")
}

// ListenPacket creates a UDP PacketConn. The initial endpoint is opened before
// returning so configuration and server capability errors are reported at the
// call site. Additional destinations are opened lazily by WriteTo.
func (c *Client) ListenPacket(ctx context.Context, endpoint string, target net.Addr) (net.PacketConn, error) {
	if endpoint == "" || target == nil {
		return nil, errors.New("wtp: missing UDP target endpoint")
	}
	if c.closed.Load() {
		return nil, errClientClosed
	}

	pc := newUDPConn(c)
	if _, err := pc.ensure(ctx, target, endpoint); err != nil {
		_ = pc.Close()
		return nil, err
	}
	return pc, nil
}

// Close releases every pooled TCP session and active UDP session.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.janitor)
		c.janitorWG.Wait()

		c.closeErr = c.pool.close()

		c.udpMu.Lock()
		sessions := make([]*session, 0, len(c.udpSession))
		for s := range c.udpSession {
			sessions = append(sessions, s)
		}
		c.udpSession = make(map[*session]struct{})
		c.udpMu.Unlock()
		for _, s := range sessions {
			if err := s.Close(); err != nil && c.closeErr == nil {
				c.closeErr = err
			}
		}
	})
	return c.closeErr
}

func (c *Client) runJanitor() {
	defer c.janitorWG.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.pool.reap(idleSession, maxIdleTCPSession)
			c.reapUDPSessions()
		case <-c.janitor:
			return
		}
	}
}

func (c *Client) reapUDPSessions() {
	c.udpMu.Lock()
	var stale []*session
	for s := range c.udpSession {
		if s.protocol == "udp" && s.idleSince() >= idleSession {
			s.closed.Store(true)
			stale = append(stale, s)
		}
	}
	c.udpMu.Unlock()
	for _, s := range stale {
		_ = s.Close()
	}
}

func (c *Client) newSession(ctx context.Context, protocol, endpoint string, onClosed func(*session)) (*session, error) {
	if c.closed.Load() {
		return nil, errClientClosed
	}
	setupCtx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()

	tlsConfig := c.option.TLSConfig.Clone()
	quicConfig := c.option.QUICConfig.Clone()
	pc, qconn, err := common.DialQuic(
		setupCtx,
		c.option.Address,
		c.option.DialOptions,
		c.option.Dialer,
		tlsConfig,
		quicConfig,
		common.DialQuicOption{},
	)
	if err != nil {
		return nil, err
	}
	common.SetCongestionController(qconn, c.option.CongestionController, c.option.CWND, c.option.BBRProfile)

	s := &session{
		client:    c,
		protocol:  protocol,
		endpoint:  endpoint,
		pc:        pc,
		qconn:     qconn,
		active:    new(atomic.Int32),
		lastUsed:  new(atomic.Int64),
		onClosed:  onClosed,
		maxStream: maxTCPStreams,
	}
	s.touch()

	transport := &http3.Transport{
		EnableDatagrams:    true,
		DisableCompression: true,
		AdditionalSettings: webTransportSettings(),
	}
	s.h3 = transport.NewClientConn(qconn)

	go func() {
		<-qconn.Context().Done()
		_ = s.Close()
	}()

	select {
	case <-s.h3.ReceivedSettings():
	case <-setupCtx.Done():
		_ = s.Close()
		return nil, setupCtx.Err()
	case <-qconn.Context().Done():
		_ = s.Close()
		return nil, context.Cause(qconn.Context())
	}
	settings := s.h3.Settings()
	if settings == nil || !settings.EnableExtendedConnect || !settings.EnableDatagrams || settings.Other[webTransportSetting] == 0 {
		_ = s.Close()
		return nil, errServerUnsupported
	}

	request, err := s.h3.OpenRequestStream(setupCtx)
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	s.request = request

	u := &url.URL{Scheme: "https", Host: c.option.Authority, Path: c.option.Path}
	req := &http.Request{
		Method: http.MethodConnect,
		Proto:  "webtransport",
		Host:   c.option.Authority,
		URL:    u,
		Header: http.Header{},
	}
	req.Header.Set("Sec-Webtransport-Http3-Draft02", "1")
	req.Header.Set("Proxy-Protocol", protocol)
	req.Header.Set("Proxy-Endpoint", endpoint)
	response, err := sendRequestAndReadResponse(setupCtx, request, req)
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_ = s.Close()
		return nil, fmt.Errorf("wtp: server rejected CONNECT: %s", response.Status)
	}

	return s, nil
}

func sendRequestAndReadResponse(ctx context.Context, request requestStream, req *http.Request) (*http.Response, error) {
	done := make(chan struct{})
	stop := contextutils.AfterFunc(ctx, func() {
		defer close(done)
		request.CancelRead(0)
		request.CancelWrite(0)
	})
	finish := func(err error) error {
		if !stop() {
			<-done
			if ctxErr := context.Cause(ctx); ctxErr != nil {
				return ctxErr
			}
		}
		return err
	}

	if err := request.SendRequestHeader(req); err != nil {
		return nil, finish(err)
	}
	response, err := request.ReadResponse()
	if err = finish(err); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) registerUDP(s *session) bool {
	c.udpMu.Lock()
	defer c.udpMu.Unlock()
	if c.closed.Load() {
		return false
	}
	c.udpSession[s] = struct{}{}
	return true
}

func (c *Client) unregisterUDP(s *session) {
	c.udpMu.Lock()
	delete(c.udpSession, s)
	c.udpMu.Unlock()
}

type session struct {
	client   *Client
	protocol string
	endpoint string

	pc      net.PacketConn
	qconn   *quic.Conn
	h3      *http3.ClientConn
	request *http3.RequestStream

	active    *atomic.Int32
	lastUsed  *atomic.Int64
	maxStream int32
	full      atomic.Bool
	onClosed  func(*session)

	closeOnce sync.Once
	closeErr  error
	closed    atomic.Bool
}

func (s *session) touch() {
	s.lastUsed.Store(time.Now().UnixNano())
}

func (s *session) idleSince() time.Duration {
	last := time.Unix(0, s.lastUsed.Load())
	return time.Since(last)
}

func (s *session) reserveTCP() bool {
	if s.protocol != "tcp" || s.closed.Load() || s.full.Load() {
		return false
	}
	for {
		current := s.active.Load()
		if current >= s.maxStream {
			return false
		}
		if s.active.CompareAndSwap(current, current+1) {
			s.touch()
			return true
		}
	}
}

func (s *session) releaseTCP() {
	active := s.active.Add(-1)
	if active < 0 {
		s.active.Store(0)
	}
	s.touch()
}

func (s *session) openTCP(ctx context.Context, endpoint string) (net.Conn, error) {
	if s.closed.Load() {
		return nil, errSessionClosed
	}
	stream, err := s.qconn.OpenStream()
	if err != nil {
		if isStreamLimitError(err) {
			s.full.Store(true)
		}
		if s.qconn.Context().Err() != nil {
			s.releaseTCP()
			return nil, errSessionClosed
		}
		s.releaseTCP()
		return nil, err
	}
	header := quicvarint.Append(nil, webTransportStream)
	header = quicvarint.Append(header, uint64(s.request.StreamID()))
	if _, err := stream.Write(header); err != nil {
		_ = stream.Close()
		s.releaseTCP()
		if s.qconn.Context().Err() != nil {
			s.closed.Store(true)
			return nil, errSessionClosed
		}
		return nil, err
	}
	if ctx.Err() != nil {
		_ = stream.Close()
		s.releaseTCP()
		return nil, ctx.Err()
	}
	return &streamConn{
		Stream:  stream,
		session: s,
		remote:  endpointAddr{network: "tcp", address: endpoint},
	}, nil
}

func (s *session) sendDatagram(ctx context.Context, payload []byte) error {
	if s.closed.Load() {
		return errSessionClosed
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if err := s.request.SendDatagram(payload); err != nil {
		if s.qconn.Context().Err() != nil {
			s.closed.Store(true)
			return errSessionClosed
		}
		return err
	}
	s.touch()
	return nil
}

func (s *session) receiveDatagram(ctx context.Context) ([]byte, error) {
	if s.closed.Load() {
		return nil, errSessionClosed
	}
	return s.request.ReceiveDatagram(ctx)
}

func (s *session) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		if s.request != nil {
			s.request.CancelRead(0)
			s.request.CancelWrite(0)
		}
		if s.h3 != nil {
			s.closeErr = s.h3.CloseWithError(0, "client closed")
		}
		if s.qconn != nil {
			if err := s.qconn.CloseWithError(0, "client closed"); err != nil && s.closeErr == nil {
				s.closeErr = err
			}
		}
		if s.pc != nil {
			if err := s.pc.Close(); err != nil && s.closeErr == nil {
				s.closeErr = err
			}
		}
		if s.onClosed != nil {
			s.onClosed(s)
		}
		if s.client != nil {
			s.client.unregisterUDP(s)
		}
	})
	return s.closeErr
}

type streamConn struct {
	*quic.Stream
	session  *session
	remote   net.Addr
	once     sync.Once
	closeErr error
}

func (c *streamConn) LocalAddr() net.Addr  { return c.session.qconn.LocalAddr() }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

func (c *streamConn) Close() error {
	c.once.Do(func() {
		c.CancelRead(0)
		c.closeErr = c.Stream.Close()
		c.session.releaseTCP()
	})
	return c.closeErr
}

func isStreamLimitError(err error) bool {
	var limit *quic.StreamLimitReachedError
	return errors.As(err, &limit)
}

type endpointAddr struct {
	network string
	address string
}

func (a endpointAddr) Network() string { return a.network }
func (a endpointAddr) String() string  { return a.address }

type tcpPool struct {
	mu     sync.Mutex
	states map[string]*tcpEndpoint
	closed bool
}

type tcpEndpoint struct {
	key      string
	sessions []*session
	dialing  bool
	wait     chan struct{}
}

func newTCPPool() *tcpPool {
	return &tcpPool{states: make(map[string]*tcpEndpoint)}
}

func (p *tcpPool) acquire(ctx context.Context, endpoint string, create func(context.Context) (*session, error)) (*session, error) {
	key := normalizeEndpoint(endpoint)
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, errClientClosed
		}
		state := p.states[key]
		if state == nil {
			state = &tcpEndpoint{key: key}
			p.states[key] = state
		}
		for _, s := range state.sessions {
			if s.reserveTCP() {
				p.mu.Unlock()
				return s, nil
			}
		}
		if !state.dialing {
			state.dialing = true
			state.wait = make(chan struct{})
			wait := state.wait
			p.mu.Unlock()

			s, err := create(ctx)
			p.mu.Lock()
			state.dialing = false
			close(wait)
			if err == nil && p.closed {
				err = errClientClosed
			}
			if err == nil {
				state.sessions = append(state.sessions, s)
				if !s.reserveTCP() {
					err = errors.New("wtp: new session has no stream capacity")
				}
			}
			p.mu.Unlock()
			if err != nil {
				if s != nil {
					_ = s.Close()
				}
				return nil, err
			}
			return s, nil
		}
		wait := state.wait
		p.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (p *tcpPool) remove(s *session) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.states[normalizeEndpoint(s.endpoint)]
	if state == nil {
		return
	}
	for i, current := range state.sessions {
		if current == s {
			state.sessions = append(state.sessions[:i], state.sessions[i+1:]...)
			break
		}
	}
	if len(state.sessions) == 0 && !state.dialing {
		delete(p.states, state.key)
	}
}

func (p *tcpPool) reap(maxAge time.Duration, maxIdle int) {
	p.mu.Lock()
	var idle []*session
	for key, state := range p.states {
		for _, s := range state.sessions {
			if s.active.Load() == 0 {
				idle = append(idle, s)
			}
		}
		if len(state.sessions) == 0 && !state.dialing {
			delete(p.states, key)
		}
	}
	sort.Slice(idle, func(i, j int) bool {
		return idle[i].lastUsed.Load() < idle[j].lastUsed.Load()
	})
	closeOver := len(idle) - maxIdle
	if closeOver < 0 {
		closeOver = 0
	}
	toClose := make([]*session, 0, len(idle))
	for i, s := range idle {
		if i < closeOver || s.idleSince() >= maxAge {
			s.closed.Store(true)
			toClose = append(toClose, s)
		}
	}
	p.mu.Unlock()
	for _, s := range toClose {
		p.remove(s)
		_ = s.Close()
	}
}

func (p *tcpPool) close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	var sessions []*session
	for _, state := range p.states {
		sessions = append(sessions, state.sessions...)
	}
	p.states = make(map[string]*tcpEndpoint)
	p.mu.Unlock()

	var first error
	for _, s := range sessions {
		if err := s.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func normalizeEndpoint(endpoint string) string {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return strings.ToLower(endpoint)
	}
	return net.JoinHostPort(strings.ToLower(host), port)
}
