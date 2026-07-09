package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/wtp"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type Wtp struct {
	*Base
	option *WtpOption
	pool   *wtp.PoolClient
}

type WtpOption struct {
	BasicOption
	Name           string   `proxy:"name"`
	Server         string   `proxy:"server"`
	Port           int      `proxy:"port"`
	Path           string   `proxy:"path,omitempty"`
	SNI            string   `proxy:"sni,omitempty"`
	ALPN           []string `proxy:"alpn,omitempty"`
	SkipCertVerify bool     `proxy:"skip-cert-verify,omitempty"`
	Fingerprint    string   `proxy:"fingerprint,omitempty"`
	Certificate    string   `proxy:"certificate,omitempty"`
	PrivateKey     string   `proxy:"private-key,omitempty"`
	UDP            bool     `proxy:"udp,omitempty"`

	KeepAlive            int    `proxy:"keep-alive,omitempty"`
	CongestionController string `proxy:"congestion-controller,omitempty"`
	CWND                 int    `proxy:"cwnd,omitempty"`
	BBRProfile           string `proxy:"bbr-profile,omitempty"`
	MaxOpenStreams       int    `proxy:"max-open-streams,omitempty"`
}

func (w *Wtp) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	conn, err := w.pool.DialContext(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, w), nil
}

func (w *Wtp) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := w.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	pc, err := w.pool.ListenPacket(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return newPacketConn(pc, w), nil
}

func (w *Wtp) SupportUOT() bool { return true }

func (w *Wtp) ProxyInfo() C.ProxyInfo {
	info := w.Base.ProxyInfo()
	info.DialerProxy = w.option.DialerProxy
	return info
}

func (w *Wtp) Close() error { return w.pool.Close() }

func NewWtp(option WtpOption) (*Wtp, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	serverName := option.Server
	if option.SNI != "" {
		serverName = option.SNI
	}

	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: option.SkipCertVerify,
			MinVersion:         tls.VersionTLS13,
		},
		Fingerprint: option.Fingerprint,
		Certificate: option.Certificate,
		PrivateKey:  option.PrivateKey,
	})
	if err != nil {
		return nil, err
	}

	if option.ALPN != nil {
		tlsConfig.NextProtos = option.ALPN
	} else {
		tlsConfig.NextProtos = []string{"h3"}
	}

	if option.Path == "" {
		option.Path = "/wtp"
	}
	if option.Port == 0 {
		option.Port = 443
	}

	if option.MaxOpenStreams == 0 {
		option.MaxOpenStreams = 100
	}

	keepAlivePeriod := time.Duration(option.KeepAlive) * time.Second
	if option.KeepAlive == 0 {
		keepAlivePeriod = 60 * time.Second
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:                 5 * time.Minute,
		KeepAlivePeriod:                keepAlivePeriod,
		EnableDatagrams:                true,
		InitialPacketSize:              1200,
		InitialStreamReceiveWindow:     4 * 1024 * 1024,  // 4 MiB 初始流窗口
		InitialConnectionReceiveWindow: 8 * 1024 * 1024,  // 8 MiB 初始连接窗口
		MaxStreamReceiveWindow:         16 * 1024 * 1024, // 16 MiB 单流窗口
		MaxConnectionReceiveWindow:     32 * 1024 * 1024, // 32 MiB 连接窗口
		MaxIncomingStreams:             1024,
		HandshakeIdleTimeout:           10 * time.Second,
		DisablePathMTUDiscovery:        true,
	}

	outbound := &Wtp{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Wtp,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}

	outbound.dialer = option.NewDialer(outbound.DialOptions())
	if outbound.dialer == nil {
		return nil, fmt.Errorf("wtp: failed to create dialer")
	}

	dialFn := func(ctx context.Context, endpoint, protocol string) (*wtp.Session, error) {
		return wtp.Dial(ctx, addr, wtp.DialOptions{
			Dialer:               outbound.dialer,
			DialOptions:          outbound.DialOptions(),
			TLSConfig:            tlsConfig,
			QUICConfig:           quicConfig,
			CongestionController: option.CongestionController,
			CWND:                 option.CWND,
			BBRProfile:           option.BBRProfile,
		}, option.Path, protocol, endpoint)
	}

	clientOption := &wtp.ClientOption{
		MaxOpenStreams: int64(option.MaxOpenStreams),
	}

	outbound.pool = wtp.NewPoolClient(clientOption, dialFn)

	return outbound, nil
}
