package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/wtp"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type Wtp struct {
	*Base
	option *WtpOption
	client *wtp.Client
}

type WtpOption struct {
	BasicOption
	Name   string `proxy:"name"`
	Server string `proxy:"server"`
	Port   int    `proxy:"port"`
	Path   string `proxy:"path"`
	SNI    string `proxy:"sni,omitempty"`
	UDP    bool   `proxy:"udp,omitempty"`

	CongestionController string `proxy:"congestion-controller,omitempty"`
	CWND                 int    `proxy:"cwnd,omitempty"`
	BBRProfile           string `proxy:"bbr-profile,omitempty"`

	// ClientFingerprint is accepted for configuration compatibility. The
	// current QUIC stack cannot apply uTLS browser fingerprints to QUIC.
	ClientFingerprint string `proxy:"client-fingerprint,omitempty"`

	SkipCertVerify bool   `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify string `proxy:"name-cert-verify,omitempty"`
	Fingerprint    string `proxy:"fingerprint,omitempty"`
	Certificate    string `proxy:"certificate,omitempty"`
	PrivateKey     string `proxy:"private-key,omitempty"`
}

func (w *Wtp) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	conn, err := w.client.DialContext(ctx, metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return NewConn(conn, w), nil
}

func (w *Wtp) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if !w.option.UDP {
		return nil, C.ErrNotSupport
	}
	if err := w.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	target := metadata.UDPAddr()
	if target == nil {
		return nil, errors.New("wtp: UDP destination is unresolved")
	}
	pc, err := w.client.ListenPacket(ctx, metadata.RemoteAddress(), target)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(N.NewThreadSafePacketConn(pc), w), nil
}

func (w *Wtp) Close() error {
	if w.client == nil {
		return nil
	}
	return w.client.Close()
}

func (w *Wtp) ProxyInfo() C.ProxyInfo {
	info := w.Base.ProxyInfo()
	info.DialerProxy = w.option.DialerProxy
	return info
}

func NewWtp(option WtpOption) (*Wtp, error) {
	if option.Server == "" {
		return nil, errors.New("wtp: missing server")
	}
	if option.Port < 1 || option.Port > 65535 {
		return nil, errors.New("wtp: invalid port")
	}
	if option.Path == "" || !strings.HasPrefix(option.Path, "/") {
		return nil, errors.New("wtp: path must start with '/'")
	}
	if err := validateWtpCongestion(option.CongestionController, option.BBRProfile); err != nil {
		return nil, err
	}

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
			NextProtos:         []string{"h3"},
		},
		Fingerprint:    option.Fingerprint,
		NameCertVerify: option.NameCertVerify,
		Certificate:    option.Certificate,
		PrivateKey:     option.PrivateKey,
	})
	if err != nil {
		return nil, err
	}

	quicConfig := &quic.Config{
		InitialPacketSize:              1200,
		KeepAlivePeriod:                60 * time.Second,
		MaxIdleTimeout:                 5 * time.Minute,
		HandshakeIdleTimeout:           10 * time.Second,
		InitialStreamReceiveWindow:     8 * 1024 * 1024,
		MaxStreamReceiveWindow:         16 * 1024 * 1024,
		InitialConnectionReceiveWindow: 16 * 1024 * 1024,
		MaxConnectionReceiveWindow:     64 * 1024 * 1024,
		EnableDatagrams:                true,
	}

	outbound := &Wtp{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Wtp,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())

	authority := net.JoinHostPort(serverName, strconv.Itoa(option.Port))
	outbound.client, err = wtp.NewClient(wtp.ClientOption{
		Address:              addr,
		Authority:            authority,
		Path:                 option.Path,
		TLSConfig:            tlsConfig,
		QUICConfig:           quicConfig,
		Dialer:               outbound.dialer,
		DialOptions:          outbound.DialOptions(),
		CongestionController: option.CongestionController,
		CWND:                 option.CWND,
		BBRProfile:           option.BBRProfile,
	})
	if err != nil {
		return nil, err
	}
	return outbound, nil
}

func validateWtpCongestion(controller, profile string) error {
	switch controller {
	case "", "cubic", "new_reno", "bbr", "bbr_meta_v1", "bbr_meta_v2":
	default:
		return fmt.Errorf("wtp: unknown congestion-controller %q", controller)
	}
	switch profile {
	case "", "standard", "conservative", "aggressive":
	default:
		return fmt.Errorf("wtp: unknown bbr-profile %q", profile)
	}
	if profile != "" && controller != "" && controller != "bbr" && controller != "bbr_meta_v2" {
		return fmt.Errorf("wtp: bbr-profile requires a BBR congestion-controller")
	}
	return nil
}
