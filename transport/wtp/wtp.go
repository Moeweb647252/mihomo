package wtp

import (
	"context"
	"fmt"
	"net/url"

	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	tuicCommon "github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/quic-go/quicvarint"
	"github.com/metacubex/tls"
)

const (
	webTransportFrameType = 0x41
)

type Session struct {
	quicConn   *quic.Conn
	pc         interface{ Close() error }
	tr         *http3.Transport
	hconn      *http3.ClientConn
	requestStr *http3.RequestStream
	sessionID  uint64
}

type DialOptions struct {
	Dialer               C.Dialer
	DialOptions          []dialer.Option
	TLSConfig            *tls.Config
	QUICConfig           *quic.Config
	CongestionController string
	CWND                 int
	BBRProfile           string
}

func Dial(ctx context.Context, serverAddr string, opts DialOptions, path, protocol, endpoint string) (*Session, error) {
	pc, quicConn, err := tuicCommon.DialQuic(ctx, serverAddr, opts.DialOptions, opts.Dialer, opts.TLSConfig, opts.QUICConfig, false)
	if err != nil {
		return nil, fmt.Errorf("wtp: QUIC dial: %w", err)
	}
	tuicCommon.SetCongestionController(quicConn, opts.CongestionController, opts.CWND, opts.BBRProfile)

	tr := &http3.Transport{
		EnableDatagrams:    true,
		DisableCompression: true,
		AdditionalSettings: map[uint64]uint64{
			0x8:        1,
			0x2b603742: 1,
			0x2c7cf000: 1,
		},
	}

	hconn := tr.NewClientConn(quicConn)

	select {
	case <-hconn.ReceivedSettings():
	case <-ctx.Done():
		_ = pc.Close()
		_ = tr.Close()
		return nil, ctx.Err()
	}

	u := &url.URL{
		Scheme: "https",
		Host:   serverAddr,
		Path:   path,
	}

	reqHeaders := http.Header{}
	reqHeaders.Set("Sec-Webtransport-Http3-Draft02", "1")
	reqHeaders.Set("proxy-protocol", protocol)
	reqHeaders.Set("proxy-endpoint", endpoint)

	rstr, err := hconn.OpenRequestStream(ctx)
	if err != nil {
		_ = pc.Close()
		_ = tr.Close()
		return nil, fmt.Errorf("wtp: open request stream: %w", err)
	}

	if err := rstr.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  "webtransport",
		Host:   serverAddr,
		URL:    u,
		Header: reqHeaders,
	}); err != nil {
		_ = pc.Close()
		_ = tr.Close()
		return nil, fmt.Errorf("wtp: send request header: %w", err)
	}

	rsp, err := rstr.ReadResponse()
	if err != nil {
		_ = pc.Close()
		_ = tr.Close()
		return nil, fmt.Errorf("wtp: read response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		_ = pc.Close()
		_ = tr.Close()
		return nil, fmt.Errorf("wtp: server responded with %d", rsp.StatusCode)
	}

	return &Session{
		quicConn:   quicConn,
		pc:         pc,
		tr:         tr,
		hconn:      hconn,
		requestStr: rstr,
		sessionID:  uint64(rstr.StreamID()),
	}, nil
}

func (s *Session) OpenBidiStream(ctx context.Context) (*quic.Stream, error) {
	str, err := s.quicConn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("wtp: open bidi stream: %w", err)
	}
	header := quicvarint.Append(nil, webTransportFrameType)
	header = quicvarint.Append(header, s.sessionID)
	if _, err := str.Write(header); err != nil {
		_ = str.Close()
		return nil, fmt.Errorf("wtp: write stream header: %w", err)
	}
	return str, nil
}

func (s *Session) SendDatagram(data []byte) error {
	return s.requestStr.SendDatagram(data)
}

func (s *Session) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.requestStr.ReceiveDatagram(ctx)
}

func (s *Session) Close() error {
	_ = s.pc.Close()
	_ = s.tr.Close()
	return s.quicConn.CloseWithError(0, "")
}
