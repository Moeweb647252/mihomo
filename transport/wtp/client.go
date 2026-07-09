package wtp

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	atomic2 "github.com/metacubex/mihomo/common/atomic"
	C "github.com/metacubex/mihomo/constant"
)

// DialFunc creates a new Session for the given endpoint and protocol.
// The endpoint is the proxy-endpoint value for the WebTransport CONNECT request.
// The protocol is "tcp" or "udp".
type DialFunc func(ctx context.Context, endpoint, protocol string) (*Session, error)

type ClientOption struct {
	MaxOpenStreams int64
}

type Client struct {
	*ClientOption
	dialFn DialFunc

	session   *Session
	connMutex sync.Mutex

	openStreams atomic.Int64
	closed      atomic.Bool

	lastVisited atomic2.TypedValue[time.Time]
}

func (c *Client) OpenStreams() int64 {
	return c.openStreams.Load()
}

func (c *Client) LastVisited() time.Time {
	return c.lastVisited.Load()
}

func (c *Client) SetLastVisited(last time.Time) {
	c.lastVisited.Store(last)
}

func (c *Client) getSession(ctx context.Context, endpoint, protocol string) (*Session, error) {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	if c.session != nil {
		return c.session, nil
	}
	session, err := c.dialFn(ctx, endpoint, protocol)
	if err != nil {
		return nil, err
	}
	c.session = session
	c.openStreams.Store(0)
	return session, nil
}

func (c *Client) DialContext(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed
	}
	endpoint := metadata.RemoteAddress()
	session, err := c.getSession(ctx, endpoint, "tcp")
	if err != nil {
		return nil, err
	}

	openStreams := c.openStreams.Add(1)
	if openStreams > c.MaxOpenStreams {
		c.openStreams.Add(-1)
		return nil, ErrTooManyOpenStreams
	}

	quicStream, err := session.OpenBidiStream(ctx)
	if err != nil {
		// OpenStreamSync 失败几乎都意味着 session 已坏(QUIC 错误),
		// 保守关闭重建比残留坏 session 更稳;先归还计数再 forceClose。
		c.openStreams.Add(-1)
		c.forceClose(session, err)
		return nil, err
	}
	conn := NewConn(session, quicStream, func() {
		time.AfterFunc(C.DefaultTCPTimeout, func() {
			openStreams := c.openStreams.Add(-1)
			if openStreams == 0 && c.closed.Load() {
				c.forceClose(nil, ErrClientClosed)
			}
		})
	})
	return conn, nil
}

func (c *Client) ListenPacket(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed
	}
	target := net.JoinHostPort(metadata.DstIP.String(), strconv.FormatUint(uint64(metadata.DstPort), 10))
	session, err := c.getSession(ctx, target, "udp")
	if err != nil {
		return nil, err
	}

	openStreams := c.openStreams.Add(1)
	if openStreams > c.MaxOpenStreams {
		c.openStreams.Add(-1)
		return nil, ErrTooManyOpenStreams
	}

	pc := NewPacketConn(session, func() {
		time.AfterFunc(C.DefaultUDPTimeout, func() {
			openStreams := c.openStreams.Add(-1)
			if openStreams == 0 && c.closed.Load() {
				c.forceClose(nil, ErrClientClosed)
			}
		})
	})
	return pc, nil
}

func (c *Client) forceClose(session *Session, err error) {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	if session == nil {
		session = c.session
	}
	if session != nil {
		if session == c.session {
			c.session = nil
		}
	}
	if session != nil {
		_ = session.Close()
	}
}

func (c *Client) Close() {
	c.closed.Store(true)
	if c.openStreams.Load() == 0 {
		c.forceClose(nil, ErrClientClosed)
	}
}

func NewClient(clientOption *ClientOption, dialFn DialFunc) *Client {
	return &Client{
		ClientOption: clientOption,
		dialFn:       dialFn,
	}
}
