package wtp

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/metacubex/quic-go"
)

type Conn struct {
	session      *Session
	stream       *quic.Stream
	closeDeferFn func()
	closeOnce    sync.Once
}

func NewConn(session *Session, stream *quic.Stream, closeDeferFn func()) *Conn {
	return &Conn{session: session, stream: stream, closeDeferFn: closeDeferFn}
}

func (c *Conn) Read(b []byte) (int, error)  { return c.stream.Read(b) }
func (c *Conn) Write(b []byte) (int, error) { return c.stream.Write(b) }
func (c *Conn) Close() error {
	// 用 sync.Once 保证 closeDeferFn(其中会 openStreams.Add(-1))只执行一次,
	// 避免被上层重复 Close 时计数器被多次扣减变负。
	c.closeOnce.Do(func() {
		_ = c.stream.Close()
		if c.closeDeferFn != nil {
			c.closeDeferFn()
		}
	})
	return nil
}
func (c *Conn) LocalAddr() net.Addr                { return c.session.quicConn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.session.quicConn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

type PacketConn struct {
	session      *Session
	closeDeferFn func()
	closeOnce    sync.Once
	ctx          context.Context
	cancel       context.CancelFunc
}

func NewPacketConn(session *Session, closeDeferFn func()) *PacketConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &PacketConn{
		session:      session,
		closeDeferFn: closeDeferFn,
		ctx:          ctx,
		cancel:       cancel,
	}
}

func (pc *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	// 用可取消的 ctx 调 ReceiveDatagram:Close 时取消 ctx,让阻塞中的读取
	// goroutine 返回 context.Canceled,避免泄漏到整个 Session 被销毁。
	data, err := pc.session.ReceiveDatagram(pc.ctx)
	if err != nil {
		return 0, nil, err
	}
	// 当 datagram 比 p 长时静默截断且不报错,与 net.PacketConn 的标准行为一致;
	// 调用方需保证传入足够大的缓冲(典型 65536)以容纳完整 datagram,否则会
	// 丢失尾部字节且无法通过返回值察觉丢失量。
	n := copy(p, data)
	return n, pc.session.quicConn.RemoteAddr(), nil
}

func (pc *PacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if err := pc.session.SendDatagram(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (pc *PacketConn) Close() error {
	// 用 sync.Once 保证取消与计数扣减只执行一次,避免重复 Close 错乱计数。
	pc.closeOnce.Do(func() {
		pc.cancel()
		if pc.closeDeferFn != nil {
			pc.closeDeferFn()
		}
	})
	return nil
}
func (pc *PacketConn) LocalAddr() net.Addr { return pc.session.quicConn.LocalAddr() }

// SetDeadline / SetReadDeadline / SetWriteDeadline 对 datagram 通道无意义
// (http3.RequestStream 的 deadline 仅作用于字节流 Read/Write),
// 这里返回 nil 与无法支持 datagram deadline 的语义一致。
// 隧道层(Tunnel)通过 N.NewDeadlineEnhancePacketConn 包装自行管理 UDP 超时,
// 不依赖这里返回的 deadline。
func (pc *PacketConn) SetDeadline(_ time.Time) error      { return nil }
func (pc *PacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (pc *PacketConn) SetWriteDeadline(_ time.Time) error { return nil }
