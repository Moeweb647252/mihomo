package wtp

import (
	"context"
	"net"
	"time"

	"github.com/metacubex/quic-go"
)

type Conn struct {
	session *Session
	stream  *quic.Stream
}

func NewConn(session *Session, stream *quic.Stream) *Conn {
	return &Conn{session: session, stream: stream}
}

func (c *Conn) Read(b []byte) (int, error)       { return c.stream.Read(b) }
func (c *Conn) Write(b []byte) (int, error)      { return c.stream.Write(b) }
func (c *Conn) Close() error                      { c.stream.Close(); return c.session.Close() }
func (c *Conn) LocalAddr() net.Addr               { return c.session.quicConn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr              { return c.session.quicConn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

type PacketConn struct {
	session *Session
}

func NewPacketConn(session *Session) *PacketConn {
	return &PacketConn{session: session}
}

func (pc *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	data, err := pc.session.ReceiveDatagram(context.Background())
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, data)
	return n, pc.session.quicConn.RemoteAddr(), nil
}

func (pc *PacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if err := pc.session.SendDatagram(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (pc *PacketConn) Close() error                     { return pc.session.Close() }
func (pc *PacketConn) LocalAddr() net.Addr               { return pc.session.quicConn.LocalAddr() }
func (pc *PacketConn) SetDeadline(_ time.Time) error      { return nil }
func (pc *PacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (pc *PacketConn) SetWriteDeadline(_ time.Time) error { return nil }
