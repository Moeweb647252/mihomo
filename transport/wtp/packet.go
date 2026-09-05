package wtp

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
)

type udpPacket struct {
	data []byte
	addr net.Addr
}

type udpConn struct {
	client *Client

	mu        sync.Mutex
	sessions  map[string]*udpAssociation
	pending   map[string]chan struct{}
	closed    chan struct{}
	closeOnce sync.Once

	input chan udpPacket

	readDeadline  deadline.PipeDeadline
	writeDeadline deadline.PipeDeadline
}

type udpAssociation struct {
	parent  *udpConn
	key     string
	target  net.Addr
	session *session

	closeOnce sync.Once
}

func newUDPConn(client *Client) *udpConn {
	return &udpConn{
		client:        client,
		sessions:      make(map[string]*udpAssociation),
		pending:       make(map[string]chan struct{}),
		closed:        make(chan struct{}),
		input:         make(chan udpPacket, packetQueueSize),
		readDeadline:  deadline.MakePipeDeadline(),
		writeDeadline: deadline.MakePipeDeadline(),
	}
}

func (c *udpConn) ensure(ctx context.Context, target net.Addr, endpoint string) (*udpAssociation, error) {
	key, normalized, err := targetEndpoint(target)
	if err != nil {
		return nil, err
	}
	select {
	case <-c.closed:
		return nil, net.ErrClosed
	case <-c.writeDeadline.Wait():
		return nil, os.ErrDeadlineExceeded
	default:
	}

	c.mu.Lock()
	if association := c.sessions[key]; association != nil && !association.session.closed.Load() {
		c.mu.Unlock()
		return association, nil
	}
	if wait := c.pending[key]; wait != nil {
		c.mu.Unlock()
		select {
		case <-wait:
			return c.ensure(ctx, target, endpoint)
		case <-c.closed:
			return nil, net.ErrClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if len(c.sessions) >= maxUDPSessions {
		var oldest *udpAssociation
		for _, association := range c.sessions {
			if association.session.idleSince() < idleSession {
				continue
			}
			if oldest == nil || association.session.idleSince() > oldest.session.idleSince() {
				oldest = association
			}
		}
		if oldest != nil {
			delete(c.sessions, oldest.key)
			go oldest.close()
		} else {
			c.mu.Unlock()
			return nil, errUDPSessionLimit
		}
	}
	wait := make(chan struct{})
	c.pending[key] = wait
	c.mu.Unlock()

	sessionEndpoint := endpoint
	if sessionEndpoint == "" {
		sessionEndpoint = normalized
	}
	s, err := c.client.newSession(ctx, "udp", sessionEndpoint, func(s *session) {
		c.removeSession(s)
	})
	c.mu.Lock()
	delete(c.pending, key)
	close(wait)
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	association := &udpAssociation{
		parent:  c,
		key:     key,
		target:  cloneAddr(target),
		session: s,
	}
	if !c.client.registerUDP(s) {
		c.mu.Unlock()
		_ = s.Close()
		return nil, errClientClosed
	}
	if isClosed(c.closed) {
		c.mu.Unlock()
		_ = s.Close()
		return nil, net.ErrClosed
	}
	c.sessions[key] = association
	c.mu.Unlock()

	go association.readLoop()
	return association, nil
}

func (c *udpConn) removeSession(s *session) {
	c.mu.Lock()
	for key, association := range c.sessions {
		if association.session == s {
			delete(c.sessions, key)
			break
		}
	}
	c.mu.Unlock()
}

func (a *udpAssociation) readLoop() {
	for {
		data, err := a.session.receiveDatagram(a.session.qconn.Context())
		if err != nil {
			_ = a.close()
			return
		}
		packet := udpPacket{data: data, addr: a.target}
		select {
		case a.parent.input <- packet:
			a.session.touch()
		case <-a.parent.closed:
			_ = a.close()
			return
		case <-a.session.qconn.Context().Done():
			_ = a.close()
			return
		default:
			// Datagram transport is lossy by design. Dropping here keeps one
			// noisy target from blocking all other targets.
		}
	}
}

func (a *udpAssociation) close() error {
	a.closeOnce.Do(func() {
		a.parent.removeSession(a.session)
		_ = a.session.Close()
	})
	return nil
}

func (c *udpConn) ReadFrom(p []byte) (int, net.Addr, error) {
	packet, err := c.nextPacket()
	if err != nil {
		return 0, nil, err
	}
	return copy(p, packet.data), packet.addr, nil
}

func (c *udpConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	packet, err := c.nextPacket()
	if err != nil {
		return nil, nil, nil, err
	}
	return packet.data, nil, packet.addr, nil
}

func (c *udpConn) nextPacket() (udpPacket, error) {
	select {
	case packet := <-c.input:
		return packet, nil
	case <-c.closed:
		return udpPacket{}, net.ErrClosed
	case <-c.readDeadline.Wait():
		return udpPacket{}, os.ErrDeadlineExceeded
	}
}

func (c *udpConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if len(p) == 0 {
		// Empty QUIC datagrams are valid, so let the server receive them.
	}
	_, normalized, err := targetEndpoint(addr)
	if err != nil {
		return 0, err
	}
	association, err := c.ensure(context.Background(), addr, normalized)
	if err != nil {
		return 0, err
	}
	if err := association.session.sendDatagram(context.Background(), p); err != nil {
		if errors.Is(err, errSessionClosed) {
			c.removeSession(association.session)
		}
		return 0, err
	}
	return len(p), nil
}

func (c *udpConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.readDeadline.Set(time.Now())
		c.writeDeadline.Set(time.Now())
		c.mu.Lock()
		associations := make([]*udpAssociation, 0, len(c.sessions))
		for _, association := range c.sessions {
			associations = append(associations, association)
		}
		c.sessions = make(map[string]*udpAssociation)
		c.mu.Unlock()
		for _, association := range associations {
			_ = association.session.Close()
		}
	})
	return nil
}

func (c *udpConn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, association := range c.sessions {
		return association.session.qconn.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (c *udpConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *udpConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *udpConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	return nil
}

func targetEndpoint(addr net.Addr) (key, endpoint string, err error) {
	if addr == nil {
		return "", "", errors.New("wtp: missing UDP destination")
	}
	endpoint = addr.String()
	if udp, ok := addr.(*net.UDPAddr); ok {
		if udp.Port == 0 || udp.IP == nil {
			return "", "", errors.New("wtp: invalid UDP destination")
		}
		endpoint = net.JoinHostPort(udp.IP.String(), strconv.Itoa(udp.Port))
	}
	host, port, splitErr := net.SplitHostPort(endpoint)
	if splitErr != nil || host == "" || port == "" {
		return "", "", errors.New("wtp: UDP destination must be host:port")
	}
	portNumber, parseErr := strconv.ParseUint(port, 10, 16)
	if parseErr != nil || portNumber == 0 {
		return "", "", errors.New("wtp: invalid UDP destination port")
	}
	port = strconv.FormatUint(portNumber, 10)
	endpoint = net.JoinHostPort(host, port)
	key = normalizeEndpoint(endpoint)
	return key, endpoint, nil
}

func cloneAddr(addr net.Addr) net.Addr {
	switch value := addr.(type) {
	case *net.UDPAddr:
		copyValue := *value
		if value.IP != nil {
			copyValue.IP = append(net.IP(nil), value.IP...)
		}
		return &copyValue
	default:
		return endpointAddr{network: addr.Network(), address: addr.String()}
	}
}

var _ net.PacketConn = (*udpConn)(nil)
var _ net.Conn = (*streamConn)(nil)

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
