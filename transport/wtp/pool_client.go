package wtp

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

type PoolClient struct {
	clientOption *ClientOption
	dialFn       DialFunc

	tcpClients map[string]*Client
	tcpMutex   sync.Mutex
	udpClients map[string]*Client
	udpMutex   sync.Mutex
}

func (p *PoolClient) DialContext(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	endpoint := metadata.RemoteAddress()
	client := p.getClient(false, endpoint)
	conn, err := client.DialContext(ctx, metadata)
	if errors.Is(err, ErrTooManyOpenStreams) {
		client = p.createClient(false, endpoint)
		conn, err = client.DialContext(ctx, metadata)
	}
	if err != nil {
		return nil, err
	}
	return N.NewRefConn(conn, p), err
}

func (p *PoolClient) ListenPacket(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error) {
	target := net.JoinHostPort(metadata.DstIP.String(), strconv.FormatUint(uint64(metadata.DstPort), 10))
	client := p.getClient(true, target)
	pc, err := client.ListenPacket(ctx, metadata)
	if errors.Is(err, ErrTooManyOpenStreams) {
		client = p.createClient(true, target)
		pc, err = client.ListenPacket(ctx, metadata)
	}
	if err != nil {
		return nil, err
	}
	return N.NewRefPacketConn(pc, p), nil
}

func (p *PoolClient) createClient(udp bool, endpoint string) *Client {
	clients := &p.tcpClients
	mutex := &p.tcpMutex
	if udp {
		clients = &p.udpClients
		mutex = &p.udpMutex
	}

	mutex.Lock()
	defer mutex.Unlock()

	// 覆盖前主动关闭旧 Client,避免 ErrTooManyOpenStreams 回退路径
	// 把旧 session(连同底层 QUIC 连接)直接丢弃而泄漏。
	if old, ok := (*clients)[endpoint]; ok {
		old.Close()
	}
	client := NewClient(p.clientOption, p.dialFn)
	(*clients)[endpoint] = client
	return client
}

// Close 关闭池中所有 Client(及其底层 QUIC 连接),并清空两个 endpoint map。
// 供 Wtp.Close 在节点卸载/热重载时调用,避免长期 keepalive 的 QUIC 连接泄漏。
func (p *PoolClient) Close() error {
	p.tcpMutex.Lock()
	for _, c := range p.tcpClients {
		c.Close()
	}
	p.tcpClients = make(map[string]*Client)
	p.tcpMutex.Unlock()

	p.udpMutex.Lock()
	for _, c := range p.udpClients {
		c.Close()
	}
	p.udpClients = make(map[string]*Client)
	p.udpMutex.Unlock()
	return nil
}

func (p *PoolClient) getClient(udp bool, endpoint string) *Client {
	clients := &p.tcpClients
	mutex := &p.tcpMutex
	if udp {
		clients = &p.udpClients
		mutex = &p.udpMutex
	}

	mutex.Lock()
	defer mutex.Unlock()

	client, ok := (*clients)[endpoint]
	if ok {
		return client
	}

	client = NewClient(p.clientOption, p.dialFn)
	(*clients)[endpoint] = client
	return client
}

func NewPoolClient(clientOption *ClientOption, dialFn DialFunc) *PoolClient {
	newClientOption := *clientOption
	return &PoolClient{
		clientOption: &newClientOption,
		dialFn:       dialFn,
		tcpClients:   make(map[string]*Client),
		udpClients:   make(map[string]*Client),
	}
}
