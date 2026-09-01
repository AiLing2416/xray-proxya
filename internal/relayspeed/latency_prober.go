package relayspeed

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"xray-proxya/pkg/utils"
)

var defaultDNSTargets = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

// dnsTCPQuery is a 28-byte standard DNS A query over TCP (prefixed with 2-byte length: 0x00, 0x1c).
var dnsTCPQuery = []byte{
	0x00, 0x1c, // Length: 28 bytes
	0x12, 0x34, // Transaction ID
	0x01, 0x00, // Flags: Standard query, recursion desired
	0x00, 0x01, // QDCOUNT: 1
	0x00, 0x00, // ANCOUNT: 0
	0x00, 0x00, // NSCOUNT: 0
	0x00, 0x00, // ARCOUNT: 0
	0x06, 'g', 'o', 'o', 'g', 'l', 'e',
	0x03, 'c', 'o', 'm',
	0x00,
	0x00, 0x01, // QTYPE: A (1)
	0x00, 0x01, // QCLASS: IN (1)
}

// LatencyProber maintains a single persistent TCP connection through the SOCKS5 proxy to measure RTT.
// It sends lightweight 28-byte Anycast DNS queries to eliminate connection churn, rate limiting, and NAT table overload.
type LatencyProber struct {
	dialer  *utils.SOCKS5Dialer
	targets []string
	conn    net.Conn
	mu      sync.Mutex
	closed  bool
}

// NewLatencyProber creates a prober using the provided SOCKS5 dialer.
func NewLatencyProber(dialer *utils.SOCKS5Dialer) *LatencyProber {
	return &LatencyProber{
		dialer:  dialer,
		targets: defaultDNSTargets,
	}
}

// Close closes the underlying persistent TCP connection.
func (p *LatencyProber) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
}

func (p *LatencyProber) getConn(ctx context.Context) (net.Conn, error) {
	if p.conn != nil {
		return p.conn, nil
	}
	if p.closed {
		return nil, fmt.Errorf("prober is closed")
	}
	if p.dialer == nil {
		return nil, fmt.Errorf("nil SOCKS5 dialer")
	}

	var lastErr error
	for _, target := range p.targets {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		conn, err := p.dialer.Dial("tcp", target)
		if err == nil {
			p.conn = conn
			return p.conn, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("failed to connect to latency anycast targets: %w", lastErr)
}

// Probe executes a single RTT probe over the persistent connection.
func (p *LatencyProber) Probe(ctx context.Context, timeout time.Duration) (time.Duration, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	conn, err := p.getConn(ctx)
	if err != nil {
		return 0, err
	}

	start := time.Now()
	if err := conn.SetDeadline(start.Add(timeout)); err != nil {
		p.resetConn()
		return 0, err
	}

	if _, err := conn.Write(dnsTCPQuery); err != nil {
		p.resetConn()
		return 0, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		p.resetConn()
		return 0, err
	}

	respLen := binary.BigEndian.Uint16(lenBuf[:])
	if respLen > 4096 {
		p.resetConn()
		return 0, fmt.Errorf("invalid DNS response length: %d", respLen)
	}

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		p.resetConn()
		return 0, err
	}

	return time.Since(start), nil
}

func (p *LatencyProber) resetConn() {
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
}
