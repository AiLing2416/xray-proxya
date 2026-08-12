// Package pathd implements the authenticated local PathLink protocol.
package pathd

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	maxFrameSize    = 16 << 10
	protocolVersion = 1
	maxInFlight     = 32
)

type frame struct {
	Version      uint8  `json:"v"`
	Type         string `json:"type"`
	Token        string `json:"token,omitempty"`
	ID           uint64 `json:"id,omitempty"`
	Target       string `json:"target,omitempty"`
	Timeout      int    `json:"timeout_ms,omitempty"`
	TTL          int    `json:"ttl,omitempty"`
	PayloadSize  int    `json:"payload_size,omitempty"`
	DontFragment bool   `json:"dont_fragment,omitempty"`
	Relay        bool   `json:"relay,omitempty"`
	EchoData     []byte `json:"echo_data,omitempty"`
	RTT          int64  `json:"rtt_ns,omitempty"`
	Echo         bool   `json:"echo,omitempty"`
	ICMPType     uint8  `json:"icmp_type,omitempty"`
	ICMPCode     uint8  `json:"icmp_code,omitempty"`
	Responder    string `json:"responder,omitempty"`
	MTU          int    `json:"mtu,omitempty"`
	Error        string `json:"error,omitempty"`
}

func writeFrame(w io.Writer, f frame) error {
	f.Version = protocolVersion
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(b) > maxFrameSize {
		return fmt.Errorf("pathd frame is too large")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(b)))
	if _, err := w.Write(size[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
func readFrame(r io.Reader) (frame, error) {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return frame{}, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > maxFrameSize {
		return frame{}, fmt.Errorf("invalid pathd frame size %d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return frame{}, err
	}
	var f frame
	if err := json.Unmarshal(b, &f); err != nil {
		return frame{}, err
	}
	if f.Version != protocolVersion {
		return frame{}, fmt.Errorf("unsupported pathd protocol version %d", f.Version)
	}
	return f, nil
}

// Client multiplexes bounded probe requests over one PathLink stream.
type Client struct {
	conn      net.Conn
	writeMu   sync.Mutex
	mu        sync.Mutex
	nextID    uint64
	pending   map[uint64]chan clientResult
	done      chan struct{}
	closeOnce sync.Once
}
type clientResult struct {
	probe ProbeResult
	err   error
}

func NewClient(conn net.Conn, token string) (*Client, error) {
	if token == "" {
		conn.Close()
		return nil, fmt.Errorf("pathd token is empty")
	}
	if err := writeFrame(conn, frame{Type: "hello", Token: token}); err != nil {
		conn.Close()
		return nil, err
	}
	response, err := readFrame(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if response.Type != "ready" {
		conn.Close()
		return nil, fmt.Errorf("pathd authentication failed: %s", response.Error)
	}
	client := &Client{conn: conn, pending: make(map[uint64]chan clientResult), done: make(chan struct{})}
	go client.readLoop()
	return client, nil
}
func (c *Client) Close() error {
	c.closeOnce.Do(func() { close(c.done); _ = c.conn.Close(); c.failPending(fmt.Errorf("PathLink closed")) })
	return nil
}
func (c *Client) Ping(target string, timeoutMS int) (int64, error) {
	result, err := c.Probe(target, timeoutMS)
	return result.RTT.Nanoseconds(), err
}

func (c *Client) Probe(target string, timeoutMS int) (ProbeResult, error) {
	return c.ProbeWithOptions(target, timeoutMS, ProbeOptions{TTL: 64, PayloadSize: 8})
}

func (c *Client) ProbeTTL(target string, timeoutMS, ttl int) (ProbeResult, error) {
	return c.ProbeWithOptions(target, timeoutMS, ProbeOptions{TTL: ttl, PayloadSize: 8})
}

func (c *Client) ProbeWithOptions(target string, timeoutMS int, options ProbeOptions) (ProbeResult, error) {
	return c.probe(target, timeoutMS, options, false, nil)
}

// RelayEcho asks pathd to transmit the caller's ICMP echo payload from the
// remote node. The outer IP headers are intentionally not carried: remote
// source NAT is required for public replies to return to the proxy node.
func (c *Client) RelayEcho(target string, timeoutMS, ttl int, data []byte, dontFragment bool) (ProbeResult, error) {
	return c.probe(target, timeoutMS, ProbeOptions{TTL: ttl, PayloadSize: 8, DontFragment: dontFragment}, true, data)
}

func (c *Client) probe(target string, timeoutMS int, options ProbeOptions, relay bool, echoData []byte) (ProbeResult, error) {
	if err := ValidateProbeTarget(net.ParseIP(target)); err != nil {
		return ProbeResult{}, err
	}
	if timeoutMS < 100 || timeoutMS > 15000 {
		return ProbeResult{}, fmt.Errorf("invalid pathd timeout")
	}
	if options.TTL < 1 || options.TTL > 255 {
		return ProbeResult{}, fmt.Errorf("invalid ICMP TTL")
	}
	if !relay && (options.PayloadSize < 8 || options.PayloadSize > maxPayloadSize) {
		return ProbeResult{}, fmt.Errorf("invalid ICMP payload size")
	}
	if relay && len(echoData) > maxPayloadSize {
		return ProbeResult{}, fmt.Errorf("ICMP echo payload is too large")
	}
	c.mu.Lock()
	if len(c.pending) >= maxInFlight {
		c.mu.Unlock()
		return ProbeResult{}, fmt.Errorf("PathLink is busy")
	}
	c.nextID++
	id := c.nextID
	resultCh := make(chan clientResult, 1)
	c.pending[id] = resultCh
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, id); c.mu.Unlock() }()
	c.writeMu.Lock()
	err := writeFrame(c.conn, frame{Type: "icmp_echo", ID: id, Target: target, Timeout: timeoutMS, TTL: options.TTL, PayloadSize: options.PayloadSize, DontFragment: options.DontFragment, Relay: relay, EchoData: echoData})
	c.writeMu.Unlock()
	if err != nil {
		c.failPending(err)
		return ProbeResult{}, err
	}
	select {
	case result := <-resultCh:
		return result.probe, result.err
	case <-time.After(time.Duration(timeoutMS+2000) * time.Millisecond):
		return ProbeResult{}, fmt.Errorf("PathLink request timed out")
	case <-c.done:
		return ProbeResult{}, fmt.Errorf("PathLink closed")
	}
}
func (c *Client) readLoop() {
	for {
		response, err := readFrame(c.conn)
		if err != nil {
			c.failPending(err)
			return
		}
		if response.Type != "result" {
			continue
		}
		c.mu.Lock()
		waiter := c.pending[response.ID]
		c.mu.Unlock()
		if waiter == nil {
			continue
		}
		result := clientResult{probe: ProbeResult{RTT: time.Duration(response.RTT), Echo: response.Echo, ICMPType: response.ICMPType, ICMPCode: response.ICMPCode, MTU: response.MTU, Responder: net.ParseIP(response.Responder)}}
		if response.Error != "" {
			result.err = fmt.Errorf("pathd probe: %s", response.Error)
		}
		select {
		case waiter <- result:
		default:
		}
	}
}
func (c *Client) failPending(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, waiter := range c.pending {
		select {
		case waiter <- clientResult{err: err}:
		default:
		}
	}
}
func tokenEqual(expected, got string) bool {
	return expected != "" && len(expected) == len(got) && subtle.ConstantTimeCompare([]byte(expected), []byte(got)) == 1
}
