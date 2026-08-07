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
	Version uint8  `json:"v"`
	Type    string `json:"type"`
	Token   string `json:"token,omitempty"`
	ID      uint64 `json:"id,omitempty"`
	Target  string `json:"target,omitempty"`
	Timeout int    `json:"timeout_ms,omitempty"`
	RTT     int64  `json:"rtt_ns,omitempty"`
	Error   string `json:"error,omitempty"`
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
	rtt int64
	err error
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
	if err := ValidateProbeTarget(net.ParseIP(target)); err != nil {
		return 0, err
	}
	if timeoutMS < 100 || timeoutMS > 15000 {
		return 0, fmt.Errorf("invalid pathd timeout")
	}
	c.mu.Lock()
	if len(c.pending) >= maxInFlight {
		c.mu.Unlock()
		return 0, fmt.Errorf("PathLink is busy")
	}
	c.nextID++
	id := c.nextID
	resultCh := make(chan clientResult, 1)
	c.pending[id] = resultCh
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, id); c.mu.Unlock() }()
	c.writeMu.Lock()
	err := writeFrame(c.conn, frame{Type: "icmp_echo", ID: id, Target: target, Timeout: timeoutMS})
	c.writeMu.Unlock()
	if err != nil {
		c.failPending(err)
		return 0, err
	}
	select {
	case result := <-resultCh:
		return result.rtt, result.err
	case <-time.After(time.Duration(timeoutMS+2000) * time.Millisecond):
		return 0, fmt.Errorf("PathLink request timed out")
	case <-c.done:
		return 0, fmt.Errorf("PathLink closed")
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
		result := clientResult{rtt: response.RTT}
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
