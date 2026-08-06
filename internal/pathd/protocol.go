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
)

const (
	maxFrameSize    = 16 << 10
	protocolVersion = 1
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

// Client is one PathLink stream. It deliberately has no reconnect loop; callers
// create it lazily and discard it after their own idle timeout.
type Client struct {
	conn net.Conn
	mu   sync.Mutex
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
	return &Client{conn: conn}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) Ping(target string, timeoutMS int) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if net.ParseIP(target) == nil {
		return 0, fmt.Errorf("pathd accepts literal IP targets only")
	}
	if timeoutMS < 100 || timeoutMS > 15000 {
		return 0, fmt.Errorf("invalid pathd timeout")
	}
	if err := writeFrame(c.conn, frame{Type: "icmp_echo", ID: 1, Target: target, Timeout: timeoutMS}); err != nil {
		return 0, err
	}
	response, err := readFrame(c.conn)
	if err != nil {
		return 0, err
	}
	if response.Type != "result" {
		return 0, fmt.Errorf("unexpected pathd response %q", response.Type)
	}
	if response.Error != "" {
		return 0, fmt.Errorf("pathd probe: %s", response.Error)
	}
	return response.RTT, nil
}

func tokenEqual(expected, got string) bool {
	if expected == "" || len(expected) != len(got) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(got)) == 1
}
