package pathd

import (
	"net"
	"sync"
	"time"
	"xray-proxya/pkg/utils"
)

// IdleClient carries PathLink over a SOCKS inbound pinned to the chosen relay.
// It intentionally holds only one stream and tears it down after inactivity.
type IdleClient struct {
	socks, target, token string
	idle                 time.Duration
	mu                   sync.Mutex
	client               *Client
	last                 time.Time
}

func NewIdleClient(socks, target, token string, idle time.Duration) *IdleClient {
	return &IdleClient{socks: socks, target: target, token: token, idle: idle}
}

func (c *IdleClient) Ping(ip net.IP) (time.Duration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil && time.Since(c.last) > c.idle {
		_ = c.client.Close()
		c.client = nil
	}
	if c.client == nil {
		dialer, err := utils.NewSOCKS5DialerWithTimeout(c.socks, 10*time.Second)
		if err != nil {
			return 0, err
		}
		conn, err := dialer.Dial("tcp", c.target)
		if err != nil {
			return 0, err
		}
		client, err := NewClient(conn, c.token)
		if err != nil {
			return 0, err
		}
		c.client = client
	}
	rtt, err := c.client.Ping(ip.String(), 8000)
	c.last = time.Now()
	if err != nil {
		_ = c.client.Close()
		c.client = nil
		return 0, err
	}
	return time.Duration(rtt), nil
}

func (c *IdleClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		err := c.client.Close()
		c.client = nil
		return err
	}
	return nil
}
