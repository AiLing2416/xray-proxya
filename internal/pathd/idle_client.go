package pathd

import (
	"net"
	"sync"
	"time"
	"xray-proxya/pkg/utils"
)

// IdleClient carries bounded concurrent PathLink requests over a relay-pinned
// SOCKS stream and closes that stream after genuine inactivity.
type IdleClient struct {
	socks, target, token string
	idle                 time.Duration
	mu                   sync.Mutex
	client               *Client
	last                 time.Time
	timer                *time.Timer
}

func NewIdleClient(socks, target, token string, idle time.Duration) *IdleClient {
	return &IdleClient{socks: socks, target: target, token: token, idle: idle}
}

func (c *IdleClient) Ping(ip net.IP) (time.Duration, error) {
	c.mu.Lock()
	if c.client != nil && time.Since(c.last) > c.idle {
		_ = c.client.Close()
		c.client = nil
	}
	if c.client == nil {
		dialer, err := utils.NewSOCKS5DialerWithTimeout(c.socks, 10*time.Second)
		if err != nil {
			c.mu.Unlock()
			return 0, err
		}
		conn, err := dialer.Dial("tcp", c.target)
		if err != nil {
			c.mu.Unlock()
			return 0, err
		}
		client, err := NewClient(conn, c.token)
		if err != nil {
			c.mu.Unlock()
			return 0, err
		}
		c.client = client
	}
	client := c.client
	c.last = time.Now()
	c.resetIdleTimerLocked()
	c.mu.Unlock()
	rtt, err := client.Ping(ip.String(), 8000)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = time.Now()
	c.resetIdleTimerLocked()
	if err != nil && c.client == client {
		_ = client.Close()
		c.client = nil
	}
	return time.Duration(rtt), err
}

func (c *IdleClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
	}
	if c.client != nil {
		err := c.client.Close()
		c.client = nil
		return err
	}
	return nil
}
func (c *IdleClient) resetIdleTimerLocked() {
	if c.idle <= 0 {
		return
	}
	if c.timer != nil {
		c.timer.Stop()
	}
	client := c.client
	c.timer = time.AfterFunc(c.idle, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.client == client && time.Since(c.last) >= c.idle {
			_ = client.Close()
			c.client = nil
		}
	})
}
