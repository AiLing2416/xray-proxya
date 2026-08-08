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
	inFlight             int
	lastRTT              time.Duration
	lastError            string
}

// RuntimeSnapshot is safe to persist or display without exposing the token.
type RuntimeSnapshot struct {
	Connected    bool
	InFlight     int
	LastActivity time.Time
	LastRTT      time.Duration
	LastError    string
}

func NewIdleClient(socks, target, token string, idle time.Duration) *IdleClient {
	return &IdleClient{socks: socks, target: target, token: token, idle: idle}
}

func (c *IdleClient) Ping(ip net.IP) (time.Duration, error) {
	result, err := c.Probe(ip)
	if err != nil {
		return 0, err
	}
	return result.RTT, result.Error()
}

func (c *IdleClient) Probe(ip net.IP) (ProbeResult, error) {
	return c.ProbeTTL(ip, 64)
}

func (c *IdleClient) ProbeTTL(ip net.IP, ttl int) (ProbeResult, error) {
	return c.ProbeWithOptions(ip, ProbeOptions{TTL: ttl, PayloadSize: 8})
}

func (c *IdleClient) ProbeWithOptions(ip net.IP, options ProbeOptions) (ProbeResult, error) {
	c.mu.Lock()
	if c.client != nil && time.Since(c.last) > c.idle {
		_ = c.client.Close()
		c.client = nil
	}
	if c.client == nil {
		dialer, err := utils.NewSOCKS5DialerWithTimeout(c.socks, 10*time.Second)
		if err != nil {
			c.mu.Unlock()
			return ProbeResult{}, err
		}
		conn, err := dialer.Dial("tcp", c.target)
		if err != nil {
			c.mu.Unlock()
			return ProbeResult{}, err
		}
		client, err := NewClient(conn, c.token)
		if err != nil {
			c.mu.Unlock()
			return ProbeResult{}, err
		}
		c.client = client
	}
	client := c.client
	c.last = time.Now()
	c.inFlight++
	c.resetIdleTimerLocked()
	c.mu.Unlock()
	result, err := client.ProbeWithOptions(ip.String(), 8000, options)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inFlight--
	c.last = time.Now()
	c.lastRTT = result.RTT
	c.lastError = ""
	c.resetIdleTimerLocked()
	if err != nil && c.client == client {
		c.lastError = err.Error()
		_ = client.Close()
		c.client = nil
	}
	return result, err
}

func (c *IdleClient) Snapshot() RuntimeSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return RuntimeSnapshot{Connected: c.client != nil, InFlight: c.inFlight, LastActivity: c.last, LastRTT: c.lastRTT, LastError: c.lastError}
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
