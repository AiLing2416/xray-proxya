package endpoint

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// TestIPv6Reachability tests IPv6 Internet reachability with LocalAddr bound to sourceIPv6.
// It uses Happy Eyeballs concurrent probing against Cloudflare ([2606:4700:4700::1111]:53)
// and Google ([2001:4860:4860::8888]:53) via TCP port 53. If either handshake succeeds,
// it returns true, the round-trip latency, and nil. If both fail, it returns false, 0, and the last error.
func TestIPv6Reachability(sourceIPv6 string, timeout time.Duration) (bool, time.Duration, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	src := net.ParseIP(sourceIPv6)
	if src == nil || src.To4() != nil {
		return false, 0, fmt.Errorf("invalid source IPv6 address: %q", sourceIPv6)
	}

	targets := []string{
		"[2606:4700:4700::1111]:53", // Cloudflare DNS
		"[2001:4860:4860::8888]:53", // Google DNS
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type result struct {
		ok  bool
		rtt time.Duration
		err error
	}

	resCh := make(chan result, len(targets))
	for _, target := range targets {
		go func(t string) {
			start := time.Now()
			d := net.Dialer{
				LocalAddr: &net.TCPAddr{IP: src},
			}
			conn, err := d.DialContext(ctx, "tcp6", t)
			rtt := time.Since(start)
			if err == nil {
				conn.Close()
				resCh <- result{ok: true, rtt: rtt}
				return
			}
			resCh <- result{ok: false, err: err}
		}(target)
	}

	var lastErr error
	for range targets {
		res := <-resCh
		if res.ok {
			cancel()
			return true, res.rtt, nil
		}
		if res.err != nil {
			lastErr = res.err
		}
	}
	return false, 0, lastErr
}

// TestHostReachability tests the reachability of a target host or IP (IPv4 or IPv6)
// by probing standard ports (443, 80, 53) or the specified port if one is provided.
func TestHostReachability(host string, timeout time.Duration) (bool, time.Duration, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	cleanHost := strings.TrimSpace(host)
	if cleanHost == "" {
		return false, 0, fmt.Errorf("empty host specified")
	}

	var targets []string
	if _, _, err := net.SplitHostPort(cleanHost); err == nil {
		targets = []string{cleanHost}
	} else {
		// Probe standard ports
		for _, port := range []string{"443", "80", "53"} {
			targets = append(targets, net.JoinHostPort(cleanHost, port))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type result struct {
		ok  bool
		rtt time.Duration
		err error
	}

	resCh := make(chan result, len(targets))
	for _, target := range targets {
		go func(t string) {
			start := time.Now()
			d := net.Dialer{}
			conn, err := d.DialContext(ctx, "tcp", t)
			rtt := time.Since(start)
			if err == nil {
				conn.Close()
				resCh <- result{ok: true, rtt: rtt}
				return
			}
			// If connection refused (RST), the remote host is alive and responded!
			if strings.Contains(err.Error(), "connection refused") {
				resCh <- result{ok: true, rtt: rtt}
				return
			}
			resCh <- result{ok: false, err: err}
		}(target)
	}

	var lastErr error
	for range targets {
		res := <-resCh
		if res.ok {
			cancel()
			return true, res.rtt, nil
		}
		if res.err != nil {
			lastErr = res.err
		}
	}
	return false, 0, lastErr
}
