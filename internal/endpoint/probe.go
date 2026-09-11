package endpoint

import (
	"fmt"
	"net"
	"time"
)

// TestIPv6Reachability tests IPv6 Internet reachability with LocalAddr bound to sourceIPv6.
// It sequentially dials Cloudflare ([2606:4700:4700::1111]:53) and Google ([2001:4860:4860::8888]:53)
// via TCP port 53. If either handshake succeeds, it returns true, the round-trip latency, and nil.
// If both fail, it returns false, 0, and the last dial error.
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

	var lastErr error
	for _, target := range targets {
		start := time.Now()
		d := net.Dialer{
			LocalAddr: &net.TCPAddr{IP: src},
			Timeout:   timeout,
		}
		conn, err := d.Dial("tcp6", target)
		if err == nil {
			rtt := time.Since(start)
			conn.Close()
			return true, rtt, nil
		}
		lastErr = err
	}
	return false, 0, lastErr
}
