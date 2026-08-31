package doctor

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/http"
	"time"
)

var ntpServers = []string{
	"pool.ntp.org:123",
	"time.cloudflare.com:123",
	"time.google.com:123",
	"time.apple.com:123",
}

var httpTimeServers = []string{
	"https://1.1.1.1",
	"https://www.cloudflare.com",
	"https://www.google.com",
}

// CheckClockSkew queries public NTP pools (with HTTP Date fallback) to calculate
// the local host clock offset.
func CheckClockSkew(ctx context.Context) CheckResult {
	start := time.Now()

	// 1. Try SNTP first
	for _, srv := range ntpServers {
		offset, rtt, err := querySNTP(ctx, srv)
		if err == nil {
			return evaluateClockOffset(offset, srv, rtt, time.Since(start))
		}
	}

	// 2. Fallback to HTTP Date header
	for _, srv := range httpTimeServers {
		offset, rtt, err := queryHTTPTime(ctx, srv)
		if err == nil {
			return evaluateClockOffset(offset, srv+" (HTTP)", rtt, time.Since(start))
		}
	}

	return CheckResult{
		Category:    "Time & Clock",
		Name:        "System Clock Skew",
		Status:      StatusFail,
		Detail:      "Unable to reach any public NTP or HTTP time server",
		Remediation: "Verify outbound network connectivity and DNS resolution",
		DurationMs:  time.Since(start).Milliseconds(),
	}
}

func evaluateClockOffset(offset time.Duration, source string, rtt time.Duration, totalDuration time.Duration) CheckResult {
	absSeconds := math.Abs(offset.Seconds())
	formattedOffset := formatOffset(offset)

	if absSeconds < 5.0 {
		return CheckResult{
			Category:   "Time & Clock",
			Name:       "System Clock Skew",
			Status:     StatusPass,
			Detail:     fmt.Sprintf("Offset: %s (source: %s, RTT: %dms)", formattedOffset, source, rtt.Milliseconds()),
			DurationMs: totalDuration.Milliseconds(),
		}
	} else if absSeconds < 30.0 {
		return CheckResult{
			Category:    "Time & Clock",
			Name:        "System Clock Skew",
			Status:      StatusWarn,
			Detail:      fmt.Sprintf("Clock drift detected: %s (source: %s)", formattedOffset, source),
			Remediation: "Synchronize host clock using systemd-timesyncd or chrony",
			DurationMs:  totalDuration.Milliseconds(),
		}
	} else {
		return CheckResult{
			Category:    "Time & Clock",
			Name:        "System Clock Skew",
			Status:      StatusFail,
			Detail:      fmt.Sprintf("Severe clock skew: %s (source: %s)", formattedOffset, source),
			Remediation: "Sync time immediately (e.g. 'chronyd -q \"server pool.ntp.org iburst\"') to prevent TLS/Reality handshake failures",
			DurationMs:  totalDuration.Milliseconds(),
		}
	}
}

func formatOffset(d time.Duration) string {
	sign := "+"
	if d < 0 {
		sign = "-"
		d = -d
	}
	if d < time.Second {
		return fmt.Sprintf("%s%dms", sign, d.Milliseconds())
	}
	return fmt.Sprintf("%s%.2fs", sign, d.Seconds())
}

// querySNTP performs a standard SNTP (RFC 4330 / 5905) packet exchange.
func querySNTP(ctx context.Context, server string) (time.Duration, time.Duration, error) {
	d := net.Dialer{Timeout: 2500 * time.Millisecond}
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()

	// 48-byte request packet: LI=0, VN=3 (NTPv3), Mode=3 (Client)
	req := make([]byte, 48)
	req[0] = 0x1B

	t0 := time.Now()
	if err := conn.SetDeadline(time.Now().Add(2500 * time.Millisecond)); err != nil {
		return 0, 0, err
	}
	if _, err := conn.Write(req); err != nil {
		return 0, 0, err
	}

	resp := make([]byte, 48)
	n, err := conn.Read(resp)
	t3 := time.Now()
	if err != nil {
		return 0, 0, err
	}
	if n < 48 {
		return 0, 0, fmt.Errorf("truncated NTP packet (%d bytes)", n)
	}

	// Transmit Timestamp (T2) at byte 40..47
	secs := binary.BigEndian.Uint32(resp[40:44])
	frac := binary.BigEndian.Uint32(resp[44:48])

	if secs == 0 {
		return 0, 0, fmt.Errorf("invalid zero timestamp from NTP server")
	}

	// NTP Epoch is 1900-01-01; Unix Epoch is 1970-01-01 (70 years = 2208988800 seconds)
	const ntpEpochOffset = 2208988800
	unixSecs := int64(secs) - ntpEpochOffset
	nanosecs := (int64(frac) * 1e9) >> 32
	serverTime := time.Unix(unixSecs, nanosecs)

	// Round-trip time and clock offset
	rtt := t3.Sub(t0)
	// Offset = (T2 - T0) - RTT/2
	offset := serverTime.Sub(t0.Add(rtt / 2))

	return offset, rtt, nil
}

// queryHTTPTime uses the HTTP Date header as fallback.
func queryHTTPTime(ctx context.Context, url string) (time.Duration, time.Duration, error) {
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return 0, 0, err
	}

	t0 := time.Now()
	resp, err := client.Do(req)
	t3 := time.Now()
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	dateStr := resp.Header.Get("Date")
	if dateStr == "" {
		return 0, 0, fmt.Errorf("missing Date header")
	}

	serverTime, err := http.ParseTime(dateStr)
	if err != nil {
		return 0, 0, err
	}

	rtt := t3.Sub(t0)
	offset := serverTime.Sub(t0.Add(rtt / 2))
	return offset, rtt, nil
}
