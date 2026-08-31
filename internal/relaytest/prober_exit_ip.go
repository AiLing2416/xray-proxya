package relaytest

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ipv4LookupURLs = []string{
		"https://api4.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://v4.ident.me",
	}

	ipv6LookupURLs = []string{
		"https://api6.ipify.org",
		"https://ipv6.icanhazip.com",
		"https://v6.ident.me",
	}
)

func probeExitIP(ctx context.Context, session *TestSession, transport TransportResult) ExitIPResult {
	// Fail-fast: If transport completely failed, skip exit IP lookups to avoid waiting on dead proxy
	if transport.TCPStatus == StatusFail && transport.UDPStatus == StatusFail {
		return ExitIPResult{
			IPv4Status: StatusFail,
			IPv6Status: StatusFail,
		}
	}

	// 10s independent timeout for Exit IP probing
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	res := ExitIPResult{
		IPv4Status: StatusFail,
		IPv6Status: StatusFail,
	}

	var wg sync.WaitGroup

	// 1. Fetch IPv4
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, u := range ipv4LookupURLs {
			ip := fetchIPString(probeCtx, session.HTTPClient, u)
			if ip != "" && isIPv4(ip) {
				res.IPv4 = ip
				res.IPv4Status = StatusPass
				return
			}
		}
	}()

	// 2. Fetch IPv6
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, u := range ipv6LookupURLs {
			ip := fetchIPString(probeCtx, session.HTTPClient, u)
			if ip != "" && isIPv6(ip) {
				res.IPv6 = ip
				res.IPv6Status = StatusPass
				return
			}
		}
	}()

	wg.Wait()
	return res
}

func fetchIPString(ctx context.Context, client *http.Client, targetURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "curl/8.4.0")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return ""
	}
	raw := strings.TrimSpace(string(body))
	parsed := net.ParseIP(raw)
	if parsed != nil {
		return parsed.String()
	}
	return ""
}

func isIPv4(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.To4() != nil
}

func isIPv6(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.To4() == nil && ip.To16() != nil
}
