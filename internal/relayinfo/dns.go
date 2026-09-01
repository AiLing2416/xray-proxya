package relayinfo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"xray-proxya/internal/relaytest"
)

var (
	ErrNoIPv6Address = errors.New("no IPv6 (AAAA) record found for domain")
	ErrNoIPv4Address = errors.New("no IPv4 (A) record found for domain")
)

// newDirectedHTTPClient creates an HTTP client customized for a specific IP family policy.
func newDirectedHTTPClient(session *relaytest.TestSession, family IPFamily) *http.Client {
	if session == nil {
		return nil
	}
	if family == IPFamilyNatural {
		return session.HTTPClient
	}

	dialer := session.Dialer
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			targetAddr, err := resolveTargetAddress(ctx, session.HTTPClient, addr, family)
			if err != nil {
				return nil, err
			}
			return dialer.Dial(network, targetAddr)
		},
		DisableCompression:    true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   0,
	}
}

func resolveTargetAddress(ctx context.Context, client *http.Client, hostPort string, family IPFamily) (string, error) {
	if family == IPFamilyNatural {
		return hostPort, nil
	}

	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort, err
	}

	// If host is already an IP literal, return as is
	cleanHost := strings.Trim(host, "[]")
	if ip := net.ParseIP(cleanHost); ip != nil {
		if family == IPFamilyIPv6 && ip.To4() != nil {
			return "", ErrNoIPv6Address
		}
		if family == IPFamilyIPv4 && ip.To4() == nil {
			return "", ErrNoIPv4Address
		}
		return hostPort, nil
	}

	qType := "A"
	if family == IPFamilyIPv6 {
		qType = "AAAA"
	}

	// Resolve via DoH through the proxy following CNAME chains recursively
	ip, err := lookupDoHWithCNAME(ctx, client, host, qType, 0)
	if err != nil {
		return "", err
	}

	return net.JoinHostPort(ip, port), nil
}

func lookupDoHWithCNAME(ctx context.Context, client *http.Client, domain, qType string, depth int) (string, error) {
	if depth > 5 {
		if qType == "AAAA" {
			return "", ErrNoIPv6Address
		}
		return "", ErrNoIPv4Address
	}

	dohProviders := []string{
		"https://1.1.1.1/dns-query",
		"https://dns.google/resolve",
	}

	for _, provider := range dohProviders {
		reqURL := fmt.Sprintf("%s?name=%s&type=%s", provider, url.QueryEscape(domain), qType)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		req.Header.Set("User-Agent", "curl/8.4.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			continue
		}

		var dohRes struct {
			Status int `json:"Status"`
			Answer []struct {
				Name string `json:"name"`
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}

		err = json.NewDecoder(resp.Body).Decode(&dohRes)
		resp.Body.Close()
		if err != nil {
			continue
		}

		targetType := 1 // A
		if qType == "AAAA" {
			targetType = 28 // AAAA
		}

		// 1. First pass: look for direct matching IP address record
		for _, ans := range dohRes.Answer {
			if ans.Type == targetType && ans.Data != "" {
				data := strings.TrimSpace(ans.Data)
				if net.ParseIP(data) != nil {
					return data, nil
				}
			}
		}

		// 2. Second pass: if no IP found, follow CNAME records
		var lastCNAME string
		for _, ans := range dohRes.Answer {
			if ans.Type == 5 && ans.Data != "" { // CNAME
				lastCNAME = strings.TrimSuffix(strings.TrimSpace(ans.Data), ".")
			}
		}

		if lastCNAME != "" && !strings.EqualFold(lastCNAME, domain) {
			// Query the CNAME target recursively
			cnameIP, err := lookupDoHWithCNAME(ctx, client, lastCNAME, qType, depth+1)
			if err == nil && cnameIP != "" {
				return cnameIP, nil
			}
		}
	}

	if qType == "AAAA" {
		return "", ErrNoIPv6Address
	}
	return "", ErrNoIPv4Address
}
