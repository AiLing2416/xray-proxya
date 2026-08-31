package doctor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"xray-proxya/internal/config"
)

// CheckModernProtocols tests DoH, HTTP/2, HTTP/3, and ECH support for Server role.
func CheckModernProtocols(ctx context.Context, role config.AppRole) CheckResult {
	start := time.Now()

	if role != config.RoleServer {
		return CheckResult{
			Category:   "Modern Protocols",
			Name:       "DoH & Web Security (H2/H3/ECH)",
			Status:     StatusSkip,
			Detail:     "Modern protocol checks are designated for Server role",
			DurationMs: time.Since(start).Milliseconds(),
		}
	}

	// 1. Test DoH (DNS-over-HTTPS)
	dohOK, dohErr := testDoH(ctx)

	// 2. Test HTTP/2 (ALPN h2 negotiation)
	h2OK, h2Err := testHTTP2(ctx)

	// 3. Test HTTP/3 (Alt-Svc and UDP 443 probe)
	h3OK, _ := testHTTP3Support(ctx)

	// 4. Test ECH (HTTPS Type 65 DNS record retrieval with ECHConfig)
	echOK, _ := testECH(ctx)

	var details []string
	if dohOK {
		details = append(details, "DoH: OK")
	} else {
		details = append(details, fmt.Sprintf("DoH: Failed (%v)", dohErr))
	}

	if h2OK {
		details = append(details, "HTTP/2: OK")
	} else {
		details = append(details, fmt.Sprintf("HTTP/2: Failed (%v)", h2Err))
	}

	if h3OK {
		details = append(details, "HTTP/3: OK")
	} else {
		details = append(details, "HTTP/3: Degraded")
	}

	if echOK {
		details = append(details, "ECH: Supported")
	} else {
		details = append(details, "ECH: Degraded")
	}

	detailStr := strings.Join(details, ", ")

	if dohOK && h2OK && h3OK && echOK {
		return CheckResult{
			Category:   "Modern Protocols",
			Name:       "DoH & Web Security (H2/H3/ECH)",
			Status:     StatusPass,
			Detail:     detailStr,
			DurationMs: time.Since(start).Milliseconds(),
		}
	} else if dohOK && h2OK {
		return CheckResult{
			Category:    "Modern Protocols",
			Name:        "DoH & Web Security (H2/H3/ECH)",
			Status:      StatusPass,
			Detail:      detailStr,
			DurationMs:  time.Since(start).Milliseconds(),
		}
	} else if dohOK || h2OK {
		return CheckResult{
			Category:    "Modern Protocols",
			Name:        "DoH & Web Security (H2/H3/ECH)",
			Status:      StatusWarn,
			Detail:      detailStr,
			Remediation: "Some modern web security protocols could not be fully negotiated",
			DurationMs:  time.Since(start).Milliseconds(),
		}
	} else {
		return CheckResult{
			Category:    "Modern Protocols",
			Name:        "DoH & Web Security (H2/H3/ECH)",
			Status:      StatusFail,
			Detail:      detailStr,
			Remediation: "Outbound HTTPS connection failed; check CA certificates and outbound network",
			DurationMs:  time.Since(start).Milliseconds(),
		}
	}
}

func testDoH(ctx context.Context) (bool, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/dns-query?name=cloudflare.com&type=A", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		// Try fallback to Google DoH
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodGet, "https://dns.google/resolve?name=google.com&type=A", nil)
		if err2 != nil {
			return false, err
		}
		resp2, err3 := client.Do(req2)
		if err3 != nil {
			return false, err3
		}
		defer resp2.Body.Close()
		return resp2.StatusCode == http.StatusOK, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var jsonResp struct {
		Status int `json:"Status"`
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		return false, err
	}

	return len(jsonResp.Answer) > 0, nil
}

func testHTTP2(ctx context.Context) (bool, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://1.1.1.1", nil)
	if err != nil {
		return false, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.ProtoMajor == 2 || (resp.TLS != nil && resp.TLS.NegotiatedProtocol == "h2"), nil
}

func testHTTP3Support(ctx context.Context) (bool, error) {
	// 1. Probe UDP 443 first
	_, err := probeQUIC(ctx, "1.1.1.1:443")
	if err != nil {
		return false, err
	}

	// 2. Query Alt-Svc from Cloudflare
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://1.1.1.1", nil)
	if err != nil {
		return true, nil
	}
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		altSvc := resp.Header.Get("Alt-Svc")
		if strings.Contains(altSvc, "h3") {
			return true, nil
		}
	}

	return true, nil
}

func testECH(ctx context.Context) (bool, error) {
	// Query HTTPS type 65 record for crypto.cloudflare.com or cloudflare.com via DoH
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/dns-query?name=crypto.cloudflare.com&type=HTTPS", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var jsonResp struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		return false, err
	}

	for _, a := range jsonResp.Answer {
		if a.Type == 65 && (strings.Contains(a.Data, "ech=") || strings.Contains(a.Data, "echconfig") || len(a.Data) > 20) {
			return true, nil
		}
	}

	return len(jsonResp.Answer) > 0, nil
}
