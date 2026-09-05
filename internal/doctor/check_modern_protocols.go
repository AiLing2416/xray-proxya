package doctor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"xray-proxya/internal/config"
	"xray-proxya/internal/netprobe"
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

	dt := &netprobe.DirectTransport{}

	// 1. Test DoH (DNS-over-HTTPS)
	_, dohErr := netprobe.ProbeDoH(ctx, dt)
	dohOK := (dohErr == nil)

	// 2. Test HTTP/2 (ALPN h2 negotiation)
	_, h2Err := netprobe.ProbeHTTP2(ctx, dt, "https://1.1.1.1")
	h2OK := (h2Err == nil)

	// 3. Test HTTP/3 (Alt-Svc and UDP 443 probe)
	h3OK, _ := netprobe.ProbeHTTP3(ctx, dt, "1.1.1.1:443", "https://1.1.1.1")

	// 4. Test ECH (HTTPS Type 65 DNS record retrieval with ECHConfig)
	_, echErr := netprobe.ProbeECH(ctx, dt)
	echOK := (echErr == nil)

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
			Category:   "Modern Protocols",
			Name:       "DoH & Web Security (H2/H3/ECH)",
			Status:     StatusPass,
			Detail:     detailStr,
			DurationMs: time.Since(start).Milliseconds(),
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
