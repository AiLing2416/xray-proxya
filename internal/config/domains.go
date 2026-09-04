package config

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// CloudVendor identifiers
const (
	VendorAWS        = "aws"
	VendorGCP        = "gcp"
	VendorAzure      = "azure"
	VendorCloudflare = "cloudflare"
	VendorOracle     = "oracle"
	VendorGeneric    = "generic"
)

// ==============================================================================
// REALITY Target Selection Principles and Exclusion Rules:
//
// 1. Multi-Tenant Shared CDNs (CRITICAL RELAY RISK - STRICTLY PROHIBITED):
//    - Prohibited: Cloudflare (cdn.jsdelivr.net, cdnjs.cloudflare.com, www.cloudflare.com,
//                  *.workers.dev, *.pages.dev), AWS CloudFront (*.cloudfront.net),
//                  Fastly (*.fastly.net), Akamai multi-tenant clusters.
//    - Rationale: REALITY performs raw L4 TCP/TLS fallback upon unauthenticated probes.
//      Multi-tenant Anycast CDNs share edge IPs across millions of independent customers
//      (including OpenAI, financial portals, and API gateways). Unauthenticated scanners
//      exploit this to use the VPS as an open proxy relay, hammering OpenAI/Cloudflare.
//      This results in massive resource theft/abuse complaints and hoster VM suspension.
//
// 2. Region-Dedicated / China-Specific Geo-Split CDNs (CROSS-BORDER INSTABILITY):
//    - Excluded: Microsoft (*.microsoft.com, *.azure.com, *.live.com, *.office.com, *.windows.com, *.bing.com),
//                Apple (*.apple.com, *.icloud.com, *.itunes.apple.com, *.mzstatic.com),
//                Canvas LMS (*.instructure.com, *.canvaslms.com).
//    - Rationale: These global services maintain segregated domestic infrastructure
//      (e.g., 21Vianet for Microsoft, local CDNs for Apple/Canvas). Geo-DNS and cross-border
//      routing differences induce SNI mismatches, handshake anomalies, and unstable links.
//
// 3. Microsoft-Managed Public Infrastructure with High Handshake Failure Rates:
//    - Excluded: GitHub (*.github.com, *.github.io, *.githubassets.com, *.githubusercontent.com, api.github.com).
//    - Rationale: Public endpoints frequently suffer from cross-border TCP resets, SNI filtering,
//      and high TLS handshake failure rates.
//
// 4. Approved Safe Targets (Single-Tenant / Dedicated Infrastructure):
//    - Approved: Linux distro & kernel mirrors (kernel.org, ubuntu.com),
//                Google dedicated developer infrastructure (pkg.go.dev, fonts.gstatic.com),
//                Oracle dedicated Linux repos (yum.oracle.com, docs.oracle.com, apex.oracle.com, cloud.oracle.com),
//                AWS dedicated official portals (a0.awsstatic.com, aws.amazon.com, d1.awsstatic.com, images-na.ssl-images-amazon.com, slack-imgs.com).
// ==============================================================================

var cloudVendorDomains = map[string][]string{
	VendorAWS: {
		"a0.awsstatic.com",
		"aws.amazon.com",
		"images-na.ssl-images-amazon.com",
		"www.imdb.com",
		"slack-imgs.com",
		"d1.awsstatic.com",
	},
	VendorGCP: {
		"pkg.go.dev",
		"fonts.gstatic.com",
	},
	VendorAzure:      {}, // Empty - Excluded due to region-split routing and cross-border handshake instability
	VendorCloudflare: {}, // Empty - Prohibited due to multi-tenant open proxy relay abuse vulnerability
	VendorOracle: {
		"docs.oracle.com",
		"apex.oracle.com",
		"cloud.oracle.com",
		"www.oracle.com",
	},
	VendorGeneric: {
		"www.debian.org",
		"www.kernel.org",
		"kernel.org",
		"ubuntu.com",
		"pkg.go.dev",
		"docs.oracle.com",
		"a0.awsstatic.com",
		"aws.amazon.com",
		"fonts.gstatic.com",
		"www.imdb.com",
		"cloud.oracle.com",
	},
}

// NormalizeVendor maps aliases to canonical vendor names.
func NormalizeVendor(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	switch lower {
	case "aws", "amazon", "cloudfront":
		return VendorAWS
	case "gcp", "google", "googlecloud":
		return VendorGCP
	case "azure", "microsoft", "ms":
		return VendorAzure
	case "cloudflare", "cf":
		return VendorCloudflare
	case "oracle", "oci":
		return VendorOracle
	case "generic", "global", "default":
		return VendorGeneric
	default:
		return lower
	}
}

// GetAllCloudVendors returns all supported vendor names for candidate target selection.
func GetAllCloudVendors() []string {
	return []string{
		VendorAWS,
		VendorGCP,
		VendorOracle,
		VendorGeneric,
	}
}

// IsValidCloudVendor checks if vendor is one of the recognized cloud vendors.
func IsValidCloudVendor(vendor string) bool {
	v := NormalizeVendor(vendor)
	for _, recognized := range GetAllCloudVendors() {
		if v == recognized {
			return true
		}
	}
	return false
}

// GetCloudVendorDomains returns domains for a specific vendor, or an error if unknown or empty.
func GetCloudVendorDomains(vendor string) ([]string, error) {
	v := NormalizeVendor(vendor)
	if v == VendorCloudflare {
		return nil, fmt.Errorf("Cloudflare is a multi-tenant shared CDN and is strictly prohibited as a REALITY target due to open proxy relay abuse risks (e.g. DMIT/OpenAI abuse incident)")
	}
	if v == VendorAzure {
		return nil, fmt.Errorf("Azure/Microsoft domains are excluded due to China-dedicated region-split routing and cross-border TLS handshake instability")
	}

	domains, ok := cloudVendorDomains[v]
	if !ok {
		return nil, fmt.Errorf("unknown cloud vendor %q", vendor)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("no candidate domains available for vendor %q", vendor)
	}
	out := make([]string, len(domains))
	copy(out, domains)
	return out, nil
}

// GetAllRealityDomains returns all deduplicated domains across all pools.
func GetAllRealityDomains() []string {
	seen := make(map[string]struct{})
	var all []string
	for _, domains := range cloudVendorDomains {
		for _, d := range domains {
			if _, ok := seen[d]; !ok {
				seen[d] = struct{}{}
				all = append(all, d)
			}
		}
	}
	return all
}

// GetRandomRealityDomain returns a random domain from the generic pool.
func GetRandomRealityDomain() string {
	domains := cloudVendorDomains[VendorGeneric]
	if len(domains) == 0 {
		return ""
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(domains))))
	if err != nil || n.Int64() >= int64(len(domains)) {
		return domains[0]
	}
	return domains[n.Int64()]
}

// DetectCloudVendor attempts to detect the current server's public cloud provider
// by inspecting the ASN/Org of its public IP.
func DetectCloudVendor() string {
	client := &http.Client{Timeout: 3 * time.Second}
	endpoints := []string{
		"https://ipinfo.io/json",
		"https://api.ip.sb/geoip",
	}

	for _, ep := range endpoints {
		req, err := http.NewRequest("GET", ep, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "xray-proxya")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if err != nil || len(body) == 0 {
			continue
		}

		var data struct {
			Org          string `json:"org"`
			Organization string `json:"organization"`
			ASNOrg       string `json:"asn_organization"`
			ASN          any    `json:"asn"`
		}
		if err := json.Unmarshal(body, &data); err != nil {
			continue
		}

		combined := strings.ToLower(fmt.Sprintf("%s %s %s %v", data.Org, data.Organization, data.ASNOrg, data.ASN))

		switch {
		case strings.Contains(combined, "amazon") || strings.Contains(combined, "aws") || strings.Contains(combined, "as16509") || strings.Contains(combined, "as14618"):
			return VendorAWS
		case strings.Contains(combined, "google") || strings.Contains(combined, "as15169") || strings.Contains(combined, "as396982"):
			return VendorGCP
		case strings.Contains(combined, "microsoft") || strings.Contains(combined, "azure") || strings.Contains(combined, "as8075"):
			return VendorAzure
		case strings.Contains(combined, "cloudflare") || strings.Contains(combined, "as13335"):
			return VendorCloudflare
		case strings.Contains(combined, "oracle") || strings.Contains(combined, "as31898"):
			return VendorOracle
		}
	}
	return ""
}

// NormalizeRealityTarget parses, normalizes, and validates a REALITY destination target.
// Returns normalized host (lowercase, no trailing dot), port, targetAddr (host:port), and any error.
func NormalizeRealityTarget(target string) (string, int, string, error) {
	raw := strings.TrimSpace(target)
	if raw == "" {
		return "", 0, "", fmt.Errorf("target cannot be empty")
	}
	if strings.Contains(raw, "://") || strings.Contains(raw, "/") || strings.Contains(raw, "?") || strings.Contains(raw, "#") {
		return "", 0, "", fmt.Errorf("target %q must be host or host:port, not a URL or path", target)
	}

	var host string
	var portStr string
	if strings.Contains(raw, ":") {
		var err error
		host, portStr, err = net.SplitHostPort(raw)
		if err != nil {
			return "", 0, "", fmt.Errorf("invalid target %q: %w", target, err)
		}
	} else {
		host = raw
		portStr = "443"
	}

	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return "", 0, "", fmt.Errorf("target host cannot be empty")
	}
	if net.ParseIP(host) != nil {
		return "", 0, "", fmt.Errorf("target %q must be a domain name, not an IP address literal", target)
	}
	if strings.ContainsAny(host, " \t\r\n/\\:*?\"<>|") {
		return "", 0, "", fmt.Errorf("target host %q contains invalid characters", host)
	}
	if !strings.Contains(host, ".") {
		return "", 0, "", fmt.Errorf("target host %q must be a fully qualified domain name", host)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, "", fmt.Errorf("target port in %q must be between 1 and 65535", target)
	}

	return host, port, net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// ValidateRealitySNIAndDest ensures that SNI is a normalized domain name and dest is host:port
// with the host matching SNI exactly. If dest is empty, it defaults to <SNI>:443.
func ValidateRealitySNIAndDest(sni, dest string) (string, string, error) {
	normSNI := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(sni)), ".")
	if normSNI == "" {
		return "", "", fmt.Errorf("REALITY SNI cannot be empty")
	}
	if net.ParseIP(normSNI) != nil {
		return "", "", fmt.Errorf("REALITY SNI %q cannot be an IP address", sni)
	}
	if strings.ContainsAny(normSNI, " \t\r\n/\\:*?\"<>|") || !strings.Contains(normSNI, ".") {
		return "", "", fmt.Errorf("REALITY SNI %q must be a valid domain name", sni)
	}

	dest = strings.TrimSpace(dest)
	if dest == "" {
		dest = net.JoinHostPort(normSNI, "443")
	}

	// Allow loopback destination for local skin fallback
	if strings.HasPrefix(dest, "127.0.0.1:") || strings.HasPrefix(dest, "localhost:") || strings.HasPrefix(dest, "[::1]:") {
		host, portStr, err := net.SplitHostPort(dest)
		if err == nil {
			if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 {
				return normSNI, net.JoinHostPort(host, strconv.Itoa(port)), nil
			}
		}
	}

	destHost, _, normDest, err := NormalizeRealityTarget(dest)
	if err != nil {
		return "", "", fmt.Errorf("invalid REALITY dest %q: %w", dest, err)
	}

	if destHost != normSNI {
		return "", "", fmt.Errorf("REALITY dest host %q must match SNI %q", destHost, normSNI)
	}

	return normSNI, normDest, nil
}

type targetValidatorOptions struct {
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	rootCAs     *x509.CertPool
}

var defaultTargetValidatorOpts = targetValidatorOptions{}

// ValidateRealityTarget performs comprehensive qualification for a Reality fallback target:
// 1. Host/port normalization and rejection of IP literals / invalid targets
// 2. TCP connectivity
// 3. Mandatory TLS 1.3 protocol negotiation with X25519 support
// 4. Valid certificate matching hostname (no InsecureSkipVerify)
// 5. ALPN negotiation of HTTP/2 ("h2")
// 6. HTTP/2 GET request to "/" confirming non-redirect (rejects any 3xx) and valid status (2xx, 401, 403, 404; rejects 5xx).
// Returns measured handshake RTT on success.
func ValidateRealityTarget(target string, timeout time.Duration) (time.Duration, error) {
	return validateSkinTargetInternal(target, timeout, defaultTargetValidatorOpts)
}

// ValidateSkinTarget is a backward-compatible alias for ValidateRealityTarget.
func ValidateSkinTarget(target string, timeout time.Duration) (time.Duration, error) {
	return ValidateRealityTarget(target, timeout)
}

func validateSkinTargetInternal(target string, timeout time.Duration, opts targetValidatorOptions) (time.Duration, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	host, _, targetAddr, err := NormalizeRealityTarget(target)
	if err != nil {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialFn := opts.dialContext
	if dialFn == nil {
		dialer := &net.Dialer{Timeout: timeout}
		dialFn = dialer.DialContext
	}

	rawConn, err := dialFn(ctx, "tcp", targetAddr)
	if err != nil {
		return 0, fmt.Errorf("TCP connection to %s failed: %w", targetAddr, err)
	}
	defer rawConn.Close()

	tlsConfig := &tls.Config{
		ServerName:       host,
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		NextProtos:       []string{"h2"},
		CurvePreferences: []tls.CurveID{tls.X25519},
		RootCAs:          opts.rootCAs,
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	start := time.Now()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return 0, fmt.Errorf("TLS 1.3 handshake failed for %s: %w", host, err)
	}
	rtt := time.Since(start)

	state := tlsConn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		return 0, fmt.Errorf("server %s negotiated TLS version 0x%04x (TLS 1.3 required)", host, state.Version)
	}
	if state.NegotiatedProtocol != "h2" {
		return 0, fmt.Errorf("server %s negotiated ALPN protocol %q (h2 required)", host, state.NegotiatedProtocol)
	}
	if len(state.PeerCertificates) == 0 {
		return 0, fmt.Errorf("no peer certificate presented by %s", host)
	}
	if err := state.PeerCertificates[0].VerifyHostname(host); err != nil {
		return 0, fmt.Errorf("certificate does not match %s: %w", host, err)
	}

	t := &http2.Transport{}
	clientConn, err := t.NewClientConn(tlsConn)
	if err != nil {
		return 0, fmt.Errorf("HTTP/2 client init failed for %s: %w", host, err)
	}
	defer clientConn.Close()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+targetAddr+"/", nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create HTTP/2 request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := clientConn.RoundTrip(req)
	if err != nil {
		return 0, fmt.Errorf("HTTP/2 request failed for %s: %w", host, err)
	}
	defer resp.Body.Close()

	// Read limited body to release stream properly
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return 0, fmt.Errorf("target %s returned HTTP redirect (%d), expected non-redirect response", host, resp.StatusCode)
	}
	if resp.StatusCode >= 500 {
		return 0, fmt.Errorf("target %s returned server error (%d)", host, resp.StatusCode)
	}
	if !((resp.StatusCode >= 200 && resp.StatusCode < 300) ||
		resp.StatusCode == http.StatusUnauthorized ||
		resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusNotFound) {
		return 0, fmt.Errorf("target %s returned unexpected HTTP status %d (expected 2xx, 401, 403, or 404)", host, resp.StatusCode)
	}

	return rtt, nil
}

// BenchmarkDomains probes candidate domains concurrently and returns the fastest valid candidate.
func BenchmarkDomains(domains []string, timeout time.Duration) (string, time.Duration, error) {
	return benchmarkDomainsInternal(domains, timeout, defaultTargetValidatorOpts)
}

func benchmarkDomainsInternal(domains []string, timeout time.Duration, opts targetValidatorOptions) (string, time.Duration, error) {
	if len(domains) == 0 {
		return "", 0, fmt.Errorf("no candidate domains provided")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	const maxWorkers = 8
	sem := make(chan struct{}, maxWorkers)

	type probeResult struct {
		domain string
		rtt    time.Duration
		err    error
	}

	results := make(chan probeResult, len(domains))
	var wg sync.WaitGroup

	for _, d := range domains {
		domain := d
		wg.Add(1)
		go func(dom string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rtt, err := validateSkinTargetInternal(dom, timeout, opts)
			results <- probeResult{domain: dom, rtt: rtt, err: err}
		}(domain)
	}

	wg.Wait()
	close(results)

	var bestDomain string
	var bestRTT time.Duration = time.Hour
	var allErrs []string

	for res := range results {
		if res.err == nil {
			if res.rtt < bestRTT {
				bestRTT = res.rtt
				bestDomain = res.domain
			}
		} else {
			allErrs = append(allErrs, fmt.Sprintf("%s: %v", res.domain, res.err))
		}
	}

	if bestDomain == "" {
		return "", 0, fmt.Errorf("no candidate domains qualified (%s)", strings.Join(allErrs, "; "))
	}
	return bestDomain, bestRTT, nil
}

var cloudflareCIDRs = []string{
	// Cloudflare IPv4
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	// Cloudflare IPv6
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

var parsedCloudflareIPNets []*net.IPNet

func init() {
	for _, cidr := range cloudflareCIDRs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedCloudflareIPNets = append(parsedCloudflareIPNets, ipnet)
		}
	}
}

func matchDomainSuffix(host, pattern string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if host == pattern {
		return true
	}
	if strings.HasSuffix(host, "."+pattern) {
		return true
	}
	return false
}

// InspectRealityDomainRisk evaluates a target hostname or address against known high-risk categories.
// Returns (isRisky, riskReason).
func InspectRealityDomainRisk(target string) (bool, string) {
	normHost, _, _, err := NormalizeRealityTarget(target)
	if err != nil {
		normHost = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
		if strings.Contains(normHost, ":") {
			if h, _, e := net.SplitHostPort(normHost); e == nil {
				normHost = h
			}
		}
	}
	if normHost == "" {
		return false, ""
	}

	// 1. Multi-Tenant Shared CDNs (Critical Open Relay / Proxy Abuse Risk)
	multiTenantPatterns := []string{
		"cloudflare.com",
		"cloudflare.net",
		"workers.dev",
		"pages.dev",
		"jsdelivr.net",
		"cloudfront.net",
		"fastly.net",
		"fastlylb.net",
		"akamaized.net",
		"akamaihd.net",
		"akamai.net",
		"edgekey.net",
		"edgesuite.net",
		"edgecastcdn.net",
		"hwcdn.net",
	}
	for _, p := range multiTenantPatterns {
		if matchDomainSuffix(normHost, p) {
			return true, fmt.Sprintf("Multi-tenant shared CDN (%s) detected. REALITY fallback will expose your VPS as an open proxy relay, causing abuse complaints and provider suspension (e.g. DMIT/OpenAI abuse incident).", p)
		}
	}

	// 2. Region-Dedicated / China-Specific Geo-Split CDNs
	chinaGeoSplitPatterns := []string{
		"apple.com",
		"icloud.com",
		"itunes.apple.com",
		"mzstatic.com",
		"aaplimg.com",
		"instructure.com",
		"canvaslms.com",
		"microsoft.com",
		"azure.com",
		"live.com",
		"office.com",
		"windows.com",
		"bing.com",
		"microsoftonline.com",
		"msn.com",
	}
	for _, p := range chinaGeoSplitPatterns {
		if matchDomainSuffix(normHost, p) {
			return true, fmt.Sprintf("Domain belongs to service with China-dedicated / region-split CDN infrastructure (%s). Geo-DNS and cross-border routing induce SNI mismatches and connection instability.", p)
		}
	}

	// 3. Microsoft-managed public infrastructure with high handshake failure rates
	msPublicPatterns := []string{
		"github.com",
		"github.io",
		"githubassets.com",
		"githubusercontent.com",
	}
	for _, p := range msPublicPatterns {
		if matchDomainSuffix(normHost, p) {
			return true, fmt.Sprintf("Public service infrastructure (%s) experiences frequent cross-border TCP resets and TLS handshake failures.", p)
		}
	}

	// 4. IP-based Cloudflare detection (in case domain uses custom CNAME / Cloudflare proxy)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	var resolver net.Resolver
	ips, err := resolver.LookupIP(ctx, "ip", normHost)
	if err == nil {
		for _, ip := range ips {
			for _, ipnet := range parsedCloudflareIPNets {
				if ipnet.Contains(ip) {
					return true, fmt.Sprintf("Target resolves to Cloudflare Anycast IP (%s). Multi-tenant CDN fallback creates an open proxy relay vulnerability.", ip.String())
				}
			}
		}
	}

	return false, ""
}
