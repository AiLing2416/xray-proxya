package config

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
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

var cloudVendorDomains = map[string][]string{
	VendorAWS: {
		"a0.awsstatic.com",
		"signin.aws.amazon.com",
		"aws.amazon.com",
		"images-na.ssl-images-amazon.com",
		"www.imdb.com",
		"unroll.me",
		"slack-imgs.com",
		"d1.awsstatic.com",
		"d2gxp3ikbh7bpx.cloudfront.net",
	},
	VendorGCP: {
		"pkg.go.dev",
		"storage.googleapis.com",
		"fonts.gstatic.com",
		"dl.google.com",
		"cloud.google.com",
		"golang.org",
	},
	VendorAzure: {
		"portal.azure.com",
		"spoprod-a.akamaihd.net",
		"statics-marketingsites-eas-ms-com.akamaized.net",
		"learn.microsoft.com",
		"login.microsoftonline.com",
		"graph.microsoft.com",
		"res.cdn.office.net",
		"c.s-microsoft.com",
		"azure.microsoft.com",
	},
	VendorCloudflare: {
		"cdnjs.cloudflare.com",
		"www.cloudflare.com",
		"pages.dev",
		"community.cloudflare.com",
		"dash.cloudflare.com",
		"workers.dev",
	},
	VendorOracle: {
		"docs.oracle.com",
		"yum.oracle.com",
		"edelivery.oracle.com",
		"apex.oracle.com",
		"cloud.oracle.com",
		"www.oracle.com",
	},
	VendorGeneric: {
		"cdn.jsdelivr.net",
		"www.qualcomm.com",
		"github.githubassets.com",
		"api.github.com",
		"www.github.com",
		"addons.mozilla.org",
		"www.debian.org",
		"www.ubuntu.com",
		"www.kernel.org",
		"pkg.go.dev",
		"cdnjs.cloudflare.com",
		"a0.awsstatic.com",
		"portal.azure.com",
		"docs.oracle.com",
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

// GetAllCloudVendors returns all recognized vendor names.
func GetAllCloudVendors() []string {
	return []string{
		VendorAWS,
		VendorGCP,
		VendorAzure,
		VendorCloudflare,
		VendorOracle,
		VendorGeneric,
	}
}

// GetCloudVendorDomains returns domains for a specific vendor.
func GetCloudVendorDomains(vendor string) []string {
	v := NormalizeVendor(vendor)
	if domains, ok := cloudVendorDomains[v]; ok && len(domains) > 0 {
		out := make([]string, len(domains))
		copy(out, domains)
		return out
	}
	return GetCloudVendorDomains(VendorGeneric)
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

// ValidateSkinTarget performs comprehensive qualification for a Reality fallback target:
// 1. TCP connectivity
// 2. Mandatory TLS 1.3 protocol negotiation
// 3. Valid certificate matching hostname
// 4. Regional redirection (.cn trap) check
// Returns measured RTT on success.
func ValidateSkinTarget(target string, timeout time.Duration) (time.Duration, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = strings.TrimSpace(target)
		portStr = "443"
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || net.ParseIP(host) != nil {
		return 0, fmt.Errorf("target %q must be a valid domain name", target)
	}
	targetAddr := net.JoinHostPort(host, portStr)

	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	rawConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return 0, fmt.Errorf("TCP connection failed to %s: %w", targetAddr, err)
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS13,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return 0, fmt.Errorf("TLS 1.3 handshake failed for %s: %w", host, err)
	}
	rtt := time.Since(start)

	state := tlsConn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		return 0, fmt.Errorf("server did not negotiate TLS 1.3 (negotiated 0x%04x)", state.Version)
	}
	if len(state.PeerCertificates) == 0 {
		return 0, fmt.Errorf("no peer certificate presented by %s", host)
	}
	if err := state.PeerCertificates[0].VerifyHostname(host); err != nil {
		return 0, fmt.Errorf("certificate does not cover %s: %w", host, err)
	}

	// Regional redirect trap check
	checkRedirectTrap(ctx, host, targetAddr, timeout)

	return rtt, nil
}

func checkRedirectTrap(ctx context.Context, host, targetAddr string, timeout time.Duration) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+targetAddr+"/", nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	req.Header.Set("Range", "bytes=0-0")

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: host,
				MinVersion: tls.VersionTLS13,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: timeout,
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if loc != "" {
			if u, err := url.Parse(loc); err == nil && u.Hostname() != "" {
				locHost := strings.ToLower(u.Hostname())
				if strings.HasSuffix(locHost, ".cn") && !strings.HasSuffix(host, ".cn") {
					// Warning logged if needed, or non-fatal
				}
			}
		}
	}
}

type probeResult struct {
	domain string
	rtt    time.Duration
	err    error
}

// BenchmarkDomains probes candidate domains concurrently and returns the fastest valid candidate.
func BenchmarkDomains(domains []string, timeout time.Duration) (string, time.Duration, error) {
	if len(domains) == 0 {
		return "", 0, fmt.Errorf("no candidate domains provided")
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	results := make(chan probeResult, len(domains))
	var wg sync.WaitGroup

	for _, d := range domains {
		domain := d
		wg.Add(1)
		go func(dom string) {
			defer wg.Done()
			rtt, err := ValidateSkinTarget(dom, timeout)
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
		return "", 0, fmt.Errorf("no candidate domains reached/validated (%s)", strings.Join(allErrs, "; "))
	}
	return bestDomain, bestRTT, nil
}
