package config

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestNormalizeVendor(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"aws", VendorAWS},
		{"Amazon", VendorAWS},
		{"gcp", VendorGCP},
		{"google", VendorGCP},
		{"azure", VendorAzure},
		{"Microsoft", VendorAzure},
		{"cloudflare", VendorCloudflare},
		{"cf", VendorCloudflare},
		{"oracle", VendorOracle},
		{"oci", VendorOracle},
		{"generic", VendorGeneric},
		{"unknown", "unknown"},
	}

	for _, c := range cases {
		if got := NormalizeVendor(c.input); got != c.expected {
			t.Errorf("NormalizeVendor(%q) = %q; want %q", c.input, got, c.expected)
		}
	}
}

func TestIsValidCloudVendor(t *testing.T) {
	valid := []string{"aws", "AWS", "gcp", "GCP", "azure", "cloudflare", "oracle", "generic"}
	for _, v := range valid {
		if !IsValidCloudVendor(v) {
			t.Errorf("IsValidCloudVendor(%q) = false; want true", v)
		}
	}

	invalid := []string{"", "unknown", "alibaba", "tencent", "digitalocean"}
	for _, v := range invalid {
		if IsValidCloudVendor(v) {
			t.Errorf("IsValidCloudVendor(%q) = true; want false", v)
		}
	}
}

func TestGetCloudVendorDomains(t *testing.T) {
	awsDomains, err := GetCloudVendorDomains(VendorAWS)
	if err != nil || len(awsDomains) == 0 {
		t.Fatalf("expected AWS domains, got err=%v, len=%d", err, len(awsDomains))
	}

	gcpDomains, err := GetCloudVendorDomains(VendorGCP)
	if err != nil || len(gcpDomains) == 0 {
		t.Fatalf("expected GCP domains, got err=%v, len=%d", err, len(gcpDomains))
	}

	cfDomains, err := GetCloudVendorDomains(VendorCloudflare)
	if err != nil || len(cfDomains) == 0 {
		t.Fatalf("expected Cloudflare domains, got err=%v, len=%d", err, len(cfDomains))
	}

	// Azure pool must be empty and return an error
	_, err = GetCloudVendorDomains(VendorAzure)
	if err == nil {
		t.Errorf("expected error for empty Azure pool, got nil")
	}

	// Unknown vendor must return an error
	_, err = GetCloudVendorDomains("unknown_vendor")
	if err == nil {
		t.Errorf("expected error for unknown vendor, got nil")
	}

	// Check exclusion of redirect and forbidden domains
	forbiddenDomains := []string{
		"www.github.com",
		"pages.dev",
		"workers.dev",
		"portal.azure.com",
		"spoprod-a.akamaihd.net",
		"statics-marketingsites-eas-ms-com.akamaized.net",
		"learn.microsoft.com",
		"login.microsoftonline.com",
		"graph.microsoft.com",
		"res.cdn.office.net",
		"c.s-microsoft.com",
		"azure.microsoft.com",
		"www.apple.com",
		"www.nvidia.com",
		"www.intel.com",
		"www.icloud.com",
	}

	allDomains := GetAllRealityDomains()
	for _, d := range allDomains {
		for _, forbidden := range forbiddenDomains {
			if strings.EqualFold(d, forbidden) {
				t.Errorf("forbidden domain %q found in candidate pool", d)
			}
		}
	}
}

func TestGetRandomRealityDomain(t *testing.T) {
	d := GetRandomRealityDomain()
	if d == "" {
		t.Fatalf("expected random domain, got empty")
	}
}

func TestNormalizeRealityTarget(t *testing.T) {
	validCases := []struct {
		input    string
		wantHost string
		wantPort int
		wantAddr string
	}{
		{"example.com", "example.com", 443, "example.com:443"},
		{"example.com:443", "example.com", 443, "example.com:443"},
		{"example.com:8443", "example.com", 8443, "example.com:8443"},
		{"SUB.Example.COM.:443", "sub.example.com", 443, "sub.example.com:443"},
		{"  a.b.c:1234  ", "a.b.c", 1234, "a.b.c:1234"},
	}

	for _, c := range validCases {
		host, port, addr, err := NormalizeRealityTarget(c.input)
		if err != nil {
			t.Errorf("NormalizeRealityTarget(%q) unexpected error: %v", c.input, err)
			continue
		}
		if host != c.wantHost || port != c.wantPort || addr != c.wantAddr {
			t.Errorf("NormalizeRealityTarget(%q) = (%q, %d, %q); want (%q, %d, %q)",
				c.input, host, port, addr, c.wantHost, c.wantPort, c.wantAddr)
		}
	}

	invalidCases := []string{
		"",
		"   ",
		"1.2.3.4",
		"1.2.3.4:443",
		"[::1]:443",
		"example",
		"http://example.com",
		"https://example.com/path",
		"example.com:0",
		"example.com:70000",
		"example.com:abc",
		"example .com:443",
		":443",
	}

	for _, input := range invalidCases {
		_, _, _, err := NormalizeRealityTarget(input)
		if err == nil {
			t.Errorf("NormalizeRealityTarget(%q) expected error, got nil", input)
		}
	}
}

func TestValidateRealitySNIAndDest(t *testing.T) {
	// Valid matching SNI and Dest
	sni, dest, err := ValidateRealitySNIAndDest("example.com", "example.com:443")
	if err != nil || sni != "example.com" || dest != "example.com:443" {
		t.Errorf("ValidateRealitySNIAndDest valid case failed: sni=%q, dest=%q, err=%v", sni, dest, err)
	}

	// Empty Dest defaults to <SNI>:443
	sni, dest, err = ValidateRealitySNIAndDest("example.com", "")
	if err != nil || sni != "example.com" || dest != "example.com:443" {
		t.Errorf("ValidateRealitySNIAndDest empty dest failed: sni=%q, dest=%q, err=%v", sni, dest, err)
	}

	// Matching SNI and Dest with non-standard port
	sni, dest, err = ValidateRealitySNIAndDest("example.com", "example.com:8443")
	if err != nil || sni != "example.com" || dest != "example.com:8443" {
		t.Errorf("ValidateRealitySNIAndDest non-443 dest failed: sni=%q, dest=%q, err=%v", sni, dest, err)
	}

	// Mismatched Dest host
	_, _, err = ValidateRealitySNIAndDest("example.com", "other.com:443")
	if err == nil {
		t.Errorf("ValidateRealitySNIAndDest mismatched dest host expected error, got nil")
	}

	// Invalid SNI (IP address)
	_, _, err = ValidateRealitySNIAndDest("1.2.3.4", "1.2.3.4:443")
	if err == nil {
		t.Errorf("ValidateRealitySNIAndDest IP SNI expected error, got nil")
	}
}

// Helper to generate self-signed test certificate
func generateTestCert(t *testing.T, host string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: host,
		},
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(parsedCert)

	return cert, pool
}

func startMockServer(t *testing.T, tlsConfig *tls.Config, handler http.Handler) (net.Listener, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	tlsListener := tls.NewListener(listener, tlsConfig)
	srv := &http.Server{
		Handler: handler,
	}

	// Configure HTTP/2 support if ALPN contains "h2"
	for _, proto := range tlsConfig.NextProtos {
		if proto == "h2" {
			_ = http2.ConfigureServer(srv, &http2.Server{})
			break
		}
	}

	go func() {
		_ = srv.Serve(tlsListener)
	}()

	cleanup := func() {
		_ = srv.Close()
		_ = tlsListener.Close()
	}

	return listener, cleanup
}

func TestValidateSkinTarget_Hermetic(t *testing.T) {
	testHost := "test.target.local"
	cert, rootCAs := generateTestCert(t, testHost)

	tests := []struct {
		name          string
		tlsConfig     *tls.Config
		handler       http.Handler
		target        string
		targetHost    string
		expectSuccess bool
		errContains   string
	}{
		{
			name: "Success: TLS 1.3 + X25519 + H2 + 200 OK",
			tlsConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{"h2"},
			},
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("OK"))
			}),
			target:        testHost + ":443",
			targetHost:    testHost,
			expectSuccess: true,
		},
		{
			name: "Success: TLS 1.3 + H2 + 401 Unauthorized",
			tlsConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{"h2"},
			},
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			}),
			target:        testHost + ":443",
			targetHost:    testHost,
			expectSuccess: true,
		},
		{
			name: "Success: TLS 1.3 + H2 + 403 Forbidden",
			tlsConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{"h2"},
			},
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			}),
			target:        testHost + ":443",
			targetHost:    testHost,
			expectSuccess: true,
		},
		{
			name: "Success: TLS 1.3 + H2 + 404 Not Found",
			tlsConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{"h2"},
			},
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}),
			target:        testHost + ":443",
			targetHost:    testHost,
			expectSuccess: true,
		},
		{
			name: "Reject: TLS 1.2 Only",
			tlsConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
				MaxVersion:   tls.VersionTLS12,
				NextProtos:   []string{"h2"},
			},
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
			target:        testHost + ":443",
			targetHost:    testHost,
			expectSuccess: false,
			errContains:   "handshake failed",
		},
		{
			name: "Reject: TLS 1.3 with ALPN HTTP/1.1 Only (No H2)",
			tlsConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{"http/1.1"},
			},
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
			target:        testHost + ":443",
			targetHost:    testHost,
			expectSuccess: false,
			errContains:   "protocol",
		},
		{
			name: "Reject: 301 Redirect",
			tlsConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{"h2"},
			},
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://somewhere.else/login", http.StatusMovedPermanently)
			}),
			target:        testHost + ":443",
			targetHost:    testHost,
			expectSuccess: false,
			errContains:   "HTTP redirect (301)",
		},
		{
			name: "Reject: 302 Redirect",
			tlsConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{"h2"},
			},
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://somewhere.else/login", http.StatusFound)
			}),
			target:        testHost + ":443",
			targetHost:    testHost,
			expectSuccess: false,
			errContains:   "HTTP redirect (302)",
		},
		{
			name: "Reject: 500 Server Error",
			tlsConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{"h2"},
			},
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}),
			target:        testHost + ":443",
			targetHost:    testHost,
			expectSuccess: false,
			errContains:   "server error (500)",
		},
		{
			name: "Reject: 502 Bad Gateway",
			tlsConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{"h2"},
			},
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
			}),
			target:        testHost + ":443",
			targetHost:    testHost,
			expectSuccess: false,
			errContains:   "server error (502)",
		},
		{
			name: "Reject: Hostname Mismatch",
			tlsConfig: &tls.Config{
				Certificates: []tls.Certificate{cert}, // Cert is for test.target.local
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{"h2"},
			},
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
			target:        "other.domain.local:443",
			targetHost:    "other.domain.local",
			expectSuccess: false,
			errContains:   "certificate",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			listener, cleanup := startMockServer(t, tc.tlsConfig, tc.handler)
			defer cleanup()

			serverAddr := listener.Addr().String()

			// Inject dialer redirecting targetAddr to serverAddr
			opts := targetValidatorOptions{
				rootCAs: rootCAs,
				dialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialer := &net.Dialer{Timeout: 2 * time.Second}
					return dialer.DialContext(ctx, "tcp", serverAddr)
				},
			}

			rtt, err := validateSkinTargetInternal(tc.target, 2*time.Second, opts)
			if tc.expectSuccess {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				if rtt <= 0 {
					t.Fatalf("expected positive RTT, got %v", rtt)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContains)
				}
				if tc.errContains != "" && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.errContains)) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errContains)
				}
			}
		})
	}
}

func TestBenchmarkDomains_Hermetic(t *testing.T) {
	testHostValid := "valid.target.local"
	testHostInvalid := "invalid.target.local"

	certValid, poolValid := generateTestCert(t, testHostValid)
	certInvalid, _ := generateTestCert(t, testHostInvalid)

	// Combine cert pools
	combinedPool := x509.NewCertPool()
	for _, c := range poolValid.Subjects() {
		_ = c
	}
	// Add both to combined pool
	combinedPool = poolValid
	for _, der := range certInvalid.Certificate {
		c, _ := x509.ParseCertificate(der)
		combinedPool.AddCert(c)
	}

	// 1. Start valid mock server
	listenerValid, cleanupValid := startMockServer(t, &tls.Config{
		Certificates: []tls.Certificate{certValid},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer cleanupValid()

	// 2. Start invalid mock server (returns 500)
	listenerInvalid, cleanupInvalid := startMockServer(t, &tls.Config{
		Certificates: []tls.Certificate{certInvalid},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer cleanupInvalid()

	validAddr := listenerValid.Addr().String()
	invalidAddr := listenerInvalid.Addr().String()

	opts := targetValidatorOptions{
		rootCAs: combinedPool,
		dialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 2 * time.Second}
			if strings.HasPrefix(addr, testHostValid) {
				return dialer.DialContext(ctx, "tcp", validAddr)
			}
			return dialer.DialContext(ctx, "tcp", invalidAddr)
		},
	}

	// Benchmark both domains - must pick validDomain
	best, rtt, err := benchmarkDomainsInternal([]string{testHostInvalid, testHostValid}, 2*time.Second, opts)
	if err != nil {
		t.Fatalf("BenchmarkDomains failed: %v", err)
	}
	if best != testHostValid {
		t.Errorf("BenchmarkDomains picked %q; want %q", best, testHostValid)
	}
	if rtt <= 0 {
		t.Errorf("expected positive RTT, got %v", rtt)
	}

	// Benchmark with only invalid domains - must return error
	_, _, err = benchmarkDomainsInternal([]string{testHostInvalid}, 2*time.Second, opts)
	if err == nil {
		t.Errorf("BenchmarkDomains with only failing domains expected error, got nil")
	}
}
