package certmanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"xray-proxya/internal/config"

	"golang.org/x/crypto/acme"
)

// RenewalThreshold defines how early before expiration auto-renewal is triggered (last 7 days).
const RenewalThreshold = 7 * 24 * time.Hour

// Hookable dependencies for testing.
var (
	lookupIPFunc = func(domain string) ([]net.IP, error) {
		return net.LookupIP(domain)
	}
	interfaceAddrsFunc = func() ([]net.Addr, error) {
		return net.InterfaceAddrs()
	}
	httpListenFunc = func(addr string, handler http.Handler) (net.Listener, error) {
		return net.Listen("tcp", addr)
	}
	issueACMEFunc func(ctx context.Context, domain, email, certDir string) (*config.ManagedCert, error)
)

// VerifyDNS checks whether the specified domain resolves to one of the host's IP addresses.
func VerifyDNS(domain string) (string, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return "", errors.New("empty domain name")
	}

	ips, err := lookupIPFunc(domain)
	if err != nil {
		return "", fmt.Errorf("DNS lookup failed for %s: %w", domain, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("domain %s resolved to no IP addresses", domain)
	}

	addrs, err := interfaceAddrsFunc()
	if err != nil {
		return ips[0].String(), nil // permissive if cannot inspect local ifaddrs
	}

	localIPs := make(map[string]bool)
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			localIPs[ipnet.IP.String()] = true
		}
	}

	for _, ip := range ips {
		if localIPs[ip.String()] {
			return ip.String(), nil
		}
	}

	// If none matched local interfaces, return warning/error with first resolved IP
	return ips[0].String(), fmt.Errorf("domain %s resolves to %s, which does not match local host network interfaces", domain, ips[0].String())
}

// IssueCertificate requests a TLS certificate via Let's Encrypt HTTP-01 challenge.
func IssueCertificate(domain, email string) (*config.ManagedCert, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return nil, errors.New("domain name cannot be empty")
	}

	cfg, _ := config.LoadConfigEx(true)
	certDir := filepath.Join(config.GetConfigDir(), "certs", domain)
	if cfg != nil {
		certDir = filepath.Join(cfg.GetCertDir(), domain)
	}

	if issueACMEFunc != nil {
		return issueACMEFunc(context.Background(), domain, email, certDir)
	}

	return performACMEHttp01(context.Background(), domain, email, certDir)
}

func performACMEHttp01(ctx context.Context, domain, email, certDir string) (*config.ManagedCert, error) {
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("create cert directory: %w", err)
	}

	accountKeyPath := filepath.Join(filepath.Dir(certDir), "acme_account.key")
	accountKey, err := getOrCreatePrivateKey(accountKeyPath)
	if err != nil {
		return nil, fmt.Errorf("acme account key: %w", err)
	}

	client := &acme.Client{
		Key: accountKey,
	}

	// Register account if not already registered
	account := &acme.Account{
		Contact: []string{},
	}
	if email != "" {
		account.Contact = []string{"mailto:" + email}
	}
	_, _ = client.Register(ctx, account, acme.AcceptTOS)

	// Authorize order
	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: domain}})
	if err != nil {
		return nil, fmt.Errorf("authorize order: %w", err)
	}

	var http01Chal *acme.Challenge
	for _, authURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authURL)
		if err != nil {
			return nil, fmt.Errorf("get authorization: %w", err)
		}
		for _, chal := range authz.Challenges {
			if chal.Type == "http-01" {
				http01Chal = chal
				break
			}
		}
	}

	if http01Chal == nil {
		return nil, errors.New("no http-01 challenge found in ACME order")
	}

	responseVal, err := client.HTTP01ChallengeResponse(http01Chal.Token)
	if err != nil {
		return nil, fmt.Errorf("compute challenge response: %w", err)
	}

	// Spin up temporary HTTP server on port 80
	challengePath := client.HTTP01ChallengePath(http01Chal.Token)
	mux := http.NewServeMux()
	mux.HandleFunc(challengePath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(responseVal))
	})

	listener, err := httpListenFunc(":80", mux)
	if err != nil {
		return nil, fmt.Errorf("listen on port 80 for ACME challenge: %w (ensure port 80 is free)", err)
	}
	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()
	defer func() {
		_ = server.Shutdown(context.Background())
	}()

	// Accept challenge
	if _, err := client.Accept(ctx, http01Chal); err != nil {
		return nil, fmt.Errorf("accept ACME challenge: %w", err)
	}

	// Wait for authorization
	if _, err := client.WaitOrder(ctx, order.URI); err != nil {
		return nil, fmt.Errorf("wait order: %w", err)
	}

	// Generate certificate private key and CSR
	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate cert private key: %w", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, certPrivKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	// Finalize order & retrieve certificate
	derCerts, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, fmt.Errorf("create order cert: %w", err)
	}

	certPath := filepath.Join(certDir, "fullchain.pem")
	keyPath := filepath.Join(certDir, "privkey.pem")

	// Save certs
	certFile, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("save fullchain.pem: %w", err)
	}
	defer certFile.Close()

	for _, b := range derCerts {
		if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: b}); err != nil {
			return nil, fmt.Errorf("encode certificate: %w", err)
		}
	}

	// Save private key
	keyBytes, err := x509.MarshalECPrivateKey(certPrivKey)
	if err != nil {
		return nil, fmt.Errorf("marshal EC private key: %w", err)
	}
	keyFile, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("save privkey.pem: %w", err)
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return nil, fmt.Errorf("encode private key: %w", err)
	}

	// Parse first certificate to get metadata
	leafCert, err := x509.ParseCertificate(derCerts[0])
	if err != nil {
		return nil, fmt.Errorf("parse issued cert: %w", err)
	}

	return &config.ManagedCert{
		Domain:    domain,
		CertPath:  certPath,
		KeyPath:   keyPath,
		IssuedAt:  leafCert.NotBefore,
		ExpiresAt: leafCert.NotAfter,
		Issuer:    leafCert.Issuer.CommonName,
		AutoRenew: true,
	}, nil
}

func getOrCreatePrivateKey(keyPath string) (crypto.Signer, error) {
	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return key, nil
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		return nil, err
	}
	return key, nil
}

// CheckAndRenewCerts inspects all managed certs and triggers renewal for certs expiring within 7 days.
// If a certificate is expired and cannot be renewed, any presets depending on this certificate are disabled.
func CheckAndRenewCerts(cfg *config.UserConfig, force bool) (renewed []string, expiredFailed []string, err error) {
	if cfg == nil {
		return nil, nil, errors.New("nil config")
	}

	now := time.Now()
	for i := range cfg.Certs {
		cert := &cfg.Certs[i]
		needsRenew := force || cert.AutoRenew && time.Until(cert.ExpiresAt) <= RenewalThreshold

		renewSuccess := false
		if needsRenew {
			newCert, err := IssueCertificate(cert.Domain, "")
			if err == nil {
				cert.IssuedAt = newCert.IssuedAt
				cert.ExpiresAt = newCert.ExpiresAt
				cert.CertPath = newCert.CertPath
				cert.KeyPath = newCert.KeyPath
				cert.Issuer = newCert.Issuer
				renewed = append(renewed, cert.Domain)
				renewSuccess = true
			}
		}

		// Check if expired and unrenewed
		if now.After(cert.ExpiresAt) && !renewSuccess {
			// Trigger expiration safety fuse: disable any presets bound to this domain
			disabledAny := false
			for j := range cfg.Presets {
				p := &cfg.Presets[j]
				if p.Enabled && (strings.EqualFold(p.SkinDomain, cert.Domain) || strings.EqualFold(p.SNI, cert.Domain)) {
					p.Enabled = false
					disabledAny = true
				}
			}
			if disabledAny {
				expiredFailed = append(expiredFailed, cert.Domain)
			}
		}
	}

	return renewed, expiredFailed, nil
}

// RemoveCertificate deregisters a domain's certificate, deletes local files,
// and disables any presets depending on this certificate.
func RemoveCertificate(cfg *config.UserConfig, domain string) (disabledPresets []int, err error) {
	if cfg == nil {
		return nil, errors.New("nil config")
	}

	d := strings.ToLower(strings.TrimSpace(domain))
	cert := cfg.FindCert(d)
	if cert == nil {
		return nil, fmt.Errorf("domain %s is not registered", domain)
	}

	// Disable dependent presets
	for i := range cfg.Presets {
		p := &cfg.Presets[i]
		isBound := strings.EqualFold(p.SkinDomain, d) || (p.Skin != "" && strings.EqualFold(p.SNI, d))
		if isBound {
			if p.Enabled {
				p.Enabled = false
			}
			p.Skin = ""
			p.SkinDomain = ""
			disabledPresets = append(disabledPresets, i+1)
		}
	}

	// Remove files
	certDir := filepath.Dir(cert.CertPath)
	if certDir != "" && certDir != "/" && certDir != "." {
		_ = os.RemoveAll(certDir)
	}

	cfg.RemoveCert(d)
	return disabledPresets, nil
}
