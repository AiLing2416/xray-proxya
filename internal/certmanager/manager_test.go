package certmanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
	"xray-proxya/internal/config"
)

func TestVerifyDNS(t *testing.T) {
	origLookup := lookupIPFunc
	origIfAddrs := interfaceAddrsFunc
	t.Cleanup(func() {
		lookupIPFunc = origLookup
		interfaceAddrsFunc = origIfAddrs
	})

	// 1. Success matching
	lookupIPFunc = func(domain string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.2.3.4")}, nil
	}
	interfaceAddrsFunc = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(32, 32)},
		}, nil
	}

	ip, err := VerifyDNS("sea.ailing.dev")
	if err != nil {
		t.Fatalf("VerifyDNS unexpected error: %v", err)
	}
	if ip != "1.2.3.4" {
		t.Fatalf("VerifyDNS ip = %q, want 1.2.3.4", ip)
	}

	// 2. Mismatch error
	lookupIPFunc = func(domain string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("5.6.7.8")}, nil
	}
	_, err = VerifyDNS("sea.ailing.dev")
	if err == nil {
		t.Fatalf("expected error for mismatched IP")
	}
}

func TestCheckAndRenewCerts(t *testing.T) {
	origIssue := issueACMEFunc
	t.Cleanup(func() {
		issueACMEFunc = origIssue
	})

	tempDir := t.TempDir()
	certDir := filepath.Join(tempDir, "certs", "sea.ailing.dev")
	_ = os.MkdirAll(certDir, 0700)
	certPath := filepath.Join(certDir, "fullchain.pem")
	keyPath := filepath.Join(certDir, "privkey.pem")
	_ = os.WriteFile(certPath, []byte("fake cert"), 0600)
	_ = os.WriteFile(keyPath, []byte("fake key"), 0600)

	cfg := &config.UserConfig{
		Presets: []config.ModeInfo{
			{
				Mode:       config.ModeVLESSVision,
				Enabled:    true,
				Port:       443,
				SNI:        "sea.ailing.dev",
				Skin:       "seafile",
				SkinDomain: "sea.ailing.dev",
			},
			{
				Mode:    config.ModeVLESSReality,
				Enabled: true,
				Port:    8443,
				SNI:     "aws.amazon.com",
			},
		},
		Certs: []config.ManagedCert{
			{
				Domain:    "sea.ailing.dev",
				CertPath:  certPath,
				KeyPath:   keyPath,
				IssuedAt:  time.Now().Add(-85 * 24 * time.Hour),
				ExpiresAt: time.Now().Add(5 * 24 * time.Hour), // Expiring in 5 days (within 7d threshold)
				Issuer:    "Let's Encrypt",
				AutoRenew: true,
			},
		},
	}

	// Mock successful renew
	renewCalls := 0
	issueACMEFunc = func(ctx context.Context, domain, email, certDir string) (*config.ManagedCert, error) {
		renewCalls++
		return &config.ManagedCert{
			Domain:    domain,
			CertPath:  certPath,
			KeyPath:   keyPath,
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
			Issuer:    "Let's Encrypt",
			AutoRenew: true,
		}, nil
	}

	renewed, failed, expired, err := CheckAndRenewCerts(cfg, false)
	if err != nil {
		t.Fatalf("CheckAndRenewCerts error = %v", err)
	}
	if renewCalls != 1 {
		t.Fatalf("renewCalls = %d, want 1", renewCalls)
	}
	if len(renewed) != 1 || renewed[0] != "sea.ailing.dev" {
		t.Fatalf("renewed = %v, want [sea.ailing.dev]", renewed)
	}
	if len(failed) != 0 {
		t.Fatalf("failed = %v, want empty", failed)
	}
	if len(expired) != 0 {
		t.Fatalf("expired = %v, want empty", expired)
	}
	if !cfg.Presets[0].Enabled {
		t.Fatalf("Preset 0 should remain enabled after successful renewal")
	}

	// Test force renewal on a specific domain
	renewCalls = 0
	renewed, failed, expired, err = CheckAndRenewCerts(cfg, true, "nonexistent.domain")
	if err != nil {
		t.Fatalf("CheckAndRenewCerts filter error = %v", err)
	}
	if renewCalls != 0 || len(renewed) != 0 {
		t.Fatalf("should not renew when filtered out")
	}

	// Test renewal failure before expiration (reported in failed list, not expiredFailed)
	cfg.Certs[0].ExpiresAt = time.Now().Add(20 * 24 * time.Hour) // Not expired yet!
	issueACMEFunc = func(ctx context.Context, domain, email, certDir string) (*config.ManagedCert, error) {
		return nil, os.ErrDeadlineExceeded // renewal fails
	}
	renewed, failed, expired, err = CheckAndRenewCerts(cfg, true) // Force renewal
	if err != nil {
		t.Fatalf("CheckAndRenewCerts error = %v", err)
	}
	if len(renewed) != 0 {
		t.Fatalf("renewed = %v, want 0", renewed)
	}
	if len(failed) != 1 || failed[0].Domain != "sea.ailing.dev" {
		t.Fatalf("failed = %v, want [sea.ailing.dev]", failed)
	}
	if len(expired) != 0 {
		t.Fatalf("expired = %v, want empty (cert not expired yet)", expired)
	}
	if !cfg.Presets[0].Enabled {
		t.Fatalf("Preset 0 should remain enabled because cert has not expired yet")
	}

	// Now test expiration fuse: expired cert and renewal failure
	cfg.Certs[0].ExpiresAt = time.Now().Add(-1 * time.Hour) // expired
	issueACMEFunc = func(ctx context.Context, domain, email, certDir string) (*config.ManagedCert, error) {
		return nil, os.ErrDeadlineExceeded // renewal fails
	}

	renewed, failed, expired, err = CheckAndRenewCerts(cfg, false)
	if err != nil {
		t.Fatalf("CheckAndRenewCerts error = %v", err)
	}
	if len(renewed) != 0 {
		t.Fatalf("renewed = %v, want 0", renewed)
	}
	if len(failed) != 1 {
		t.Fatalf("failed = %v, want 1", failed)
	}
	if len(expired) != 1 || expired[0] != "sea.ailing.dev" {
		t.Fatalf("expired = %v, want [sea.ailing.dev]", expired)
	}
	// Preset 0 MUST be disabled by safety fuse!
	if cfg.Presets[0].Enabled {
		t.Fatalf("Preset 0 should be DISABLED by expiration safety fuse")
	}
	// Preset 1 (aws.amazon.com) should remain untouched
	if !cfg.Presets[1].Enabled {
		t.Fatalf("Preset 1 should remain enabled")
	}
}

func TestRemoveCertificate(t *testing.T) {
	tempDir := t.TempDir()
	certDir := filepath.Join(tempDir, "certs", "sea.ailing.dev")
	_ = os.MkdirAll(certDir, 0700)
	certPath := filepath.Join(certDir, "fullchain.pem")
	keyPath := filepath.Join(certDir, "privkey.pem")
	_ = os.WriteFile(certPath, []byte("cert"), 0600)
	_ = os.WriteFile(keyPath, []byte("key"), 0600)

	cfg := &config.UserConfig{
		Presets: []config.ModeInfo{
			{
				Mode:       config.ModeVLESSVision,
				Enabled:    true,
				Port:       443,
				SNI:        "sea.ailing.dev",
				Skin:       "seafile",
				SkinDomain: "sea.ailing.dev",
			},
			{
				Mode:    config.ModeVLESSReality,
				Enabled: true,
				Port:    8443,
				SNI:     "other.com",
			},
		},
		Certs: []config.ManagedCert{
			{
				Domain:   "sea.ailing.dev",
				CertPath: certPath,
				KeyPath:  keyPath,
			},
		},
	}

	disabled, err := RemoveCertificate(cfg, "sea.ailing.dev")
	if err != nil {
		t.Fatalf("RemoveCertificate error = %v", err)
	}

	if len(disabled) != 1 || disabled[0] != 1 {
		t.Fatalf("disabled presets = %v, want [1]", disabled)
	}

	if cfg.Presets[0].Enabled {
		t.Errorf("Preset 0 should be disabled")
	}
	if cfg.Presets[0].Skin != "" || cfg.Presets[0].SkinDomain != "" {
		t.Errorf("Preset 0 skin should be cleared")
	}

	if cfg.FindCert("sea.ailing.dev") != nil {
		t.Errorf("Cert should be removed from config")
	}

	if _, err := os.Stat(certDir); !os.IsNotExist(err) {
		t.Errorf("Cert directory should be deleted")
	}
}

func TestSaveCertificateFilesPermissions(t *testing.T) {
	tempDir := t.TempDir()
	certDir := filepath.Join(tempDir, "certs", "test.example.com")
	if err := os.MkdirAll(certDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Create dummy certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPath, keyPath, err := saveCertificateFiles(certDir, [][]byte{derBytes}, privKey)
	if err != nil {
		t.Fatalf("saveCertificateFiles: %v", err)
	}

	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat cert: %v", err)
	}
	if perm := certInfo.Mode().Perm(); perm != 0600 {
		t.Fatalf("cert file perm = %o, want 0600", perm)
	}

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0600 {
		t.Fatalf("key file perm = %o, want 0600", perm)
	}
}

func TestChallengeSharedFileHandling(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", tempDir)

	token := "test-token-12345"
	path := "/.well-known/acme-challenge/" + token
	response := "test-challenge-response-abcde"

	// 1. Register challenge -> should populate memory map and create disk file
	RegisterChallenge(path, response)

	filePath := filepath.Join(tempDir, "acme-challenges", token)
	if data, err := os.ReadFile(filePath); err != nil || string(data) != response {
		t.Fatalf("expected file content %q, got err=%v, content=%q", response, err, string(data))
	}

	// 2. Simulate cross-process daemon: clear in-memory map so only disk file remains
	challengesMu.Lock()
	delete(activeChallenges, path)
	challengesMu.Unlock()

	req, _ := http.NewRequest("GET", path, nil)
	rr := httptest.NewRecorder()
	handled := HandleChallenge(rr, req)
	if !handled {
		t.Fatalf("HandleChallenge should return true from disk file fallback")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", rr.Code)
	}
	if rr.Body.String() != response {
		t.Fatalf("body = %q, want %q", rr.Body.String(), response)
	}

	// 3. Unregister challenge -> file should be deleted
	UnregisterChallenge(path)
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatalf("challenge file should have been deleted after unregister")
	}
}
