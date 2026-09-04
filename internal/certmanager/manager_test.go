package certmanager

import (
	"context"
	"net"
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
	_ = os.WriteFile(certPath, []byte("fake cert"), 0644)
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

	renewed, expired, err := CheckAndRenewCerts(cfg, false)
	if err != nil {
		t.Fatalf("CheckAndRenewCerts error = %v", err)
	}
	if renewCalls != 1 {
		t.Fatalf("renewCalls = %d, want 1", renewCalls)
	}
	if len(renewed) != 1 || renewed[0] != "sea.ailing.dev" {
		t.Fatalf("renewed = %v, want [sea.ailing.dev]", renewed)
	}
	if len(expired) != 0 {
		t.Fatalf("expired = %v, want empty", expired)
	}
	if !cfg.Presets[0].Enabled {
		t.Fatalf("Preset 0 should remain enabled after successful renewal")
	}

	// Now test expiration fuse: expired cert and renewal failure
	cfg.Certs[0].ExpiresAt = time.Now().Add(-1 * time.Hour) // expired
	issueACMEFunc = func(ctx context.Context, domain, email, certDir string) (*config.ManagedCert, error) {
		return nil, os.ErrDeadlineExceeded // renewal fails
	}

	renewed, expired, err = CheckAndRenewCerts(cfg, false)
	if err != nil {
		t.Fatalf("CheckAndRenewCerts error = %v", err)
	}
	if len(renewed) != 0 {
		t.Fatalf("renewed = %v, want 0", renewed)
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
	_ = os.WriteFile(certPath, []byte("cert"), 0644)
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
