package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"
	"xray-proxya/internal/certmanager"
	"xray-proxya/internal/config"
)

func TestCertListEmpty(t *testing.T) {
	setupTestConfigDir(t)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
	}
	_ = cfg.SaveEx(true)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := certListCmd.RunE(certListCmd, []string{})
	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("certListCmd error: %v", err)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "No managed domains/certificates found") {
		t.Errorf("expected empty cert message, got: %s", output)
	}
}

func TestCertListAndRemove(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Presets: []config.ModeInfo{
			{
				Mode:       config.ModeVLESSVision,
				Enabled:    true,
				Port:       443,
				SNI:        "sea.ailing.dev",
				Skin:       "seafile",
				SkinDomain: "sea.ailing.dev",
			},
		},
		Certs: []config.ManagedCert{
			{
				Domain:    "sea.ailing.dev",
				IssuedAt:  time.Now().Add(-10 * 24 * time.Hour),
				ExpiresAt: time.Now().Add(80 * 24 * time.Hour),
				Issuer:    "Let's Encrypt",
				AutoRenew: true,
			},
		},
	}
	_ = cfg.SaveEx(true)

	// Test cert list
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := certListCmd.RunE(certListCmd, []string{})
	w.Close()
	os.Stdout = oldStdout
	if err != nil {
		t.Fatalf("certListCmd error: %v", err)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "sea.ailing.dev") {
		t.Errorf("cert list should contain domain sea.ailing.dev")
	}
	if !strings.Contains(out, "#1 (vless-vision-reality-tcp)") {
		t.Errorf("cert list should display attached preset #1")
	}

	// Test cert remove
	err = certRemoveCmd.RunE(certRemoveCmd, []string{"sea.ailing.dev"})
	if err != nil {
		t.Fatalf("certRemoveCmd error: %v", err)
	}

	loaded, _ := config.LoadConfigEx(true)
	if len(loaded.Certs) != 0 {
		t.Errorf("cert list should be empty after removal")
	}
	// Preset 1 should be disabled!
	if loaded.Presets[0].Enabled {
		t.Errorf("Preset 0 should be disabled after cert removal")
	}
}

func TestCertAddCommand(t *testing.T) {
	setupTestConfigDir(t)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
	}
	_ = cfg.SaveEx(true)

	// Mock certmanager issue
	origIssue := certmanager.IssueCertificate
	_ = origIssue // placeholder

	certSkipDNS = true
	t.Cleanup(func() {
		certSkipDNS = false
	})

	// To avoid calling real ACME, create a temp cert via mocked manager logic or test env
	// We can test certAddCmd argument validation
	err := certAddCmd.RunE(certAddCmd, []string{""})
	if err == nil {
		t.Errorf("expected error for empty domain")
	}
}

func TestCertRootRequired(t *testing.T) {
	// PersistentPreRunE calls utils.RequireRootShell("cert")
	if certCmd.PersistentPreRunE == nil {
		t.Fatalf("certCmd.PersistentPreRunE must not be nil")
	}

	// Non-root user (euid != 0) must be rejected
	errNonRoot := certCmd.PersistentPreRunE(certCmd, nil)
	if os.Geteuid() != 0 && errNonRoot == nil {
		t.Errorf("certCmd should reject non-root execution")
	}
}

func TestCertRemoveCompletion(t *testing.T) {
	setupTestConfigDir(t)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Certs: []config.ManagedCert{
			{Domain: "domain1.example.com"},
			{Domain: "domain2.example.com"},
		},
	}
	_ = cfg.SaveEx(true)

	if certRemoveCmd.ValidArgsFunction == nil {
		t.Fatalf("certRemoveCmd.ValidArgsFunction must not be nil")
	}

	completions, _ := certRemoveCmd.ValidArgsFunction(certRemoveCmd, []string{}, "")
	if len(completions) != 2 {
		t.Fatalf("expected 2 completions, got %d: %v", len(completions), completions)
	}
	if completions[0] != "domain1.example.com" || completions[1] != "domain2.example.com" {
		t.Errorf("unexpected completions: %v", completions)
	}
}
