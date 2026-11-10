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

func TestCertRenewCommand_Empty(t *testing.T) {
	setupTestConfigDir(t)
	cfg := &config.UserConfig{Role: config.RoleServer}
	_ = cfg.SaveEx(true)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := certRenewCmd.RunE(certRenewCmd, []string{})
	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	if !strings.Contains(buf.String(), "No certificates to renew.") {
		t.Errorf("expected 'No certificates to renew.', got: %s", buf.String())
	}
}

func TestCertRenewCommand_UnregisteredDomain(t *testing.T) {
	setupTestConfigDir(t)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Certs: []config.ManagedCert{
			{Domain: "exists.example.com"},
		},
	}
	_ = cfg.SaveEx(true)

	err := certRenewCmd.RunE(certRenewCmd, []string{"notexists.example.com"})
	if err == nil || !strings.Contains(err.Error(), "is not registered") {
		t.Fatalf("expected unregistered domain error, got: %v", err)
	}
}

func TestCertRenewCommand_ForceWithFailureReportsError(t *testing.T) {
	setupTestConfigDir(t)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Certs: []config.ManagedCert{
			{
				Domain:    "fail.example.com",
				IssuedAt:  time.Now().Add(-10 * 24 * time.Hour),
				ExpiresAt: time.Now().Add(50 * 24 * time.Hour), // Not expired yet!
				AutoRenew: true,
			},
		},
	}
	_ = cfg.SaveEx(true)

	certForce = true
	t.Cleanup(func() {
		certForce = false
	})

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := certRenewCmd.RunE(certRenewCmd, []string{"fail.example.com"})
	w.Close()
	os.Stdout = oldStdout

	// Because ACME fails against real Let's Encrypt in unit test (or no network), it MUST return error
	// and must NOT report 'All certificates are healthy'!
	if err == nil {
		t.Fatalf("expected error when renewal fails, got nil")
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()
	if strings.Contains(out, "All certificates are healthy") {
		t.Errorf("must NOT print 'All certificates are healthy' when renewal failed! output: %s", out)
	}
	if !strings.Contains(out, "Failed to renew certificate for fail.example.com") {
		t.Errorf("expected failure message, got: %s", out)
	}
}

func TestCertRenewCompletion(t *testing.T) {
	setupTestConfigDir(t)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Certs: []config.ManagedCert{
			{Domain: "domain1.example.com"},
			{Domain: "domain2.example.com"},
		},
	}
	_ = cfg.SaveEx(true)

	if certRenewCmd.ValidArgsFunction == nil {
		t.Fatalf("certRenewCmd.ValidArgsFunction must not be nil")
	}

	completions, _ := certRenewCmd.ValidArgsFunction(certRenewCmd, []string{}, "")
	if len(completions) != 2 {
		t.Fatalf("expected 2 completions, got %d: %v", len(completions), completions)
	}
	if completions[0] != "domain1.example.com" || completions[1] != "domain2.example.com" {
		t.Errorf("unexpected completions: %v", completions)
	}
}
