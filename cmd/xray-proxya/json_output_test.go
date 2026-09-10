package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
	"xray-proxya/internal/config"
)

func TestStatusJSONOutput(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Presets: []config.ModeInfo{
			{Mode: config.ModeVLESSReality, Enabled: true, Port: 443},
		},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "hk-node", Enabled: true},
		},
		Guests: []config.GuestConfig{
			{Alias: "guest1", UUID: "uuid-1", Enabled: true, LimitBytes: 1024},
		},
	}
	cfgPath := filepath.Join(tempHome, ".config", "xray-proxya", "config.json")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(cfgPath, data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	statusJSON = true
	t.Cleanup(func() { statusJSON = false })

	out := captureStdout(t, func() {
		if err := statusCmd.RunE(statusCmd, nil); err != nil {
			t.Fatalf("statusCmd.RunE error: %v", err)
		}
	})

	var result StatusJSONOutput
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("failed to unmarshal status JSON: %v\nOutput was:\n%s", err, out)
	}

	if result.Role != "server" {
		t.Errorf("expected role 'server', got %q", result.Role)
	}
	if !result.StagingClean {
		t.Errorf("expected staging_clean true")
	}
	if len(result.ManagedServices) == 0 {
		t.Errorf("expected non-empty managed_services")
	}
}

func TestGuestsListJSONOutput(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Guests: []config.GuestConfig{
			{Alias: "alice", UUID: "uuid-alice", Enabled: true, LimitBytes: 5000, ResetDay: 1},
		},
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save error: %v", err)
	}

	guestsListJSON = true
	t.Cleanup(func() { guestsListJSON = false })

	out := captureStdout(t, func() {
		if err := runGuestsList(guestsListCmd, nil); err != nil {
			t.Fatalf("runGuestsList error: %v", err)
		}
	})

	var guests []map[string]interface{}
	if err := json.Unmarshal([]byte(out), &guests); err != nil {
		t.Fatalf("failed to unmarshal guests JSON: %v\nOutput:\n%s", err, out)
	}
	if len(guests) != 1 {
		t.Fatalf("expected 1 guest, got %d", len(guests))
	}
	if guests[0]["alias"] != "alice" {
		t.Errorf("expected guest alias 'alice', got %v", guests[0]["alias"])
	}
}

func TestRelayListJSONOutput(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:   "relay-test",
				Enabled: true,
				Config:  map[string]interface{}{"protocol": "freedom"},
			},
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("SaveEx error: %v", err)
	}

	relayListJSON = true
	t.Cleanup(func() { relayListJSON = false })

	out := captureStdout(t, func() {
		if err := runListOutbound(listOutboundCmd, nil); err != nil {
			t.Fatalf("runListOutbound error: %v", err)
		}
	})

	var relays []RelayListItemJSON
	if err := json.Unmarshal([]byte(out), &relays); err != nil {
		t.Fatalf("failed to unmarshal relay JSON: %v\nOutput:\n%s", err, out)
	}
	if len(relays) != 1 {
		t.Fatalf("expected 1 relay, got %d", len(relays))
	}
	if relays[0].Alias != "relay-test" {
		t.Errorf("expected alias 'relay-test', got %q", relays[0].Alias)
	}
}

func TestCertListJSONOutput(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Certs: []config.ManagedCert{
			{
				Domain:    "example.com",
				Issuer:    "Let's Encrypt",
				IssuedAt:  time.Now().Add(-24 * time.Hour),
				ExpiresAt: time.Now().Add(89 * 24 * time.Hour),
			},
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("SaveEx error: %v", err)
	}

	certListJSON = true
	t.Cleanup(func() { certListJSON = false })

	out := captureStdout(t, func() {
		if err := certListCmd.RunE(certListCmd, nil); err != nil {
			t.Fatalf("certListCmd error: %v", err)
		}
	})

	var certs []CertListItemJSON
	if err := json.Unmarshal([]byte(out), &certs); err != nil {
		t.Fatalf("failed to unmarshal cert JSON: %v\nOutput:\n%s", err, out)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %q", certs[0].Domain)
	}
	if certs[0].DaysRemaining < 80 {
		t.Errorf("expected days remaining ~89, got %d", certs[0].DaysRemaining)
	}
}
