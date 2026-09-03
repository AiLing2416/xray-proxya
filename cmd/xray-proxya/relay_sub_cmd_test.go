package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

func TestMaskURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "https://sub.example.com/api/v1/client/subscribe?token=1234567890abcdef",
			want:  "https://sub.example.com/api/v1/client/subscribe?token=123***def",
		},
		{
			input: "http://example.com/sub?key=secret",
			want:  "http://example.com/sub?key=***",
		},
		{
			input: "https://sub.example.com/sub.txt",
			want:  "https://sub.example.com/sub.txt",
		},
	}

	for _, tt := range tests {
		got := maskURL(tt.input)
		if got != tt.want {
			t.Errorf("maskURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRelaySubLifecycle(t *testing.T) {
	// Set up temporary config directory
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	cfgDir := filepath.Join(tmpDir, ".config", "xray-proxya")
	if err := os.MkdirAll(cfgDir, 0755); err != nil {
		t.Fatalf("failed to create temp config dir: %v", err)
	}

	initialCfg := &config.UserConfig{
		Role: config.RoleServer,
		UUID: "00000000-0000-0000-0000-000000000000",
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "manual-vps", Enabled: true},
		},
	}
	if err := initialCfg.SaveEx(true); err != nil {
		t.Fatalf("failed to save initial staging config: %v", err)
	}

	// Mock subscription server
	link1 := "vless://c8abfd6a-bba7-4db9-b43e-82c2beb76049@1.2.3.4:443?security=none#HK-01"
	link2 := "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@5.6.7.8:8388#US-01"
	payload := base64.StdEncoding.EncodeToString([]byte(link1 + "\n" + link2))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(payload))
	}))
	defer server.Close()

	// 1. Test relay sub add
	relaySubAddCmd.Run(relaySubAddCmd, []string{"myair", server.URL})

	cfg, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("failed to reload staging config: %v", err)
	}
	if cfg.RelaySubs["myair"] != server.URL {
		t.Errorf("expected RelaySubs[myair] = %q, got %q", server.URL, cfg.RelaySubs["myair"])
	}
	if len(cfg.CustomOutbounds) != 3 { // manual-vps + myair/HK-01 + myair/US-01
		t.Fatalf("expected 3 custom outbounds, got %d", len(cfg.CustomOutbounds))
	}

	// Verify completion functions
	names := getRelaySubNames()
	if len(names) != 1 || names[0] != "myair" {
		t.Errorf("expected getRelaySubNames() = ['myair'], got %v", names)
	}
	comp, _ := completeRelaySubNamesArg(&cobra.Command{}, nil, "")
	if len(comp) != 1 || comp[0] != "myair" {
		t.Errorf("expected completion = ['myair'], got %v", comp)
	}

	// 2. Test relay sub update (with updated payload)
	link3 := "vless://c8abfd6a-bba7-4db9-b43e-82c2beb76049@1.2.3.4:443?security=none#HK-01" // unchanged
	link4 := "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@9.9.9.9:8388#JP-01"                      // new (US-01 removed)
	payload = base64.StdEncoding.EncodeToString([]byte(link3 + "\n" + link4))

	relaySubUpdateCmd.Run(relaySubUpdateCmd, []string{"myair"})

	cfg, err = config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("failed to reload staging config: %v", err)
	}
	if len(cfg.CustomOutbounds) != 3 { // manual-vps + myair/HK-01 + myair/JP-01
		t.Fatalf("expected 3 custom outbounds after update, got %d", len(cfg.CustomOutbounds))
	}
	foundJP := false
	foundUS := false
	for _, co := range cfg.CustomOutbounds {
		if co.Alias == "myair/JP-01" {
			foundJP = true
		}
		if co.Alias == "myair/US-01" {
			foundUS = true
		}
	}
	if !foundJP {
		t.Errorf("expected myair/JP-01 to be present after update")
	}
	if foundUS {
		t.Errorf("expected myair/US-01 to be removed after update")
	}

	// 3. Test relay sub remove
	relaySubRemoveCmd.Run(relaySubRemoveCmd, []string{"myair"})

	cfg, err = config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("failed to reload staging config: %v", err)
	}
	if _, exists := cfg.RelaySubs["myair"]; exists {
		t.Errorf("expected myair removed from RelaySubs")
	}
	if len(cfg.CustomOutbounds) != 1 || cfg.CustomOutbounds[0].Alias != "manual-vps" {
		t.Fatalf("expected only manual-vps remaining, got %v", cfg.CustomOutbounds)
	}
}
