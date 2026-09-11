package main

import (
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func TestEnsureManagedSubscriptionCreatesAdminEntry(t *testing.T) {
	cfg := &config.UserConfig{}
	subEntry := ensureManagedSubscription(cfg)
	if subEntry == nil {
		t.Fatalf("expected managed subscription to be created")
	}
	if subEntry.TargetType != "direct" {
		t.Fatalf("target_type = %q, want direct", subEntry.TargetType)
	}
	if subEntry.Token == "" {
		t.Fatalf("expected generated token")
	}
}

func TestManagedSubURLUsesOverrideAddress(t *testing.T) {
	// Port 8443 auto-promoted to https
	cfg := &config.UserConfig{AdminSub: config.AdminSubConfig{Port: 8443}}
	subEntry := &config.AdminSubConfig{Token: "abc123", Address: "sub.example.com"}
	got := managedSubURL(cfg, subEntry)
	want := "https://sub.example.com:8443/abc123"
	if got != want {
		t.Fatalf("managedSubURL = %q, want %q", got, want)
	}

	// Non-secure port 8080 falls back to http
	cfg8080 := &config.UserConfig{AdminSub: config.AdminSubConfig{Port: 8080}}
	subEntry8080 := &config.AdminSubConfig{Token: "abc123", Address: "sub.example.com"}
	got8080 := managedSubURL(cfg8080, subEntry8080)
	want8080 := "http://sub.example.com:8080/abc123"
	if got8080 != want8080 {
		t.Fatalf("managedSubURL = %q, want %q", got8080, want8080)
	}
}

func TestManagedSubURLPrioritizesGateURL(t *testing.T) {
	cfg := &config.UserConfig{
		GateURL:    "https://gate.example.com",
		AddressSub: "https://old.example.com",
		AdminSub:   config.AdminSubConfig{Port: 8443, Token: "abc123"},
	}
	got := managedSubURL(cfg, &cfg.AdminSub)
	want := "https://gate.example.com/abc123"
	if got != want {
		t.Fatalf("managedSubURL = %q, want %q", got, want)
	}
}

func TestManagedSubURLHandlesHostWithPort(t *testing.T) {
	cfg := &config.UserConfig{AdminSub: config.AdminSubConfig{Port: 8443}}
	subEntry := &config.AdminSubConfig{Token: "abc123", Address: "sub.example.com:9443"}
	got := managedSubURL(cfg, subEntry)
	want := "http://sub.example.com:9443/abc123"
	if got != want {
		t.Fatalf("managedSubURL = %q, want %q", got, want)
	}
}

func TestManagedSubURLSupportsAddressSubWithScheme(t *testing.T) {
	cfg := &config.UserConfig{
		AddressSub: "https://sub.example.com",
		AdminSub:   config.AdminSubConfig{Port: 8443, Token: "abc123"},
	}
	got := managedSubURL(cfg, &cfg.AdminSub)
	want := "https://sub.example.com/abc123"
	if got != want {
		t.Fatalf("managedSubURL = %q, want %q", got, want)
	}
}

func TestEnsureSubPortConfiguredKeepsExistingPort(t *testing.T) {
	cfg := &config.UserConfig{AdminSub: config.AdminSubConfig{Port: 9443}}
	ensureSubPortConfigured(cfg)
	if cfg.AdminSub.Port != 9443 {
		t.Fatalf("admin_sub.port = %d, want 9443", cfg.AdminSub.Port)
	}
}

func TestManagedSubscriptionReusesExistingEntry(t *testing.T) {
	cfg := &config.UserConfig{
		AdminSub: config.AdminSubConfig{Token: "existing", TargetType: "direct"},
	}
	subEntry := ensureManagedSubscription(cfg)
	if subEntry.Token != "existing" {
		t.Fatalf("token = %q, want existing", subEntry.Token)
	}
	url := managedSubURL(&config.UserConfig{AdminSub: config.AdminSubConfig{Port: 8443}}, subEntry)
	if !strings.HasSuffix(url, "/existing") {
		t.Fatalf("expected managed URL path to end with /existing, got %q", url)
	}
}

func TestSubscriptionServiceManagement(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", tempDir)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		AdminSub: config.AdminSubConfig{
			Token: "default-tok",
			Port:  8443,
		},
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("save config: %v", err)
	}

	subServ, err := subscriptionInstance()
	if err != nil || subServ.Port != 8443 {
		t.Fatalf("load sub: %v, port: %d", err, subServ.Port)
	}
	if subServ.AdminSub.Token != "default-tok" {
		t.Fatalf("token = %q, want default-tok", subServ.AdminSub.Token)
	}
}

func TestSubShowInstancePenetration(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		AdminSub: config.AdminSubConfig{
			Token:      "admin-tok-12345",
			Port:       8443,
			Listen:     "127.0.0.1",
			TargetType: "direct",
		},
		SubscriptionInstances: map[string]config.AdminSubConfig{
			"default": {
				Token:      "admin-tok-12345",
				Port:       8443,
				Listen:     "127.0.0.1",
				TargetType: "direct",
			},
			"node-hk": {
				Token:      "hk-token-9999",
				Port:       9443,
				Listen:     "127.0.0.1",
				TargetType: "direct",
			},
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("save active config: %v", err)
	}

	// 1. Show existing custom instance
	out := captureStdout(t, func() {
		err := subShowCmd.RunE(subShowCmd, []string{"node-hk"})
		if err != nil {
			t.Fatalf("sub show node-hk failed: %v", err)
		}
	})
	if !strings.Contains(out, "Subscription Instance: node-hk") || !strings.Contains(out, "hk-token-9999") {
		t.Errorf("expected node-hk details in output, got: %s", out)
	}
	if strings.Contains(out, "admin-tok-12345") {
		t.Errorf("sub show node-hk should not display default instance details")
	}

	// 2. Show nonexistent instance
	err := subShowCmd.RunE(subShowCmd, []string{"nonexistent"})
	if err == nil || !strings.Contains(err.Error(), "Subscription instance 'nonexistent' not found.") {
		t.Fatalf("expected not found error, got %v", err)
	}

	// 3. Show all instances (no args)
	allOut := captureStdout(t, func() {
		err := subShowCmd.RunE(subShowCmd, []string{})
		if err != nil {
			t.Fatalf("sub show failed: %v", err)
		}
	})
	if !strings.Contains(allOut, "Admin Subscription") || !strings.Contains(allOut, "admin-tok-12345") {
		t.Errorf("expected Admin Subscription in output, got: %s", allOut)
	}
	if !strings.Contains(allOut, "node-hk") || !strings.Contains(allOut, "hk-token-9999") {
		t.Errorf("expected node-hk in output, got: %s", allOut)
	}

	// 4. Validate instance penetration
	if err := subValidateCmd.RunE(subValidateCmd, []string{"node-hk"}); err != nil {
		t.Errorf("sub validate node-hk failed: %v", err)
	}
	if err := subValidateCmd.RunE(subValidateCmd, []string{"nonexistent"}); err == nil {
		t.Errorf("expected error validating nonexistent instance, got nil")
	}
}
