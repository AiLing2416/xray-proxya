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
	if !subEntry.Enabled {
		t.Fatalf("expected admin sub to be enabled")
	}
}

func TestCurrentSubMode(t *testing.T) {
	if got := currentSubMode(&config.UserConfig{}); got != "fixed" {
		t.Fatalf("mode = %q, want fixed", got)
	}
	if got := currentSubMode(&config.UserConfig{AdminSub: config.AdminSubConfig{Mode: config.AdminSubModeIPv6Rotate}}); got != "ipv6-rotate" {
		t.Fatalf("mode = %q, want ipv6-rotate", got)
	}
}

func TestManagedSubURLUsesOverrideAddress(t *testing.T) {
	cfg := &config.UserConfig{AdminSub: config.AdminSubConfig{Port: 8443}}
	subEntry := &config.AdminSubConfig{Token: "abc123", Address: "sub.example.com"}
	got := managedSubURL(cfg, subEntry)
	want := "http://sub.example.com:8443/sub/abc123"
	if got != want {
		t.Fatalf("managedSubURL = %q, want %q", got, want)
	}
}

func TestManagedSubURLHandlesHostWithPort(t *testing.T) {
	cfg := &config.UserConfig{AdminSub: config.AdminSubConfig{Port: 8443}}
	subEntry := &config.AdminSubConfig{Token: "abc123", Address: "sub.example.com:9443"}
	got := managedSubURL(cfg, subEntry)
	want := "http://sub.example.com:9443/sub/abc123"
	if got != want {
		t.Fatalf("managedSubURL = %q, want %q", got, want)
	}
}

func TestDetectOrUseIPv6SettingsUsesOverrides(t *testing.T) {
	cfg := &config.UserConfig{}
	err := detectOrUseIPv6Settings(cfg, "eth0", "2001:db8::/64", 9, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AdminSub.IPv6Rotate.Interface != "eth0" {
		t.Fatalf("interface = %q, want eth0", cfg.AdminSub.IPv6Rotate.Interface)
	}
	if cfg.AdminSub.IPv6Rotate.Subnet != "2001:db8::/64" {
		t.Fatalf("subnet = %q", cfg.AdminSub.IPv6Rotate.Subnet)
	}
	if cfg.AdminSub.IPv6Rotate.MaxAddresses != 9 {
		t.Fatalf("max = %d, want 9", cfg.IPv6Pool.MaxAddresses)
	}
	if cfg.AdminSub.IPv6Rotate.EnableNDP {
		t.Fatalf("ndp = true, want false")
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
		AdminSub: config.AdminSubConfig{Enabled: true, Token: "existing", TargetType: "direct"},
	}
	subEntry := ensureManagedSubscription(cfg)
	if subEntry.Token != "existing" {
		t.Fatalf("token = %q, want existing", subEntry.Token)
	}
	if count := strings.Count(managedSubURL(&config.UserConfig{AdminSub: config.AdminSubConfig{Port: 8443}}, subEntry), "/sub/"); count != 1 {
		t.Fatalf("expected managed URL path once")
	}
}
