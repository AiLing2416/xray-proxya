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
	if subEntry.Alias != managedSubAlias {
		t.Fatalf("alias = %q, want %q", subEntry.Alias, managedSubAlias)
	}
	if subEntry.TargetType != "direct" {
		t.Fatalf("target_type = %q, want direct", subEntry.TargetType)
	}
	if subEntry.Token == "" {
		t.Fatalf("expected generated token")
	}
}

func TestCurrentSubMode(t *testing.T) {
	if got := currentSubMode(&config.UserConfig{}); got != "fixed" {
		t.Fatalf("mode = %q, want fixed", got)
	}
	if got := currentSubMode(&config.UserConfig{IPv6Pool: config.IPv6Config{Enabled: true}}); got != "ipv6-rotate" {
		t.Fatalf("mode = %q, want ipv6-rotate", got)
	}
}

func TestManagedSubURLUsesOverrideAddress(t *testing.T) {
	cfg := &config.UserConfig{SubPort: 8443}
	subEntry := &config.Subscription{Token: "abc123", Address: "sub.example.com"}
	got := managedSubURL(cfg, subEntry)
	want := "https://sub.example.com:8443/sub/abc123"
	if got != want {
		t.Fatalf("managedSubURL = %q, want %q", got, want)
	}
}

func TestManagedSubURLHandlesHostWithPort(t *testing.T) {
	cfg := &config.UserConfig{SubPort: 8443}
	subEntry := &config.Subscription{Token: "abc123", Address: "sub.example.com:9443"}
	got := managedSubURL(cfg, subEntry)
	want := "https://sub.example.com:9443/sub/abc123"
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
	if cfg.IPv6Pool.Interface != "eth0" {
		t.Fatalf("interface = %q, want eth0", cfg.IPv6Pool.Interface)
	}
	if cfg.IPv6Pool.Subnet != "2001:db8::/64" {
		t.Fatalf("subnet = %q", cfg.IPv6Pool.Subnet)
	}
	if cfg.IPv6Pool.MaxAddresses != 9 {
		t.Fatalf("max = %d, want 9", cfg.IPv6Pool.MaxAddresses)
	}
	if cfg.IPv6Pool.EnableNDP {
		t.Fatalf("ndp = true, want false")
	}
}

func TestEnsureSubPortConfiguredKeepsExistingPort(t *testing.T) {
	cfg := &config.UserConfig{SubPort: 9443}
	ensureSubPortConfigured(cfg)
	if cfg.SubPort != 9443 {
		t.Fatalf("sub_port = %d, want 9443", cfg.SubPort)
	}
}

func TestManagedSubscriptionReusesExistingEntry(t *testing.T) {
	cfg := &config.UserConfig{
		Subscriptions: []config.Subscription{{Alias: managedSubAlias, TargetType: "direct", Token: "existing"}},
	}
	subEntry := ensureManagedSubscription(cfg)
	if subEntry.Token != "existing" {
		t.Fatalf("token = %q, want existing", subEntry.Token)
	}
	if count := strings.Count(managedSubURL(&config.UserConfig{SubPort: 8443}, subEntry), "/sub/"); count != 1 {
		t.Fatalf("expected managed URL path once")
	}
}
