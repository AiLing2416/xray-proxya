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
	if count := strings.Count(managedSubURL(&config.UserConfig{AdminSub: config.AdminSubConfig{Port: 8443}}, subEntry), "/sub/"); count != 1 {
		t.Fatalf("expected managed URL path once")
	}
}
