package tui

import (
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func TestIsConfigurableService(t *testing.T) {
	tests := []struct {
		item ManagedServiceItem
		want bool
	}{
		{item: ManagedServiceItem{DisplayName: "Core"}, want: false},
		{item: ManagedServiceItem{DisplayName: "Pathd"}, want: true},
		{item: ManagedServiceItem{DisplayName: "Sub@default"}, want: true},
		{item: ManagedServiceItem{DisplayName: "Sub@custom"}, want: true},
		{item: ManagedServiceItem{DisplayName: "IPv6-Rotate"}, want: false},
		{item: ManagedServiceItem{DisplayName: "Rotate"}, want: false},
	}

	for _, tt := range tests {
		if got := isConfigurableService(tt.item); got != tt.want {
			t.Errorf("isConfigurableService(%s) = %v, want %v", tt.item.DisplayName, got, tt.want)
		}
	}
}

func TestPathdConfigValidationAndStaging(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleServer,
	}
	item := ManagedServiceItem{DisplayName: "Pathd", UnitName: "xray-proxya-pathd.service"}

	props := loadServiceProperties(cfg, item)
	if len(props) != 3 {
		t.Fatalf("expected 3 properties for Pathd, got %d", len(props))
	}

	// 1. Valid Listen
	err := validateAndApplyServiceProp(cfg, item, props[0], "127.0.0.1:2828")
	if err != nil {
		t.Fatalf("expected valid listen, got err: %v", err)
	}
	if cfg.Path.Listen != "127.0.0.1:2828" {
		t.Errorf("expected Listen to be 127.0.0.1:2828, got %s", cfg.Path.Listen)
	}

	// 2. Invalid Listen (non-loopback rejected by pathd)
	err = validateAndApplyServiceProp(cfg, item, props[0], "192.168.1.1:2828")
	if err == nil {
		t.Fatalf("expected non-loopback listen to fail validation")
	}

	// 3. Token validation
	err = validateAndApplyServiceProp(cfg, item, props[1], "   ")
	if err == nil {
		t.Fatalf("expected empty token to fail")
	}
	err = validateAndApplyServiceProp(cfg, item, props[1], "secret-token")
	if err != nil || cfg.Path.Token != "secret-token" {
		t.Fatalf("expected valid token, got %v", err)
	}

	// 4. Idle timeout
	err = validateAndApplyServiceProp(cfg, item, props[2], "0")
	if err == nil {
		t.Fatalf("expected 0 idle to fail")
	}
	err = validateAndApplyServiceProp(cfg, item, props[2], "30")
	if err != nil || cfg.Path.IdleSeconds != 30 {
		t.Fatalf("expected idle 30, got %v", err)
	}
}

func TestSubConfigValidation(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleServer,
	}
	item := ManagedServiceItem{DisplayName: "Sub", UnitName: "xray-proxya-sub.service"}

	props := loadServiceProperties(cfg, item)
	if len(props) != 7 {
		t.Fatalf("expected 7 properties for Sub, got %d", len(props))
	}

	// 1. Port validation
	portProp := props[0]
	err := validateAndApplyServiceProp(cfg, item, portProp, "70000")
	if err == nil {
		t.Fatalf("expected port > 65535 to fail")
	}
	err = validateAndApplyServiceProp(cfg, item, portProp, "9000")
	if err != nil {
		t.Fatalf("expected port 9000 to pass, got: %v", err)
	}
	if cfg.AdminSub.Port != 9000 {
		t.Errorf("expected port 9000 saved, got %d", cfg.AdminSub.Port)
	}

	// 2. Listen validation
	listenProp := props[1]
	err = validateAndApplyServiceProp(cfg, item, listenProp, "")
	if err == nil {
		t.Fatalf("expected empty listen to fail")
	}
	err = validateAndApplyServiceProp(cfg, item, listenProp, "127.0.0.1")
	if err != nil {
		t.Fatalf("expected listen 127.0.0.1 to pass: %v", err)
	}

	// 3. Token validation
	tokenProp := props[6]
	err = validateAndApplyServiceProp(cfg, item, tokenProp, "")
	if err == nil {
		t.Fatalf("expected empty token to fail")
	}
	err = validateAndApplyServiceProp(cfg, item, tokenProp, "token123")
	if err != nil || cfg.AdminSub.Token != "token123" {
		t.Fatalf("expected token123, got: %v", err)
	}
}

func TestServiceHasStagedChanges(t *testing.T) {
	active := &config.UserConfig{
		Role: config.RoleServer,
		Path: config.PathConfig{Listen: "127.0.0.1:2828", Token: "orig-token", IdleSeconds: 20},
	}
	staging := &config.UserConfig{
		Role: config.RoleServer,
		Path: config.PathConfig{Listen: "127.0.0.1:2828", Token: "orig-token", IdleSeconds: 20},
	}

	pathdItem := ManagedServiceItem{DisplayName: "Pathd", UnitName: "xray-proxya-pathd.service"}

	if serviceHasStagedChanges(active, staging, pathdItem) {
		t.Errorf("expected no staged changes initially")
	}

	staging.Path.Token = "new-token"
	if !serviceHasStagedChanges(active, staging, pathdItem) {
		t.Errorf("expected staged changes detected after token modification")
	}
}

func TestRenderVerticalChoiceList(t *testing.T) {
	choices := []string{"disabled", "forward-only", "proxy"}

	// Test full rendering
	lines := RenderVerticalChoiceList(choices, 1, 0)
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if !strings.Contains(lines[1], "forward-only") || !strings.Contains(lines[1], ">") {
		t.Errorf("expected selected indicator on line 1, got %q", lines[1])
	}
	if strings.Contains(lines[0], ">") {
		t.Errorf("line 0 should not have selected indicator, got %q", lines[0])
	}

	// Test scrolling window
	lines = RenderVerticalChoiceList(choices, 2, 2)
	if len(lines) != 2 {
		t.Fatalf("expected 2 windowed lines, got %d", len(lines))
	}
}

func TestRenderServiceListStagedIndicator(t *testing.T) {
	active := &config.UserConfig{
		Role: config.RoleServer,
		Path: config.PathConfig{Listen: "127.0.0.1:2828", Token: "orig-token", IdleSeconds: 20},
	}
	staging := &config.UserConfig{
		Role: config.RoleServer,
		Path: config.PathConfig{Listen: "127.0.0.1:2828", Token: "orig-token", IdleSeconds: 20},
	}

	services := []ManagedServiceItem{
		{DisplayName: "Core", UnitName: "xray-proxya.service", Status: "Running", Active: true},
		{DisplayName: "Pathd", UnitName: "xray-proxya-pathd.service", Status: "Stopped", Active: false},
	}

	// Initially, no staged changes
	out := RenderServiceList(active, staging, services, 0, 80)
	if strings.Contains(out, "[*]") {
		t.Errorf("expected no [*] indicator when staging matches active, got:\n%s", out)
	}

	// Modify staging for Pathd
	staging.Path.Token = "new-token"
	out = RenderServiceList(active, staging, services, 0, 80)
	if !strings.Contains(out, "[*]") {
		t.Errorf("expected [*] indicator for Pathd when staging differs from active, got:\n%s", out)
	}
}
