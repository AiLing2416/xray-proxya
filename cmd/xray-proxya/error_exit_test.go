package main

import (
	"path/filepath"
	"testing"
	"xray-proxya/internal/config"
)

func TestErrorExitCodes(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	// Status on uninitialized should error
	if err := statusCmd.RunE(statusCmd, nil); err == nil {
		t.Fatalf("expected statusCmd to return error when uninitialized")
	}

	// Initialize empty staging config
	cfg := &config.UserConfig{
		Role: config.RoleServer,
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("SaveEx error: %v", err)
	}

	// Guests commands error checks
	if err := guestsRemoveCmd.RunE(guestsRemoveCmd, []string{"non-existent"}); err == nil {
		t.Fatalf("expected guestsRemoveCmd to return error for non-existent guest")
	}
	if err := guestsAddCmd.RunE(guestsAddCmd, []string{"x"}); err == nil {
		t.Fatalf("expected guestsAddCmd to return error for short alias")
	}
	if err := guestsSetCmd.RunE(guestsSetCmd, []string{"non-existent"}); err == nil {
		t.Fatalf("expected guestsSetCmd to return error for non-existent guest")
	}
	if err := guestsPauseCmd.RunE(guestsPauseCmd, []string{"non-existent"}); err == nil {
		t.Fatalf("expected guestsPauseCmd to return error for non-existent guest")
	}
	if err := guestsResumeCmd.RunE(guestsResumeCmd, []string{"non-existent"}); err == nil {
		t.Fatalf("expected guestsResumeCmd to return error for non-existent guest")
	}
	if err := guestsInfoCmd.RunE(guestsInfoCmd, []string{"non-existent"}); err == nil {
		t.Fatalf("expected guestsInfoCmd to return error for non-existent guest")
	}

	// Relay commands error checks
	if err := removeOutboundCmd.RunE(removeOutboundCmd, []string{"non-existent"}); err == nil {
		t.Fatalf("expected removeOutboundCmd to return error for non-existent relay")
	}
	if err := addOutboundCmd.RunE(addOutboundCmd, []string{"alias", "invalid-link"}); err == nil {
		t.Fatalf("expected addOutboundCmd to return error for invalid link")
	}
	if err := setDNSRelayCmd.RunE(setDNSRelayCmd, []string{"non-existent"}); err == nil {
		t.Fatalf("expected setDNSRelayCmd to return error when no flags or non-existent")
	}
	if err := setPrivateTargetsRelayCmd.RunE(setPrivateTargetsRelayCmd, []string{"non-existent", "true"}); err == nil {
		t.Fatalf("expected setPrivateTargetsRelayCmd to return error for non-existent relay")
	}

	// Proxy commands error checks
	if err := proxySetCmd.RunE(proxySetCmd, []string{"non-existent"}); err == nil {
		t.Fatalf("expected proxySetCmd to return error for non-existent relay")
	}
	if err := proxyUnsetCmd.RunE(proxyUnsetCmd, []string{"non-existent"}); err == nil {
		t.Fatalf("expected proxyUnsetCmd to return error for non-existent relay")
	}
	if err := proxyTestCmd.RunE(proxyTestCmd, []string{"non-existent"}); err == nil {
		t.Fatalf("expected proxyTestCmd to return error for non-existent relay")
	}

	// Tune verify error checks
	if err := tuneVerifyCmd.RunE(tuneVerifyCmd, []string{"non-existent-profile"}); err == nil {
		t.Fatalf("expected tuneVerifyCmd to return error for non-existent profile")
	}

	// Config upgrade error checks
	t.Setenv("HOME", filepath.Join(tempHome, "no-such-dir"))
	if err := configUpgradeCmd.RunE(configUpgradeCmd, nil); err == nil {
		t.Fatalf("expected configUpgradeCmd to return error when config missing")
	}
}
