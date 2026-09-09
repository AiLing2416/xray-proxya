package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"xray-proxya/internal/config"
)

func setupTestConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", dir)
	return dir
}

func TestServerInitSelectsOneRealityTargetAndEnablesOnlyPreset1(t *testing.T) {
	setupTestConfigDir(t)

	selectorCalls := 0
	cleanupCalls := 0

	origSelector := realityTargetSelector
	origCleanup := prepareFreshInitFunc
	origEnsure := ensureXrayBinaryFunc
	t.Cleanup(func() {
		realityTargetSelector = origSelector
		prepareFreshInitFunc = origCleanup
		ensureXrayBinaryFunc = origEnsure
	})

	realityTargetSelector = func() (string, string, error) {
		selectorCalls++
		return "selected.test.domain", "selected.test.domain:443", nil
	}
	prepareFreshInitFunc = func() {
		cleanupCalls++
	}
	ensureXrayBinaryFunc = func() error {
		return nil
	}

	forceInit = true
	roleStr = "server"

	if err := runInit(nil, nil); err != nil {
		t.Fatalf("runInit failed: %v", err)
	}

	if selectorCalls != 1 {
		t.Errorf("selectorCalls = %d; want 1", selectorCalls)
	}
	if cleanupCalls != 1 {
		t.Errorf("cleanupCalls = %d; want 1", cleanupCalls)
	}

	cfg, err := config.LoadConfigEx(false)
	if err != nil {
		t.Fatalf("LoadConfigEx failed: %v", err)
	}

	if cfg.Role != config.RoleServer {
		t.Errorf("Role = %q, want %q", cfg.Role, config.RoleServer)
	}

	// Verify only preset 1 is enabled
	enabledCount := 0
	for i, m := range cfg.Presets {
		if m.Enabled {
			enabledCount++
			if m.Mode != config.ModeVLESSVision {
				t.Errorf("Preset %d (%s) is enabled; only ModeVLESSVision should be enabled", i+1, m.Mode)
			}
		}
	}
	if enabledCount != 1 {
		t.Errorf("enabledCount = %d, want 1", enabledCount)
	}

	// Verify both REALITY presets share the exact same target
	var visionMode, realityMode *config.ModeInfo
	for i := range cfg.Presets {
		if cfg.Presets[i].Mode == config.ModeVLESSVision {
			visionMode = &cfg.Presets[i]
		} else if cfg.Presets[i].Mode == config.ModeVLESSReality {
			realityMode = &cfg.Presets[i]
		}
	}

	if visionMode == nil || realityMode == nil {
		t.Fatalf("REALITY presets missing in config")
	}

	if visionMode.SNI != "selected.test.domain" || visionMode.Dest != "selected.test.domain:443" {
		t.Errorf("Vision target = (%q, %q), want (selected.test.domain, selected.test.domain:443)",
			visionMode.SNI, visionMode.Dest)
	}
	if !config.IsAllowedRealityFingerprint(visionMode.Fingerprint) {
		t.Errorf("Vision fingerprint %q not in allowlist", visionMode.Fingerprint)
	}

	if realityMode.SNI != "selected.test.domain" || realityMode.Dest != "selected.test.domain:443" {
		t.Errorf("Reality target = (%q, %q), want (selected.test.domain, selected.test.domain:443)",
			realityMode.SNI, realityMode.Dest)
	}
	if !config.IsAllowedRealityFingerprint(realityMode.Fingerprint) {
		t.Errorf("Reality fingerprint %q not in allowlist", realityMode.Fingerprint)
	}
}

func TestGatewayInitDoesNotCallSelectorAndDisablesAllPresets(t *testing.T) {
	setupTestConfigDir(t)

	selectorCalls := 0
	cleanupCalls := 0

	origSelector := realityTargetSelector
	origCleanup := prepareFreshInitFunc
	origEnsure := ensureXrayBinaryFunc
	t.Cleanup(func() {
		realityTargetSelector = origSelector
		prepareFreshInitFunc = origCleanup
		ensureXrayBinaryFunc = origEnsure
	})

	realityTargetSelector = func() (string, string, error) {
		selectorCalls++
		return "mock.com", "mock.com:443", nil
	}
	prepareFreshInitFunc = func() {
		cleanupCalls++
	}
	ensureXrayBinaryFunc = func() error {
		return nil
	}

	forceInit = true
	roleStr = "gateway"

	if err := runInit(nil, nil); err != nil {
		t.Fatalf("runInit failed: %v", err)
	}

	if selectorCalls != 0 {
		t.Errorf("selectorCalls = %d; want 0 for gateway", selectorCalls)
	}
	if cleanupCalls != 1 {
		t.Errorf("cleanupCalls = %d; want 1", cleanupCalls)
	}

	cfg, err := config.LoadConfigEx(false)
	if err != nil {
		t.Fatalf("LoadConfigEx failed: %v", err)
	}

	if cfg.Role != config.RoleGateway {
		t.Errorf("Role = %q, want %q", cfg.Role, config.RoleGateway)
	}

	for i, m := range cfg.Presets {
		if m.Enabled {
			t.Errorf("Gateway preset %d (%s) is enabled; want all disabled", i+1, m.Mode)
		}
	}
}

func TestServerInitPreflightFailureDoesNotCallCleanupOrOverwrite(t *testing.T) {
	configDir := setupTestConfigDir(t)

	// Create an existing config
	existingConfigFile := filepath.Join(configDir, "config.json")
	initialContent := []byte(`{"role":"server","uuid":"existing-uuid"}`)
	if err := os.WriteFile(existingConfigFile, initialContent, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	selectorCalls := 0
	cleanupCalls := 0

	origSelector := realityTargetSelector
	origCleanup := prepareFreshInitFunc
	origEnsure := ensureXrayBinaryFunc
	t.Cleanup(func() {
		realityTargetSelector = origSelector
		prepareFreshInitFunc = origCleanup
		ensureXrayBinaryFunc = origEnsure
	})

	// Preflight fails
	realityTargetSelector = func() (string, string, error) {
		selectorCalls++
		return "", "", errors.New("qualification failed for all candidates")
	}
	prepareFreshInitFunc = func() {
		cleanupCalls++
	}
	ensureXrayBinaryFunc = func() error {
		return nil
	}

	forceInit = true
	roleStr = "server"

	err := runInit(nil, nil)
	if err == nil {
		t.Fatalf("runInit with failing preflight expected error, got nil")
	}

	if selectorCalls != 1 {
		t.Errorf("selectorCalls = %d; want 1", selectorCalls)
	}
	if cleanupCalls != 0 {
		t.Errorf("cleanupCalls = %d; want 0 when preflight fails", cleanupCalls)
	}

	// Verify original config was not modified/overwritten
	content, _ := os.ReadFile(existingConfigFile)
	if string(content) != string(initialContent) {
		t.Errorf("existing config was overwritten: got %q, want %q", string(content), string(initialContent))
	}
}

func TestInitPositionalRoleGateway(t *testing.T) {
	setupTestConfigDir(t)

	origCleanup := prepareFreshInitFunc
	origEnsure := ensureXrayBinaryFunc
	t.Cleanup(func() {
		prepareFreshInitFunc = origCleanup
		ensureXrayBinaryFunc = origEnsure
		forceInit = false
		roleStr = "server"
	})
	prepareFreshInitFunc = func() {}
	ensureXrayBinaryFunc = func() error { return nil }

	forceInit = true
	roleStr = "server" // default flag value

	// Pass "gateway" as positional argument
	err := runInit(nil, []string{"gateway"})
	if err != nil {
		t.Fatalf("runInit with positional 'gateway' failed: %v", err)
	}

	cfg, err := config.LoadConfigEx(false)
	if err != nil {
		t.Fatalf("LoadConfigEx failed: %v", err)
	}
	if cfg.Role != config.RoleGateway {
		t.Errorf("Role = %q, want %q", cfg.Role, config.RoleGateway)
	}
}

func TestInitInvalidRoleFails(t *testing.T) {
	setupTestConfigDir(t)

	origCleanup := prepareFreshInitFunc
	origEnsure := ensureXrayBinaryFunc
	t.Cleanup(func() {
		prepareFreshInitFunc = origCleanup
		ensureXrayBinaryFunc = origEnsure
		forceInit = false
		roleStr = "server"
	})
	prepareFreshInitFunc = func() {}
	ensureXrayBinaryFunc = func() error { return nil }

	forceInit = true

	// Test positional invalid role
	err := runInit(nil, []string{"client"})
	if err == nil {
		t.Fatal("expected error for invalid positional role 'client', got nil")
	}

	// Test flag invalid role
	roleStr = "unknown"
	err = runInit(nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid flag role 'unknown', got nil")
	}
}

func TestInitRoleConflictFails(t *testing.T) {
	setupTestConfigDir(t)

	origCleanup := prepareFreshInitFunc
	origEnsure := ensureXrayBinaryFunc
	t.Cleanup(func() {
		prepareFreshInitFunc = origCleanup
		ensureXrayBinaryFunc = origEnsure
		forceInit = false
		roleStr = "server"
		initCmd.Flags().Lookup("role").Changed = false
	})
	prepareFreshInitFunc = func() {}
	ensureXrayBinaryFunc = func() error { return nil }

	forceInit = true
	roleStr = "server"
	initCmd.Flags().Lookup("role").Changed = true

	// Positional argument "gateway" conflicts with flag "server"
	err := runInit(initCmd, []string{"gateway"})
	if err == nil {
		t.Fatal("expected error for conflicting positional and flag roles, got nil")
	}
}

func TestInitConfigExistsWithoutForceFails(t *testing.T) {
	configDir := setupTestConfigDir(t)

	existingConfigFile := filepath.Join(configDir, "config.json")
	if err := os.WriteFile(existingConfigFile, []byte(`{"role":"server"}`), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	forceInit = false
	roleStr = "server"

	err := runInit(nil, nil)
	if err == nil {
		t.Fatal("expected error when config already exists without force, got nil")
	}
}

func TestInitForceShorthandFlag(t *testing.T) {
	flag := initCmd.Flags().Lookup("force")
	if flag == nil {
		t.Fatal("flag --force not found on initCmd")
	}
	if flag.Shorthand != "f" {
		t.Fatalf("flag --force shorthand = %q, want %q", flag.Shorthand, "f")
	}
}

