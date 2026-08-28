package main

import (
	"errors"
	"testing"
	"xray-proxya/internal/config"
)

func TestValidateManualTargetUsesSNIAndDefaultHTTPSPort(t *testing.T) {
	originalChecker := checkTargetAvailability
	t.Cleanup(func() { checkTargetAvailability = originalChecker })

	calledTarget := ""
	checkTargetAvailability = func(target string) error {
		calledTarget = target
		return nil
	}
	if err := validateManualTarget("WWW.Intel.COM.", ""); err != nil {
		t.Fatalf("validateManualTarget() error = %v", err)
	}
	if calledTarget != "www.intel.com:443" {
		t.Fatalf("target = %q, want www.intel.com:443", calledTarget)
	}
}

func TestValidateManualTargetReturnsAvailabilityFailure(t *testing.T) {
	originalChecker := checkTargetAvailability
	t.Cleanup(func() { checkTargetAvailability = originalChecker })

	want := errors.New("unreachable")
	checkTargetAvailability = func(string) error { return want }
	if err := validateManualTarget("www.intel.com", "www.intel.com:443"); !errors.Is(err, want) {
		t.Fatalf("validateManualTarget() error = %v, want %v", err, want)
	}
}

func TestSupportsSkin(t *testing.T) {
	if !supportsSkin(config.ModeVLESSVision) {
		t.Errorf("expected ModeVLESSVision to support skin")
	}
	if !supportsSkin(config.ModeVLESSReality) {
		t.Errorf("expected ModeVLESSReality to support skin")
	}
	if supportsSkin(config.ModeVLESSXHTTP) {
		t.Errorf("expected ModeVLESSXHTTP not to support skin")
	}
	if supportsSkin(config.ModeVMessWS) {
		t.Errorf("expected ModeVMessWS not to support skin")
	}
	if supportsSkin(config.ModeShadowsocksTCP) {
		t.Errorf("expected ModeShadowsocksTCP not to support skin")
	}
}

func TestPresetsSetRiskyTargetInteractiveReject(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Presets: []config.ModeInfo{
			{Mode: config.ModeVLESSVision, Enabled: true, Port: 443, SNI: "pkg.go.dev", Dest: "pkg.go.dev:443"},
		},
	}
	_ = cfg.SaveEx(true)

	origPrompt := promptConfirmFunc
	origChecker := checkTargetAvailability
	t.Cleanup(func() {
		promptConfirmFunc = origPrompt
		checkTargetAvailability = origChecker
		presetSkinManual = ""
		presetSNI = ""
		presetDest = ""
		presetSkinManualForce = false
	})

	promptCalls := 0
	promptConfirmFunc = func(prompt string) bool {
		promptCalls++
		return false // reject
	}
	checkTargetAvailability = func(string) error { return nil }

	presetSkinManual = "cdn.jsdelivr.net"
	presetSkinManualForce = false

	presetsSetCmd.Run(presetsSetCmd, []string{"1"})

	if promptCalls != 1 {
		t.Errorf("promptCalls = %d, want 1", promptCalls)
	}

	loaded, _ := config.LoadConfigEx(true)
	if loaded.Presets[0].SNI != "pkg.go.dev" {
		t.Errorf("SNI = %q, want pkg.go.dev (unchanged)", loaded.Presets[0].SNI)
	}
}

func TestPresetsSetRiskyTargetInteractiveConfirm(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Presets: []config.ModeInfo{
			{Mode: config.ModeVLESSVision, Enabled: true, Port: 443, SNI: "pkg.go.dev", Dest: "pkg.go.dev:443"},
		},
	}
	_ = cfg.SaveEx(true)

	origPrompt := promptConfirmFunc
	origChecker := checkTargetAvailability
	t.Cleanup(func() {
		promptConfirmFunc = origPrompt
		checkTargetAvailability = origChecker
		presetSkinManual = ""
		presetSNI = ""
		presetDest = ""
		presetSkinManualForce = false
	})

	promptCalls := 0
	promptConfirmFunc = func(prompt string) bool {
		promptCalls++
		return true // confirm
	}
	checkTargetAvailability = func(string) error { return nil }

	presetSkinManual = "cdn.jsdelivr.net"
	presetSkinManualForce = false

	presetsSetCmd.Run(presetsSetCmd, []string{"1"})

	if promptCalls != 1 {
		t.Errorf("promptCalls = %d, want 1", promptCalls)
	}

	loaded, _ := config.LoadConfigEx(true)
	if loaded.Presets[0].SNI != "cdn.jsdelivr.net" {
		t.Errorf("SNI = %q, want cdn.jsdelivr.net", loaded.Presets[0].SNI)
	}
}

func TestPresetsSetRiskyTargetWithForceFlag(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Presets: []config.ModeInfo{
			{Mode: config.ModeVLESSVision, Enabled: true, Port: 443, SNI: "pkg.go.dev", Dest: "pkg.go.dev:443"},
		},
	}
	_ = cfg.SaveEx(true)

	origPrompt := promptConfirmFunc
	origChecker := checkTargetAvailability
	t.Cleanup(func() {
		promptConfirmFunc = origPrompt
		checkTargetAvailability = origChecker
		presetSkinManual = ""
		presetSNI = ""
		presetDest = ""
		presetSkinManualForce = false
	})

	promptCalls := 0
	promptConfirmFunc = func(prompt string) bool {
		promptCalls++
		return false
	}
	checkTargetAvailability = func(string) error { return nil }

	presetSkinManual = "cdn.jsdelivr.net"
	presetSkinManualForce = true

	presetsSetCmd.Run(presetsSetCmd, []string{"1"})

	if promptCalls != 0 {
		t.Errorf("promptCalls = %d, want 0 when forced", promptCalls)
	}

	loaded, _ := config.LoadConfigEx(true)
	if loaded.Presets[0].SNI != "cdn.jsdelivr.net" {
		t.Errorf("SNI = %q, want cdn.jsdelivr.net", loaded.Presets[0].SNI)
	}
}
