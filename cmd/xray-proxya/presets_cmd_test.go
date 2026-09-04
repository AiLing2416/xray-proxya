package main

import (
	"errors"
	"testing"
	"time"
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

func TestSupportsRealityAndSkin(t *testing.T) {
	if !supportsReality(config.ModeVLESSVision) {
		t.Errorf("expected ModeVLESSVision to support reality")
	}
	if !supportsReality(config.ModeVLESSReality) {
		t.Errorf("expected ModeVLESSReality to support reality")
	}
	if supportsReality(config.ModeVLESSXHTTP) {
		t.Errorf("expected ModeVLESSXHTTP not to support reality")
	}
	if supportsReality(config.ModeVMessWS) {
		t.Errorf("expected ModeVMessWS not to support reality")
	}
	if supportsReality(config.ModeShadowsocksTCP) {
		t.Errorf("expected ModeShadowsocksTCP not to support reality")
	}

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
		presetSNIManual = ""
		presetSNI = ""
		presetDest = ""
		presetSNIForce = false
	})

	promptCalls := 0
	promptConfirmFunc = func(prompt string) bool {
		promptCalls++
		return false // reject
	}
	checkTargetAvailability = func(string) error { return nil }

	presetSNIManual = "cdn.jsdelivr.net"
	presetSNIForce = false

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
		presetSNIManual = ""
		presetSNI = ""
		presetDest = ""
		presetSNIForce = false
	})

	promptCalls := 0
	promptConfirmFunc = func(prompt string) bool {
		promptCalls++
		return true // confirm
	}
	checkTargetAvailability = func(string) error { return nil }

	presetSNIManual = "cdn.jsdelivr.net"
	presetSNIForce = false

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
		presetSNIManual = ""
		presetSNI = ""
		presetDest = ""
		presetSNIForce = false
	})

	promptCalls := 0
	promptConfirmFunc = func(prompt string) bool {
		promptCalls++
		return false
	}
	checkTargetAvailability = func(string) error { return nil }

	presetSNIManual = "cdn.jsdelivr.net"
	presetSNIForce = true

	presetsSetCmd.Run(presetsSetCmd, []string{"1"})

	if promptCalls != 0 {
		t.Errorf("promptCalls = %d, want 0 when forced", promptCalls)
	}

	loaded, _ := config.LoadConfigEx(true)
	if loaded.Presets[0].SNI != "cdn.jsdelivr.net" {
		t.Errorf("SNI = %q, want cdn.jsdelivr.net", loaded.Presets[0].SNI)
	}
}

func TestPresetsSetSkinRequiresDomainAndCert(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Presets: []config.ModeInfo{
			{Mode: config.ModeVLESSVision, Enabled: true, Port: 443, SNI: "pkg.go.dev", Dest: "pkg.go.dev:443"},
		},
		Certs: []config.ManagedCert{
			{
				Domain:    "sea.ailing.dev",
				IssuedAt:  time.Now().Add(-10 * 24 * time.Hour),
				ExpiresAt: time.Now().Add(80 * 24 * time.Hour),
				Issuer:    "Let's Encrypt",
			},
		},
	}
	_ = cfg.SaveEx(true)

	t.Cleanup(func() {
		presetSkin = ""
		presetSkinDomain = ""
		_ = presetsSetCmd.Flags().Set("skin", "")
		_ = presetsSetCmd.Flags().Set("skin-domain", "")
		if f := presetsSetCmd.Flags().Lookup("skin"); f != nil {
			f.Changed = false
		}
		if f := presetsSetCmd.Flags().Lookup("skin-domain"); f != nil {
			f.Changed = false
		}
	})

	// 1. Setting --skin seafile without domain -> should be rejected
	if err := presetsSetCmd.ParseFlags([]string{"--skin", "seafile"}); err != nil {
		t.Fatalf("ParseFlags error: %v", err)
	}
	presetsSetCmd.Run(presetsSetCmd, []string{"1"})

	loaded, _ := config.LoadConfigEx(true)
	if loaded.Presets[0].Skin != "" {
		t.Errorf("Skin should not be set without domain")
	}

	// 2. Setting --skin seafile with uncertified domain -> should be rejected
	if err := presetsSetCmd.ParseFlags([]string{"--skin", "seafile", "--skin-domain", "uncerted.com"}); err != nil {
		t.Fatalf("ParseFlags error: %v", err)
	}
	presetsSetCmd.Run(presetsSetCmd, []string{"1"})

	loaded, _ = config.LoadConfigEx(true)
	if loaded.Presets[0].Skin != "" {
		t.Errorf("Skin should not be set with uncertified domain")
	}

	// 3. Setting --skin seafile with registered domain sea.ailing.dev -> succeeds!
	if err := presetsSetCmd.ParseFlags([]string{"--skin", "seafile", "--skin-domain", "sea.ailing.dev"}); err != nil {
		t.Fatalf("ParseFlags error: %v", err)
	}
	presetsSetCmd.Run(presetsSetCmd, []string{"1"})

	loaded, _ = config.LoadConfigEx(true)
	if loaded.Presets[0].Skin != "seafile" {
		t.Errorf("Skin = %q, want seafile", loaded.Presets[0].Skin)
	}
	if loaded.Presets[0].SkinDomain != "sea.ailing.dev" {
		t.Errorf("SkinDomain = %q, want sea.ailing.dev", loaded.Presets[0].SkinDomain)
	}
	if loaded.Presets[0].SNI != "sea.ailing.dev" {
		t.Errorf("SNI = %q, want sea.ailing.dev", loaded.Presets[0].SNI)
	}
	if loaded.Presets[0].Dest != "127.0.0.1:9443" {
		t.Errorf("Dest = %q, want 127.0.0.1:9443", loaded.Presets[0].Dest)
	}

	// 4. Setting --skin off -> disables skin
	if err := presetsSetCmd.ParseFlags([]string{"--skin", "off"}); err != nil {
		t.Fatalf("ParseFlags error: %v", err)
	}
	presetsSetCmd.Run(presetsSetCmd, []string{"1"})

	loaded, _ = config.LoadConfigEx(true)
	if loaded.Presets[0].Skin != "" {
		t.Errorf("Skin should be cleared on --skin off")
	}
}

func TestPresetsSetMinVer(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Presets: []config.ModeInfo{
			{Mode: config.ModeVLESSVision, Enabled: true, Port: 443, SNI: "pkg.go.dev", Dest: "pkg.go.dev:443"},
			{Mode: config.ModeVMessWS, Enabled: true, Port: 8080, Path: "/vmess"},
		},
	}
	_ = cfg.SaveEx(true)

	t.Cleanup(func() {
		presetMinVer = ""
		_ = presetsSetCmd.Flags().Set("min-ver", "")
	})

	// 1. Valid min-ver for VLESSVision
	if err := presetsSetCmd.ParseFlags([]string{"--min-ver", "26.3.27"}); err != nil {
		t.Fatalf("ParseFlags error: %v", err)
	}
	presetsSetCmd.Run(presetsSetCmd, []string{"1"})

	loaded, _ := config.LoadConfigEx(true)
	if loaded.Presets[0].MinClientVer != "26.3.27" {
		t.Errorf("MinClientVer = %q, want 26.3.27", loaded.Presets[0].MinClientVer)
	}

	// 2. Set min-ver to 0.0.0 (compatible mode)
	if err := presetsSetCmd.ParseFlags([]string{"--min-ver", "0.0.0"}); err != nil {
		t.Fatalf("ParseFlags error: %v", err)
	}
	presetsSetCmd.Run(presetsSetCmd, []string{"1"})

	loaded, _ = config.LoadConfigEx(true)
	if loaded.Presets[0].MinClientVer != "0.0.0" {
		t.Errorf("MinClientVer = %q, want 0.0.0", loaded.Presets[0].MinClientVer)
	}

	// 3. Invalid min-ver format - should reject and keep previous
	if err := presetsSetCmd.ParseFlags([]string{"--min-ver", "invalid.version"}); err != nil {
		t.Fatalf("ParseFlags error: %v", err)
	}
	presetsSetCmd.Run(presetsSetCmd, []string{"1"})

	loaded, _ = config.LoadConfigEx(true)
	if loaded.Presets[0].MinClientVer != "0.0.0" {
		t.Errorf("MinClientVer mutated on invalid input: got %q, want 0.0.0", loaded.Presets[0].MinClientVer)
	}

	// 4. Unsupported mode (VMessWS is slot 4)
	if err := presetsSetCmd.ParseFlags([]string{"--min-ver", "26.3.27"}); err != nil {
		t.Fatalf("ParseFlags error: %v", err)
	}
	presetsSetCmd.Run(presetsSetCmd, []string{"4"})

	loaded, _ = config.LoadConfigEx(true)
	if loaded.Presets[3].MinClientVer != "" {
		t.Errorf("unsupported mode got MinClientVer = %q, want empty", loaded.Presets[3].MinClientVer)
	}
}
