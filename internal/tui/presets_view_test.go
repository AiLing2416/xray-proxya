package tui

import (
	"strings"
	"testing"

	"xray-proxya/internal/config"
)

func TestRenderPresetsWithSkin(t *testing.T) {
	active := &config.UserConfig{
		Role: config.RoleServer,
		Presets: []config.ModeInfo{
			{
				Mode:       config.ModeVLESSReality,
				Port:       443,
				Enabled:    true,
				Skin:       "seafile",
				SkinDomain: "sea.example.com",
			},
		},
	}
	staging := &config.UserConfig{
		Role: config.RoleServer,
		Presets: []config.ModeInfo{
			{
				Mode:       config.ModeVLESSReality,
				Port:       443,
				Enabled:    true,
				Skin:       "nextcloud",
				SkinDomain: "cloud.example.com",
			},
		},
	}

	out := RenderPresets(active, staging, 0, 100)
	if !strings.Contains(out, "SKIN") {
		t.Errorf("expected RenderPresets output to contain 'SKIN' header, got: %s", out)
	}
	if !strings.Contains(out, "nextcloud (cloud.example.com)") {
		t.Errorf("expected RenderPresets output to contain skin name and domain, got: %s", out)
	}
	// Since active skin differs from staging skin, it must show [*] indicator
	if !strings.Contains(out, "[*]") {
		t.Errorf("expected RenderPresets to show [*] modified indicator when skin changes, got: %s", out)
	}
}

func TestRenderPresetsEmpty(t *testing.T) {
	out := RenderPresets(nil, nil, 0, 100)
	if !strings.Contains(out, "No presets found") {
		t.Errorf("expected 'No presets found', got: %s", out)
	}
}

func TestGetSecurityName(t *testing.T) {
	tests := []struct {
		mode     config.ModeInfo
		expected string
	}{
		{
			mode:     config.ModeInfo{Mode: config.ModeVMessWS},
			expected: "chacha20-poly1305",
		},
		{
			mode:     config.ModeInfo{Mode: config.ModeVMessWS, Settings: config.Settings{Cipher: "aes-128-gcm"}},
			expected: "aes-128-gcm",
		},
		{
			mode:     config.ModeInfo{Mode: config.ModeVLESSReality},
			expected: "Reality",
		},
		{
			mode:     config.ModeInfo{Mode: config.ModeVLESSVision},
			expected: "Vision-Reality",
		},
		{
			mode:     config.ModeInfo{Mode: config.ModeVLESSXHTTP},
			expected: "ML-KEM768",
		},
		{
			mode:     config.ModeInfo{Mode: config.ModeShadowsocksTCP},
			expected: "aes-256-gcm",
		},
		{
			mode:     config.ModeInfo{Mode: config.ModeShadowsocksTCP, Settings: config.Settings{Cipher: "chacha20-poly1305"}},
			expected: "chacha20-poly1305",
		},
	}

	for _, tc := range tests {
		got := getSecurityName(tc.mode)
		if got != tc.expected {
			t.Errorf("getSecurityName for mode %s with cipher %q: got %q, want %q", tc.mode.Mode, tc.mode.Settings.Cipher, got, tc.expected)
		}
	}
}
