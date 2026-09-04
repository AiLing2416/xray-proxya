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
