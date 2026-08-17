package presets

import (
	"testing"
	"xray-proxya/internal/config"
)

func TestRegenerateMarkedModesPreservesRealitySNIAndDest(t *testing.T) {
	origSNIVision := "vision.example.com"
	origDestVision := "vision.example.com:443"
	origSNIReality := "reality.example.org"
	origDestReality := "reality.example.org:8443"

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Presets: []config.ModeInfo{
			{
				Mode:      config.ModeVLESSVision,
				Enabled:   true,
				SNI:       origSNIVision,
				Dest:      origDestVision,
				RegenFlag: true,
				Settings: config.Settings{
					PrivateKey: "old-priv",
					PublicKey:  "old-pub",
					ShortID:    "old-id",
				},
			},
			{
				Mode:      config.ModeVLESSReality,
				Enabled:   true,
				SNI:       origSNIReality,
				Dest:      origDestReality,
				Path:      "/old-path",
				RegenFlag: true,
				Settings: config.Settings{
					PrivateKey: "old-priv2",
					PublicKey:  "old-pub2",
					ShortID:    "old-id2",
				},
			},
		},
	}

	if err := RegenerateMarkedModes(cfg); err != nil {
		t.Fatalf("RegenerateMarkedModes failed: %v", err)
	}

	// Vision checks
	v := cfg.Presets[0]
	if v.RegenFlag {
		t.Errorf("Vision RegenFlag was not cleared")
	}
	if v.SNI != origSNIVision {
		t.Errorf("Vision SNI = %q, want %q", v.SNI, origSNIVision)
	}
	if v.Dest != origDestVision {
		t.Errorf("Vision Dest = %q, want %q", v.Dest, origDestVision)
	}
	if v.Settings.PrivateKey == "old-priv" || v.Settings.PrivateKey == "" {
		t.Errorf("Vision PrivateKey was not regenerated")
	}
	if v.Settings.ShortID == "old-id" || v.Settings.ShortID == "" {
		t.Errorf("Vision ShortID was not regenerated")
	}
	if !config.IsAllowedRealityFingerprint(v.Fingerprint) {
		t.Errorf("Vision Fingerprint %q not in allowlist", v.Fingerprint)
	}

	// Reality checks
	r := cfg.Presets[1]
	if r.RegenFlag {
		t.Errorf("Reality RegenFlag was not cleared")
	}
	if r.SNI != origSNIReality {
		t.Errorf("Reality SNI = %q, want %q", r.SNI, origSNIReality)
	}
	if r.Dest != origDestReality {
		t.Errorf("Reality Dest = %q, want %q", r.Dest, origDestReality)
	}
	if r.Path == "/old-path" || r.Path == "" {
		t.Errorf("Reality Path was not regenerated")
	}
	if r.Settings.PrivateKey == "old-priv2" || r.Settings.PrivateKey == "" {
		t.Errorf("Reality PrivateKey was not regenerated")
	}
	if !config.IsAllowedRealityFingerprint(r.Fingerprint) {
		t.Errorf("Reality Fingerprint %q not in allowlist", r.Fingerprint)
	}
}
