package main

import (
	"testing"
	"xray-proxya/internal/config"
)

func TestConfigureSkinTargetDefaultsToSNI(t *testing.T) {
	m := &config.ModeInfo{SNI: "WWW.Intel.COM."}
	if err := configureSkinTarget(m, false); err != nil {
		t.Fatalf("configureSkinTarget() error = %v", err)
	}
	if m.Dest != "www.intel.com:443" {
		t.Fatalf("dest = %q, want www.intel.com:443", m.Dest)
	}
}

func TestConfigureSkinTargetRejectsDifferentHost(t *testing.T) {
	m := &config.ModeInfo{SNI: "www.intel.com", Dest: "www.google.com:443"}
	if err := configureSkinTarget(m, true); err == nil {
		t.Fatal("configureSkinTarget() succeeded for mismatched SNI and destination")
	}
}

func TestConfigureSkinTargetAcceptsMatchingHost(t *testing.T) {
	m := &config.ModeInfo{SNI: "www.intel.com", Dest: "www.intel.com:8443"}
	if err := configureSkinTarget(m, true); err != nil {
		t.Fatalf("configureSkinTarget() error = %v", err)
	}
}
