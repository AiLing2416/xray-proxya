package main

import (
	"errors"
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
