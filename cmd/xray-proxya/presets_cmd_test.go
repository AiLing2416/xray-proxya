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
