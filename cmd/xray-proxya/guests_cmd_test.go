package main

import (
	"testing"

	"xray-proxya/internal/config"
)

func TestFormatGuestQuotaKeepsSmallDecimals(t *testing.T) {
	if got := formatGuestQuota(0.001); got != "0.001GB" {
		t.Fatalf("formatGuestQuota(0.001) = %q, want %q", got, "0.001GB")
	}
	if got := formatGuestQuota(0.125); got != "0.125GB" {
		t.Fatalf("formatGuestQuota(0.125) = %q, want %q", got, "0.125GB")
	}
}

func TestGuestStateAndReasonLabels(t *testing.T) {
	guest := config.GuestConfig{Enabled: false, DisabledReason: config.GuestDisabledQuotaReached}
	if got := guestStateLabel(guest); got != "QUOTA" {
		t.Fatalf("guestStateLabel() = %q, want %q", got, "QUOTA")
	}
	if got := guestReasonLabel(guest); got != "quota reached" {
		t.Fatalf("guestReasonLabel() = %q, want %q", got, "quota reached")
	}
}
