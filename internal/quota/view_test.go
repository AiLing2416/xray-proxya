package quota

import (
	"testing"
	"time"

	"xray-proxya/internal/config"
)

func TestFormatQuota(t *testing.T) {
	tests := []struct {
		input float64
		want  string
	}{
		{-1, "Unlimited"},
		{-0.01, "Unlimited"},
		{0, "Paused"},
		{0.001, "0.001GB"},
		{0.125, "0.125GB"},
		{0.5, "0.5GB"},
		{1.0, "1.00GB"},
		{1.25, "1.25GB"},
		{9.99, "9.99GB"},
		{10.0, "10.0GB"},
		{25.5, "25.5GB"},
	}

	for _, tc := range tests {
		got := FormatQuota(tc.input)
		if got != tc.want {
			t.Errorf("FormatQuota(%v) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestGuestStateLabel(t *testing.T) {
	tests := []struct {
		guest config.GuestConfig
		want  string
	}{
		{config.GuestConfig{Enabled: true}, "ON"},
		{config.GuestConfig{Enabled: false, DisabledReason: config.GuestDisabledQuotaReached}, "QUOTA"},
		{config.GuestConfig{Enabled: false, DisabledReason: config.GuestDisabledQuotaZero}, "PAUSED"},
		{config.GuestConfig{Enabled: false, DisabledReason: config.GuestDisabledManual}, "PAUSED"},
		{config.GuestConfig{Enabled: false, DisabledReason: ""}, "OFF"},
	}

	for _, tc := range tests {
		got := GuestStateLabel(tc.guest)
		if got != tc.want {
			t.Errorf("GuestStateLabel(%+v) = %q, want %q", tc.guest, got, tc.want)
		}
	}
}

func TestGuestReasonLabel(t *testing.T) {
	tests := []struct {
		guest config.GuestConfig
		want  string
	}{
		{config.GuestConfig{DisabledReason: config.GuestDisabledManual}, "manual"},
		{config.GuestConfig{DisabledReason: config.GuestDisabledQuotaReached}, "quota reached"},
		{config.GuestConfig{DisabledReason: config.GuestDisabledQuotaZero}, "quota=0"},
		{config.GuestConfig{DisabledReason: ""}, "-"},
	}

	for _, tc := range tests {
		got := GuestReasonLabel(tc.guest)
		if got != tc.want {
			t.Errorf("GuestReasonLabel(%+v) = %q, want %q", tc.guest, got, tc.want)
		}
	}
}

func TestBuildGuestView(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	// Case 1: Unlimited guest
	unlimitedGuest := config.GuestConfig{
		Alias:    "alice",
		UUID:     "uuid-1",
		Enabled:  true,
		QuotaGB:  -1,
		ResetDay: 1,
	}
	view1 := BuildGuestView(unlimitedGuest, now)
	if view1.Alias != "alice" || view1.StateLabel != "ON" || view1.RelayLabel != "direct" {
		t.Errorf("unexpected unlimited view: %+v", view1)
	}
	if view1.LimitBytes != -1 || view1.UsagePercent != -1 || view1.QuotaFormatted != "Unlimited" {
		t.Errorf("unexpected metrics for unlimited guest: %+v", view1)
	}

	// Case 2: Capped guest with 10GB quota, 5GB used, custom outbound link
	cappedGuest := config.GuestConfig{
		Alias:           "bob",
		UUID:            "uuid-2",
		Enabled:         false,
		DisabledReason:  config.GuestDisabledQuotaReached,
		QuotaGB:         10,
		UsedBytes:       5 * config.GigaByte,
		OutboundLink:    "vless://something",
		AlertedTriggers: []string{"80%", "100%"},
	}
	view2 := BuildGuestView(cappedGuest, now)
	if view2.Alias != "bob" || view2.StateLabel != "QUOTA" || view2.RelayLabel != "custom-link" {
		t.Errorf("unexpected capped view: %+v", view2)
	}
	if view2.UsagePercent != 50.0 {
		t.Errorf("expected UsagePercent 50.0, got %v", view2.UsagePercent)
	}
	if view2.RemainingBytes != 5*config.GigaByte {
		t.Errorf("expected RemainingBytes 5GB, got %v", view2.RemainingBytes)
	}
	if len(view2.AlertedTriggers) != 2 {
		t.Errorf("expected 2 alerted triggers, got %v", view2.AlertedTriggers)
	}

	// Case 3: BuildAllGuestViews
	allViews := BuildAllGuestViews([]config.GuestConfig{unlimitedGuest, cappedGuest}, now)
	if len(allViews) != 2 {
		t.Fatalf("expected 2 views, got %d", len(allViews))
	}
	if allViews[0].Alias != "alice" || allViews[1].Alias != "bob" {
		t.Errorf("unexpected views slice: %+v", allViews)
	}
}
