package tui

import (
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func TestRenderGuestsWithEndpointAndLimit(t *testing.T) {
	active := &config.UserConfig{
		Guests: []config.GuestConfig{
			{
				Alias:      "alice",
				UUID:       "uuid-1",
				Enabled:    true,
				LimitBytes: 10 * 1000 * 1000 * 1000,
				QuotaGB:    10,
				ResetDay:   1,
				Endpoint:   "default",
			},
		},
	}
	staging := &config.UserConfig{
		Guests: []config.GuestConfig{
			{
				Alias:      "alice",
				UUID:       "uuid-1",
				Enabled:    true,
				LimitBytes: 10 * 1000 * 1000 * 1000,
				QuotaGB:    10,
				ResetDay:   1,
				Endpoint:   "default",
			},
			{
				Alias:        "bob",
				UUID:         "uuid-2",
				Enabled:      true,
				LimitBytes:   500 * 1000 * 1000,
				QuotaGB:      0.5,
				ResetDay:     15,
				Endpoint:     "he-pool",
				OutboundLink: "hk-node",
			},
		},
	}

	rendered := RenderGuests(active, staging, 0, 100)
	if !strings.Contains(rendered, "ENDPOINT") {
		t.Fatalf("expected RenderGuests to contain 'ENDPOINT' column header, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "default") {
		t.Fatalf("expected RenderGuests to display default endpoint for alice, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "he-pool") {
		t.Fatalf("expected RenderGuests to display he-pool endpoint for bob, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "hk-node") {
		t.Fatalf("expected RenderGuests to display relay alias hk-node for bob, got:\n%s", rendered)
	}

	// Test BuildGuestReport includes Endpoint
	report := BuildGuestReport(staging.Guests[1])
	if !strings.Contains(report, "Endpoint: he-pool") {
		t.Fatalf("expected BuildGuestReport to contain 'Endpoint: he-pool', got:\n%s", report)
	}
}

func TestGuestChangedDetection(t *testing.T) {
	active := &config.UserConfig{
		Guests: []config.GuestConfig{
			{
				Alias:      "alice",
				UUID:       "uuid-1",
				Enabled:    true,
				LimitBytes: 1000,
				QuotaGB:    1,
				ResetDay:   1,
				Endpoint:   "default",
			},
		},
	}

	// Unchanged
	same := config.GuestConfig{
		Alias:      "alice",
		UUID:       "uuid-1",
		Enabled:    true,
		LimitBytes: 1000,
		QuotaGB:    1,
		ResetDay:   1,
		Endpoint:   "default",
	}
	if guestChanged(active, same) {
		t.Errorf("expected guestChanged to return false for identical guest")
	}

	// Endpoint changed
	epDiff := same
	epDiff.Endpoint = "he-pool"
	if !guestChanged(active, epDiff) {
		t.Errorf("expected guestChanged to return true when Endpoint changes")
	}

	// LimitBytes changed
	limitDiff := same
	limitDiff.LimitBytes = 2000
	if !guestChanged(active, limitDiff) {
		t.Errorf("expected guestChanged to return true when LimitBytes changes")
	}

	// Outbound changed
	outDiff := same
	outDiff.OutboundLink = "relay-hk"
	if !guestChanged(active, outDiff) {
		t.Errorf("expected guestChanged to return true when OutboundLink changes")
	}
}
