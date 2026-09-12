package tui

import (
	"strings"
	"testing"
	"xray-proxya/internal/config"

	tea "github.com/charmbracelet/bubbletea"
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

func TestGuestEndpointAndRelaySelectMenu(t *testing.T) {
	m := InitialModel()
	m.currentTab = tabGuests
	m.staging = &config.UserConfig{
		Endpoints: map[string]config.EndpointConfig{
			"he-pool": {Type: config.EndpointTypeStatic, Host: "1.1.1.1"},
			"v6-pool": {Type: config.EndpointTypeAuto, Family: "v6"},
		},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "hk-node"},
			{Alias: "jp-node"},
		},
		Guests: []config.GuestConfig{
			{
				Alias:    "alice",
				UUID:     "uuid-1",
				Endpoint: "he-pool",
			},
		},
	}
	m.cursor = 0

	// 1. Press "e" -> opens endpoint choice menu
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	model := updated.(Model)
	if !model.infoSelectMode {
		t.Fatal("expected infoSelectMode to be true after pressing 'e'")
	}
	if model.infoSelectTarget != "guest-endpoint-choice" {
		t.Fatalf("expected target 'guest-endpoint-choice', got %s", model.infoSelectTarget)
	}
	// "Custom..." must be the FIRST item (index 0)
	if len(model.infoSelectChoices) < 3 || model.infoSelectChoices[0] != "Custom..." {
		t.Fatalf("expected first choice to be 'Custom...', got %v", model.infoSelectChoices)
	}
	if model.infoSelectChoices[1] != "default" {
		t.Fatalf("expected second choice to be 'default', got %v", model.infoSelectChoices)
	}
	// Current is "he-pool", so selection should match "he-pool"
	if model.infoSelectChoices[model.infoSelectIdx] != "he-pool" {
		t.Fatalf("expected selected item to be 'he-pool', got %s", model.infoSelectChoices[model.infoSelectIdx])
	}

	// Confirm "default" (index 1)
	model.infoSelectIdx = 1
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if model.infoSelectMode {
		t.Fatal("expected infoSelectMode to be false after confirmation")
	}
	if model.staging.Guests[0].Endpoint != "default" {
		t.Fatalf("expected endpoint 'default', got %s", model.staging.Guests[0].Endpoint)
	}

	// Select "Custom..." (index 0) -> enters text input
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	model = updated.(Model)
	model.infoSelectIdx = 0
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if model.inputMode != inputSetGuestEndpoint {
		t.Fatalf("expected inputMode inputSetGuestEndpoint, got %v", model.inputMode)
	}

	// Reset input mode
	model.inputMode = inputNone

	// 2. Press "r" -> opens relay choice menu
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	model = updated.(Model)
	if !model.infoSelectMode {
		t.Fatal("expected infoSelectMode to be true after pressing 'r'")
	}
	if model.infoSelectTarget != "guest-outbound-choice" {
		t.Fatalf("expected target 'guest-outbound-choice', got %s", model.infoSelectTarget)
	}
	// "Custom..." must be the FIRST item (index 0)
	if len(model.infoSelectChoices) < 3 || model.infoSelectChoices[0] != "Custom..." {
		t.Fatalf("expected first choice to be 'Custom...', got %v", model.infoSelectChoices)
	}
	if model.infoSelectChoices[1] != "Direct" {
		t.Fatalf("expected second choice to be 'Direct', got %v", model.infoSelectChoices)
	}
	// Existing relays should be present
	foundHK := false
	for _, c := range model.infoSelectChoices {
		if c == "hk-node" {
			foundHK = true
			break
		}
	}
	if !foundHK {
		t.Fatalf("expected choices to contain 'hk-node', got %v", model.infoSelectChoices)
	}

	// Select "hk-node"
	for idx, c := range model.infoSelectChoices {
		if c == "hk-node" {
			model.infoSelectIdx = idx
			break
		}
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if model.infoSelectMode {
		t.Fatal("expected infoSelectMode to be false after confirming relay")
	}
	if model.staging.Guests[0].OutboundLink != "hk-node" {
		t.Fatalf("expected OutboundLink 'hk-node', got %s", model.staging.Guests[0].OutboundLink)
	}
}
