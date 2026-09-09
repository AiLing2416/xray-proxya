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

func TestGuestsSetNotifyAndWebhook(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Guests: []config.GuestConfig{{
			Alias:    "guest-tom",
			UUID:     "uuid-tom",
			Enabled:  true,
			QuotaGB:  10,
			ResetDay: 1,
			Notify:   config.GuestNotifyOff,
		}},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}

	// 1. Set --notify header
	notifyStr = "header"
	_ = guestsSetCmd.Flags().Set("notify", "header")
	guestsSetCmd.Run(guestsSetCmd, []string{"guest-tom"})

	staged, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load staged: %v", err)
	}
	if staged.Guests[0].Notify != config.GuestNotifyHeader {
		t.Fatalf("expected notify header, got %s", staged.Guests[0].Notify)
	}

	// 2. Set --notify-webhook
	notifyWebhookStr = "https://example.com/hook"
	_ = guestsSetCmd.Flags().Set("notify-webhook", "https://example.com/hook")
	guestsSetCmd.Run(guestsSetCmd, []string{"guest-tom"})

	staged2, _ := config.LoadConfigEx(true)
	if staged2.Guests[0].NotifyWebhook != "https://example.com/hook" {
		t.Fatalf("expected webhook https://example.com/hook, got %s", staged2.Guests[0].NotifyWebhook)
	}

	// 3. Clear --notify-webhook
	notifyWebhookStr = ""
	_ = guestsSetCmd.Flags().Set("notify-webhook", "")
	guestsSetCmd.Run(guestsSetCmd, []string{"guest-tom"})

	staged3, _ := config.LoadConfigEx(true)
	if staged3.Guests[0].NotifyWebhook != "" {
		t.Fatalf("expected empty webhook, got %s", staged3.Guests[0].NotifyWebhook)
	}
}

func TestGuestsSetLimitAndTriggerValidation(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Guests: []config.GuestConfig{{
			Alias:      "guest-amy",
			UUID:       "uuid-amy",
			Enabled:    true,
			LimitBytes: 10 * config.GigaByte, // 10 GB
			ResetDay:   1,
		}},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}

	// 1. Set --limit 50GB (Base 10)
	limitStr = "50GB"
	_ = guestsSetCmd.Flags().Set("limit", "50GB")
	guestsSetCmd.Run(guestsSetCmd, []string{"guest-amy"})

	staged, _ := config.LoadConfigEx(true)
	if staged.Guests[0].EffectiveLimitBytes() != 50*config.GigaByte {
		t.Fatalf("expected 50GB limit, got %d", staged.Guests[0].EffectiveLimitBytes())
	}

	// 2. Set valid triggers: 80p, 45p, 40G, 5G
	notifyTriggerStr = "80p,45p,40G,5G"
	_ = guestsSetCmd.Flags().Set("notify-trigger", "80p,45p,40G,5G")
	guestsSetCmd.Run(guestsSetCmd, []string{"guest-amy"})

	staged2, _ := config.LoadConfigEx(true)
	if len(staged2.Guests[0].NotifyTrigger) != 4 {
		t.Fatalf("expected 4 notify triggers, got %v", staged2.Guests[0].NotifyTrigger)
	}

	// 3. Reject trigger exceeding Limit: 60G > 50G
	notifyTriggerStr = "60G"
	_ = guestsSetCmd.Flags().Set("notify-trigger", "60G")
	guestsSetCmd.Run(guestsSetCmd, []string{"guest-amy"})

	staged3, _ := config.LoadConfigEx(true)
	if len(staged3.Guests[0].NotifyTrigger) != 4 {
		t.Fatalf("triggers should not have been updated when validation failed, got %v", staged3.Guests[0].NotifyTrigger)
	}

	// 4. Reject trigger percentage > 100%
	notifyTriggerStr = "105p"
	_ = guestsSetCmd.Flags().Set("notify-trigger", "105p")
	guestsSetCmd.Run(guestsSetCmd, []string{"guest-amy"})

	staged4, _ := config.LoadConfigEx(true)
	if len(staged4.Guests[0].NotifyTrigger) != 4 {
		t.Fatalf("triggers should not have been updated when validation failed, got %v", staged4.Guests[0].NotifyTrigger)
	}

	// 5. Clear triggers with 'none'
	notifyTriggerStr = "none"
	_ = guestsSetCmd.Flags().Set("notify-trigger", "none")
	guestsSetCmd.Run(guestsSetCmd, []string{"guest-amy"})

	staged5, _ := config.LoadConfigEx(true)
	if len(staged5.Guests[0].NotifyTrigger) != 0 {
		t.Fatalf("expected triggers cleared, got %v", staged5.Guests[0].NotifyTrigger)
	}
}

func TestGuestsSetRelayAndRelayLink(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Guests: []config.GuestConfig{{
			Alias:   "guest-bob",
			UUID:    "uuid-bob",
			Enabled: true,
		}},
		CustomOutbounds: []config.CustomOutbound{{
			Alias:   "us-node",
			Enabled: true,
			Config:  map[string]interface{}{"protocol": "freedom"},
		}},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}

	defer func() {
		relayStr = ""
		relayLinkStr = ""
		outboundStr = ""
		limitStr = ""
		quotaStr = ""
		notifyStr = ""
		notifyWebhookStr = ""
		notifyTriggerStr = ""
		guestsSetCmd.Flags().Lookup("relay").Changed = false
		guestsSetCmd.Flags().Lookup("relay-link").Changed = false
		guestsSetCmd.Flags().Lookup("limit").Changed = false
		guestsSetCmd.Flags().Lookup("quota").Changed = false
		guestsSetCmd.Flags().Lookup("notify-trigger").Changed = false
		guestsSetCmd.Flags().Lookup("notify").Changed = false
		guestsSetCmd.Flags().Lookup("notify-webhook").Changed = false
	}()

	limitStr = ""
	quotaStr = ""
	notifyStr = ""
	notifyWebhookStr = ""
	notifyTriggerStr = ""
	guestsSetCmd.Flags().Lookup("limit").Changed = false
	guestsSetCmd.Flags().Lookup("quota").Changed = false
	guestsSetCmd.Flags().Lookup("notify-trigger").Changed = false
	guestsSetCmd.Flags().Lookup("notify").Changed = false
	guestsSetCmd.Flags().Lookup("notify-webhook").Changed = false

	// 1. Valid relay alias
	relayStr = "us-node"
	_ = guestsSetCmd.Flags().Set("relay", "us-node")
	guestsSetCmd.Run(guestsSetCmd, []string{"guest-bob"})

	staged1, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load staged: %v", err)
	}
	if staged1.Guests[0].OutboundLink != "us-node" || staged1.Guests[0].OutboundConf == nil {
		t.Fatalf("expected outbound link 'us-node' with non-nil config, got link=%q conf=%v", staged1.Guests[0].OutboundLink, staged1.Guests[0].OutboundConf)
	}

	// 2. Set to direct
	relayStr = "direct"
	_ = guestsSetCmd.Flags().Set("relay", "direct")
	guestsSetCmd.Run(guestsSetCmd, []string{"guest-bob"})

	staged2, _ := config.LoadConfigEx(true)
	if staged2.Guests[0].OutboundLink != "" || staged2.Guests[0].OutboundConf != nil {
		t.Fatalf("expected direct (empty link and nil conf), got link=%q conf=%v", staged2.Guests[0].OutboundLink, staged2.Guests[0].OutboundConf)
	}

	// 3. Invalid relay alias
	relayStr = "nonexistent-alias"
	_ = guestsSetCmd.Flags().Set("relay", "nonexistent-alias")
	guestsSetCmd.Run(guestsSetCmd, []string{"guest-bob"})

	staged3, _ := config.LoadConfigEx(true)
	if staged3.Guests[0].OutboundLink != "" {
		t.Fatalf("expected config unchanged for invalid relay alias, got %q", staged3.Guests[0].OutboundLink)
	}

	// 4. Raw relay link via --relay-link
	guestsSetCmd.Flags().Lookup("relay").Changed = false
	relayStr = ""
	validLink := "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=reality&pbk=1111111111111111111111111111111111111111111=&fp=chrome&sni=example.com#test-node"
	relayLinkStr = validLink
	_ = guestsSetCmd.Flags().Set("relay-link", validLink)
	guestsSetCmd.Run(guestsSetCmd, []string{"guest-bob"})

	staged4, _ := config.LoadConfigEx(true)
	if staged4.Guests[0].OutboundLink != validLink || staged4.Guests[0].OutboundConf == nil {
		t.Fatalf("expected validLink and non-nil OutboundConf, got link=%q conf=%v", staged4.Guests[0].OutboundLink, staged4.Guests[0].OutboundConf)
	}

	// 5. Mutual exclusivity: both --relay and --relay-link specified
	relayStr = "us-node"
	_ = guestsSetCmd.Flags().Set("relay", "us-node")
	relayLinkStr = validLink
	_ = guestsSetCmd.Flags().Set("relay-link", validLink)
	guestsSetCmd.Run(guestsSetCmd, []string{"guest-bob"})

	staged5, _ := config.LoadConfigEx(true)
	// Must not change from staged4 because error was reported
	if staged5.Guests[0].OutboundLink != validLink {
		t.Fatalf("config changed despite mutual exclusion error: got %q", staged5.Guests[0].OutboundLink)
	}
}



