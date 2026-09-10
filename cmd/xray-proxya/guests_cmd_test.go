package main

import (
	"strings"
	"testing"

	"xray-proxya/internal/config"

	"github.com/spf13/pflag"
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

func TestGuestsRemoveAliases(t *testing.T) {
	if guestsRemoveCmd.Name() != "remove" {
		t.Fatalf("expected command name 'remove', got %q", guestsRemoveCmd.Name())
	}
	expectedAliases := map[string]bool{"rm": true, "del": true, "delete": true}
	if len(guestsRemoveCmd.Aliases) != len(expectedAliases) {
		t.Fatalf("expected %d aliases, got %v", len(expectedAliases), guestsRemoveCmd.Aliases)
	}
	for _, alias := range guestsRemoveCmd.Aliases {
		if !expectedAliases[alias] {
			t.Errorf("unexpected alias %q", alias)
		}
	}

	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Guests: []config.GuestConfig{
			{Alias: "g-rem", UUID: "uuid-1", Enabled: true},
			{Alias: "g-rm", UUID: "uuid-2", Enabled: true},
			{Alias: "g-del", UUID: "uuid-3", Enabled: true},
			{Alias: "g-delete", UUID: "uuid-4", Enabled: true},
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}

	guestsRemoveCmd.Run(guestsRemoveCmd, []string{"g-rem"})
	staged, _ := config.LoadConfigEx(true)
	if len(staged.Guests) != 3 {
		t.Fatalf("expected 3 guests after remove, got %d", len(staged.Guests))
	}

	for _, aliasCmd := range []string{"rm", "del", "delete"} {
		cmd, _, err := rootCmd.Find([]string{"guests", aliasCmd})
		if err != nil || cmd != guestsRemoveCmd {
			t.Fatalf("expected rootCmd.Find(guests, %s) to resolve to guestsRemoveCmd, got %v (err: %v)", aliasCmd, cmd, err)
		}
	}

	guestsRemoveCmd.Run(guestsRemoveCmd, []string{"g-rm"})
	guestsRemoveCmd.Run(guestsRemoveCmd, []string{"g-del"})
	guestsRemoveCmd.Run(guestsRemoveCmd, []string{"g-delete"})

	stagedFinal, _ := config.LoadConfigEx(true)
	if len(stagedFinal.Guests) != 0 {
		t.Fatalf("expected 0 guests after all removals, got %d", len(stagedFinal.Guests))
	}
}

func resetGuestsAddFlags() {
	guestAddLimit = ""
	guestAddRelay = ""
	guestAddRelayLink = ""
	guestAddResetDay = 1
	guestAddNotify = ""
	if f := guestsAddCmd.Flags().Lookup("limit"); f != nil {
		_ = f.Value.Set("")
		f.Changed = false
	}
	if f := guestsAddCmd.Flags().Lookup("relay"); f != nil {
		_ = f.Value.Set("")
		f.Changed = false
	}
	if f := guestsAddCmd.Flags().Lookup("relay-link"); f != nil {
		_ = f.Value.Set("")
		f.Changed = false
	}
	if f := guestsAddCmd.Flags().Lookup("reset"); f != nil {
		_ = f.Value.Set("1")
		f.Changed = false
	}
	if f := guestsAddCmd.Flags().Lookup("notify"); f != nil {
		_ = f.Value.Set("")
		f.Changed = false
	}
}

func TestGuestsAddWithInlineFlags(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "relay-hk", Enabled: true},
		},
		Guests: []config.GuestConfig{},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}

	// 1. guests add bob --limit 20GB --relay direct
	resetGuestsAddFlags()
	_ = guestsAddCmd.Flags().Set("limit", "20GB")
	_ = guestsAddCmd.Flags().Set("relay", "direct")
	err := guestsAddCmd.RunE(guestsAddCmd, []string{"bob"})
	if err != nil {
		t.Fatalf("guests add bob failed: %v", err)
	}

	loaded, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(loaded.Guests) != 1 {
		t.Fatalf("expected 1 guest, got %d", len(loaded.Guests))
	}
	bob := loaded.Guests[0]
	if bob.Alias != "bob" {
		t.Errorf("alias = %q, want bob", bob.Alias)
	}
	if bob.LimitBytes != 20*1000*1000*1000 {
		t.Errorf("LimitBytes = %d, want %d", bob.LimitBytes, int64(20*1000*1000*1000))
	}
	if bob.OutboundLink != "" {
		t.Errorf("OutboundLink = %q, want empty (direct)", bob.OutboundLink)
	}
	if bob.ResetDay != 1 {
		t.Errorf("ResetDay = %d, want 1", bob.ResetDay)
	}

	// 2. guests add charlie with custom relay, reset day, and notify
	resetGuestsAddFlags()
	_ = guestsAddCmd.Flags().Set("relay", "relay-hk")
	_ = guestsAddCmd.Flags().Set("reset", "15")
	_ = guestsAddCmd.Flags().Set("notify", "header")
	err = guestsAddCmd.RunE(guestsAddCmd, []string{"charlie"})
	if err != nil {
		t.Fatalf("guests add charlie failed: %v", err)
	}
	loaded, _ = config.LoadConfigEx(true)
	if len(loaded.Guests) != 2 {
		t.Fatalf("expected 2 guests, got %d", len(loaded.Guests))
	}
	charlie := loaded.Guests[1]
	if charlie.OutboundLink != "relay-hk" {
		t.Errorf("charlie OutboundLink = %q, want relay-hk", charlie.OutboundLink)
	}
	if charlie.ResetDay != 15 {
		t.Errorf("charlie ResetDay = %d, want 15", charlie.ResetDay)
	}
	if charlie.Notify != config.GuestNotifyHeader {
		t.Errorf("charlie Notify = %s, want header", charlie.Notify)
	}

	// 3. Conflict: both --relay and --relay-link
	resetGuestsAddFlags()
	_ = guestsAddCmd.Flags().Set("relay", "direct")
	_ = guestsAddCmd.Flags().Set("relay-link", "vless://dummy")
	err = guestsAddCmd.RunE(guestsAddCmd, []string{"dave"})
	if err == nil || !strings.Contains(err.Error(), "Cannot specify both --relay and --relay-link") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func TestGuestsSubSetListen(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}

	// 1. Set --listen 127.0.0.1
	guestsSubSetCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	if err := guestsSubSetCmd.ParseFlags([]string{"--listen", "127.0.0.1"}); err != nil {
		t.Fatalf("ParseFlags error: %v", err)
	}
	if err := guestsSubSetCmd.RunE(guestsSubSetCmd, nil); err != nil {
		t.Fatalf("run guests sub set --listen failed: %v", err)
	}

	staged, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load staged: %v", err)
	}
	if staged.GuestSubBind != "127.0.0.1" {
		t.Errorf("staged.GuestSubBind = %q, want 127.0.0.1", staged.GuestSubBind)
	}

	// 2. Set -l 10.0.0.1
	guestsSubSetCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	if err := guestsSubSetCmd.ParseFlags([]string{"-l", "10.0.0.1"}); err != nil {
		t.Fatalf("ParseFlags error: %v", err)
	}
	if err := guestsSubSetCmd.RunE(guestsSubSetCmd, nil); err != nil {
		t.Fatalf("run guests sub set -l failed: %v", err)
	}

	staged, err = config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load staged: %v", err)
	}
	if staged.GuestSubBind != "10.0.0.1" {
		t.Errorf("staged.GuestSubBind = %q, want 10.0.0.1", staged.GuestSubBind)
	}

	// 3. Set --bind 192.168.1.1 (compatibility)
	guestsSubSetCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	if err := guestsSubSetCmd.ParseFlags([]string{"--bind", "192.168.1.1"}); err != nil {
		t.Fatalf("ParseFlags error: %v", err)
	}
	if err := guestsSubSetCmd.RunE(guestsSubSetCmd, nil); err != nil {
		t.Fatalf("run guests sub set --bind failed: %v", err)
	}

	staged, err = config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load staged: %v", err)
	}
	if staged.GuestSubBind != "192.168.1.1" {
		t.Errorf("staged.GuestSubBind = %q, want 192.168.1.1", staged.GuestSubBind)
	}
}

