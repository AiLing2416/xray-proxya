package quota

import (
	"os"
	"path/filepath"
	"testing"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/notify"
)

func TestUpdateGuestsTracksUsageWithoutRestart(t *testing.T) {
	monitor := NewMonitor()
	cfg := &config.UserConfig{
		Guests: []config.GuestConfig{
			{Alias: "Alice", Enabled: true, QuotaGB: 10, ResetDay: 1, LastResetYM: "2026-05"},
		},
	}

	stats := map[string]int64{
		"user>>>guest-alice>>>traffic>>>uplink":   100,
		"user>>>guest-alice>>>traffic>>>downlink": 200,
	}

	result := monitor.UpdateGuests(cfg, stats, time.Date(2026, 5, 9, 8, 0, 0, 0, time.UTC))
	if !result.Changed {
		t.Fatalf("expected config change")
	}
	if result.RestartNeeded {
		t.Fatalf("usage sync should not require restart")
	}
	if cfg.Guests[0].UsedBytes != 300 {
		t.Fatalf("UsedBytes = %d, want 300", cfg.Guests[0].UsedBytes)
	}
	if cfg.Guests[0].DisabledReason != config.GuestDisabledNone {
		t.Fatalf("DisabledReason = %q, want empty", cfg.Guests[0].DisabledReason)
	}
}

func TestUpdateGuestsDisablesExceededQuota(t *testing.T) {
	monitor := NewMonitor()
	cfg := &config.UserConfig{
		Guests: []config.GuestConfig{
			{Alias: "alice", Enabled: true, QuotaGB: 1, ResetDay: 1, LastResetYM: "2026-05"},
		},
	}

	stats := map[string]int64{
		"user>>>guest-alice>>>traffic>>>uplink":   700 * 1024 * 1024,
		"user>>>guest-alice>>>traffic>>>downlink": 400 * 1024 * 1024,
	}

	result := monitor.UpdateGuests(cfg, stats, time.Date(2026, 5, 9, 8, 0, 0, 0, time.UTC))
	if !result.RestartNeeded {
		t.Fatalf("quota exhaustion should require restart")
	}
	if cfg.Guests[0].Enabled {
		t.Fatalf("guest should be disabled after quota exhaustion")
	}
	if cfg.Guests[0].DisabledReason != config.GuestDisabledQuotaReached {
		t.Fatalf("DisabledReason = %q, want %q", cfg.Guests[0].DisabledReason, config.GuestDisabledQuotaReached)
	}
}

func TestUpdateGuestsMonthlyResetReenablesGuest(t *testing.T) {
	monitor := NewMonitor()
	cfg := &config.UserConfig{
		Guests: []config.GuestConfig{
			{Alias: "alice", Enabled: false, QuotaGB: 5, UsedBytes: 1234, ResetDay: 5, LastResetYM: "2026-04"},
		},
	}

	result := monitor.UpdateGuests(cfg, map[string]int64{}, time.Date(2026, 5, 9, 8, 0, 0, 0, time.UTC))
	if !result.RestartNeeded {
		t.Fatalf("monthly reset should require restart when re-enabling guest")
	}
	if !cfg.Guests[0].Enabled {
		t.Fatalf("guest should be re-enabled after monthly reset")
	}
	if cfg.Guests[0].UsedBytes != 0 {
		t.Fatalf("UsedBytes = %d, want 0", cfg.Guests[0].UsedBytes)
	}
	if cfg.Guests[0].LastResetYM != "2026-05" {
		t.Fatalf("LastResetYM = %q, want 2026-05", cfg.Guests[0].LastResetYM)
	}
	if cfg.Guests[0].DisabledReason != config.GuestDisabledNone {
		t.Fatalf("DisabledReason = %q, want empty", cfg.Guests[0].DisabledReason)
	}
}

func TestUpdateGuestsDoesNotResetBeforeResetDay(t *testing.T) {
	monitor := NewMonitor()
	cfg := &config.UserConfig{
		Guests: []config.GuestConfig{
			{Alias: "alice", Enabled: false, QuotaGB: 5, UsedBytes: 1234, ResetDay: 10, LastResetYM: "2026-04"},
		},
	}

	result := monitor.UpdateGuests(cfg, map[string]int64{}, time.Date(2026, 5, 9, 8, 0, 0, 0, time.UTC))
	if result.RestartNeeded {
		t.Fatalf("reset should not trigger before reset day")
	}
	if cfg.Guests[0].Enabled {
		t.Fatalf("guest should remain disabled before reset day")
	}
	if cfg.Guests[0].LastResetYM != "2026-04" {
		t.Fatalf("LastResetYM changed unexpectedly: %q", cfg.Guests[0].LastResetYM)
	}
}

func TestUpdateGuestsAccumulatesDeltasAcrossPolls(t *testing.T) {
	monitor := NewMonitor()
	cfg := &config.UserConfig{
		Guests: []config.GuestConfig{
			{Alias: "alice", Enabled: true, QuotaGB: 10, ResetDay: 1, LastResetYM: "2026-05"},
		},
	}

	first := map[string]int64{
		"user>>>guest-alice>>>traffic>>>uplink": 100,
	}
	second := map[string]int64{
		"user>>>guest-alice>>>traffic>>>uplink": 180,
	}

	monitor.UpdateGuests(cfg, first, time.Date(2026, 5, 9, 8, 0, 0, 0, time.UTC))
	monitor.UpdateGuests(cfg, second, time.Date(2026, 5, 9, 8, 1, 0, 0, time.UTC))

	if cfg.Guests[0].UsedBytes != 180 {
		t.Fatalf("UsedBytes = %d, want 180", cfg.Guests[0].UsedBytes)
	}
}

func TestMonitorSaveAndLoadState(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("HOME")
	if err := os.Setenv("HOME", tmp); err != nil {
		t.Fatalf("Setenv HOME: %v", err)
	}
	defer os.Setenv("HOME", oldHome)

	monitor := NewMonitor()
	monitor.lastObserved["alice"] = 123
	if err := monitor.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := LoadMonitor()
	if err != nil {
		t.Fatalf("LoadMonitor() error = %v", err)
	}
	if loaded.lastObserved["alice"] != 123 {
		t.Fatalf("loaded lastObserved = %d, want 123", loaded.lastObserved["alice"])
	}

	if _, err := os.Stat(filepath.Join(config.GetConfigDir(), "quota-monitor.json")); err != nil {
		t.Fatalf("quota-monitor.json not found: %v", err)
	}
}

func TestUpdateGuestsTriggersWebhook(t *testing.T) {
	var sentPayloads []notify.GuestWebhookPayload
	oldSender := notify.WebhookSender
	notify.WebhookSender = func(url string, payload notify.GuestWebhookPayload) error {
		sentPayloads = append(sentPayloads, payload)
		return nil
	}
	defer func() {
		notify.WebhookSender = oldSender
	}()

	cfg := &config.UserConfig{
		Guests: []config.GuestConfig{{
			Alias:         "amy",
			Enabled:       true,
			QuotaGB:       10,
			UsedBytes:     0,
			ResetDay:      15,
			NotifyWebhook: "https://example.com/webhook",
		}},
	}

	monitor := NewMonitor()
	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)

	// Step 1: Reach 80% (8GB = 8589934592 bytes) -> triggers quota.warning
	stats80 := map[string]int64{
		"user>>>guest-amy>>>traffic>>>downlink": 8 * 1024 * 1024 * 1024,
	}
	res := monitor.UpdateGuests(cfg, stats80, now)
	if !res.Changed {
		t.Fatalf("expected Changed = true")
	}
	// Give async goroutine a brief moment to append
	time.Sleep(20 * time.Millisecond)

	if len(sentPayloads) != 1 {
		t.Fatalf("expected 1 webhook sent, got %d", len(sentPayloads))
	}
	if sentPayloads[0].Event != "quota.warning" {
		t.Fatalf("expected event quota.warning, got %q", sentPayloads[0].Event)
	}
	if cfg.Guests[0].AlertedYM != "2026-05-warning" {
		t.Fatalf("expected AlertedYM = '2026-05-warning', got %q", cfg.Guests[0].AlertedYM)
	}

	// Step 2: Reach 100% (10GB) -> triggers quota.exceeded
	stats100 := map[string]int64{
		"user>>>guest-amy>>>traffic>>>downlink": 10 * 1024 * 1024 * 1024,
	}
	res2 := monitor.UpdateGuests(cfg, stats100, now)
	if !res2.Changed || !res2.RestartNeeded {
		t.Fatalf("expected Changed and RestartNeeded on quota exceeded")
	}
	time.Sleep(20 * time.Millisecond)

	if len(sentPayloads) != 2 {
		t.Fatalf("expected 2 webhooks sent, got %d", len(sentPayloads))
	}
	if sentPayloads[1].Event != "quota.exceeded" {
		t.Fatalf("expected event quota.exceeded, got %q", sentPayloads[1].Event)
	}
	if cfg.Guests[0].AlertedYM != "2026-05-exceeded" {
		t.Fatalf("expected AlertedYM = '2026-05-exceeded', got %q", cfg.Guests[0].AlertedYM)
	}

	// Step 3: Roll into reset day (Day 15) -> triggers quota.reset
	resetTime := time.Date(2026, 5, 15, 8, 0, 0, 0, time.UTC)
	res3 := monitor.UpdateGuests(cfg, stats100, resetTime)
	if !res3.Changed {
		t.Fatalf("expected Changed on reset")
	}
	time.Sleep(20 * time.Millisecond)

	if len(sentPayloads) != 3 {
		t.Fatalf("expected 3 webhooks sent, got %d", len(sentPayloads))
	}
	if sentPayloads[2].Event != "quota.reset" {
		t.Fatalf("expected event quota.reset, got %q", sentPayloads[2].Event)
	}
	if cfg.Guests[0].AlertedYM != "" {
		t.Fatalf("expected AlertedYM cleared to empty on reset, got %q", cfg.Guests[0].AlertedYM)
	}
	if !cfg.Guests[0].Enabled {
		t.Fatalf("expected guest re-enabled on reset")
	}
}

func TestUpdateGuestsNotifyTrigger(t *testing.T) {
	var sentPayloads []notify.GuestWebhookPayload
	oldSender := notify.WebhookSender
	notify.WebhookSender = func(url string, payload notify.GuestWebhookPayload) error {
		sentPayloads = append(sentPayloads, payload)
		return nil
	}
	defer func() {
		notify.WebhookSender = oldSender
	}()

	cfg := &config.UserConfig{
		Guests: []config.GuestConfig{{
			Alias:         "bob",
			Enabled:       true,
			LimitBytes:    50 * config.GigaByte, // 50 GB
			ResetDay:      15,
			NotifyWebhook: "https://example.com/webhook",
			NotifyTrigger: []string{"80p", "45p", "40g", "5g"},
		}},
	}

	monitor := NewMonitor()
	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)

	// Step 1: Used 12.5GB -> Remaining 37.5GB (75% < 80%, also 37.5GB < 40GB)
	// Fires "80p" and "40g"
	stats := map[string]int64{
		"user>>>guest-bob>>>traffic>>>downlink": int64(12.5 * float64(config.GigaByte)),
	}
	res := monitor.UpdateGuests(cfg, stats, now)
	if !res.Changed {
		t.Fatalf("expected Changed = true")
	}
	time.Sleep(30 * time.Millisecond)

	if len(sentPayloads) != 2 {
		t.Fatalf("expected 2 trigger webhooks, got %d", len(sentPayloads))
	}
	if len(cfg.Guests[0].AlertedTriggers) != 2 {
		t.Fatalf("expected 2 alerted triggers, got %v", cfg.Guests[0].AlertedTriggers)
	}

	// Step 2: Same usage -> no new triggers
	_ = monitor.UpdateGuests(cfg, stats, now)
	time.Sleep(20 * time.Millisecond)
	if len(sentPayloads) != 2 {
		t.Fatalf("expected still 2 webhooks, got %d", len(sentPayloads))
	}

	// Step 3: Used 46GB -> Remaining 4GB (8% < 45%, also 4GB < 5GB)
	// Fires "45p" and "5g"
	stats2 := map[string]int64{
		"user>>>guest-bob>>>traffic>>>downlink": int64(46.0 * float64(config.GigaByte)),
	}
	_ = monitor.UpdateGuests(cfg, stats2, now)
	time.Sleep(30 * time.Millisecond)

	if len(sentPayloads) != 4 {
		t.Fatalf("expected 4 trigger webhooks total, got %d", len(sentPayloads))
	}
	if len(cfg.Guests[0].AlertedTriggers) != 4 {
		t.Fatalf("expected 4 alerted triggers, got %v", cfg.Guests[0].AlertedTriggers)
	}

	// Step 4: Reset day -> triggers cleared
	resetTime := time.Date(2026, 5, 15, 8, 0, 0, 0, time.UTC)
	_ = monitor.UpdateGuests(cfg, stats2, resetTime)
	time.Sleep(20 * time.Millisecond)

	if len(cfg.Guests[0].AlertedTriggers) != 0 {
		t.Fatalf("expected AlertedTriggers cleared on reset, got %v", cfg.Guests[0].AlertedTriggers)
	}
}


