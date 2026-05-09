package quota

import (
	"testing"
	"time"
	"xray-proxya/internal/config"
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
