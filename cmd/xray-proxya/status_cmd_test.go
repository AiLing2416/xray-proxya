package main

import (
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func TestSummarizeStatsSeparatesDirectRelayAndGuests(t *testing.T) {
	allStats := map[string]int64{
		"outbound>>>direct>>>traffic>>>uplink":          100,
		"outbound>>>direct>>>traffic>>>downlink":        200,
		"outbound>>>outbound-hk>>>traffic>>>uplink":     300,
		"outbound>>>outbound-hk>>>traffic>>>downlink":   400,
		"user>>>service-user>>>traffic>>>uplink":        500,
		"user>>>relay-hk>>>traffic>>>uplink":            600,
		"user>>>relay-sg>>>traffic>>>downlink":          700,
		"user>>>guest-alice>>>traffic>>>uplink":         800,
		"user>>>guest-bob>>>traffic>>>downlink":         900,
		"user>>>custom-legacy>>>traffic>>>downlink":     1000,
		"inbound>>>vmess-ws>>>traffic>>>uplink":         1100,
		"inbound>>>relay-socks-hk>>>traffic>>>downlink": 1200,
		"inbound>>>api>>>traffic>>>downlink":            9999,
		"outbound>>>blocked>>>traffic>>>downlink":       555,
		"outbound>>>outbound-test>>>traffic>>>downlink": 50,
		"user>>>relay-hk>>>traffic>>>downlink":          40,
	}

	direct, relay, serviceStats, relayStats, guestStats, inboundStats := summarizeStats(allStats)

	if direct != 300 {
		t.Fatalf("direct = %d, want 300", direct)
	}
	if relay != 750 {
		t.Fatalf("relay = %d, want 750", relay)
	}
	if serviceStats["service-user"] != 500 {
		t.Fatalf("service-user = %d, want 500", serviceStats["service-user"])
	}
	if serviceStats["custom-legacy"] != 1000 {
		t.Fatalf("custom-legacy = %d, want 1000", serviceStats["custom-legacy"])
	}
	if relayStats["hk"] != 640 {
		t.Fatalf("relay hk = %d, want 640", relayStats["hk"])
	}
	if relayStats["sg"] != 700 {
		t.Fatalf("relay sg = %d, want 700", relayStats["sg"])
	}
	if guestStats["alice"] != 800 {
		t.Fatalf("guest alice = %d, want 800", guestStats["alice"])
	}
	if guestStats["bob"] != 900 {
		t.Fatalf("guest bob = %d, want 900", guestStats["bob"])
	}
	if inboundStats["vmess-ws"] != 1100 {
		t.Fatalf("inbound vmess-ws = %d, want 1100", inboundStats["vmess-ws"])
	}
	if inboundStats["relay-socks-hk"] != 1200 {
		t.Fatalf("inbound relay-socks-hk = %d, want 1200", inboundStats["relay-socks-hk"])
	}
	if _, ok := inboundStats["api"]; ok {
		t.Fatalf("api inbound should be excluded")
	}
}

func TestPrintGuestStatsMatchesSanitizedKeys(t *testing.T) {
	guests := []config.GuestConfig{
		{Alias: "Alice", Enabled: true, LimitBytes: 10 * 1024 * 1024 * 1024},
		{Alias: "user_test", Enabled: true, LimitBytes: -1},
	}
	// Xray gRPC stats will have sanitized keys (lowercase, dashes for underscores)
	guestStats := map[string]int64{
		"alice":     500 * 1024 * 1024,
		"user-test": 300 * 1024 * 1024,
	}

	out := captureStdout(t, func() {
		printGuestStatsWithDetails(guestStats, guests)
	})

	// Check that Alice matched 500.00 MiB and has Quota info, and is NOT split into two lines
	if !strings.Contains(out, "Alice") || !strings.Contains(out, "500.00 MiB") || !strings.Contains(out, "[ON]") {
		t.Errorf("expected Alice with 500.00 MiB [ON], got:\n%s", out)
	}
	// Check user_test matched 300.00 MiB
	if !strings.Contains(out, "user_test") || !strings.Contains(out, "300.00 MiB") {
		t.Errorf("expected user_test with 300.00 MiB, got:\n%s", out)
	}

	// Verify there is no duplicate line for "alice" or "user-test" printed as unknown
	lines := strings.Split(strings.TrimSpace(out), "\n")
	itemCount := 0
	for _, l := range lines {
		if strings.Contains(l, " - ") {
			itemCount++
		}
	}
	if itemCount != 2 {
		t.Errorf("expected exactly 2 guest lines, got %d:\n%s", itemCount, out)
	}
}

