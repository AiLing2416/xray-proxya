package main

import "testing"

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
