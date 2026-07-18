package main

import (
	"testing"
	"time"

	"xray-proxya/internal/config"
)

func TestNormalizeDNSFlagsRejectsResetCombination(t *testing.T) {
	_, _, err := normalizeDNSFlags("UseIPv4", []string{"1.1.1.1"}, true)
	if err == nil {
		t.Fatalf("normalizeDNSFlags() error = nil, want conflict error")
	}
}

func TestNormalizeDNSFlagsResetClearsWithoutError(t *testing.T) {
	strategy, servers, err := normalizeDNSFlags("", nil, true)
	if err != nil {
		t.Fatalf("normalizeDNSFlags() error = %v", err)
	}
	if strategy != "" {
		t.Fatalf("strategy = %q, want empty", strategy)
	}
	if servers != nil {
		t.Fatalf("servers = %v, want nil", servers)
	}
}

func TestNormalizeDNSFlagsNormalizesValues(t *testing.T) {
	strategy, servers, err := normalizeDNSFlags("useipv6", []string{" 1.1.1.1 ", "https://dns.google/dns-query", "1.1.1.1"}, false)
	if err != nil {
		t.Fatalf("normalizeDNSFlags() error = %v", err)
	}
	if strategy != "UseIPv6" {
		t.Fatalf("strategy = %q, want %q", strategy, "UseIPv6")
	}
	wantServers := []string{"1.1.1.1", "https://dns.google/dns-query"}
	if len(servers) != len(wantServers) {
		t.Fatalf("len(servers) = %d, want %d; servers=%v", len(servers), len(wantServers), servers)
	}
	for i := range wantServers {
		if servers[i] != wantServers[i] {
			t.Fatalf("servers[%d] = %q, want %q; servers=%v", i, servers[i], wantServers[i], servers)
		}
	}
}

func TestApplyDNSConfigUpdateResetClearsOverrides(t *testing.T) {
	co := config.CustomOutbound{
		Alias:       "relay-a",
		DNSStrategy: "UseIPv4",
		DNSServers:  []string{"1.1.1.1"},
	}

	applyDNSConfigUpdate(&co, "", nil, true)

	if co.DNSStrategy != "" {
		t.Fatalf("DNSStrategy = %q, want empty", co.DNSStrategy)
	}
	if co.DNSServers != nil {
		t.Fatalf("DNSServers = %v, want nil", co.DNSServers)
	}
}

func TestApplyDNSConfigUpdatePreservesUntouchedFields(t *testing.T) {
	co := config.CustomOutbound{
		Alias:       "relay-a",
		DNSStrategy: "UseIPv4",
		DNSServers:  []string{"1.1.1.1"},
	}

	applyDNSConfigUpdate(&co, "UseIPv6", nil, false)
	if co.DNSStrategy != "UseIPv6" {
		t.Fatalf("DNSStrategy = %q, want %q", co.DNSStrategy, "UseIPv6")
	}
	if len(co.DNSServers) != 1 || co.DNSServers[0] != "1.1.1.1" {
		t.Fatalf("DNSServers = %v, want original value", co.DNSServers)
	}

	applyDNSConfigUpdate(&co, "", []string{"8.8.8.8"}, false)
	if co.DNSStrategy != "UseIPv6" {
		t.Fatalf("DNSStrategy = %q, want %q", co.DNSStrategy, "UseIPv6")
	}
	if len(co.DNSServers) != 1 || co.DNSServers[0] != "8.8.8.8" {
		t.Fatalf("DNSServers = %v, want updated value", co.DNSServers)
	}
}

func TestLowPercentileAverageUsesBottomTwentyPercent(t *testing.T) {
	samples := []float64{100, 200, 300, 400, 500}
	got := lowPercentileAverage(samples, 0.20)
	if got != 100 {
		t.Fatalf("lowPercentileAverage() = %v, want 100", got)
	}
}

func TestWorstPercentileAverageUsesTopFivePercentLatency(t *testing.T) {
	values := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		30 * time.Millisecond,
		40 * time.Millisecond,
		250 * time.Millisecond,
	}
	got := worstPercentileAverage(values, 0.05)
	if got != 250*time.Millisecond {
		t.Fatalf("worstPercentileAverage() = %v, want 250ms", got)
	}
}

func TestFormatBitrateUsesMegabits(t *testing.T) {
	got := formatBitrate(125000)
	if got != "1.00 Mb/s" {
		t.Fatalf("formatBitrate() = %q, want %q", got, "1.00 Mb/s")
	}
}

func TestFormatDecimalBytesUsesReadableUnits(t *testing.T) {
	got := formatDecimalBytes(2_000_000)
	if got != "2.00 MB" {
		t.Fatalf("formatDecimalBytes() = %q, want %q", got, "2.00 MB")
	}
}

func TestProbeDNSViaTCPQueryFormat(t *testing.T) {
	// Verify the DNS query payload is well-formed
	query := buildDNSProbeQuery()
	if len(query) < 12 {
		t.Fatalf("DNS query too short: %d bytes", len(query))
	}
	// Check QDCOUNT = 1
	qdcount := int(query[4])<<8 | int(query[5])
	if qdcount != 1 {
		t.Fatalf("QDCOUNT = %d, want 1", qdcount)
	}
}
