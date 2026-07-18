package main

import (
	"net/http"
	"net/http/httptest"
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

func TestParseSize(t *testing.T) {
	tests := []struct {
		input   string
		want    int64
		wantErr bool
	}{
		{"100", 100, false},
		{"100B", 100, false},
		{"100b", 100, false},
		{"10K", 10_000, false},
		{"10KB", 10_000, false},
		{"10kb", 10_000, false},
		{"10Ki", 10_240, false},
		{"10KiB", 10_240, false},
		{"1.5M", 1_500_000, false},
		{"1.5MB", 1_500_000, false},
		{"1.5mb", 1_500_000, false},
		{"2Mi", 2_097_152, false},
		{"2MiB", 2_097_152, false},
		{"1G", 1_000_000_000, false},
		{"1GB", 1_000_000_000, false},
		{"1GiB", 1_073_741_824, false},
		{"", 0, true},
		{"   ", 0, true},
		{"MB", 0, true},
		{"-10M", 0, true},
		{"abc", 0, true},
		{"10Mabc", 0, true},
	}

	for _, tt := range tests {
		got, err := parseSize(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseSize(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("parseSize(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestRunSpeedPassTruncation(t *testing.T) {
	// Start a local test server that serves a large stream of dummy data
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)

		// Write 1MB of dummy data
		dummy := make([]byte, 1024)
		for i := 0; i < 1024; i++ {
			if _, err := w.Write(dummy); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	client := server.Client()
	var totalBytes int64
	var samples []float64
	maxBytes := int64(50 * 1024) // 50KB

	err := runSpeedPass(client, server.URL, time.Time{}, &totalBytes, &samples, maxBytes)
	if err != nil {
		t.Fatalf("runSpeedPass failed: %v", err)
	}

	if totalBytes != maxBytes {
		t.Errorf("totalBytes = %d, want %d", totalBytes, maxBytes)
	}
}


