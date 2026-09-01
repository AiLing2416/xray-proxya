package relayspeed

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleSpeedResult() *SpeedResult {
	return &SpeedResult{
		Alias:    "JP-TK",
		Provider: "Cloudflare",
		Download: &SpeedMetrics{
			Direction:           DirectionDownload,
			AvgSpeedBps:         85_420_000,
			PeakSpeedBps:        102_100_000,
			Low20SpeedBps:       71_200_000,
			BytesTransferred:    25_000_000,
			DurationMs:          2341,
			IdleLatencyAvg:      42 * time.Millisecond,
			LoadLatencyAvg:      58 * time.Millisecond,
			LoadLatencyLossRate: 0.0,
		},
		Upload: &SpeedMetrics{
			Direction:           DirectionUpload,
			AvgSpeedBps:         32_150_000,
			PeakSpeedBps:        38_400_000,
			Low20SpeedBps:       28_500_000,
			BytesTransferred:    10_000_000,
			DurationMs:          2488,
			IdleLatencyAvg:      42 * time.Millisecond,
			LoadLatencyAvg:      58 * time.Millisecond,
			LoadLatencyLossRate: 0.0,
		},
		TotalDurationMs: 4829,
	}
}

func TestRenderSingleCard(t *testing.T) {
	res := sampleSpeedResult()
	out := RenderSingleCard(res)

	if !strings.Contains(out, "[JP-TK] (Provider: Cloudflare)") {
		t.Fatalf("missing header: %s", out)
	}
	if !strings.Contains(out, "Download  : 85.42 Mbps (Peak: 102.10 Mbps | Low 20%: 71.20 Mbps)") {
		t.Fatalf("missing download line: %s", out)
	}
	if !strings.Contains(out, "Upload    : 32.15 Mbps (Peak: 38.40 Mbps | Low 20%: 28.50 Mbps)") {
		t.Fatalf("missing upload line: %s", out)
	}
	if !strings.Contains(out, "Data      : ↓ 25.00 MB / ↑ 10.00 MB (Time: 4.8s)") {
		t.Fatalf("missing data line: %s", out)
	}
	if !strings.Contains(out, "Latency   : Idle: 42ms | Under Load: 58ms | Loss: 0.0%") {
		t.Fatalf("missing latency line: %s", out)
	}
	// Verify NO delta (+16ms) in Under Load
	if strings.Contains(out, "(+") {
		t.Fatalf("Under Load should not contain latency delta: %s", out)
	}
}

func TestRenderTable(t *testing.T) {
	r1 := sampleSpeedResult()
	r2 := &SpeedResult{
		Alias:    "DE-LM",
		Provider: "Cloudflare",
		Download: &SpeedMetrics{
			Direction:           DirectionDownload,
			AvgSpeedBps:         120_310_000,
			PeakSpeedBps:        140_000_000,
			Low20SpeedBps:       100_000_000,
			BytesTransferred:    25_000_000,
			DurationMs:          1662,
			IdleLatencyAvg:      160 * time.Millisecond,
			LoadLatencyAvg:      185 * time.Millisecond,
			LoadLatencyLossRate: 0.0,
		},
		Upload: &SpeedMetrics{
			Direction:           DirectionUpload,
			AvgSpeedBps:         45_800_000,
			PeakSpeedBps:        50_000_000,
			Low20SpeedBps:       40_000_000,
			BytesTransferred:    10_000_000,
			DurationMs:          1746,
			IdleLatencyAvg:      160 * time.Millisecond,
			LoadLatencyAvg:      185 * time.Millisecond,
			LoadLatencyLossRate: 0.0,
		},
		TotalDurationMs: 3408,
	}

	out := RenderTable([]*SpeedResult{r1, r2})

	if !strings.Contains(out, "JP-TK") || !strings.Contains(out, "85.42 Mbps") {
		t.Fatalf("missing r1 row: %s", out)
	}
	if !strings.Contains(out, "DE-LM") || !strings.Contains(out, "120.31 Mbps") {
		t.Fatalf("missing r2 row: %s", out)
	}
}

func TestRenderJSON(t *testing.T) {
	res := sampleSpeedResult()
	jsonStr, err := RenderJSON(res)
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &m); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if m["alias"] != "JP-TK" {
		t.Fatalf("alias = %v, want JP-TK", m["alias"])
	}
	if m["provider"] != "Cloudflare" {
		t.Fatalf("provider = %v, want Cloudflare", m["provider"])
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"10mb", 10_000_000},
		{"25MB", 25_000_000},
		{"10mib", 10 * 1024 * 1024},
		{"1gb", 1_000_000_000},
		{"1GiB", 1024 * 1024 * 1024},
		{"500kb", 500_000},
		{"500000", 500000},
	}

	for _, tt := range tests {
		got, err := ParseSize(tt.input)
		if err != nil {
			t.Fatalf("ParseSize(%q) unexpected error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Fatalf("ParseSize(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestProviders(t *testing.T) {
	ctx := context.Background()

	// 1. Cloudflare
	cf, err := GetProvider("cloudflare", "", "")
	if err != nil || cf.ID() != "cloudflare" || !cf.SupportsUpload() {
		t.Fatalf("cloudflare provider error: %v", err)
	}
	req, err := cf.GetDownloadRequest(ctx, nil, 1024)
	if err != nil || !strings.Contains(req.URL.String(), "bytes=1024") {
		t.Fatalf("cloudflare dl req error: %v", err)
	}

	// 2. Fast
	fast, err := GetProvider("fast", "", "")
	if err != nil || fast.ID() != "fast" || !fast.SupportsUpload() {
		t.Fatalf("fast provider error: %v", err)
	}

	// 3. M-Lab
	mlab, err := GetProvider("mlab", "", "")
	if err != nil || mlab.ID() != "mlab" || !mlab.SupportsUpload() {
		t.Fatalf("mlab provider error: %v", err)
	}

	// 4. Ookla
	ookla, err := GetProvider("ookla", "", "")
	if err != nil || ookla.ID() != "ookla" || !ookla.SupportsUpload() {
		t.Fatalf("ookla provider error: %v", err)
	}

	// 5. Custom
	custom, err := GetProvider("custom", "https://example.com/dl.bin", "https://example.com/ul")
	if err != nil || custom.ID() != "custom" || !custom.SupportsUpload() {
		t.Fatalf("custom provider error: %v", err)
	}
}

func TestLatencyProber(t *testing.T) {
	// Verify dnsTCPQuery is 30 bytes total (2 bytes length + 28 bytes payload)
	if len(dnsTCPQuery) != 30 {
		t.Fatalf("len(dnsTCPQuery) = %d, want 30", len(dnsTCPQuery))
	}
	if dnsTCPQuery[0] != 0x00 || dnsTCPQuery[1] != 0x1c {
		t.Fatalf("dnsTCPQuery length header = %x %x, want 0x00 0x1c", dnsTCPQuery[0], dnsTCPQuery[1])
	}
}
