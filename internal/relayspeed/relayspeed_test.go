package relayspeed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

func TestApplyBrowserHeaders(t *testing.T) {
	providers := []struct {
		provider     Provider
		wantOrigin   string
		wantReferer  string
	}{
		{
			provider:    &CloudflareProvider{},
			wantOrigin:  "https://speed.cloudflare.com",
			wantReferer: "https://speed.cloudflare.com/",
		},
		{
			provider:    &FastProvider{},
			wantOrigin:  "https://fast.com",
			wantReferer: "https://fast.com/",
		},
		{
			provider:    &OoklaProvider{},
			wantOrigin:  "https://www.speedtest.net",
			wantReferer: "https://www.speedtest.net/",
		},
		{
			provider:    &CustomProvider{},
			wantOrigin:  "",
			wantReferer: "",
		},
	}

	for _, tt := range providers {
		req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
		if err != nil {
			t.Fatalf("NewRequest error: %v", err)
		}

		applyBrowserHeaders(req, tt.provider)

		if req.Header.Get("User-Agent") != defaultUserAgent {
			t.Errorf("[%s] UA = %q, want %q", tt.provider.ID(), req.Header.Get("User-Agent"), defaultUserAgent)
		}
		if req.Header.Get("Sec-Ch-Ua") != secChUa {
			t.Errorf("[%s] Sec-Ch-Ua = %q, want %q", tt.provider.ID(), req.Header.Get("Sec-Ch-Ua"), secChUa)
		}
		if req.Header.Get("Sec-Ch-Ua-Mobile") != secChUaMobile {
			t.Errorf("[%s] Sec-Ch-Ua-Mobile = %q, want %q", tt.provider.ID(), req.Header.Get("Sec-Ch-Ua-Mobile"), secChUaMobile)
		}
		if req.Header.Get("Sec-Ch-Ua-Platform") != secChUaPlatform {
			t.Errorf("[%s] Sec-Ch-Ua-Platform = %q, want %q", tt.provider.ID(), req.Header.Get("Sec-Ch-Ua-Platform"), secChUaPlatform)
		}
		if req.Header.Get("Sec-Fetch-Dest") != "empty" {
			t.Errorf("[%s] Sec-Fetch-Dest = %q, want empty", tt.provider.ID(), req.Header.Get("Sec-Fetch-Dest"))
		}
		if req.Header.Get("Sec-Fetch-Mode") != "cors" {
			t.Errorf("[%s] Sec-Fetch-Mode = %q, want cors", tt.provider.ID(), req.Header.Get("Sec-Fetch-Mode"))
		}
		if req.Header.Get("Sec-Fetch-Site") != "same-origin" {
			t.Errorf("[%s] Sec-Fetch-Site = %q, want same-origin", tt.provider.ID(), req.Header.Get("Sec-Fetch-Site"))
		}
		if req.Header.Get("Accept") != "*/*" {
			t.Errorf("[%s] Accept = %q, want */*", tt.provider.ID(), req.Header.Get("Accept"))
		}
		if req.Header.Get("Accept-Language") != "en-US,en;q=0.9" {
			t.Errorf("[%s] Accept-Language = %q, want en-US,en;q=0.9", tt.provider.ID(), req.Header.Get("Accept-Language"))
		}
		if req.Header.Get("Origin") != tt.wantOrigin {
			t.Errorf("[%s] Origin = %q, want %q", tt.provider.ID(), req.Header.Get("Origin"), tt.wantOrigin)
		}
		if req.Header.Get("Referer") != tt.wantReferer {
			t.Errorf("[%s] Referer = %q, want %q", tt.provider.ID(), req.Header.Get("Referer"), tt.wantReferer)
		}
	}
}

func TestMultiStreamDownload(t *testing.T) {
	// Mock server that returns continuous binary stream
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		buf := make([]byte, 32*1024)
		for {
			select {
			case <-r.Context().Done():
				return
			default:
			}
			_, err := w.Write(buf)
			if err != nil {
				return
			}
		}
	}))
	defer server.Close()

	customProvider, err := NewCustomProvider(server.URL, "")
	if err != nil {
		t.Fatalf("failed to create custom provider: %v", err)
	}

	sizeLimit := int64(4 * 1024 * 1024) // 4MB
	threads := 4
	var bytesTransferred int64
	var samples []float64
	var progressCalls int64

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	progressCb := func(u ProgressUpdate) {
		atomic.AddInt64(&progressCalls, 1)
		if u.Phase != "download" {
			t.Errorf("unexpected phase in progress: %s", u.Phase)
		}
		if u.Direction != DirectionDownload {
			t.Errorf("unexpected direction: %s", u.Direction)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	err = executeDownload(ctx, server.Client(), customProvider, sizeLimit, 0, true, deadline, threads, &bytesTransferred, &samples, "test-multi", progressCb)
	if err != nil {
		t.Fatalf("executeDownload failed: %v", err)
	}

	if bytesTransferred != sizeLimit {
		t.Errorf("bytesTransferred = %d, want exact %d", bytesTransferred, sizeLimit)
	}

	if len(samples) == 0 {
		t.Errorf("expected samples to be populated, got 0")
	}
	for i, s := range samples {
		if s <= 0 {
			t.Errorf("sample[%d] bps = %f, want > 0", i, s)
		}
	}
}

func TestMultiStreamDownloadTimeout(t *testing.T) {
	// Mock server that hangs until client cancels
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	customProvider, err := NewCustomProvider(server.URL, "")
	if err != nil {
		t.Fatalf("failed to create custom provider: %v", err)
	}

	sizeLimit := int64(10 * 1024 * 1024)
	threads := 4
	var bytesTransferred int64
	var samples []float64

	// Short timeout of 150ms
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	deadline := time.Now().Add(150 * time.Millisecond)
	err = executeDownload(ctx, server.Client(), customProvider, sizeLimit, 0, true, deadline, threads, &bytesTransferred, &samples, "test-timeout", nil)
	// Timeout should terminate gracefully without deadlock
	if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSingleStreamDownload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		buf := make([]byte, 32*1024)
		for {
			select {
			case <-r.Context().Done():
				return
			default:
			}
			_, err := w.Write(buf)
			if err != nil {
				return
			}
		}
	}))
	defer server.Close()

	customProvider, err := NewCustomProvider(server.URL, "")
	if err != nil {
		t.Fatalf("failed to create custom provider: %v", err)
	}

	sizeLimit := int64(2 * 1024 * 1024) // 2MB
	threads := 1
	var bytesTransferred int64
	var samples []float64

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	deadline := time.Now().Add(5 * time.Second)
	err = executeDownload(ctx, server.Client(), customProvider, sizeLimit, 0, true, deadline, threads, &bytesTransferred, &samples, "test-single", nil)
	if err != nil {
		t.Fatalf("executeDownload single failed: %v", err)
	}

	if bytesTransferred != sizeLimit {
		t.Errorf("bytesTransferred = %d, want exact %d", bytesTransferred, sizeLimit)
	}
	if len(samples) == 0 {
		t.Errorf("expected samples to be populated, got 0")
	}
}

func TestCalculateAdaptiveSize(t *testing.T) {
	tests := []struct {
		name       string
		probeBps   float64
		targetSec  float64
		wantBytes  int64
	}{
		{
			name:      "low speed 1Mbps clamped to min 2MB",
			probeBps:  1_000_000, // 1 Mbps -> ~312.5 KB
			targetSec: 2.5,
			wantBytes: 2 * 1024 * 1024,
		},
		{
			name:      "medium speed 50Mbps",
			probeBps:  50_000_000, // 50 Mbps * 2.5s / 8 = 15,625,000 bytes (~15.6MB)
			targetSec: 2.5,
			wantBytes: 15_625_000,
		},
		{
			name:      "high speed 1Gbps clamped to max 100MB",
			probeBps:  1_000_000_000, // 1 Gbps * 2.5s / 8 = 312,500,000 bytes -> 100MB
			targetSec: 2.5,
			wantBytes: 100 * 1024 * 1024,
		},
		{
			name:      "custom duration 5s",
			probeBps:  20_000_000, // 20 Mbps * 5s / 8 = 12,500,000 bytes
			targetSec: 5.0,
			wantBytes: 12_500_000,
		},
		{
			name:      "default duration fallback when zero",
			probeBps:  50_000_000,
			targetSec: 0,
			wantBytes: 15_625_000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateAdaptiveSize(tt.probeBps, tt.targetSec)
			if got != tt.wantBytes {
				t.Errorf("CalculateAdaptiveSize(%f, %f) = %d, want %d", tt.probeBps, tt.targetSec, got, tt.wantBytes)
			}
		})
	}
}

func TestProbeBandwidth(t *testing.T) {
	// 1. Mock server that returns 1MB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		data := make([]byte, 64*1024)
		for i := 0; i < 16; i++ { // 16 * 64KB = 1MB
			_, _ = w.Write(data)
		}
	}))
	defer server.Close()

	customProvider, err := NewCustomProvider(server.URL, "")
	if err != nil {
		t.Fatalf("failed to create custom provider: %v", err)
	}

	bps, rtt, err := ProbeBandwidth(context.Background(), server.Client(), customProvider)
	if err != nil {
		t.Fatalf("ProbeBandwidth failed: %v", err)
	}
	if bps <= 0 {
		t.Errorf("ProbeBandwidth bps = %f, want > 0", bps)
	}
	if rtt <= 0 {
		t.Errorf("ProbeBandwidth rtt = %v, want > 0", rtt)
	}
}

func TestParseTime(t *testing.T) {
	tests := []struct {
		input   string
		wantSec int
		wantErr bool
	}{
		{"10", 10, false},
		{"0", 0, false},
		{"10s", 10, false},
		{"15sec", 15, false},
		{"1m", 60, false},
		{"1.5m", 90, false},
		{"60s", 60, false},
		{"2min", 120, false},
		{"2minutes", 120, false},
		{"1h", 3600, false},
		{"0.5m", 30, false},
		{"", 0, true},
		{"-5s", 0, true},
		{"10x", 0, true},
		{"abc", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseTime(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseTime(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.wantSec {
				t.Errorf("ParseTime(%q) = %d, want %d", tt.input, got, tt.wantSec)
			}
		})
	}
}

func TestDurationScheduling(t *testing.T) {
	// Mock server that returns chunks continuously
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		buf := make([]byte, 64*1024)
		for i := 0; i < 16; i++ {
			select {
			case <-r.Context().Done():
				return
			default:
			}
			_, _ = w.Write(buf)
		}
	}))
	defer server.Close()

	customProvider, err := NewCustomProvider(server.URL, "")
	if err != nil {
		t.Fatalf("failed to create custom provider: %v", err)
	}

	// 200ms continuous duration test with fixedSize = false
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	durationSec := 1 // test with 200ms deadline
	deadline := time.Now().Add(200 * time.Millisecond)
	var bytesTransferred int64
	var samples []float64

	start := time.Now()
	err = executeDownload(ctx, server.Client(), customProvider, 1024*1024, durationSec, false, deadline, 1, &bytesTransferred, &samples, "test-dur", nil)
	elapsed := time.Since(start)

	if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		t.Fatalf("unexpected error: %v", err)
	}

	// In continuous mode, it should pull across chunks until deadline (~200ms)
	if elapsed < 180*time.Millisecond {
		t.Errorf("test terminated too early: elapsed = %v, expected >= 180ms", elapsed)
	}
	if bytesTransferred <= 0 {
		t.Errorf("bytesTransferred = %d, want > 0", bytesTransferred)
	}
}
