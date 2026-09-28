package relayspeed

import (
	"context"
	"encoding/json"
	"io"
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
	if !strings.Contains(out, "Latency   : Idle: 42ms | Load: 58ms (+16ms) | Loss: 0.0%") {
		t.Fatalf("missing latency line: %s", out)
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

func TestComputeSpeedStats(t *testing.T) {
	// Scenario 1: Contains TCP slow-start ramp up and zeros/glitches
	// [0, 5e6, 15e6, 30e6, 100e6, 105e6, 95e6, 100e6, 100e6, 0]
	// Zeros are stripped: [5e6, 15e6, 30e6, 100e6, 105e6, 95e6, 100e6, 100e6] (len 8)
	// Warm-up trimming removes first 3: [100e6, 105e6, 95e6, 100e6, 100e6] (len 5)
	// Peak: 105e6
	// Avg: 100e6
	// Low 20%: len 5 * 0.2 = 1 element -> 95e6 (no 0, and not the slow-start 5e6!)
	samples := []float64{0, 5e6, 15e6, 30e6, 100e6, 105e6, 95e6, 100e6, 100e6, 0}
	avg, peak, low20 := computeSpeedStats(samples, 50e6)

	if avg != 100e6 {
		t.Errorf("avg = %f, want 100e6", avg)
	}
	if peak != 105e6 {
		t.Errorf("peak = %f, want 105e6", peak)
	}
	if low20 != 95e6 {
		t.Errorf("low20 = %f, want 95e6", low20)
	}

	// Scenario 2: Empty samples falls back to fallback value
	fallback := 42e6
	avgFb, peakFb, low20Fb := computeSpeedStats(nil, fallback)
	if avgFb != fallback || peakFb != fallback || low20Fb != fallback {
		t.Errorf("expected all fallbacks, got avg=%f, peak=%f, low20=%f", avgFb, peakFb, low20Fb)
	}

	// Scenario 3: All zero samples falls back to fallback value
	avgZ, peakZ, low20Z := computeSpeedStats([]float64{0, 0, 0}, fallback)
	if avgZ != fallback || peakZ != fallback || low20Z != fallback {
		t.Errorf("expected all fallbacks on all zeros, got avg=%f, peak=%f, low20=%f", avgZ, peakZ, low20Z)
	}
}

func TestMultiStreamDurationScheduling(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	durationSec := 1
	deadline := time.Now().Add(200 * time.Millisecond)
	threads := 4
	var bytesTransferred int64
	var samples []float64

	start := time.Now()
	err = executeDownload(ctx, server.Client(), customProvider, 1024*1024, durationSec, false, deadline, threads, &bytesTransferred, &samples, "test-multi-dur", nil)
	elapsed := time.Since(start)

	if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		t.Fatalf("unexpected error: %v", err)
	}

	if elapsed < 180*time.Millisecond {
		t.Errorf("test terminated too early: elapsed = %v, expected >= 180ms", elapsed)
	}
	if bytesTransferred <= 0 {
		t.Errorf("bytesTransferred = %d, want > 0", bytesTransferred)
	}
}

func TestRunAdaptiveDownload(t *testing.T) {
	// Mock server that streams data
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

	oldMin := MinSustainDuration
	oldWin := ConvergenceWindow
	MinSustainDuration = 200 * time.Millisecond
	ConvergenceWindow = 100 * time.Millisecond
	defer func() {
		MinSustainDuration = oldMin
		ConvergenceWindow = oldWin
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var events []string
	cb := func(u ProgressUpdate) {
		events = append(events, u.Phase)
	}

	metrics, bestThreads, err := RunAdaptiveDownload(ctx, server.Client(), nil, customProvider, 10*time.Millisecond, "test-adaptive", cb)
	if err != nil {
		t.Fatalf("RunAdaptiveDownload failed: %v", err)
	}
	if metrics == nil {
		t.Fatalf("expected metrics, got nil")
	}
	if metrics.AvgSpeedBps <= 0 {
		t.Errorf("expected AvgSpeedBps > 0, got %f", metrics.AvgSpeedBps)
	}
	if bestThreads < 1 || bestThreads > 8 {
		t.Errorf("bestThreads = %d, expected between 1 and 8", bestThreads)
	}
	if metrics.BytesTransferred > MaxAutoTransferBytes {
		t.Errorf("BytesTransferred = %d, exceeded MaxAutoTransferBytes %d", metrics.BytesTransferred, MaxAutoTransferBytes)
	}
	if len(events) == 0 {
		t.Errorf("expected progress events, got none")
	}
}

func TestConvergenceDetector(t *testing.T) {
	t.Run("stable stream converges after minDuration", func(t *testing.T) {
		detector := NewConvergenceDetector(3500*time.Millisecond, 1500*time.Millisecond, 0.06, 0.05)
		baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

		// Feed stable 100 Mbps samples with tiny +/- 1% jitter every 100ms for 5 seconds
		var convergedAt time.Duration
		for i := 0; i <= 50; i++ {
			ts := baseTime.Add(time.Duration(i*100) * time.Millisecond)
			noise := float64(i%3-1) * 0.01 * 100_000_000.0
			speed := 100_000_000.0 + noise

			conv, cv, stability := detector.AddSample(ts, speed)
			if conv && convergedAt == 0 {
				convergedAt = time.Duration(i*100) * time.Millisecond
				if cv > 0.06 {
					t.Errorf("expected CV <= 0.06 at convergence, got %f", cv)
				}
				if stability < 94.0 {
					t.Errorf("expected stability >= 94%%, got %f", stability)
				}
			}
		}

		if convergedAt == 0 {
			t.Fatalf("expected stable stream to converge, but it never converged")
		}
		if convergedAt < 3500*time.Millisecond {
			t.Errorf("converged too early at %v, expected >= 3500ms", convergedAt)
		}
	})

	t.Run("jittery stream does not converge", func(t *testing.T) {
		detector := NewConvergenceDetector(3500*time.Millisecond, 1500*time.Millisecond, 0.06, 0.05)
		baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

		// High fluctuation between 30 Mbps and 120 Mbps (CV > 40%)
		for i := 0; i <= 50; i++ {
			ts := baseTime.Add(time.Duration(i*100) * time.Millisecond)
			var speed float64
			if i%2 == 0 {
				speed = 30_000_000.0
			} else {
				speed = 120_000_000.0
			}

			conv, cv, _ := detector.AddSample(ts, speed)
			if conv {
				t.Fatalf("high-jitter stream unexpectedly converged at sample %d (CV=%f)", i, cv)
			}
		}
	})

	t.Run("stable stream under minDuration does not converge", func(t *testing.T) {
		detector := NewConvergenceDetector(3500*time.Millisecond, 1500*time.Millisecond, 0.06, 0.05)
		baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

		// Stable stream for only 2 seconds (20 samples)
		for i := 0; i <= 20; i++ {
			ts := baseTime.Add(time.Duration(i*100) * time.Millisecond)
			conv, _, _ := detector.AddSample(ts, 100_000_000.0)
			if conv {
				t.Fatalf("converged at %v, before minDuration (3500ms)", time.Duration(i*100)*time.Millisecond)
			}
		}
	})

	t.Run("consecutive moving average delta convergence", func(t *testing.T) {
		detector := NewConvergenceDetector(2000*time.Millisecond, 1500*time.Millisecond, 0.01, 0.05)
		baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

		// Samples where CV is ~0.03 (above maxCV 0.01), but moving average delta is < 1% (< maxMeanDelta 0.05)
		var didConv bool
		for i := 0; i <= 30; i++ {
			ts := baseTime.Add(time.Duration(i*100) * time.Millisecond)
			speed := 50_000_000.0 + float64(i%2)*1_500_000.0
			conv, _, _ := detector.AddSample(ts, speed)
			if conv {
				didConv = true
				break
			}
		}
		if !didConv {
			t.Errorf("expected convergence via moving average delta condition")
		}
	})
}

func TestSelectInitialConcurrency(t *testing.T) {
	tests := []struct {
		name     string
		probeBps float64
		rtt      time.Duration
		want     int
	}{
		{"gigabit_fast", 150_000_000, 20 * time.Millisecond, 6},
		{"fast_50mbps", 55_000_000, 30 * time.Millisecond, 4},
		{"medium_high_rtt", 35_000_000, 120 * time.Millisecond, 4},
		{"medium_low_rtt", 35_000_000, 30 * time.Millisecond, 4},
		{"standard_15mbps", 15_000_000, 40 * time.Millisecond, 2},
		{"low_speed_low_rtt", 3_000_000, 30 * time.Millisecond, 1},
		{"low_speed_high_rtt", 3_000_000, 80 * time.Millisecond, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SelectInitialConcurrency(tt.probeBps, tt.rtt)
			if got != tt.want {
				t.Errorf("SelectInitialConcurrency(%f, %v) = %d, want %d", tt.probeBps, tt.rtt, got, tt.want)
			}
		})
	}
}

func TestRunAdaptiveBandwidthTestUpload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	customProvider, err := NewCustomProvider(server.URL, server.URL)
	if err != nil {
		t.Fatalf("failed to create custom provider: %v", err)
	}

	oldMin := MinSustainDuration
	oldWin := ConvergenceWindow
	MinSustainDuration = 200 * time.Millisecond
	ConvergenceWindow = 100 * time.Millisecond
	defer func() {
		MinSustainDuration = oldMin
		ConvergenceWindow = oldWin
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var events []string
	cb := func(u ProgressUpdate) {
		events = append(events, u.Phase)
	}

	metrics, bestThreads, err := RunAdaptiveBandwidthTest(ctx, server.Client(), nil, customProvider, DirectionUpload, 1, 10*time.Millisecond, "test-upload-adaptive", cb)
	if err != nil {
		t.Fatalf("RunAdaptiveBandwidthTest upload failed: %v", err)
	}
	if metrics == nil {
		t.Fatalf("expected metrics, got nil")
	}
	if metrics.Direction != DirectionUpload {
		t.Errorf("expected direction %q, got %q", DirectionUpload, metrics.Direction)
	}
	if metrics.AvgSpeedBps <= 0 {
		t.Errorf("expected AvgSpeedBps > 0, got %f", metrics.AvgSpeedBps)
	}
	if bestThreads < 1 || bestThreads > 8 {
		t.Errorf("bestThreads = %d, expected between 1 and 8", bestThreads)
	}
	if metrics.BytesTransferred > MaxAutoTransferBytes {
		t.Errorf("BytesTransferred = %d, exceeded MaxAutoTransferBytes %d", metrics.BytesTransferred, MaxAutoTransferBytes)
	}
	if len(events) == 0 {
		t.Errorf("expected progress events, got none")
	}
}

func TestProgressRenderer_FormatCurrentLine(t *testing.T) {
	r := &ProgressRenderer{
		activeNode: "hk-01",
	}

	// 1. idle_ping
	r.lastUpdate = ProgressUpdate{Phase: "idle_ping", Elapsed: 38200 * time.Microsecond}
	line := r.formatCurrentLine("⠋")
	if !strings.Contains(line, "⠋ [hk-01] Measuring idle latency... 38.2 ms") {
		t.Errorf("unexpected idle_ping line: %s", line)
	}

	// 2. auto_probe
	r.lastUpdate = ProgressUpdate{Phase: "auto_probe", Direction: DirectionDownload}
	line = r.formatCurrentLine("⠋")
	if !strings.Contains(line, "⠋ [hk-01] Probing download baseline...") {
		t.Errorf("unexpected auto_probe line: %s", line)
	}

	// 3. auto_ramp
	r.lastUpdate = ProgressUpdate{Phase: "auto_ramp", StepThreads: 4}
	line = r.formatCurrentLine("⠙")
	if !strings.Contains(line, "⠙ [hk-01] Ramping concurrency to 4 stream(s)...") {
		t.Errorf("unexpected auto_ramp line: %s", line)
	}

	// 4. auto_sustaining
	r.lastUpdate = ProgressUpdate{
		Phase:       "auto_sustaining",
		Direction:   DirectionDownload,
		StepThreads: 4,
		BytesDone:   58200000,
		TotalBytes:  240000000,
		CurrentBps:  142500000,
		StepGain:    96,
	}
	line = r.formatCurrentLine("⠴")
	if !strings.Contains(line, "⠴ [hk-01] Download (4 streams): [████░░░░░░░░░░░░░░]  24%  58.20 MB / 240.00 MB | 142.50 Mbps (stability: 96%)") {
		t.Errorf("unexpected auto_sustaining line: %s", line)
	}

	// 5. download standard (single stream)
	r.lastUpdate = ProgressUpdate{
		Phase:       "download",
		Direction:   DirectionDownload,
		StepThreads: 1,
		BytesDone:   16300000,
		TotalBytes:  25000000,
		CurrentBps:  86400000,
	}
	line = r.formatCurrentLine("⠸")
	if !strings.Contains(line, "⠸ [hk-01] Download: [████████████░░░░░░]  65%  16.30 MB / 25.00 MB | 86.40 Mbps") {
		t.Errorf("unexpected standard download line: %s", line)
	}
	if !strings.Contains(line, "ETA:") {
		t.Errorf("expected ETA in download line: %s", line)
	}

	// 6. upload auto sustaining
	r.lastUpdate = ProgressUpdate{
		Phase:       "auto_sustaining",
		Direction:   DirectionUpload,
		StepThreads: 2,
		BytesDone:   18500000,
		TotalBytes:  240000000,
		CurrentBps:  32100000,
		StepGain:    94,
	}
	line = r.formatCurrentLine("⠸")
	if !strings.Contains(line, "⠸ [hk-01] Upload (2 streams): [█░░░░░░░░░░░░░░░░░]   7%  18.50 MB / 240.00 MB | 32.10 Mbps (stability: 94%)") {
		t.Errorf("unexpected upload line: %s", line)
	}
}

func TestProgressRenderer_NonTTY_Fallback(t *testing.T) {
	var buf strings.Builder
	r := NewProgressRenderer(&buf, false, false)
	defer r.Stop()

	r.StartNode("JP-TK")
	out1 := buf.String()
	if !strings.Contains(out1, "[JP-TK] Starting speed test...\n") {
		t.Errorf("expected non-TTY start line, got: %q", out1)
	}
	if strings.Contains(out1, "\r") || strings.Contains(out1, "\033") {
		t.Errorf("non-TTY output must not contain ANSI control characters: %q", out1)
	}

	// Update must be completely silent in non-TTY mode
	lenBefore := buf.Len()
	r.Update(ProgressUpdate{
		Phase:      "download",
		BytesDone:  1024,
		TotalBytes: 2048,
		CurrentBps: 1000000,
	})
	if buf.Len() != lenBefore {
		t.Errorf("non-TTY mode should be completely silent during updates")
	}

	res := sampleSpeedResult()
	r.CompleteNode(res)
	out2 := buf.String()
	if !strings.Contains(out2, "[JP-TK] Done: ↓ 85.42 Mbps | ↑ 32.15 Mbps | Ping 42ms\n") {
		t.Errorf("expected non-TTY done summary, got: %q", out2)
	}
	if strings.Contains(out2, "\r") || strings.Contains(out2, "\033") {
		t.Errorf("non-TTY complete output must not contain ANSI control characters: %q", out2)
	}
}

func TestProgressRenderer_Disabled(t *testing.T) {
	var buf strings.Builder
	r := NewProgressRenderer(&buf, true, true)
	defer r.Stop()

	r.StartNode("hk-01")
	r.Update(ProgressUpdate{Phase: "download", CurrentBps: 1000000})
	r.CompleteNode(sampleSpeedResult())

	if buf.Len() != 0 {
		t.Errorf("disabled renderer must produce 0 output, got %q", buf.String())
	}
}

func TestFormatBitrateColored(t *testing.T) {
	// Color disabled
	sNoColor := FormatBitrateColored(150_000_000, false)
	if strings.Contains(sNoColor, "\033") {
		t.Errorf("color disabled should not contain escape codes: %s", sNoColor)
	}
	if sNoColor != "150.00 Mbps" {
		t.Errorf("expected 150.00 Mbps, got %s", sNoColor)
	}

	// High speed >100 Mbps
	sHigh := FormatBitrateColored(150_000_000, true)
	if !strings.HasPrefix(sHigh, "\033[1;36m") || !strings.HasSuffix(sHigh, "\033[0m") {
		t.Errorf("expected cyan bold prefix for >100Mbps: %s", sHigh)
	}

	// Normal speed 20~100 Mbps
	sNormal := FormatBitrateColored(50_000_000, true)
	if !strings.HasPrefix(sNormal, "\033[32m") || !strings.HasSuffix(sNormal, "\033[0m") {
		t.Errorf("expected green prefix for 50Mbps: %s", sNormal)
	}

	// Slow speed <20 Mbps
	sSlow := FormatBitrateColored(10_000_000, true)
	if !strings.HasPrefix(sSlow, "\033[33m") || !strings.HasSuffix(sSlow, "\033[0m") {
		t.Errorf("expected yellow prefix for 10Mbps: %s", sSlow)
	}
}

func TestFastProviderTargetsCachingAndChunkLimit(t *testing.T) {
	fp := &FastProvider{
		cachedTargets:  []string{"https://cdn1.netflix.test/up", "https://cdn2.netflix.test/up"},
		targetsUpdated: time.Now(),
	}

	// 1. Check UploadChunkLimitProvider implementation
	limitProv, ok := any(fp).(UploadChunkLimitProvider)
	if !ok {
		t.Fatalf("FastProvider should implement UploadChunkLimitProvider")
	}
	if limitProv.MaxUploadChunkSize() != 4*1024*1024 {
		t.Errorf("MaxUploadChunkSize = %d, want 4MB", limitProv.MaxUploadChunkSize())
	}

	// 2. Check chunk clamp on upload request
	req1, err := fp.GetUploadRequest(context.Background(), http.DefaultClient, strings.NewReader(""), 10*1024*1024)
	if err != nil {
		t.Fatalf("GetUploadRequest error: %v", err)
	}
	if req1.ContentLength != 4*1024*1024 {
		t.Errorf("expected ContentLength 4MB (clamped), got %d", req1.ContentLength)
	}
	if req1.URL.String() != "https://cdn1.netflix.test/up" {
		t.Errorf("expected first target cdn1, got %s", req1.URL.String())
	}

	// 3. Check round-robin across cached targets
	req2, err := fp.GetUploadRequest(context.Background(), http.DefaultClient, strings.NewReader(""), 2*1024*1024)
	if err != nil {
		t.Fatalf("GetUploadRequest 2 error: %v", err)
	}
	if req2.ContentLength != 2*1024*1024 {
		t.Errorf("expected ContentLength 2MB, got %d", req2.ContentLength)
	}
	if req2.URL.String() != "https://cdn2.netflix.test/up" {
		t.Errorf("expected second target cdn2, got %s", req2.URL.String())
	}

	// 4. Wrap around to cdn1
	req3, err := fp.GetDownloadRequest(context.Background(), http.DefaultClient, 1024)
	if err != nil {
		t.Fatalf("GetDownloadRequest error: %v", err)
	}
	if req3.URL.String() != "https://cdn1.netflix.test/up" {
		t.Errorf("expected wrap around to cdn1, got %s", req3.URL.String())
	}
}
