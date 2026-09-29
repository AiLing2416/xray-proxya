package relayspeed

import "time"

type Direction string

const (
	DirectionDownload Direction = "download"
	DirectionUpload   Direction = "upload"
	DirectionBoth     Direction = "both"
)

type SpeedSample struct {
	ElapsedMs int64   `json:"elapsed_ms"`
	BytesDone int64   `json:"bytes_done"`
	Bps       float64 `json:"bps"`
}

type SpeedMetrics struct {
	Direction           Direction     `json:"direction"`
	AvgSpeedBps         float64       `json:"avg_speed_bps"`
	PeakSpeedBps        float64       `json:"peak_speed_bps"`
	Low20SpeedBps       float64       `json:"low20_speed_bps"`
	BytesTransferred    int64         `json:"bytes_transferred"`
	DurationMs          int64         `json:"duration_ms"`
	IdleLatencyAvg      time.Duration `json:"idle_latency_avg_ms"`
	LoadLatencyAvg      time.Duration `json:"load_latency_avg_ms"`
	LoadLatencyWorst5   time.Duration `json:"load_latency_worst5_ms"`
	LoadLatencyLossRate float64       `json:"load_latency_loss_rate"`
	LoadLatencySamples  int           `json:"load_latency_samples"`
	Samples             []SpeedSample `json:"samples,omitempty"`
}

type SpeedResult struct {
	Alias             string        `json:"alias"`
	Provider          string        `json:"provider"`
	Download          *SpeedMetrics `json:"download,omitempty"`
	Upload            *SpeedMetrics `json:"upload,omitempty"`
	TotalDurationMs   int64         `json:"total_duration_ms"`
	Error             string        `json:"error,omitempty"`
	AdaptiveSizeBytes       int64         `json:"adaptive_size_bytes,omitempty"`
	OptimalThreads          int           `json:"optimal_threads,omitempty"`
	UploadAdaptiveSizeBytes int64         `json:"upload_adaptive_size_bytes,omitempty"`
	UploadOptimalThreads    int           `json:"upload_optimal_threads,omitempty"`
	ProbeDurationMs         int64         `json:"probe_duration_ms,omitempty"`
	ProbeSpeedBps           float64       `json:"probe_speed_bps,omitempty"`
}

type Options struct {
	Provider          string
	Direction         Direction
	SizeBytes         int64
	DurationSeconds   int
	Threads           int
	CustomDownloadURL string
	CustomUploadURL   string
	Auto              bool
	FixedSize         bool
}

type ProgressUpdate struct {
	Alias       string
	Phase       string // "idle_ping", "download", "upload", "done", "error", "auto_step"
	Direction   Direction
	BytesDone   int64
	TotalBytes  int64
	CurrentBps  float64
	Elapsed       time.Duration
	TotalDuration time.Duration
	StepThreads   int
	StepGain      float64
	StepMessage   string
}

type ProgressCallback func(update ProgressUpdate)
