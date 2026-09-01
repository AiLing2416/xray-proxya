package relayspeed

import "time"

type Direction string

const (
	DirectionDownload Direction = "download"
	DirectionUpload   Direction = "upload"
	DirectionBoth     Direction = "both"
)

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
}

type SpeedResult struct {
	Alias           string        `json:"alias"`
	Provider        string        `json:"provider"`
	Download        *SpeedMetrics `json:"download,omitempty"`
	Upload          *SpeedMetrics `json:"upload,omitempty"`
	TotalDurationMs int64         `json:"total_duration_ms"`
	Error           string        `json:"error,omitempty"`
}

type Options struct {
	Provider         string
	Direction        Direction
	SizeBytes        int64
	DurationSeconds  int
	CustomDownloadURL string
	CustomUploadURL   string
}

type ProgressUpdate struct {
	Alias       string
	Phase       string // "idle_ping", "download", "upload", "done", "error"
	Direction   Direction
	BytesDone   int64
	TotalBytes  int64
	CurrentBps  float64
	Elapsed     time.Duration
}

type ProgressCallback func(update ProgressUpdate)
