package relayspeed

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Provider abstracts different speed test backends.
type Provider interface {
	ID() string
	DisplayName() string
	SupportsUpload() bool
	GetDownloadRequest(ctx context.Context, client *http.Client, sizeBytes int64) (*http.Request, error)
	GetUploadRequest(ctx context.Context, client *http.Client, body io.Reader, sizeBytes int64) (*http.Request, error)
	GetPingRequest(ctx context.Context, client *http.Client) (*http.Request, error)
}

// UploadChunkLimitProvider is an optional interface that providers can implement
// to indicate the maximum allowed payload size for a single upload HTTP request.
// If not implemented or returns <= 0, the engine uses default chunk sizes.
type UploadChunkLimitProvider interface {
	MaxUploadChunkSize() int64
}

// StreamUploadProvider allows providers using streaming protocols (such as WebSocket in M-Lab NDT7)
// to manage the upload loop directly.
type StreamUploadProvider interface {
	ExecuteUploadStream(ctx context.Context, client *http.Client, sizeLimit int64, durationSec int, fixedSize bool, deadline time.Time, threads int, bytesTransferred *int64) error
}

// StreamDownloadProvider allows providers using streaming protocols (such as WebSocket in M-Lab NDT7)
// to manage the download loop directly.
type StreamDownloadProvider interface {
	ExecuteDownloadStream(ctx context.Context, client *http.Client, sizeLimit int64, durationSec int, fixedSize bool, deadline time.Time, threads int, bytesTransferred *int64) error
}

type workerIndexKey struct{}

// WithWorkerIndex attaches a deterministic worker index to context.
func WithWorkerIndex(ctx context.Context, idx int) context.Context {
	return context.WithValue(ctx, workerIndexKey{}, idx)
}

// GetWorkerIndex extracts worker index from context, or -1 if not set.
func GetWorkerIndex(ctx context.Context) int {
	if ctx == nil {
		return -1
	}
	if val, ok := ctx.Value(workerIndexKey{}).(int); ok {
		return val
	}
	return -1
}

// GetProvider returns a provider by its identifier.
func GetProvider(id string, customDL, customUL string) (Provider, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" {
		id = "cloudflare"
	}

	switch id {
	case "cloudflare", "cf":
		return &CloudflareProvider{}, nil
	case "fast", "netflix":
		return &FastProvider{}, nil
	case "mlab", "ndt7":
		return &MLabProvider{}, nil
	case "ookla", "speedtest":
		return &OoklaProvider{}, nil
	case "custom":
		return NewCustomProvider(customDL, customUL)
	default:
		return nil, fmt.Errorf("unknown provider %q (supported: cloudflare, fast, mlab, ookla, custom)", id)
	}
}

// SupportedProviders returns a list of supported provider IDs and descriptions.
func SupportedProviders() []string {
	return []string{"cloudflare", "fast", "mlab", "ookla", "custom"}
}
