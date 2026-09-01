package relayspeed

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
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
