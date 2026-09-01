package relayspeed

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// CustomProvider allows testing against arbitrary user-provided URLs.
type CustomProvider struct {
	downloadURL string
	uploadURL   string
}

// NewCustomProvider initializes a custom speed test provider with user URLs.
func NewCustomProvider(downloadURL, uploadURL string) (*CustomProvider, error) {
	downloadURL = strings.TrimSpace(downloadURL)
	uploadURL = strings.TrimSpace(uploadURL)

	if downloadURL != "" {
		if u, err := url.ParseRequestURI(downloadURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("invalid custom download URL: %q", downloadURL)
		}
	}
	if uploadURL != "" {
		if u, err := url.ParseRequestURI(uploadURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("invalid custom upload URL: %q", uploadURL)
		}
	}
	if downloadURL == "" && uploadURL == "" {
		return nil, fmt.Errorf("custom provider requires at least --link, --link-download, or --link-upload")
	}

	return &CustomProvider{
		downloadURL: downloadURL,
		uploadURL:   uploadURL,
	}, nil
}

func (c *CustomProvider) ID() string {
	return "custom"
}

func (c *CustomProvider) DisplayName() string {
	return "Custom Link"
}

func (c *CustomProvider) SupportsUpload() bool {
	return c.uploadURL != ""
}

func (c *CustomProvider) GetDownloadRequest(ctx context.Context, _ *http.Client, sizeBytes int64) (*http.Request, error) {
	if c.downloadURL == "" {
		return nil, fmt.Errorf("custom download URL not specified")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.downloadURL, nil)
	if err != nil {
		return nil, err
	}
	if sizeBytes > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", sizeBytes-1))
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	return req, nil
}

func (c *CustomProvider) GetUploadRequest(ctx context.Context, _ *http.Client, body io.Reader, sizeBytes int64) (*http.Request, error) {
	if c.uploadURL == "" {
		return nil, fmt.Errorf("custom upload URL not specified")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.uploadURL, body)
	if err != nil {
		return nil, err
	}
	req.ContentLength = sizeBytes
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	return req, nil
}

func (c *CustomProvider) GetPingRequest(ctx context.Context, _ *http.Client) (*http.Request, error) {
	target := c.downloadURL
	if target == "" {
		target = c.uploadURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", "bytes=0-0")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	return req, nil
}
