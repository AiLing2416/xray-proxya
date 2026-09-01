package relayspeed

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

type CloudflareProvider struct{}

func (c *CloudflareProvider) ID() string {
	return "cloudflare"
}

func (c *CloudflareProvider) DisplayName() string {
	return "Cloudflare"
}

func (c *CloudflareProvider) SupportsUpload() bool {
	return true
}

func (c *CloudflareProvider) GetDownloadRequest(ctx context.Context, _ *http.Client, sizeBytes int64) (*http.Request, error) {
	if sizeBytes <= 0 {
		sizeBytes = 25 * 1024 * 1024 // 25MB default
	}
	url := fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", sizeBytes)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	return req, nil
}

func (c *CloudflareProvider) GetUploadRequest(ctx context.Context, _ *http.Client, body io.Reader, sizeBytes int64) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://speed.cloudflare.com/__up", body)
	if err != nil {
		return nil, err
	}
	req.ContentLength = sizeBytes
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	return req, nil
}

func (c *CloudflareProvider) GetPingRequest(ctx context.Context, _ *http.Client) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://speed.cloudflare.com/__down?bytes=1", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	return req, nil
}
