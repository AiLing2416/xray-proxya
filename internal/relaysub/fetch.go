package relaysub

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	// DefaultUserAgent uses v2rayN for broad airport compatibility.
	DefaultUserAgent = "v2rayN/6.23"
	// MaxSubscriptionBodyBytes limits subscription payload to 5MB to prevent memory exhaustion.
	MaxSubscriptionBodyBytes = 5 * 1024 * 1024
	// DefaultFetchTimeout is the HTTP request timeout for subscription fetching.
	DefaultFetchTimeout = 20 * time.Second
)

// FetchSubscription downloads the raw subscription payload from a given HTTP/HTTPS URL.
func FetchSubscription(ctx context.Context, subURL string) ([]byte, error) {
	parsedURL, err := url.Parse(subURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return nil, fmt.Errorf("invalid subscription URL, must be http:// or https://")
	}

	ctx, cancel := context.WithTimeout(ctx, DefaultFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", DefaultUserAgent)
	req.Header.Set("Accept", "*/*")

	client := &http.Client{
		Timeout: DefaultFetchTimeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch subscription: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription server returned HTTP status %d (%s)", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxSubscriptionBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read subscription response: %w", err)
	}

	return body, nil
}
