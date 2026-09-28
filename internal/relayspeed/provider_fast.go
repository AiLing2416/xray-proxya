package relayspeed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

var (
	fastDefaultToken = "YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm"
	reFastJS         = regexp.MustCompile(`app-[a-f0-9]+\.js`)
	reFastToken      = regexp.MustCompile(`token:"([^"]+)"`)
)

type FastProvider struct {
	mu             sync.Mutex
	cachedToken    string
	tokenUpdated   time.Time
	cachedTargets  []string
	targetsUpdated time.Time
	targetIndex    uint32
}

func (f *FastProvider) ID() string {
	return "fast"
}

func (f *FastProvider) DisplayName() string {
	return "Fast.com (Netflix)"
}

func (f *FastProvider) SupportsUpload() bool {
	return true
}

func (f *FastProvider) MaxUploadChunkSize() int64 {
	return 4 * 1024 * 1024 // 4MB safe cap for Netflix Open Connect CDN
}

func (f *FastProvider) GetDownloadRequest(ctx context.Context, client *http.Client, sizeBytes int64) (*http.Request, error) {
	if client == nil {
		client = http.DefaultClient
	}

	targetURL, err := f.getTargetURL(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("fast.com get speed target: %w", err)
	}

	if sizeBytes <= 0 {
		sizeBytes = 25 * 1024 * 1024 // 25MB default
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", sizeBytes-1))
	applyBrowserHeaders(req, f)
	return req, nil
}

func (f *FastProvider) GetUploadRequest(ctx context.Context, client *http.Client, body io.Reader, sizeBytes int64) (*http.Request, error) {
	if client == nil {
		client = http.DefaultClient
	}

	targetURL, err := f.getTargetURL(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("fast.com get upload target: %w", err)
	}

	if sizeBytes > 4*1024*1024 {
		sizeBytes = 4 * 1024 * 1024
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, body)
	if err != nil {
		return nil, err
	}
	req.ContentLength = sizeBytes
	req.Header.Set("Content-Type", "application/octet-stream")
	applyBrowserHeaders(req, f)
	return req, nil
}

func (f *FastProvider) GetPingRequest(ctx context.Context, _ *http.Client) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://fast.com", nil)
	if err != nil {
		return nil, err
	}
	applyBrowserHeaders(req, f)
	return req, nil
}

func (f *FastProvider) getTargetURL(ctx context.Context, client *http.Client) (string, error) {
	f.mu.Lock()
	if len(f.cachedTargets) > 0 && time.Since(f.targetsUpdated) < 10*time.Minute {
		targets := f.cachedTargets
		f.mu.Unlock()
		idx := atomic.AddUint32(&f.targetIndex, 1) - 1
		return targets[int(idx)%len(targets)], nil
	}
	f.mu.Unlock()

	token := f.getToken(ctx, client)
	targets, err := f.fetchTargets(ctx, client, token)
	if err != nil {
		token = f.refreshToken(ctx, client)
		targets, err = f.fetchTargets(ctx, client, token)
		if err != nil {
			return "", err
		}
	}

	f.mu.Lock()
	f.cachedTargets = targets
	f.targetsUpdated = time.Now()
	f.mu.Unlock()

	idx := atomic.AddUint32(&f.targetIndex, 1) - 1
	return targets[int(idx)%len(targets)], nil
}

func (f *FastProvider) getToken(ctx context.Context, client *http.Client) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cachedToken != "" && time.Since(f.tokenUpdated) < 12*time.Hour {
		return f.cachedToken
	}
	return fastDefaultToken
}

func (f *FastProvider) refreshToken(ctx context.Context, client *http.Client) string {
	f.mu.Lock()
	defer f.mu.Unlock()

	extracted, err := f.extractTokenFromWeb(ctx, client)
	if err == nil && extracted != "" {
		f.cachedToken = extracted
		f.tokenUpdated = time.Now()
		return extracted
	}
	f.cachedToken = fastDefaultToken
	return fastDefaultToken
}

func (f *FastProvider) extractTokenFromWeb(ctx context.Context, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://fast.com", nil)
	if err != nil {
		return "", err
	}
	applyBrowserHeaders(req, f)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	jsFile := reFastJS.FindString(string(body))
	if jsFile == "" {
		return "", fmt.Errorf("fast.com js bundle not found")
	}

	jsURL := "https://fast.com/" + jsFile
	jsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, jsURL, nil)
	if err != nil {
		return "", err
	}
	applyBrowserHeaders(jsReq, f)
	jsResp, err := client.Do(jsReq)
	if err != nil {
		return "", err
	}
	defer jsResp.Body.Close()

	jsBody, _ := io.ReadAll(io.LimitReader(jsResp.Body, 1024*1024))
	matches := reFastToken.FindStringSubmatch(string(jsBody))
	if len(matches) > 1 {
		return matches[1], nil
	}
	return "", fmt.Errorf("token not found in fast.com js")
}

func (f *FastProvider) fetchTargets(ctx context.Context, client *http.Client, token string) ([]string, error) {
	apiURL := fmt.Sprintf("https://api.fast.com/netflix/speedtest/v2?https=true&token=%s&urlCount=5", token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	applyBrowserHeaders(req, f)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fast.com API status %d", resp.StatusCode)
	}

	var res struct {
		Targets []struct {
			URL string `json:"url"`
		} `json:"targets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	var urls []string
	for _, t := range res.Targets {
		if t.URL != "" {
			urls = append(urls, t.URL)
		}
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("no speed targets returned by fast.com")
	}

	return urls, nil
}
