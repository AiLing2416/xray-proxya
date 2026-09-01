package relayspeed

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	ooklaServersURL = "https://c.speedtest.net/speedtest-servers-static.php"
)

type ooklaXMLSettings struct {
	XMLName xml.Name          `xml:"settings"`
	Servers []ooklaXMLServer  `xml:"servers>server"`
}

type ooklaXMLServer struct {
	URL     string `xml:"url,attr"`
	Name    string `xml:"name,attr"`
	Country string `xml:"country,attr"`
	CC      string `xml:"cc,attr"`
	Sponsor string `xml:"sponsor,attr"`
	ID      string `xml:"id,attr"`
	Host    string `xml:"host,attr"`
}

type OoklaProvider struct {
	mu          sync.Mutex
	cachedBase  string
	cachedULURL string
	cachedName  string
	cachedSpon  string
	targetTime  time.Time
}

func (o *OoklaProvider) ID() string {
	return "ookla"
}

func (o *OoklaProvider) DisplayName() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cachedSpon != "" && o.cachedName != "" {
		return fmt.Sprintf("Ookla (%s, %s)", o.cachedSpon, o.cachedName)
	}
	return "Ookla Speedtest"
}

func (o *OoklaProvider) SupportsUpload() bool {
	return true
}

func (o *OoklaProvider) GetDownloadRequest(ctx context.Context, client *http.Client, sizeBytes int64) (*http.Request, error) {
	if client == nil {
		client = http.DefaultClient
	}

	baseURL, err := o.getBaseURL(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("ookla get server: %w", err)
	}

	// Choose appropriate Ookla JPG payload or range
	imgName := "random4000x4000.jpg" // ~31MB payload
	if sizeBytes > 0 && sizeBytes <= 2*1024*1024 {
		imgName = "random1000x1000.jpg"
	} else if sizeBytes > 0 && sizeBytes <= 8*1024*1024 {
		imgName = "random2000x2000.jpg"
	}

	dlURL := baseURL + imgName
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return nil, err
	}

	if sizeBytes > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", sizeBytes-1))
	}
	setOoklaHeaders(req)
	return req, nil
}

func (o *OoklaProvider) GetUploadRequest(ctx context.Context, client *http.Client, body io.Reader, sizeBytes int64) (*http.Request, error) {
	if client == nil {
		client = http.DefaultClient
	}

	ulURL, err := o.getUploadURL(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("ookla get upload server: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ulURL, body)
	if err != nil {
		return nil, err
	}

	req.ContentLength = sizeBytes
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setOoklaHeaders(req)
	return req, nil
}

func (o *OoklaProvider) GetPingRequest(ctx context.Context, client *http.Client) (*http.Request, error) {
	baseURL, err := o.getBaseURL(ctx, client)
	if err == nil && baseURL != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"latency.txt", nil)
		if err == nil {
			setOoklaHeaders(req)
			return req, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://c.speedtest.net/speedtest-config.php", nil)
	if err != nil {
		return nil, err
	}
	setOoklaHeaders(req)
	return req, nil
}

func (o *OoklaProvider) getBaseURL(ctx context.Context, client *http.Client) (string, error) {
	o.mu.Lock()
	if o.cachedBase != "" && time.Since(o.targetTime) < 10*time.Minute {
		b := o.cachedBase
		o.mu.Unlock()
		return b, nil
	}
	o.mu.Unlock()

	if err := o.locateServer(ctx, client); err != nil {
		return "", err
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	return o.cachedBase, nil
}

func (o *OoklaProvider) getUploadURL(ctx context.Context, client *http.Client) (string, error) {
	o.mu.Lock()
	if o.cachedULURL != "" && time.Since(o.targetTime) < 10*time.Minute {
		u := o.cachedULURL
		o.mu.Unlock()
		return u, nil
	}
	o.mu.Unlock()

	if err := o.locateServer(ctx, client); err != nil {
		return "", err
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	return o.cachedULURL, nil
}

func (o *OoklaProvider) locateServer(ctx context.Context, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ooklaServersURL, nil)
	if err != nil {
		return err
	}
	setOoklaHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch ookla servers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ookla server API HTTP %d", resp.StatusCode)
	}

	var settings ooklaXMLSettings
	if err := xml.NewDecoder(resp.Body).Decode(&settings); err != nil {
		return fmt.Errorf("decode ookla servers XML: %w", err)
	}
	if len(settings.Servers) == 0 {
		return fmt.Errorf("no ookla servers returned")
	}

	server := settings.Servers[0]
	rawURL := server.URL

	// Extract base URL (e.g. http://host:port/speedtest/upload.php -> http://host:port/speedtest/)
	lastSlash := strings.LastIndex(rawURL, "/")
	baseURL := rawURL
	if lastSlash > 0 {
		baseURL = rawURL[:lastSlash+1]
	}

	o.mu.Lock()
	o.cachedBase = baseURL
	o.cachedULURL = rawURL
	o.cachedName = server.Name
	o.cachedSpon = server.Sponsor
	o.targetTime = time.Now()
	o.mu.Unlock()

	return nil
}

func setOoklaHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Origin", "https://www.speedtest.net")
	req.Header.Set("Referer", "https://www.speedtest.net/")
}
