package relayspeed

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	ooklaServersAPI       = "https://www.speedtest.net/api/js/servers?engine=js"
	ooklaServersBackupXML = "https://c.speedtest.net/speedtest-servers-static.php"
	ooklaMaxChunkSize     = 2 * 1024 * 1024 // 2MB chunk per upload POST
	ooklaCacheTTL         = 10 * time.Minute
)

type ooklaJSONServer struct {
	URL             string  `json:"url"`
	Lat             string  `json:"lat"`
	Lon             string  `json:"lon"`
	Distance        float64 `json:"distance"`
	Name            string  `json:"name"`
	Country         string  `json:"country"`
	CC              string  `json:"cc"`
	Sponsor         string  `json:"sponsor"`
	ID              string  `json:"id"`
	Host            string  `json:"host"`
	HTTPSFunctional int     `json:"https_functional"`
}

type ooklaXMLSettings struct {
	XMLName xml.Name         `xml:"settings"`
	Servers []ooklaXMLServer `xml:"servers>server"`
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

type ooklaTarget struct {
	BaseURL    string
	UploadURL  string
	LatencyURL string
	Name       string
	Sponsor    string
	Country    string
	CC         string
	Distance   float64
}

type OoklaProvider struct {
	mu         sync.Mutex
	targets    []*ooklaTarget
	primary    *ooklaTarget
	targetTime time.Time
}

func (o *OoklaProvider) ID() string {
	return "ookla"
}

func (o *OoklaProvider) DisplayName() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.primary != nil && o.primary.Sponsor != "" && o.primary.Name != "" {
		return fmt.Sprintf("Ookla (%s, %s)", o.primary.Sponsor, o.primary.Name)
	}
	return "Ookla Speedtest"
}

func (o *OoklaProvider) SupportsUpload() bool {
	return true
}

func (o *OoklaProvider) MaxUploadChunkSize() int64 {
	return ooklaMaxChunkSize
}

func (o *OoklaProvider) GetDownloadRequest(ctx context.Context, client *http.Client, sizeBytes int64) (*http.Request, error) {
	if client == nil {
		client = http.DefaultClient
	}

	target, err := o.getTarget(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("ookla get server: %w", err)
	}

	baseURL := target.BaseURL

	// Choose appropriate Ookla JPG payload
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

	target, err := o.getTarget(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("ookla get upload server: %w", err)
	}

	uploadSize := sizeBytes
	if uploadSize > ooklaMaxChunkSize {
		uploadSize = ooklaMaxChunkSize
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.UploadURL, body)
	if err != nil {
		return nil, err
	}

	req.ContentLength = uploadSize
	req.Header.Set("Content-Type", "application/octet-stream")
	setOoklaHeaders(req)
	return req, nil
}

func (o *OoklaProvider) GetPingRequest(ctx context.Context, client *http.Client) (*http.Request, error) {
	if client == nil {
		client = http.DefaultClient
	}

	target, err := o.getTarget(ctx, client)
	if err == nil && target != nil && target.LatencyURL != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, target.LatencyURL, nil)
		if err == nil {
			setOoklaHeaders(req)
			return req, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://www.speedtest.net/latency.txt", nil)
	if err != nil {
		return nil, err
	}
	setOoklaHeaders(req)
	return req, nil
}

func (o *OoklaProvider) getTarget(ctx context.Context, client *http.Client) (*ooklaTarget, error) {
	o.mu.Lock()
	if o.primary != nil && time.Since(o.targetTime) < ooklaCacheTTL {
		target := o.primary
		o.mu.Unlock()
		return target, nil
	}
	o.mu.Unlock()

	if err := o.locateServers(ctx, client); err != nil {
		return nil, err
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	if o.primary == nil {
		return nil, fmt.Errorf("no ookla target available")
	}
	return o.primary, nil
}

func (o *OoklaProvider) locateServers(ctx context.Context, client *http.Client) error {
	targets, err := o.fetchJSONServers(ctx, client)
	if err != nil || len(targets) == 0 {
		targets, err = o.fetchXMLServers(ctx, client)
	}
	if err != nil {
		return fmt.Errorf("locate ookla servers: %w", err)
	}
	if len(targets) == 0 {
		return fmt.Errorf("no valid ookla servers found")
	}

	// Probe top candidates (up to 3) using lightweight HEAD latency.txt to select lowest RTT server as primary
	primary := targets[0]
	if len(targets) > 1 {
		bestTarget, bestRTT := o.probeBestTarget(ctx, client, targets)
		if bestTarget != nil && bestRTT > 0 {
			primary = bestTarget
		}
	}

	// Follow any 301/302/307 redirects to cache final direct POST target and prevent body drops
	o.resolveTargetUploadURL(ctx, client, primary)

	o.mu.Lock()
	o.targets = targets
	o.primary = primary
	o.targetTime = time.Now()
	o.mu.Unlock()

	return nil
}

func (o *OoklaProvider) resolveTargetUploadURL(ctx context.Context, client *http.Client, target *ooklaTarget) {
	if target == nil || target.UploadURL == "" {
		return
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodHead, target.UploadURL, nil)
	if err != nil {
		return
	}
	setOoklaHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.Request != nil && resp.Request.URL != nil {
		resolved := resp.Request.URL.String()
		if resolved != "" && resolved != target.UploadURL {
			target.UploadURL = resolved
			u, err := url.Parse(resolved)
			if err == nil {
				u.Path = path.Dir(u.Path) + "/"
				target.BaseURL = u.String()
				target.LatencyURL = target.BaseURL + "latency.txt"
			}
		}
	}
}

func (o *OoklaProvider) fetchJSONServers(ctx context.Context, client *http.Client) ([]*ooklaTarget, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ooklaServersAPI, nil)
	if err != nil {
		return nil, err
	}
	setOoklaHeaders(req)
	req.Header.Set("Accept", "application/json, text/plain, */*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JSON API HTTP %d", resp.StatusCode)
	}

	var jsonServers []ooklaJSONServer
	if err := json.NewDecoder(resp.Body).Decode(&jsonServers); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}

	var targets []*ooklaTarget
	limit := 8
	for _, s := range jsonServers {
		if s.URL == "" {
			continue
		}
		target := parseOoklaTarget(s.URL, s.Name, s.Sponsor, s.Country, s.CC, s.Distance, s.HTTPSFunctional == 1)
		targets = append(targets, target)
		if len(targets) >= limit {
			break
		}
	}

	return targets, nil
}

func (o *OoklaProvider) fetchXMLServers(ctx context.Context, client *http.Client) ([]*ooklaTarget, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ooklaServersBackupXML, nil)
	if err != nil {
		return nil, err
	}
	setOoklaHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("XML API HTTP %d", resp.StatusCode)
	}

	var settings ooklaXMLSettings
	if err := xml.NewDecoder(resp.Body).Decode(&settings); err != nil {
		return nil, fmt.Errorf("decode XML: %w", err)
	}

	var targets []*ooklaTarget
	limit := 8
	for _, s := range settings.Servers {
		if s.URL == "" {
			continue
		}
		target := parseOoklaTarget(s.URL, s.Name, s.Sponsor, s.Country, s.CC, 0, false)
		targets = append(targets, target)
		if len(targets) >= limit {
			break
		}
	}

	return targets, nil
}

func (o *OoklaProvider) probeBestTarget(ctx context.Context, client *http.Client, candidates []*ooklaTarget) (*ooklaTarget, time.Duration) {
	numProbe := 3
	if len(candidates) < numProbe {
		numProbe = len(candidates)
	}

	type probeResult struct {
		target *ooklaTarget
		rtt    time.Duration
		err    error
	}

	results := make(chan probeResult, numProbe)
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	for i := 0; i < numProbe; i++ {
		t := candidates[i]
		go func(target *ooklaTarget) {
			req, err := http.NewRequestWithContext(probeCtx, http.MethodHead, target.LatencyURL, nil)
			if err != nil {
				results <- probeResult{target: target, err: err}
				return
			}
			setOoklaHeaders(req)

			start := time.Now()
			resp, err := client.Do(req)
			rtt := time.Since(start)
			if err != nil {
				results <- probeResult{target: target, err: err}
				return
			}
			resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 400 {
				results <- probeResult{target: target, err: fmt.Errorf("status %d", resp.StatusCode)}
				return
			}
			results <- probeResult{target: target, rtt: rtt}
		}(t)
	}

	var bestTarget *ooklaTarget
	var minRTT time.Duration = time.Hour

	for i := 0; i < numProbe; i++ {
		select {
		case res := <-results:
			if res.err == nil && res.rtt < minRTT {
				minRTT = res.rtt
				bestTarget = res.target
			}
		case <-probeCtx.Done():
			break
		}
	}

	return bestTarget, minRTT
}

func parseOoklaTarget(rawURL, name, sponsor, country, cc string, distance float64, httpsFunctional bool) *ooklaTarget {
	if httpsFunctional || strings.HasPrefix(rawURL, "https://") {
		rawURL = strings.Replace(rawURL, "http://", "https://", 1)
	}

	baseURL := rawURL
	u, err := url.Parse(rawURL)
	if err == nil {
		u.Path = path.Dir(u.Path) + "/"
		baseURL = u.String()
	} else {
		lastSlash := strings.LastIndex(rawURL, "/")
		if lastSlash > 0 {
			baseURL = rawURL[:lastSlash+1]
		}
	}

	latURL := baseURL + "latency.txt"

	return &ooklaTarget{
		BaseURL:    baseURL,
		UploadURL:  rawURL,
		LatencyURL: latURL,
		Name:       name,
		Sponsor:    sponsor,
		Country:    country,
		CC:         cc,
		Distance:   distance,
	}
}

func setOoklaHeaders(req *http.Request) {
	applyBrowserHeaders(req, &OoklaProvider{})
}
