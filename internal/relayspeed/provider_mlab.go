package relayspeed

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"
)

const (
	mlabLocateURL          = "https://locate.measurementlab.net/v2/nearest/ndt/ndt7"
	mlabWSProtocol         = "net.measurementlab.ndt.v7"
	mlabInitialMessageSize = 8192         // 8KB initial frame
	mlabMaxMessageSize     = 1024 * 1024  // 1MB max frame
	mlabScalingFraction    = 16           // scale message size when bulkMessageSize <= totalSent / 16
	mlabCacheTTL           = 10 * time.Minute
)

type MLabProvider struct {
	mu          sync.Mutex
	cachedDLURL string
	cachedULURL string
	cachedCity  string
	cachedCC    string
	targetTime  time.Time
}

func (m *MLabProvider) ID() string {
	return "mlab"
}

func (m *MLabProvider) DisplayName() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cachedCity != "" && m.cachedCC != "" {
		return fmt.Sprintf("M-Lab (%s, %s)", m.cachedCity, m.cachedCC)
	}
	return "M-Lab (NDT7)"
}

func (m *MLabProvider) SupportsUpload() bool {
	return true
}

func (m *MLabProvider) GetPingRequest(ctx context.Context, _ *http.Client) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mlabLocateURL, nil)
	if err != nil {
		return nil, err
	}
	applyBrowserHeaders(req, m)
	return req, nil
}

func (m *MLabProvider) GetDownloadRequest(ctx context.Context, client *http.Client, _ int64) (*http.Request, error) {
	if client == nil {
		client = http.DefaultClient
	}
	dlURL, err := m.getDownloadURL(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("mlab locate download: %w", err)
	}
	httpURL := strings.Replace(dlURL, "wss://", "https://", 1)
	httpURL = strings.Replace(httpURL, "ws://", "http://", 1)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, nil)
	if err != nil {
		return nil, err
	}
	applyBrowserHeaders(req, m)
	return req, nil
}

func (m *MLabProvider) GetUploadRequest(ctx context.Context, client *http.Client, body io.Reader, sizeBytes int64) (*http.Request, error) {
	if client == nil {
		client = http.DefaultClient
	}
	ulURL, err := m.getUploadURL(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("mlab locate upload: %w", err)
	}
	httpURL := strings.Replace(ulURL, "wss://", "https://", 1)
	httpURL = strings.Replace(httpURL, "ws://", "http://", 1)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, httpURL, body)
	if err != nil {
		return nil, err
	}
	req.ContentLength = sizeBytes
	applyBrowserHeaders(req, m)
	return req, nil
}

// ExecuteUploadStream performs standard NDT7 upload over RFC 6455 WebSocket.
func (m *MLabProvider) ExecuteUploadStream(
	ctx context.Context,
	client *http.Client,
	sizeLimit int64,
	durationSec int,
	fixedSize bool,
	deadline time.Time,
	threads int,
	bytesTransferred *int64,
) error {
	if threads <= 0 {
		threads = 1
	}

	ulURL, err := m.getUploadURL(ctx, client)
	if err != nil {
		return fmt.Errorf("mlab locate upload: %w", err)
	}

	isDurationMode := durationSec > 0 && !fixedSize

	var wg sync.WaitGroup
	var errOnce sync.Once
	var workerErr error

	// Pre-generate a 1MB payload buffer for binary frames
	payload := make([]byte, mlabMaxMessageSize)
	for i := range payload {
		payload[i] = byte('a' + (i % 26))
	}

	for w := 0; w < threads; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			ws, err := m.dialWebSocket(ctx, client, ulURL)
			if err != nil {
				if ctx.Err() == nil {
					errOnce.Do(func() { workerErr = err })
				}
				return
			}
			defer ws.Close()

			// Discard server counterflow in background to avoid clogging TCP window
			go func() {
				var discard [4096]byte
				for {
					_, rErr := ws.Read(discard[:])
					if rErr != nil {
						return
					}
				}
			}()

			bulkSize := mlabInitialMessageSize
			var localSent int64

			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if time.Now().After(deadline) {
					return
				}

				cur := atomic.LoadInt64(bytesTransferred)
				if fixedSize && sizeLimit > 0 && cur >= sizeLimit {
					return
				}

				sendBytes := bulkSize
				if fixedSize && sizeLimit > 0 {
					rem := sizeLimit - cur
					if rem <= 0 {
						return
					}
					if int64(sendBytes) > rem {
						sendBytes = int(rem)
					}
				}

				_ = ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
				wErr := websocket.Message.Send(ws, payload[:sendBytes])
				if wErr != nil {
					if ctx.Err() == nil {
						errOnce.Do(func() { workerErr = fmt.Errorf("ws send: %w", wErr) })
					}
					return
				}

				atomic.AddInt64(bytesTransferred, int64(sendBytes))
				localSent += int64(sendBytes)

				if bulkSize < mlabMaxMessageSize && int64(bulkSize) <= localSent/mlabScalingFraction {
					bulkSize *= 2
					if bulkSize > mlabMaxMessageSize {
						bulkSize = mlabMaxMessageSize
					}
				}

				if !isDurationMode && sizeLimit > 0 && atomic.LoadInt64(bytesTransferred) >= sizeLimit {
					return
				}
			}
		}()
	}

	wg.Wait()
	return workerErr
}

// ExecuteDownloadStream performs standard NDT7 download over RFC 6455 WebSocket.
func (m *MLabProvider) ExecuteDownloadStream(
	ctx context.Context,
	client *http.Client,
	sizeLimit int64,
	durationSec int,
	fixedSize bool,
	deadline time.Time,
	threads int,
	bytesTransferred *int64,
) error {
	if threads <= 0 {
		threads = 1
	}

	dlURL, err := m.getDownloadURL(ctx, client)
	if err != nil {
		return fmt.Errorf("mlab locate download: %w", err)
	}

	isDurationMode := durationSec > 0 && !fixedSize

	var wg sync.WaitGroup
	var errOnce sync.Once
	var workerErr error

	for w := 0; w < threads; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			ws, err := m.dialWebSocket(ctx, client, dlURL)
			if err != nil {
				if ctx.Err() == nil {
					errOnce.Do(func() { workerErr = err })
				}
				return
			}
			defer ws.Close()

			buf := make([]byte, 64*1024)

			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if time.Now().After(deadline) {
					return
				}

				cur := atomic.LoadInt64(bytesTransferred)
				if fixedSize && sizeLimit > 0 && cur >= sizeLimit {
					return
				}

				_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, rErr := ws.Read(buf)
				if n > 0 {
					// NDT7 emits periodic JSON measurement messages. Only count binary goodput frames.
					if buf[0] != '{' {
						atomic.AddInt64(bytesTransferred, int64(n))
						if fixedSize && sizeLimit > 0 && atomic.LoadInt64(bytesTransferred) >= sizeLimit {
							return
						}
					}
				}

				if rErr != nil {
					if ctx.Err() == nil && rErr != io.EOF {
						errOnce.Do(func() { workerErr = fmt.Errorf("ws read: %w", rErr) })
					}
					return
				}

				if !isDurationMode && sizeLimit > 0 && atomic.LoadInt64(bytesTransferred) >= sizeLimit {
					return
				}
			}
		}()
	}

	wg.Wait()
	return workerErr
}

func (m *MLabProvider) dialWebSocket(ctx context.Context, client *http.Client, targetURL string) (*websocket.Conn, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("parse ws url: %w", err)
	}

	hostPort := u.Host
	if u.Port() == "" {
		if u.Scheme == "wss" {
			hostPort = net.JoinHostPort(u.Hostname(), "443")
		} else {
			hostPort = net.JoinHostPort(u.Hostname(), "80")
		}
	}

	dialFunc := getDialContextFunc(client)
	rawConn, err := dialFunc(ctx, "tcp", hostPort)
	if err != nil {
		return nil, fmt.Errorf("dial tcp to %s: %w", hostPort, err)
	}

	var netConn net.Conn = rawConn
	if u.Scheme == "wss" {
		tlsConfig := &tls.Config{
			ServerName: u.Hostname(),
		}
		tlsConn := tls.Client(rawConn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("tls handshake to %s: %w", hostPort, err)
		}
		netConn = tlsConn
	}

	wsConfig, err := websocket.NewConfig(targetURL, "https://locate.measurementlab.net")
	if err != nil {
		netConn.Close()
		return nil, fmt.Errorf("new ws config: %w", err)
	}
	wsConfig.Protocol = []string{mlabWSProtocol}
	wsConfig.Header.Set("User-Agent", defaultUserAgent)

	ws, err := websocket.NewClient(wsConfig, netConn)
	if err != nil {
		netConn.Close()
		return nil, fmt.Errorf("websocket handshake: %w", err)
	}

	return ws, nil
}

func (m *MLabProvider) getDownloadURL(ctx context.Context, client *http.Client) (string, error) {
	m.mu.Lock()
	if m.cachedDLURL != "" && time.Since(m.targetTime) < mlabCacheTTL {
		url := m.cachedDLURL
		m.mu.Unlock()
		return url, nil
	}
	m.mu.Unlock()

	if err := m.locateTarget(ctx, client); err != nil {
		return "", err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cachedDLURL, nil
}

func (m *MLabProvider) getUploadURL(ctx context.Context, client *http.Client) (string, error) {
	m.mu.Lock()
	if m.cachedULURL != "" && time.Since(m.targetTime) < mlabCacheTTL {
		url := m.cachedULURL
		m.mu.Unlock()
		return url, nil
	}
	m.mu.Unlock()

	if err := m.locateTarget(ctx, client); err != nil {
		return "", err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cachedULURL, nil
}

func (m *MLabProvider) locateTarget(ctx context.Context, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mlabLocateURL, nil)
	if err != nil {
		return err
	}
	applyBrowserHeaders(req, m)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("locate API HTTP %d", resp.StatusCode)
	}

	var res struct {
		Results []struct {
			Hostname string `json:"hostname"`
			Location struct {
				City    string `json:"city"`
				Country string `json:"country"`
			} `json:"location"`
			URLs map[string]string `json:"urls"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return fmt.Errorf("decode locate response: %w", err)
	}
	if len(res.Results) == 0 {
		return fmt.Errorf("no mlab targets found")
	}

	target := res.Results[0]
	dlURL := target.URLs["wss:///ndt/v7/download"]
	if dlURL == "" {
		dlURL = target.URLs["ws:///ndt/v7/download"]
	}
	ulURL := target.URLs["wss:///ndt/v7/upload"]
	if ulURL == "" {
		ulURL = target.URLs["ws:///ndt/v7/upload"]
	}

	m.mu.Lock()
	m.cachedDLURL = dlURL
	m.cachedULURL = ulURL
	m.cachedCity = target.Location.City
	m.cachedCC = target.Location.Country
	m.targetTime = time.Now()
	m.mu.Unlock()

	return nil
}

func getDialContextFunc(client *http.Client) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if client != nil {
		if tr, ok := client.Transport.(*http.Transport); ok {
			if tr.DialContext != nil {
				return tr.DialContext
			}
			if tr.Dial != nil {
				return func(ctx context.Context, network, addr string) (net.Conn, error) {
					return tr.Dial(network, addr)
				}
			}
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return dialer.DialContext
}
