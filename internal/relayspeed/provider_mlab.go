package relayspeed

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	mlabLocateURL = "https://locate.measurementlab.net/v2/nearest/ndt/ndt7"
	mlabFrameSize = 32 * 1024 // 32KB per WS frame
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

func (m *MLabProvider) GetDownloadRequest(ctx context.Context, client *http.Client, _ int64) (*http.Request, error) {
	if client == nil {
		client = http.DefaultClient
	}

	dlURL, err := m.getDownloadURL(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("mlab locate download: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return nil, err
	}

	setMLabWSHeaders(req)
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

	wsBody := newWSFramingReader(body, sizeBytes)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ulURL, wsBody)
	if err != nil {
		return nil, err
	}

	setMLabWSHeaders(req)
	return req, nil
}

func (m *MLabProvider) GetPingRequest(ctx context.Context, _ *http.Client) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mlabLocateURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	return req, nil
}

func (m *MLabProvider) getDownloadURL(ctx context.Context, client *http.Client) (string, error) {
	m.mu.Lock()
	if m.cachedDLURL != "" && time.Since(m.targetTime) < 10*time.Minute {
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
	if m.cachedULURL != "" && time.Since(m.targetTime) < 10*time.Minute {
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
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

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

	dlURL = strings.Replace(dlURL, "wss://", "https://", 1)
	dlURL = strings.Replace(dlURL, "ws://", "http://", 1)
	ulURL = strings.Replace(ulURL, "wss://", "https://", 1)
	ulURL = strings.Replace(ulURL, "ws://", "http://", 1)

	m.mu.Lock()
	m.cachedDLURL = dlURL
	m.cachedULURL = ulURL
	m.cachedCity = target.Location.City
	m.cachedCC = target.Location.Country
	m.targetTime = time.Now()
	m.mu.Unlock()

	return nil
}

func setMLabWSHeaders(req *http.Request) {
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Protocol", "net.measurementlab.ndt.v7")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
}

// wsFramingReader wraps a payload reader into RFC 6455 masked binary WebSocket frames.
type wsFramingReader struct {
	reader    io.Reader
	remaining int64
	frameBuf  []byte
	bufOffset int
}

func newWSFramingReader(reader io.Reader, totalBytes int64) *wsFramingReader {
	return &wsFramingReader{
		reader:    reader,
		remaining: totalBytes,
		frameBuf:  make([]byte, 0, mlabFrameSize+8),
	}
}

func (w *wsFramingReader) Read(p []byte) (n int, err error) {
	if len(w.frameBuf) > w.bufOffset {
		copied := copy(p, w.frameBuf[w.bufOffset:])
		w.bufOffset += copied
		return copied, nil
	}

	if w.remaining <= 0 {
		return 0, io.EOF
	}

	chunkLen := int64(mlabFrameSize)
	if chunkLen > w.remaining {
		chunkLen = w.remaining
	}

	// Build masked binary frame
	// Header: 0x82 (FIN=1, BINARY), 0xFE (MASK=1, 16-bit len), 2 bytes len, 4 bytes mask (0x00)
	w.frameBuf = w.frameBuf[:0]
	w.frameBuf = append(w.frameBuf, 0x82, 0xFE)
	var lenBytes [2]byte
	binary.BigEndian.PutUint16(lenBytes[:], uint16(chunkLen))
	w.frameBuf = append(w.frameBuf, lenBytes[0], lenBytes[1])
	w.frameBuf = append(w.frameBuf, 0x00, 0x00, 0x00, 0x00) // Mask = 0x00000000

	rawPayload := make([]byte, chunkLen)
	readN, rErr := io.ReadFull(w.reader, rawPayload)
	if readN > 0 {
		w.frameBuf = append(w.frameBuf, rawPayload[:readN]...)
		w.remaining -= int64(readN)
	}

	w.bufOffset = 0
	copied := copy(p, w.frameBuf)
	w.bufOffset = copied

	if rErr != nil && rErr != io.EOF && rErr != io.ErrUnexpectedEOF {
		return copied, rErr
	}
	return copied, nil
}
