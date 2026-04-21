package camouflage

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"xray-proxya/internal/config"
)

type CacheItem struct {
	Body       []byte
	Header     http.Header
	StatusCode int
	Expires    time.Time
}

type Manager struct {
	mu     sync.RWMutex
	cache  map[string]*CacheItem
	client *http.Client
	modes  []config.ModeInfo
}

func NewManager(modes []config.ModeInfo) *Manager {
	return &Manager{
		cache: make(map[string]*CacheItem),
		modes: modes,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: (&net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
			},
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects to keep camouflage realistic
			},
		},
	}
}

func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = r.Header.Get("X-Forwarded-Host")
	}

	// Logic:
	// 1. If host is an IP or empty -> Probe target domain without Host header (Simulate IP probe)
	// 2. If host matches one of our SNIs -> Probe target domain with correct Host header (Simulate Mirror)
	// 3. Otherwise -> 404

	targetMode := m.findModeByHost(host)
	isIPProbe := m.isIP(host) || host == ""

	var cacheKey string
	if targetMode != nil {
		if isIPProbe {
			cacheKey = "probe-" + targetMode.Dest
		} else {
			cacheKey = "mirror-" + targetMode.Dest
		}
	} else {
		// Fallback to first skinned mode if we can't match host (Xray might not pass host correctly in all cases)
		for _, info := range m.modes {
			if info.Skin {
				targetMode = &info
				cacheKey = "probe-" + info.Dest // Default to IP probe for safety
				break
			}
		}
	}

	if targetMode == nil {
		http.Error(w, "Not Found", 404)
		return
	}

	item := m.getOrFetch(cacheKey, targetMode.Dest, !isIPProbe)
	if item == nil {
		http.Error(w, "Service Unavailable", 503)
		return
	}

	// Replay
	for k, vv := range item.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(item.StatusCode)
	w.Write(item.Body)
}

func (m *Manager) findModeByHost(host string) *config.ModeInfo {
	cleanHost := strings.TrimPrefix(strings.ToLower(host), "www.")
	if h, _, err := net.SplitHostPort(cleanHost); err == nil {
		cleanHost = h
	}

	for i := range m.modes {
		if !m.modes[i].Skin {
			continue
		}
		cleanSNI := strings.TrimPrefix(strings.ToLower(m.modes[i].SNI), "www.")
		if cleanHost == cleanSNI {
			return &m.modes[i]
		}
	}
	return nil
}

func (m *Manager) isIP(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return net.ParseIP(host) != nil
}

func (m *Manager) getOrFetch(key, dest string, withHost bool) *CacheItem {
	m.mu.RLock()
	if item, ok := m.cache[key]; ok && time.Now().Before(item.Expires) {
		m.mu.RUnlock()
		return item
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double check
	if item, ok := m.cache[key]; ok && time.Now().Before(item.Expires) {
		return item
	}

	item := m.fetchTarget(dest, withHost)
	if item != nil {
		m.cache[key] = item
	}
	return item
}

func (m *Manager) fetchTarget(dest string, withHost bool) *CacheItem {
	item := m.doRequest(dest, withHost)
	if item != nil {
		// If we got a redirect to a www version, or a 4xx error on a non-www domain,
		// it's possible the CDN behavior is only visible on the www subdomain.
		isRedirectToWWW := (item.StatusCode == 301 || item.StatusCode == 302) &&
			strings.Contains(item.Header.Get("Location"), "www.")
		
		isFailure := item.StatusCode >= 400 && item.StatusCode < 500

		if (isRedirectToWWW || isFailure) && !strings.HasPrefix(dest, "www.") {
			host, port, _ := net.SplitHostPort(dest)
			if host == "" {
				host = dest
			}
			newDest := "www." + host
			if port != "" {
				newDest += ":" + port
			}
			if newItem := m.doRequest(newDest, withHost); newItem != nil {
				return newItem
			}
		}
		return item
	}

	// If initial attempt failed completely and didn't have www, try adding it
	if !strings.HasPrefix(dest, "www.") {
		host, port, _ := net.SplitHostPort(dest)
		if host == "" {
			host = dest
		}
		newDest := "www." + host
		if port != "" {
			newDest += ":" + port
		}
		return m.doRequest(newDest, withHost)
	}

	return nil
}

func (m *Manager) doRequest(dest string, withHost bool) *CacheItem {
	// dest is usually "domain:port"
	url := "https://" + dest + "/"
	req, _ := http.NewRequest("GET", url, nil)

	if !withHost {
		// Force IP-only probe by removing Host header or setting it to IP
		host, port, _ := net.SplitHostPort(dest)
		if host == "" {
			host = dest
		}
		ips, _ := net.LookupIP(host)
		if len(ips) > 0 {
			targetIP := ips[0].String()
			req.URL.Host = targetIP
			if port == "" {
				req.URL.Host += ":443"
			} else {
				req.URL.Host += ":" + port
			}
		}
		req.Host = req.URL.Host // Use IP as Host header
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Clean headers to look like a direct CDN response
	header := make(http.Header)
	copyHeader(header, resp.Header)
	header.Del("Date")
	header.Del("Server")
	header.Del("Content-Length")
	header.Del("Connection")

	return &CacheItem{
		Body:       body,
		Header:     header,
		StatusCode: resp.StatusCode,
		Expires:    time.Now().Add(24 * time.Hour),
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
