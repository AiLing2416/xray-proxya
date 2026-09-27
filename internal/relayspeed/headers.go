package relayspeed

import (
	"net/http"
)

const (
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
	secChUa          = `"Not/A)Brand";v="8", "Chromium";v="153", "Google Chrome";v="153"`
	secChUaMobile    = "?0"
	secChUaPlatform  = `"Windows"`
)

// applyBrowserHeaders injects standard Chrome desktop headers, Client Hints,
// Fetch metadata, and provider-specific anti-hotlinking headers.
func applyBrowserHeaders(req *http.Request, provider Provider) {
	if req == nil {
		return
	}

	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Sec-Ch-Ua", secChUa)
	req.Header.Set("Sec-Ch-Ua-Mobile", secChUaMobile)
	req.Header.Set("Sec-Ch-Ua-Platform", secChUaPlatform)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	if provider == nil {
		return
	}

	switch provider.ID() {
	case "cloudflare":
		req.Header.Set("Origin", "https://speed.cloudflare.com")
		req.Header.Set("Referer", "https://speed.cloudflare.com/")
	case "fast":
		req.Header.Set("Origin", "https://fast.com")
		req.Header.Set("Referer", "https://fast.com/")
	case "ookla":
		req.Header.Set("Origin", "https://www.speedtest.net")
		req.Header.Set("Referer", "https://www.speedtest.net/")
	}
}
