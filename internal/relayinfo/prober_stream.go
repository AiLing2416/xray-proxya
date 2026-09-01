package relayinfo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

var (
	reNetflix1 = regexp.MustCompile(`"id"\s*:\s*"([A-Z]{2})"\s*,\s*"countryName"`)
	reNetflix2 = regexp.MustCompile(`"requestCountryCode"\s*:\s*"([A-Z]{2})"`)
	reNetflix3 = regexp.MustCompile(`"countryCode"\s*:\s*"([A-Z]{2})"`)
	reDisney   = regexp.MustCompile(`/([a-z]{2})-([a-z]{2})/`)
	reTikTok   = regexp.MustCompile(`"region"\s*:\s*"([A-Z]{2})"`)
)

func classifyError(err error) UnlockItem {
	if err == nil {
		return UnlockItem{Status: StatusError, Detail: "unknown error"}
	}
	if errors.Is(err, ErrNoIPv6Address) || strings.Contains(err.Error(), "no IPv6 (AAAA)") {
		return UnlockItem{Status: StatusNoIPv6, Detail: "No IPv6"}
	}
	if errors.Is(err, ErrNoIPv4Address) || strings.Contains(err.Error(), "no IPv4 (A)") {
		return UnlockItem{Status: StatusNoIPv4, Detail: "No IPv4"}
	}
	return UnlockItem{Status: StatusError, Detail: err.Error()}
}

func probeStreaming(ctx context.Context, client *http.Client) StreamingUnlock {
	var (
		res StreamingUnlock
		wg  sync.WaitGroup
	)

	wg.Add(3)
	go func() {
		defer wg.Done()
		res.Netflix = probeNetflix(ctx, client)
	}()
	go func() {
		defer wg.Done()
		res.Disney = probeDisneyPlus(ctx, client)
	}()
	go func() {
		defer wg.Done()
		res.TikTok = probeTikTok(ctx, client)
	}()

	wg.Wait()
	return res
}

func probeNetflix(ctx context.Context, client *http.Client) UnlockItem {
	// 1. Test non-original title (Breaking Bad)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.netflix.com/title/70143836", nil)
	if err != nil {
		return classifyError(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept-Language", "en")

	resp, err := client.Do(req)
	if err != nil {
		return classifyError(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	bodyStr := string(body)
	hasOhNo := strings.Contains(bodyStr, "Oh no!") || strings.Contains(bodyStr, "netflix.com/browse") || resp.StatusCode == 404
	region := extractNetflixRegion(body)

	if resp.StatusCode == 200 && !hasOhNo {
		return UnlockItem{
			Status: StatusFull,
			Region: region,
		}
	}

	// 2. Test original title (Test Patterns) as fallback/originals check
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.netflix.com/title/80018499", nil)
	if err != nil {
		return classifyError(err)
	}
	req2.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req2.Header.Set("Accept-Language", "en")

	resp2, err := client.Do(req2)
	if err != nil {
		return classifyError(err)
	}
	defer resp2.Body.Close()

	body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 1024*1024))
	body2Str := string(body2)
	hasOhNo2 := strings.Contains(body2Str, "Oh no!") || strings.Contains(body2Str, "netflix.com/browse") || resp2.StatusCode == 404

	if region == "" {
		region = extractNetflixRegion(body2)
	}

	if resp2.StatusCode == 200 && !hasOhNo2 {
		return UnlockItem{
			Status: StatusOriginals,
			Region: region,
			Detail: "Originals",
		}
	}

	return UnlockItem{Status: StatusNo}
}

func extractNetflixRegion(body []byte) string {
	if m := reNetflix1.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	if m := reNetflix2.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	if m := reNetflix3.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

func probeDisneyPlus(ctx context.Context, client *http.Client) UnlockItem {
	// 1. Fast BAMGrid API block check
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://disney.api.edge.bamgrid.com/devices", strings.NewReader(`{"deviceFamily":"browser","applicationRuntime":"chrome","deviceProfile":"windows","attributes":{}}`))
	if err != nil {
		return classifyError(err)
	}
	req.Header.Set("Authorization", "Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84")
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return classifyError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		return UnlockItem{Status: StatusNo}
	}

	// 2. Page redirect check
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.disneyplus.com", nil)
	if err != nil {
		return classifyError(err)
	}
	req2.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp2, err := client.Do(req2)
	if err != nil {
		return classifyError(err)
	}
	defer resp2.Body.Close()

	finalURL := resp2.Request.URL.String()
	if strings.Contains(finalURL, "preview") || strings.Contains(finalURL, "unavailable") {
		return UnlockItem{Status: StatusNo}
	}

	if m := reDisney.FindStringSubmatch(finalURL); len(m) > 2 {
		return UnlockItem{
			Status: StatusYes,
			Region: strings.ToUpper(m[2]),
		}
	}

	return UnlockItem{Status: StatusYes}
}

func probeTikTok(ctx context.Context, client *http.Client) UnlockItem {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.tiktok.com/", nil)
	if err != nil {
		return classifyError(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return classifyError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || strings.Contains(resp.Request.URL.String(), "notfound") {
		return UnlockItem{Status: StatusNo}
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if m := reTikTok.FindSubmatch(body); len(m) > 1 {
		return UnlockItem{
			Status: StatusYes,
			Region: string(m[1]),
		}
	}

	if resp.StatusCode == 200 {
		return UnlockItem{Status: StatusYes}
	}
	return UnlockItem{Status: StatusNo, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}
