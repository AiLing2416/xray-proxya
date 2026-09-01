package relayinfo

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

func probeGeneral(ctx context.Context, client *http.Client) GeneralUnlock {
	var (
		res GeneralUnlock
		wg  sync.WaitGroup
	)

	wg.Add(3)
	go func() {
		defer wg.Done()
		res.Google = probeGoogle(ctx, client)
	}()
	go func() {
		defer wg.Done()
		res.OpenAI = probeOpenAI(ctx, client)
	}()
	go func() {
		defer wg.Done()
		res.Claude = probeClaude(ctx, client)
	}()

	wg.Wait()
	return res
}

func probeGoogle(ctx context.Context, client *http.Client) UnlockItem {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.google.com", nil)
	if err != nil {
		return classifyError(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return classifyError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return UnlockItem{Status: StatusNo, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	finalURL := resp.Request.URL.String()
	region := parseGoogleRegion(finalURL)
	return UnlockItem{
		Status: StatusYes,
		Region: region,
	}
}

func parseGoogleRegion(finalURL string) string {
	u, err := url.Parse(finalURL)
	if err != nil {
		return "US"
	}
	host := u.Host
	host = strings.TrimPrefix(host, "www.")
	if host == "google.com" {
		return "US"
	}
	if !strings.HasPrefix(host, "google.") {
		return "US"
	}
	tld := strings.TrimPrefix(host, "google.")

	switch tld {
	case "com.hk":
		return "HK"
	case "co.jp":
		return "JP"
	case "com.tw":
		return "TW"
	case "com.sg":
		return "SG"
	case "co.kr":
		return "KR"
	case "co.uk":
		return "UK"
	case "com.au":
		return "AU"
	case "co.th":
		return "TH"
	case "com.my":
		return "MY"
	case "co.id":
		return "ID"
	case "com.vn":
		return "VN"
	case "com.ph":
		return "PH"
	case "com.tr":
		return "TR"
	case "com.br":
		return "BR"
	case "ru":
		return "RU"
	case "nl":
		return "NL"
	case "it":
		return "IT"
	case "es":
		return "ES"
	case "ch":
		return "CH"
	case "se":
		return "SE"
	case "no":
		return "NO"
	case "dk":
		return "DK"
	case "fi":
		return "FI"
	case "pl":
		return "PL"
	case "cz":
		return "CZ"
	case "at":
		return "AT"
	case "be":
		return "BE"
	case "ie":
		return "IE"
	case "pt":
		return "PT"
	case "gr":
		return "GR"
	case "hu":
		return "HU"
	case "ro":
		return "RO"
	case "bg":
		return "BG"
	case "hr":
		return "HR"
	case "ua":
		return "UA"
	case "co.za":
		return "ZA"
	case "com.mx":
		return "MX"
	case "cl":
		return "CL"
	case "com.ar":
		return "AR"
	case "com.co":
		return "CO"
	case "pe":
		return "PE"
	case "com.ve":
		return "VE"
	case "com.ec":
		return "EC"
	case "com.uy":
		return "UY"
	case "co.nz":
		return "NZ"
	case "co.in":
		return "IN"
	case "com.pk":
		return "PK"
	case "com.bd":
		return "BD"
	case "lk":
		return "LK"
	case "com.np":
		return "NP"
	case "ae":
		return "AE"
	case "com.sa":
		return "SA"
	case "co.il":
		return "IL"
	case "com.eg":
		return "EG"
	case "co.ma":
		return "MA"
	case "dz":
		return "DZ"
	case "tn":
		return "TN"
	case "com.ng":
		return "NG"
	case "co.ke":
		return "KE"
	case "co.tz":
		return "TZ"
	case "co.ug":
		return "UG"
	case "com.gh":
		return "GH"
	}

	parts := strings.Split(tld, ".")
	lastPart := parts[len(parts)-1]
	if len(lastPart) == 2 {
		return strings.ToUpper(lastPart)
	}
	return "US"
}

func probeOpenAI(ctx context.Context, client *http.Client) UnlockItem {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ios.chat.openai.com/public-api/mobile/server_status/v1", nil)
	if err != nil {
		return classifyError(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return classifyError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return UnlockItem{Status: StatusYes}
	}
	if resp.StatusCode == 403 || resp.StatusCode == 400 {
		return UnlockItem{Status: StatusNo}
	}
	return UnlockItem{Status: StatusNo, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

func probeClaude(ctx context.Context, client *http.Client) UnlockItem {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://claude.ai/login", nil)
	if err != nil {
		return classifyError(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return classifyError(err)
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()
	if strings.Contains(finalURL, "/unsupported") || resp.StatusCode == 403 || resp.StatusCode == 400 {
		return UnlockItem{Status: StatusNo}
	}
	if resp.StatusCode == 200 {
		return UnlockItem{Status: StatusYes}
	}
	return UnlockItem{Status: StatusNo, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}
