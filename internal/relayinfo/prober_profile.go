package relayinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"xray-proxya/internal/relaytest"
)

var (
	ipv4LookupURLs = []string{
		"https://api4.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://v4.ident.me",
	}

	ipv6LookupURLs = []string{
		"https://api6.ipify.org",
		"https://ipv6.icanhazip.com",
		"https://v6.ident.me",
	}
)

func probeProfile(ctx context.Context, session *relaytest.TestSession, mode Mode, family IPFamily) LandingProfile {
	p := LandingProfile{
		ASN:     "N/A",
		ASNType: "N/A",
		Org:     "N/A",
		City:    "N/A",
		Region:  "N/A",
		Country: "N/A",
		Privacy: "N/A",
	}

	var (
		wg sync.WaitGroup
		v4 string
		v6 string
	)

	// 1. Probe IPv4 (unless explicitly IPv6 only)
	if family != IPFamilyIPv6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, u := range ipv4LookupURLs {
				ip := fetchIPString(ctx, session.HTTPClient, u)
				if ip != "" && isIPv4(ip) {
					v4 = ip
					return
				}
			}
		}()
	}

	// 2. Probe IPv6 (unless explicitly IPv4 only)
	if family != IPFamilyIPv4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, u := range ipv6LookupURLs {
				ip := fetchIPString(ctx, session.HTTPClient, u)
				if ip != "" && isIPv6(ip) {
					v6 = ip
					return
				}
			}
		}()
	}

	// 3. Probe GeoIP Metadata
	geoClient := newDirectedHTTPClient(session, family)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Try ip.sb -> ipwho.is -> ipinfo.io -> ip-api.com
		if probeIPSBGeoIP(ctx, geoClient, &p) {
			return
		}
		if probeIPWhois(ctx, geoClient, &p) {
			return
		}
		if probeIPInfo(ctx, geoClient, &p) {
			return
		}
		if probeIPAPI(ctx, geoClient, &p) {
			return
		}
	}()

	wg.Wait()

	p.IPv4 = v4
	p.IPv6 = v6

	// Select primary IP
	if v4 != "" {
		p.IP = v4
	} else if v6 != "" {
		p.IP = v6
	}

	// In full mode, populate timezone and local time
	if mode == ModeFull {
		if p.Timezone == "" {
			p.Timezone = "UTC"
		}
		p.LocalTime = getLocalTime(p.Timezone)
	} else {
		// In simple mode, omit timezone and local time
		p.Timezone = ""
		p.LocalTime = ""
	}

	return p
}

func probeIPSBGeoIP(ctx context.Context, client *http.Client, p *LandingProfile) bool {
	var res struct {
		IP          string `json:"ip"`
		ASN         int    `json:"asn"`
		ISP         string `json:"isp"`
		City        string `json:"city"`
		Region      string `json:"region"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Timezone    string `json:"timezone"`
	}
	if !fetchJSONWithContext(ctx, client, "https://api.ip.sb/geoip", &res) || res.IP == "" {
		return false
	}
	p.IP = res.IP
	if res.ISP != "" {
		p.Org = res.ISP
		p.ASNType = "DataCenter"
	}
	if res.City != "" {
		p.City = res.City
	}
	if res.Region != "" {
		p.Region = res.Region
	}
	if res.Country != "" {
		p.Country = res.Country
	}
	if res.CountryCode != "" {
		p.CountryCode = strings.ToUpper(res.CountryCode)
	}
	if res.Timezone != "" {
		p.Timezone = res.Timezone
	}
	if res.ASN > 0 {
		p.ASN = fmt.Sprintf("AS%d", res.ASN)
	}
	p.Privacy = "Clear"
	return true
}

func probeIPInfo(ctx context.Context, client *http.Client, p *LandingProfile) bool {
	var res struct {
		IP       string `json:"ip"`
		Org      string `json:"org"`
		City     string `json:"city"`
		Region   string `json:"region"`
		Country  string `json:"country"`
		Timezone string `json:"timezone"`
	}
	if !fetchJSONWithContext(ctx, client, "https://ipinfo.io/json", &res) || res.IP == "" {
		return false
	}
	p.IP = res.IP
	if res.Org != "" {
		p.Org = res.Org
		p.ASN = res.Org
		p.ASNType = "DataCenter"
	}
	if res.City != "" {
		p.City = res.City
	}
	if res.Region != "" {
		p.Region = res.Region
	}
	if res.Country != "" {
		p.Country = res.Country
		if len(res.Country) == 2 {
			p.CountryCode = strings.ToUpper(res.Country)
		}
	}
	if res.Timezone != "" {
		p.Timezone = res.Timezone
	}
	p.Privacy = "Clear"
	return true
}

func probeIPAPI(ctx context.Context, client *http.Client, p *LandingProfile) bool {
	var res struct {
		Query       string `json:"query"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		RegionName  string `json:"regionName"`
		City        string `json:"city"`
		Org         string `json:"org"`
		AS          string `json:"as"`
		Timezone    string `json:"timezone"`
		Hosting     bool   `json:"hosting"`
		Proxy       bool   `json:"proxy"`
	}
	if !fetchJSONWithContext(ctx, client, "http://ip-api.com/json/?fields=66846719", &res) || res.Query == "" {
		return false
	}
	p.IP = res.Query
	if res.Country != "" {
		p.Country = res.Country
	}
	if res.CountryCode != "" {
		p.CountryCode = strings.ToUpper(res.CountryCode)
	}
	if res.RegionName != "" {
		p.Region = res.RegionName
	}
	if res.City != "" {
		p.City = res.City
	}
	if res.Org != "" {
		p.Org = res.Org
	}
	if res.AS != "" {
		p.ASN = res.AS
	}
	if res.Timezone != "" {
		p.Timezone = res.Timezone
	}
	p.ASNType = "ISP"
	if res.Hosting {
		p.ASNType = "DataCenter"
	}
	p.Privacy = "Clear"
	if res.Proxy {
		p.Privacy = "Flagged"
	}
	return true
}

func probeIPWhois(ctx context.Context, client *http.Client, p *LandingProfile) bool {
	var res struct {
		IP          string `json:"ip"`
		Success     bool   `json:"success"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Region      string `json:"region"`
		City        string `json:"city"`
		Connection  struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
		Timezone struct {
			ID string `json:"id"`
		} `json:"timezone"`
	}
	if !fetchJSONWithContext(ctx, client, "https://ipwho.is/", &res) || !res.Success || res.IP == "" {
		return false
	}
	p.IP = res.IP
	if res.Connection.Org != "" {
		p.Org = res.Connection.Org
	} else if res.Connection.ISP != "" {
		p.Org = res.Connection.ISP
	}
	p.ASNType = "DataCenter"
	if res.City != "" {
		p.City = res.City
	}
	if res.Region != "" {
		p.Region = res.Region
	}
	if res.Country != "" {
		p.Country = res.Country
	}
	if res.CountryCode != "" {
		p.CountryCode = strings.ToUpper(res.CountryCode)
	}
	if res.Timezone.ID != "" {
		p.Timezone = res.Timezone.ID
	}
	if res.Connection.ASN > 0 {
		p.ASN = fmt.Sprintf("AS%d", res.Connection.ASN)
	}
	p.Privacy = "Clear"
	return true
}

func fetchJSONWithContext(ctx context.Context, client *http.Client, url string, target interface{}) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	return json.NewDecoder(resp.Body).Decode(target) == nil
}

func fetchIPString(ctx context.Context, client *http.Client, targetURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return ""
	}
	raw := strings.TrimSpace(string(body))
	parsed := net.ParseIP(raw)
	if parsed != nil {
		return parsed.String()
	}
	return ""
}

func isIPv4(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.To4() != nil
}

func isIPv6(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.To4() == nil && ip.To16() != nil
}

func getLocalTime(tz string) string {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.Now().UTC().Format("2006-01-02 15:04:05")
	}
	return time.Now().In(loc).Format("2006-01-02 15:04:05")
}
