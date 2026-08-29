package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

type Profile struct {
	IP, IPv4, IPv6, ASN, Org, City, Region, Country, Timezone, LocalTime string
	ASNType, Privacy                                                     string
}

type ProbeResult struct {
	TCP  string
	UDP  string
	DNS  string
	IPv4 string
	IPv6 string
}

type SpeedResult struct {
	Direction           string
	Link                string
	Duration            time.Duration
	BytesTransferred    int64
	Low20SpeedBps       float64
	AvgSpeedBps         float64
	PeakSpeedBps        float64
	IdleLatencyAvg      time.Duration
	LoadLatencyAvg      time.Duration
	LoadLatencyWorst5   time.Duration
	LoadLatencySamples  int
	LoadLatencyLossRate float64
}

type speedTestDirection string

const (
	speedTestDownload speedTestDirection = "Download"
	speedTestUpload   speedTestDirection = "Upload"
	defaultSpeedTestSize                 = int64(50_000_000)
)

var (
	outboundIPv4 bool
	outboundIPv6 bool
	speedLink    string
	speedUploadLink string
	speedDownloadLink string
	speedTime    int
	speedSize    string
	speedUpload  bool
	speedDownload bool
	speedBoth    bool
)

const (
	defaultSpeedTestLink    = "https://speed.cloudflare.com/__down?bytes=50000000"
	defaultUploadTestLink   = "https://speed.cloudflare.com/__up"
	maxSpeedTestSeconds     = 3600
	defaultSpeedTestTimeout = 2 * time.Minute
	latencyProbeTimeout     = 20 * time.Second
	speedSampleInterval     = time.Second
	latencyProbeInterval    = time.Second
	defaultLatencyProbeRuns = 5
)

var outboundCmd = &cobra.Command{
	Use:     "relay",
	Aliases: []string{"relays", "outbound", "outbounds", "node"},
	Short:   "Manage relay nodes (custom outbounds) in the staging config",
}

func getRelayAliases() []string {
	cfg, _ := config.LoadConfigEx(true)
	if cfg == nil {
		return nil
	}
	var aliases []string
	for _, co := range cfg.CustomOutbounds {
		aliases = append(aliases, co.Alias)
	}
	return aliases
}

func completeRelayAliasesArg(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) != 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
}

var addOutboundCmd = &cobra.Command{
	Use:   "add [alias] [link]",
	Short: "Import a relay node from a link (STAGING)",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		alias, link := args[0], args[1]
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			cfg = &config.UserConfig{UUID: uuid.New().String(), Role: config.RoleServer}
		}
		for _, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				fmt.Printf("❌ Alias '%s' already exists.\n", alias)
				return
			}
		}
		out, err := xray.ParseProxyLink(link)
		if err != nil {
			fmt.Printf("❌ Failed to parse link: %v\n", err)
			return
		}
		newCO := config.CustomOutbound{Alias: alias, Enabled: true, UserUUID: uuid.New().String(), Config: out}
		cfg.CustomOutbounds = append(cfg.CustomOutbounds, newCO)
		fmt.Printf("🔍 Testing node '%s' connectivity...\n", alias)
		results := runIsolatedTest(cfg, newCO)
		printProbeResults(alias, results)
		if err := cfg.SaveEx(true); err == nil {
			fmt.Println("✅ Added to STAGING. Run 'apply' to commit.")
		}
	},
}

var listOutboundCmd = &cobra.Command{
	Use:   "list",
	Short: "List relay nodes with remote endpoint and local bind details",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		fmt.Printf("\n%-3s | %-14s | %-5s | %-11s | %-30s | %-20s | %-18s | %-8s | %-s\n", "ID", "ALIAS", "STATE", "PROTO", "REMOTE", "TRANSPORT", "INTERNAL", "PRIVATE", "DNS")
		fmt.Println("---------------------------------------------------------------------------------------------------------------------------------------------------")
		for i, co := range cfg.CustomOutbounds {
			status := "OFF"
			if co.Enabled {
				status = "ON"
			}
			internal := "-"
			if co.InternalProxyPort > 0 {
				internal = fmt.Sprintf("socks:%d http:%d", co.InternalProxyPort, co.InternalProxyPort+1)
			}
			strategy := co.DNSStrategy
			if strategy == "" {
				strategy = "default"
			}
			privateTargets := "BLOCKED"
			if co.AllowPrivateTargets {
				privateTargets = "ALLOWED"
			}
			fmt.Printf(
				"%-3d | %-14s | %-5s | %-11s | %-30s | %-20s | %-18s | %-8s | %-s\n",
				i+1,
				co.Alias,
				status,
				outboundProtocol(co),
				outboundRemoteSummary(co),
				outboundTransportSummary(co),
				internal,
				privateTargets,
				outboundDNSSummary(co, strategy),
			)
		}
		fmt.Println()
	},
}

func outboundProtocol(co config.CustomOutbound) string {
	if proto, _ := co.Config["protocol"].(string); proto != "" {
		return proto
	}
	return "unknown"
}

func outboundRemoteSummary(co config.CustomOutbound) string {
	server := outboundServerSpec(co)
	if server == "" {
		return "-"
	}
	return trimText(server, 30)
}

func outboundServerSpec(co config.CustomOutbound) string {
	settings, _ := co.Config["settings"].(map[string]interface{})
	switch outboundProtocol(co) {
	case "vless", "vmess":
		vnext := getMapSlice(settings, "vnext")
		if len(vnext) == 0 {
			return ""
		}
		return joinHostPort(vnext[0]["address"], vnext[0]["port"])
	case "shadowsocks":
		servers := getMapSlice(settings, "servers")
		if len(servers) == 0 {
			return ""
		}
		return joinHostPort(servers[0]["address"], servers[0]["port"])
	case "socks", "http":
		servers := getMapSlice(settings, "servers")
		if len(servers) == 0 {
			return ""
		}
		return joinHostPort(servers[0]["address"], servers[0]["port"])
	case "freedom":
		sendThrough, _ := co.Config["sendThrough"].(string)
		if sendThrough != "" {
			return sendThrough
		}
		return "direct"
	default:
		return ""
	}
}

func outboundTransportSummary(co config.CustomOutbound) string {
	stream, _ := co.Config["streamSettings"].(map[string]interface{})
	parts := []string{}

	network := stringValue(stream["network"])
	if network == "" {
		switch outboundProtocol(co) {
		case "shadowsocks", "socks", "http", "freedom":
			network = "tcp"
		}
	}
	if network != "" {
		parts = append(parts, network)
	}

	security := stringValue(stream["security"])
	if security != "" && security != "none" {
		parts = append(parts, security)
	}

	serverName := firstNonEmpty(
		nestedString(stream, "realitySettings", "serverName"),
		nestedString(stream, "tlsSettings", "serverName"),
	)
	if serverName != "" {
		parts = append(parts, "sni="+serverName)
	}

	host := outboundHeaderHost(stream)
	if host != "" && host != serverName {
		parts = append(parts, "host="+host)
	}

	path := firstNonEmpty(
		nestedString(stream, "wsSettings", "path"),
		nestedString(stream, "xhttpSettings", "path"),
	)
	if path != "" {
		parts = append(parts, "path="+path)
	}

	fp := nestedString(stream, "realitySettings", "fingerprint")
	if fp != "" {
		parts = append(parts, "fp="+fp)
	}

	if len(parts) == 0 {
		return "-"
	}
	return trimText(strings.Join(parts, " "), 20)
}

func outboundHeaderHost(stream map[string]interface{}) string {
	if host := nestedString(stream, "xhttpSettings", "host"); host != "" {
		return host
	}
	if host := nestedString(stream, "wsSettings", "headers", "Host"); host != "" {
		return host
	}
	if vals := nestedStringSlice(stream, "httpSettings", "host"); len(vals) > 0 {
		return strings.Join(vals, ",")
	}
	return ""
}

func outboundDNSSummary(co config.CustomOutbound, fallback string) string {
	if len(co.DNSServers) == 0 {
		return fallback
	}
	return trimText(fallback+" "+strings.Join(co.DNSServers, ","), 48)
}

func normalizeDNSFlags(strategy string, servers []string, reset bool) (string, []string, error) {
	if reset {
		if strings.TrimSpace(strategy) != "" || len(servers) > 0 {
			return "", nil, fmt.Errorf("--reset cannot be combined with --strategy or --servers")
		}
		return "", nil, nil
	}

	normalizedServers := make([]string, 0, len(servers))
	seen := make(map[string]struct{}, len(servers))
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		if _, ok := seen[server]; ok {
			continue
		}
		seen[server] = struct{}{}
		normalizedServers = append(normalizedServers, server)
	}

	strategy = strings.TrimSpace(strategy)
	if strategy == "" {
		return "", normalizedServers, nil
	}

	normalizedStrategy, ok := xray.NormalizeDNSQueryStrategy(strategy)
	if !ok {
		return "", nil, fmt.Errorf("unsupported strategy %q (allowed: UseIP, UseIPv4, UseIPv6)", strategy)
	}
	return normalizedStrategy, normalizedServers, nil
}

func waitForLocalTCPPort(address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timed out waiting for %s", address)
	}
	return lastErr
}

func resolveDNSWithRetry(serverAddr string, domain string, qtype uint16, attempts int) ([]string, time.Duration, error) {
	if attempts < 1 {
		attempts = 1
	}
	var lastAnswers []string
	var lastDuration time.Duration
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		answers, duration, err := xray.ResolveDNSTCP(serverAddr, domain, qtype)
		lastAnswers, lastDuration, lastErr = answers, duration, err
		if err == nil {
			return answers, duration, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return lastAnswers, lastDuration, lastErr
}

func applyDNSConfigUpdate(co *config.CustomOutbound, strategy string, servers []string, reset bool) {
	if reset {
		co.DNSStrategy = ""
		co.DNSServers = nil
		return
	}
	if strategy != "" {
		co.DNSStrategy = strategy
	}
	if len(servers) > 0 {
		co.DNSServers = servers
	}
}

func getMapSlice(m map[string]interface{}, key string) []map[string]interface{} {
	raw, ok := m[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, item := range raw {
		if mm, ok := item.(map[string]interface{}); ok {
			out = append(out, mm)
		}
	}
	return out
}

func joinHostPort(hostVal, portVal interface{}) string {
	host := stringValue(hostVal)
	port := stringValue(portVal)
	if host == "" {
		return ""
	}
	if port == "" || port == "0" {
		return host
	}
	return net.JoinHostPort(host, port)
}

func stringValue(v interface{}) string {
	switch vv := v.(type) {
	case string:
		return vv
	case float64:
		return fmt.Sprintf("%.0f", vv)
	case int:
		return fmt.Sprintf("%d", vv)
	case int64:
		return fmt.Sprintf("%d", vv)
	case json.Number:
		return vv.String()
	default:
		return ""
	}
}

func nestedString(m map[string]interface{}, keys ...string) string {
	var cur interface{} = m
	for _, key := range keys {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return ""
		}
		cur, ok = mm[key]
		if !ok {
			return ""
		}
	}
	return stringValue(cur)
}

func nestedStringSlice(m map[string]interface{}, keys ...string) []string {
	var cur interface{} = m
	for _, key := range keys {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur, ok = mm[key]
		if !ok {
			return nil
		}
	}
	raw, ok := cur.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if v := stringValue(item); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func trimText(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	if limit <= 3 {
		return value[:limit]
	}
	return value[:limit-3] + "..."
}

var testOutboundCmd = &cobra.Command{
	Use:               "test [alias]",
	Short:             "Verify relay node connectivity",
	ValidArgsFunction: completeRelayAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		target := ""
		if len(args) > 0 {
			target = args[0]
		}
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		found := false
		for _, co := range cfg.CustomOutbounds {
			if target != "" && co.Alias != target {
				continue
			}
			found = true
			results := runIsolatedTest(cfg, co)
			printProbeResults(co.Alias, results)
		}
		if target != "" && !found {
			fmt.Printf("❌ Relay '%s' not found.\n", target)
		}
	},
}

var infoOutboundCmd = &cobra.Command{
	Use:               "info [alias]",
	Short:             "Fetch detailed landing profile and media unlock status",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		var target *config.CustomOutbound
		for _, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				target = &co
				break
			}
		}
		if target == nil {
			fmt.Printf("❌ Relay '%s' not found.\n", alias)
			return
		}
		fmt.Printf("🔍 Querying profile for [%s]...\n", alias)
		bin := xray.GetXrayBinaryPath()
		if _, err := os.Stat(bin); os.IsNotExist(err) {
			fmt.Println("⬇️ Xray core missing, downloading for test...")
			if err := xray.DownloadXray(); err != nil {
				fmt.Printf("❌ Failed to download Xray: %v\n", err)
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		testSocksPort, err := xray.GetFreePort()
		if err != nil {
			fmt.Printf("❌ Failed to allocate port: %v\n", err)
			return
		}
		apiPort, err := xray.GetFreePort()
		if err != nil {
			fmt.Printf("❌ Failed to allocate port: %v\n", err)
			return
		}

		testCfg := *cfg
		testCfg.Role = config.RoleServer
		testCfg.Gateway = config.GatewayConfig{}

		// v0.2.4: Randomize all active presets to avoid "device busy" during info test
		overrides := map[string]int{"test-socks": testSocksPort, "api": apiPort}
		for _, m := range testCfg.Presets {
			if m.Enabled {
				p, err := xray.GetFreePort()
				if err != nil {
					fmt.Printf("❌ Failed to allocate port: %v\n", err)
					return
				}
				overrides[string(m.Mode)] = p
			}
		}

		jsonData, _ := xray.GenerateXrayJSON(&testCfg, overrides, alias)
		_, cleanup, err := xray.StartXrayTemp(jsonData)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			return
		}
		defer cleanup()

		// Wait for Xray to bind
		socksAddr := fmt.Sprintf("127.0.0.1:%d", testSocksPort)
		if err := waitForLocalTCPPort(socksAddr, 5*time.Second); err != nil {
			fmt.Printf("❌ Test listener did not become ready: %v\n", err)
			cleanup()
			return
		}

		dialer, err := utils.NewSOCKS5Dialer(socksAddr)
		if err != nil {
			fmt.Printf("❌ Failed to build SOCKS5 dialer: %v\n", err)
			return
		}
		httpClient := &http.Client{
			Transport: &http.Transport{
				Dial:                  dialer.Dial,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
			},
			Timeout: 15 * time.Second,
		}
		profile := fetchProfile(httpClient)
		nf := testNetflix(httpClient)
		ds := testDisneyPlus(httpClient)
		tk := testTikTok(httpClient)
		gg := testGoogle(httpClient)
		oa := testOpenAI(httpClient)
		cl := testClaude(httpClient)
		fmt.Printf("\n✨ Landing Profile: %s\n   Exit IP: %s\n   Exit IPv4: %s\n   Exit IPv6: %s\n   ASN Type: %s (%s)\n   ASN: %s\n   Company: %s\n   Local: %s, %s, %s\n   Local Time: %s\n   Time Zone: %s\n\n   Media Unlock Tests (Streaming):\n   Netflix: %s  Disney+: %s  TikTok: %s\n\n   Media Unlock Tests (General):\n   Google: %s  OpenAI: %s  Claude: %s\n\n",
			alias, choosePrimaryIP(profile.IPv4, profile.IPv6), valueOrNA(profile.IPv4), valueOrNA(profile.IPv6), profile.ASNType, profile.Privacy, profile.ASN, profile.Org, profile.City, profile.Region, profile.Country, profile.LocalTime, profile.Timezone,
			nf, ds, tk, gg, oa, cl)
	},
}

func fetchProfile(client *http.Client) Profile {
	p := Profile{IP: "Unknown", ASN: "N/A", Org: "N/A", City: "N/A", Region: "N/A", Country: "N/A", Timezone: "UTC", ASNType: "N/A", Privacy: "N/A"}
	type fetchFn func(*http.Client, *Profile) bool
	for _, fn := range []fetchFn{fetchIPSBGeoIP, fetchIPInfo, fetchIPAPI, fetchPlainIP} {
		if fn(client, &p) && p.IP != "" && p.IP != "Unknown" {
			if p.LocalTime == "" {
				p.LocalTime = getLocalTime(p.Timezone)
			}
			enrichProfileIPFamilies(client, &p)
			return p
		}
	}
	if p.LocalTime == "" {
		p.LocalTime = getLocalTime(p.Timezone)
	}
	enrichProfileIPFamilies(client, &p)
	return p
}

func fetchJSON(client *http.Client, url string, target interface{}) bool {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "xray-proxya/"+Version)
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

func fetchText(client *http.Client, url string) string {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "xray-proxya/"+Version)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

func fetchIPSBGeoIP(client *http.Client, p *Profile) bool {
	var res struct {
		IP       string `json:"ip"`
		ASN      int    `json:"asn"`
		ISP      string `json:"isp"`
		City     string `json:"city"`
		Region   string `json:"region"`
		Country  string `json:"country"`
		Timezone string `json:"timezone"`
	}
	if !fetchJSON(client, "https://api.ip.sb/geoip", &res) || res.IP == "" {
		return false
	}
	p.IP, p.Org, p.City, p.Region, p.Country = res.IP, res.ISP, res.City, res.Region, res.Country
	p.Timezone = res.Timezone
	if res.ASN > 0 {
		p.ASN = fmt.Sprintf("AS%d", res.ASN)
	}
	if res.ISP != "" {
		p.ASNType = "DataCenter"
	}
	return true
}

func fetchIPInfo(client *http.Client, p *Profile) bool {
	var res struct {
		IP       string `json:"ip"`
		Org      string `json:"org"`
		City     string `json:"city"`
		Region   string `json:"region"`
		Country  string `json:"country"`
		Timezone string `json:"timezone"`
	}
	if !fetchJSON(client, "https://ipinfo.io/json", &res) || res.IP == "" {
		return false
	}
	p.IP, p.Org, p.City, p.Region, p.Country, p.Timezone = res.IP, res.Org, res.City, res.Region, res.Country, res.Timezone
	p.ASN = res.Org
	if res.Org != "" {
		p.ASNType = "DataCenter"
	}
	return true
}

func fetchIPAPI(client *http.Client, p *Profile) bool {
	var res struct {
		Query      string `json:"query"`
		Country    string `json:"country"`
		RegionName string `json:"regionName"`
		City       string `json:"city"`
		Org        string `json:"org"`
		AS         string `json:"as"`
		Timezone   string `json:"timezone"`
		Hosting    bool   `json:"hosting"`
		Proxy      bool   `json:"proxy"`
	}
	if !fetchJSON(client, "http://ip-api.com/json/?fields=66846719", &res) || res.Query == "" {
		return false
	}
	p.IP, p.Country, p.Region, p.City, p.Org, p.ASN, p.Timezone = res.Query, res.Country, res.RegionName, res.City, res.Org, res.AS, res.Timezone
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

func fetchPlainIP(client *http.Client, p *Profile) bool {
	for _, url := range []string{"https://ifconfig.me/ip", "https://api.ip.sb/ip", "https://ident.me"} {
		if ip := fetchText(client, url); ip != "" {
			p.IP = ip
			return true
		}
	}
	return false
}

func enrichProfileIPFamilies(client *http.Client, p *Profile) {
	if p.IPv4 == "" {
		p.IPv4 = fetchFamilyIP(client, "4")
	}
	if p.IPv6 == "" {
		p.IPv6 = fetchFamilyIP(client, "6")
	}
	if p.IP == "" || p.IP == "Unknown" {
		p.IP = choosePrimaryIP(p.IPv4, p.IPv6)
	}
}

func fetchFamilyIP(client *http.Client, family string) string {
	var urls []string
	switch family {
	case "4":
		urls = []string{"https://v4.ident.me", "https://ipv4.icanhazip.com", "https://api4.ipify.org"}
	case "6":
		urls = []string{"https://v6.ident.me", "https://ipv6.icanhazip.com", "https://api6.ipify.org"}
	default:
		urls = []string{"https://ident.me", "https://icanhazip.com", "https://api.ipify.org"}
	}
	for _, url := range urls {
		if ip := fetchText(client, url); ip != "" {
			return ip
		}
	}
	return ""
}

func getLocalTime(tz string) string {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.Now().Format("15:04:05")
	}
	return time.Now().In(loc).Format("2006-01-02 15:04:05")
}

func extractNetflixRegion(body []byte) string {
	re1 := regexp.MustCompile(`"id"\s*:\s*"([A-Z]{2})"\s*,\s*"countryName"`)
	if m := re1.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	re2 := regexp.MustCompile(`"requestCountryCode"\s*:\s*"([A-Z]{2})"`)
	if m := re2.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	re3 := regexp.MustCompile(`"countryCode"\s*:\s*"([A-Z]{2})"`)
	if m := re3.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
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

func testNetflix(client *http.Client) string {
	// 1. Test non-original title (Breaking Bad)
	req, err := http.NewRequest("GET", "https://www.netflix.com/title/70143836", nil)
	if err != nil {
		return "🔴"
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept-Language", "en")
	resp, err := client.Do(req)
	if err != nil {
		return "🔴"
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	bodyStr := string(body)

	hasOhNo := strings.Contains(bodyStr, "Oh no!") || strings.Contains(bodyStr, "netflix.com/browse") || resp.StatusCode == 404
	region := extractNetflixRegion(body)

	if resp.StatusCode == 200 && !hasOhNo {
		if region != "" {
			return region
		}
		return "🟢"
	}

	// 2. Test original title (Test Patterns) as fallback/originals check
	req2, err := http.NewRequest("GET", "https://www.netflix.com/title/80018499", nil)
	if err != nil {
		return "🔴"
	}
	req2.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req2.Header.Set("Accept-Language", "en")
	resp2, err := client.Do(req2)
	if err != nil {
		return "🔴"
	}
	defer resp2.Body.Close()

	body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 1024*1024))
	body2Str := string(body2)
	hasOhNo2 := strings.Contains(body2Str, "Oh no!") || strings.Contains(body2Str, "netflix.com/browse") || resp2.StatusCode == 404

	if region == "" {
		region = extractNetflixRegion(body2)
	}

	if resp2.StatusCode == 200 && !hasOhNo2 {
		if region != "" {
			return fmt.Sprintf("Originals (%s)", region)
		}
		return "Originals"
	}

	return "🚫"
}

func testDisneyPlus(client *http.Client) string {
	// 1. Fast BAMGrid API block check
	req, err := http.NewRequest("POST", "https://disney.api.edge.bamgrid.com/devices", strings.NewReader(`{"deviceFamily":"browser","applicationRuntime":"chrome","deviceProfile":"windows","attributes":{}}`))
	if err != nil {
		return "🔴"
	}
	req.Header.Set("Authorization", "Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84")
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return "🔴"
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		return "🚫"
	}

	// 2. Page redirect check
	req2, err := http.NewRequest("GET", "https://www.disneyplus.com", nil)
	if err != nil {
		return "🔴"
	}
	req2.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	resp2, err := client.Do(req2)
	if err != nil {
		return "🔴"
	}
	defer resp2.Body.Close()

	finalURL := resp2.Request.URL.String()
	if strings.Contains(finalURL, "preview") || strings.Contains(finalURL, "unavailable") {
		return "🚫"
	}

	re := regexp.MustCompile(`/([a-z]{2})-([a-z]{2})/`)
	if m := re.FindStringSubmatch(finalURL); len(m) > 2 {
		return strings.ToUpper(m[2])
	}

	return "🟢"
}

func testTikTok(client *http.Client) string {
	req, err := http.NewRequest("GET", "https://www.tiktok.com/", nil)
	if err != nil {
		return "🔴"
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return "🔴"
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || strings.Contains(resp.Request.URL.String(), "notfound") {
		return "🚫"
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	re := regexp.MustCompile(`"region"\s*:\s*"([A-Z]{2})"`)
	if m := re.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}

	if resp.StatusCode == 200 {
		return "🟢"
	}
	return fmt.Sprintf("⚠️%d", resp.StatusCode)
}

func testGoogle(client *http.Client) string {
	req, err := http.NewRequest("GET", "https://www.google.com", nil)
	if err != nil {
		return "🔴"
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return "🔴"
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Sprintf("⚠️%d", resp.StatusCode)
	}

	finalURL := resp.Request.URL.String()
	return parseGoogleRegion(finalURL)
}

func testOpenAI(client *http.Client) string {
	req, err := http.NewRequest("GET", "https://ios.chat.openai.com/public-api/mobile/server_status/v1", nil)
	if err != nil {
		return "🔴"
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return "🔴"
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return "🟢"
	}
	if resp.StatusCode == 403 || resp.StatusCode == 400 {
		return "🚫"
	}
	return fmt.Sprintf("⚠️%d", resp.StatusCode)
}

func testClaude(client *http.Client) string {
	req, err := http.NewRequest("GET", "https://claude.ai/login", nil)
	if err != nil {
		return "🔴"
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return "🔴"
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()
	if strings.Contains(finalURL, "/unsupported") || resp.StatusCode == 403 || resp.StatusCode == 400 {
		return "🚫"
	}
	if resp.StatusCode == 200 {
		return "🟢"
	}
	return fmt.Sprintf("⚠️%d", resp.StatusCode)
}

var probeLocalOutboundCmd = &cobra.Command{
	Use:               "probe-local [alias]",
	Short:             "Probe a relay's bound local socks/http listeners",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		for _, co := range cfg.CustomOutbounds {
			if co.Alias != alias {
				continue
			}
			if co.InternalProxyPort <= 0 {
				fmt.Printf("❌ Relay '%s' has no bound local proxy. Use 'proxy set %s'.\n", alias, alias)
				return
			}
			printProxyProbe(alias, "SOCKS", probeBoundProxy("socks5h://127.0.0.1:"+fmt.Sprint(co.InternalProxyPort)))
			printProxyProbe(alias, "HTTP", probeBoundProxy("http://127.0.0.1:"+fmt.Sprint(co.InternalProxyPort+1)))
			return
		}
		fmt.Printf("❌ Relay '%s' not found.\n", alias)
	},
}

var resolveOutboundCmd = &cobra.Command{
	Use:   "resolve [alias] [domain]",
	Short: "Resolve a domain through a relay's DNS path",
	Long: strings.TrimSpace(`
Start a temporary Xray instance with the selected relay and send explicit DNS
queries through that relay's configured DNS path.

This is useful for verifying per-relay DNS overrides from 'outbound set-dns'
without changing the running service.
`),
	Example: strings.TrimSpace(`
  xray-proxya outbound resolve test1 openai.com
  xray-proxya outbound resolve via-a-test1 example.org
`),
	Args: cobra.ExactArgs(2),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 0 {
			return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		alias, domain := args[0], args[1]
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}

		found := false
		for _, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("❌ Relay '%s' not found.\n", alias)
			return
		}

		bin := xray.GetXrayBinaryPath()
		if _, err := os.Stat(bin); os.IsNotExist(err) {
			fmt.Println("⬇️ Xray core missing, downloading for test...")
			if err := xray.DownloadXray(); err != nil {
				fmt.Printf("❌ Failed to download Xray: %v\n", err)
				return
			}
			time.Sleep(500 * time.Millisecond)
		}

		testCfg := *cfg
		testCfg.Role = config.RoleServer
		testCfg.Gateway = config.GatewayConfig{}

		testSocksPort, err := xray.GetFreePort()
		if err != nil {
			fmt.Printf("❌ Failed to allocate port: %v\n", err)
			return
		}
		apiPort, err := xray.GetFreePort()
		if err != nil {
			fmt.Printf("❌ Failed to allocate port: %v\n", err)
			return
		}
		dnsPort, err := xray.GetFreePort()
		if err != nil {
			fmt.Printf("❌ Failed to allocate port: %v\n", err)
			return
		}
		overrides := map[string]int{"test-socks": testSocksPort, "api": apiPort, "dns-in": dnsPort}
		for _, m := range testCfg.Presets {
			if m.Enabled {
				p, err := xray.GetFreePort()
				if err != nil {
					fmt.Printf("❌ Failed to allocate port: %v\n", err)
					return
				}
				overrides[string(m.Mode)] = p
			}
		}

		jsonData, err := xray.GenerateXrayJSON(&testCfg, overrides, alias)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			return
		}
		_, cleanup, err := xray.StartXrayTemp(jsonData)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			return
		}
		defer cleanup()

		serverAddr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
		if err := waitForLocalTCPPort(serverAddr, 5*time.Second); err != nil {
			fmt.Printf("❌ DNS test listener did not become ready: %v\n", err)
			return
		}
		for _, queryType := range []struct {
			label string
			value uint16
		}{
			{label: "A", value: xray.DNSTypeA},
			{label: "AAAA", value: xray.DNSTypeAAAA},
		} {
			answers, duration, err := resolveDNSWithRetry(serverAddr, domain, queryType.value, 3)
			if err != nil {
				fmt.Printf("%s  %s  ❌ %v\n", alias, queryType.label, err)
				continue
			}
			if len(answers) == 0 {
				fmt.Printf("%s  %s  ⚠️ no records (%dms)\n", alias, queryType.label, duration.Milliseconds())
				continue
			}
			fmt.Printf("%s  %s  %s  (%dms)\n", alias, queryType.label, strings.Join(answers, ", "), duration.Milliseconds())
		}
	},
}

var speedOutboundCmd = &cobra.Command{
	Use:               "speed [alias]",
	Short:             "Measure relay throughput, latency under load, and packet loss",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		var target *config.CustomOutbound
		for _, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				copy := co
				target = &copy
				break
			}
		}
		if target == nil {
			fmt.Printf("❌ Relay '%s' not found.\n", alias)
			return
		}

		sizeLimit := defaultSpeedTestSize
		if speedSize != "" {
			var err error
			sizeLimit, err = parseSize(speedSize)
			if err != nil {
				fmt.Printf("❌ Invalid size: %v\n", err)
				return
			}
			if sizeLimit <= 0 {
				fmt.Println("❌ Size must be greater than 0.")
				return
			}

		}

		duration := 0
		if speedTime > 0 {
			if speedTime > maxSpeedTestSeconds {
				fmt.Printf("❌ Speed test duration must be between 1 and %d seconds.\n", maxSpeedTestSeconds)
				return
			}
			duration = speedTime
		}

		runDownload := speedDownload || speedBoth
		runUpload := speedUpload || speedBoth
		if !runDownload && !runUpload {
			runDownload = true // Preserve the existing default behavior.
		}

		if runDownload {
			link, err := resolveSpeedTestLink(speedTestDownload, sizeLimit)
			if err != nil {
				fmt.Printf("❌ Invalid download test link: %v\n", err)
				return
			}
			if err := runRelaySpeedTest(cfg, *target, alias, speedTestDownload, link, duration, sizeLimit); err != nil {
				fmt.Printf("❌ Download speed test failed: %v\n", err)
				return
			}
		}
		if runUpload {
			link, err := resolveSpeedTestLink(speedTestUpload, sizeLimit)
			if err != nil {
				fmt.Printf("❌ Invalid upload test link: %v\n", err)
				return
			}
			if err := runRelaySpeedTest(cfg, *target, alias, speedTestUpload, link, duration, sizeLimit); err != nil {
				fmt.Printf("❌ Upload speed test failed: %v\n", err)
			}
		}
	},
}

func resolveSpeedTestLink(direction speedTestDirection, sizeLimit int64) (string, error) {
	link := strings.TrimSpace(speedLink)
	if direction == speedTestDownload && strings.TrimSpace(speedDownloadLink) != "" {
		link = strings.TrimSpace(speedDownloadLink)
	}
	if direction == speedTestUpload && strings.TrimSpace(speedUploadLink) != "" {
		link = strings.TrimSpace(speedUploadLink)
	}
	if link == "" {
		if direction == speedTestUpload {
			link = defaultUploadTestLink
		} else {
			link = defaultSpeedTestLink
		}
	}

	u, err := url.ParseRequestURI(link)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("must be an absolute HTTP(S) URL")
	}
	if direction == speedTestDownload && (strings.EqualFold(u.Hostname(), "speed.cloudflare.com") || u.Query().Get("bytes") != "") {
		q := u.Query()
		q.Set("bytes", fmt.Sprintf("%d", sizeLimit))
		u.RawQuery = q.Encode()
		link = u.String()
	}
	return link, nil
}

func runRelaySpeedTest(cfg *config.UserConfig, co config.CustomOutbound, alias string, direction speedTestDirection, link string, duration int, sizeLimit int64) error {
	fmt.Printf("🚀 Running %s speed test for [%s]\n", strings.ToLower(string(direction)), alias)
	fmt.Printf("   Link: %s\n", link)
	fmt.Printf("   Size Limit: %s\n", formatDecimalBytes(sizeLimit))
	if duration > 0 {
		fmt.Printf("   Duration: %ds\n", duration)
	} else {
		fmt.Printf("   Duration: single pass (timeout %s)\n", defaultSpeedTestTimeout)
	}

	result, err := runIsolatedSpeedTest(cfg, co, link, speedLatencyLink(direction, link), duration, sizeLimit, direction)
	if err != nil {
		return err
	}
	printSpeedResults(alias, result)
	return nil
}

func speedLatencyLink(direction speedTestDirection, speedLink string) string {
	u, err := url.Parse(speedLink)
	if err == nil && direction == speedTestUpload && strings.EqualFold(u.Hostname(), "speed.cloudflare.com") && u.Path == "/__up" {
		return "https://speed.cloudflare.com/__down?bytes=1"
	}
	return speedLink
}

func probeBoundProxy(proxyURL string) map[string]string {
	results := map[string]string{"IPv4": "N/A", "IPv6": "N/A"}
	transport := &http.Transport{Proxy: func(req *http.Request) (*url.URL, error) { return url.Parse(proxyURL) }}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	if wantIPv4() {
		if ip := fetchFamilyIP(client, "4"); ip != "" {
			results["IPv4"] = ip
		}
	}
	if wantIPv6() {
		if ip := fetchFamilyIP(client, "6"); ip != "" {
			results["IPv6"] = ip
		}
	}
	return results
}

func printProxyProbe(alias, proto string, results map[string]string) {
	fmt.Printf("[%s/%s] -> IPv4: %s | IPv6: %s\n", alias, proto, results["IPv4"], results["IPv6"])
}

func printProbeResults(alias string, results ProbeResult) {
	fmt.Printf("[%s] -> TCP: %s | UDP: %s | DNS: %s | IPv4: %s | IPv6: %s\n", alias, results.TCP, results.UDP, results.DNS, results.IPv4, results.IPv6)
}

func printSpeedResults(alias string, result SpeedResult) {
	fmt.Printf("\n[%s] %s Speed Test\n", alias, result.Direction)
	fmt.Printf("  Link: %s\n", result.Link)
	fmt.Printf("  Duration: %s\n", result.Duration.Round(time.Millisecond))
	fmt.Printf("  Data: %s\n", formatDecimalBytes(result.BytesTransferred))
	fmt.Printf("  Low 20%%: %s\n", formatBitrate(result.Low20SpeedBps))
	fmt.Printf("  Average: %s\n", formatBitrate(result.AvgSpeedBps))
	fmt.Printf("  Peak: %s\n", formatBitrate(result.PeakSpeedBps))
	fmt.Printf("  Idle Latency Avg: %s\n", formatDurationMetric(result.IdleLatencyAvg))
	fmt.Printf("  Load Latency Avg: %s\n", formatDurationMetric(result.LoadLatencyAvg))
	fmt.Printf("  Load Worst 5%%: %s\n", formatDurationMetric(result.LoadLatencyWorst5))
	fmt.Printf("  Latency Probe Failures: %.1f%% (%d samples)\n\n", result.LoadLatencyLossRate*100, result.LoadLatencySamples)
}

func choosePrimaryIP(v4, v6 string) string {
	if outboundIPv6 && !outboundIPv4 && v6 != "" {
		return v6
	}
	if outboundIPv4 && !outboundIPv6 && v4 != "" {
		return v4
	}
	if v4 != "" {
		return v4
	}
	if v6 != "" {
		return v6
	}
	return "Unknown"
}

func wantIPv4() bool {
	return outboundIPv4 || !outboundIPv6
}

func wantIPv6() bool {
	return outboundIPv6 || !outboundIPv4
}

func valueOrNA(v string) string {
	if v == "" {
		return "N/A"
	}
	return v
}

func startIsolatedOutboundInstance(cfg *config.UserConfig, alias string) (*http.Client, string, func(), error) {
	testSocksPort, err := xray.GetFreePort()
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to allocate port: %w", err)
	}
	apiPort, err := xray.GetFreePort()
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to allocate port: %w", err)
	}

	testCfg := *cfg
	testCfg.Role = config.RoleServer
	testCfg.Gateway = config.GatewayConfig{}

	overrides := map[string]int{"test-socks": testSocksPort, "api": apiPort}
	for _, m := range testCfg.Presets {
		if m.Enabled {
			p, err := xray.GetFreePort()
			if err != nil {
				return nil, "", nil, fmt.Errorf("failed to allocate port: %w", err)
			}
			overrides[string(m.Mode)] = p
		}
	}

	jsonData, err := xray.GenerateXrayJSON(&testCfg, overrides, alias)
	if err != nil {
		return nil, "", nil, err
	}

	_, cleanup, err := xray.StartXrayTemp(jsonData)
	if err != nil {
		return nil, "", nil, err
	}

	socksAddr := fmt.Sprintf("127.0.0.1:%d", testSocksPort)
	if err := waitForLocalTCPPort(socksAddr, 5*time.Second); err != nil {
		cleanup()
		return nil, "", nil, err
	}

	dialer, err := utils.NewSOCKS5Dialer(socksAddr)
	if err != nil {
		cleanup()
		return nil, "", nil, err
	}

	transport := &http.Transport{
		Dial:                  dialer.Dial,
		DisableCompression:    true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: 0}
	return client, socksAddr, cleanup, nil
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}

	var multiplier int64 = 1
	var unitLen int

	if strings.HasSuffix(s, "gib") || strings.HasSuffix(s, "gi") {
		multiplier = 1024 * 1024 * 1024
		unitLen = 3
		if strings.HasSuffix(s, "gi") {
			unitLen = 2
		}
	} else if strings.HasSuffix(s, "mib") || strings.HasSuffix(s, "mi") {
		multiplier = 1024 * 1024
		unitLen = 3
		if strings.HasSuffix(s, "mi") {
			unitLen = 2
		}
	} else if strings.HasSuffix(s, "kib") || strings.HasSuffix(s, "ki") {
		multiplier = 1024
		unitLen = 3
		if strings.HasSuffix(s, "ki") {
			unitLen = 2
		}
	} else if strings.HasSuffix(s, "gb") || strings.HasSuffix(s, "g") {
		multiplier = 1000 * 1000 * 1000
		unitLen = 2
		if strings.HasSuffix(s, "g") {
			unitLen = 1
		}
	} else if strings.HasSuffix(s, "mb") || strings.HasSuffix(s, "m") {
		multiplier = 1000 * 1000
		unitLen = 2
		if strings.HasSuffix(s, "m") {
			unitLen = 1
		}
	} else if strings.HasSuffix(s, "kb") || strings.HasSuffix(s, "k") {
		multiplier = 1000
		unitLen = 2
		if strings.HasSuffix(s, "k") {
			unitLen = 1
		}
	} else if strings.HasSuffix(s, "b") {
		multiplier = 1
		unitLen = 1
	}

	numStr := strings.TrimSpace(s[:len(s)-unitLen])
	if numStr == "" {
		return 0, fmt.Errorf("invalid size format: %q", s)
	}

	val, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size value: %w", err)
	}
	if val < 0 {
		return 0, fmt.Errorf("size cannot be negative")
	}

	return int64(val * float64(multiplier)), nil
}

func runIsolatedSpeedTest(cfg *config.UserConfig, co config.CustomOutbound, link, latencyLink string, durationSeconds int, maxBytes int64, direction speedTestDirection) (SpeedResult, error) {
	result := SpeedResult{Direction: string(direction), Link: link}

	client, _, cleanup, err := startIsolatedOutboundInstance(cfg, co.Alias)
	if err != nil {
		return result, err
	}
	defer cleanup()

	idleLatencies := measureLatencySeries(client, latencyLink, defaultLatencyProbeRuns)
	result.IdleLatencyAvg = averageDuration(idleLatencies)

	deadline := time.Now().Add(defaultSpeedTestTimeout)
	userDeadline := false
	if durationSeconds > 0 {
		deadline = time.Now().Add(time.Duration(durationSeconds) * time.Second)
		userDeadline = true
	}

	probeStop := make(chan struct{})
	var wg sync.WaitGroup
	var loadLatencies []time.Duration
	var loadProbeTotal int
	var loadProbeFailed int

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(latencyProbeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-probeStop:
				return
			case <-ticker.C:
				loadProbeTotal++
				latency, err := measureLatency(client, latencyLink)
				if err != nil {
					loadProbeFailed++
					continue
				}
				loadLatencies = append(loadLatencies, latency)
			}
		}
	}()

	startedAt := time.Now()
	var samples []float64
	probesClosed := false

	for {
		if time.Now().After(deadline) {
			break
		}
		if maxBytes > 0 && result.BytesTransferred >= maxBytes {
			break
		}
		var passErr error
		if direction == speedTestUpload {
			passErr = runUploadPass(client, link, deadline, &result.BytesTransferred, &samples, maxBytes)
		} else {
			passErr = runSpeedPass(client, link, deadline, &result.BytesTransferred, &samples, maxBytes)
		}
		if passErr != nil {
			if !probesClosed {
				close(probeStop)
				probesClosed = true
			}
			wg.Wait()
			if result.BytesTransferred == 0 {
				return result, passErr
			}
			break
		}
		if !userDeadline {
			break
		}
	}

	if !probesClosed {
		close(probeStop)
	}
	wg.Wait()

	if result.BytesTransferred == 0 {
		return result, fmt.Errorf("no data transferred")
	}

	result.Duration = time.Since(startedAt)
	if userDeadline {
		target := time.Duration(durationSeconds) * time.Second
		if result.Duration > target {
			result.Duration = target
		}
	}
	if result.Duration <= 0 {
		result.Duration = time.Millisecond
	}

	result.AvgSpeedBps = float64(result.BytesTransferred) / result.Duration.Seconds()
	result.PeakSpeedBps = peakSample(samples)
	result.Low20SpeedBps = lowPercentileAverage(samples, 0.20)
	result.LoadLatencyAvg = averageDuration(loadLatencies)
	result.LoadLatencyWorst5 = worstPercentileAverage(loadLatencies, 0.05)
	result.LoadLatencySamples = loadProbeTotal
	if loadProbeTotal > 0 {
		result.LoadLatencyLossRate = float64(loadProbeFailed) / float64(loadProbeTotal)
	}
	return result, nil
}

func setSpeedTestHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if req.URL != nil {
		origin := fmt.Sprintf("%s://%s", req.URL.Scheme, req.URL.Host)
		req.Header.Set("Origin", origin)
		req.Header.Set("Referer", origin+"/")
	} else {
		req.Header.Set("Origin", "https://speed.cloudflare.com")
		req.Header.Set("Referer", "https://speed.cloudflare.com/")
	}
	req.Header.Set("Accept-Encoding", "identity")
}

func runSpeedPass(client *http.Client, rawURL string, deadline time.Time, totalBytes *int64, samples *[]float64, maxBytes int64) error {
	ctx := context.Background()
	cancel := func() {}
	if !deadline.IsZero() {
		ctx, cancel = context.WithDeadline(ctx, deadline)
	}
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return err
	}
	setSpeedTestHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if !isSuccessfulSpeedStatus(resp.StatusCode) {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	buf := make([]byte, 128*1024)
	lastSampleAt := time.Now()
	var intervalBytes int64

	for {
		if !deadline.IsZero() && time.Now().After(deadline) {
			flushSpeedSample(samples, intervalBytes, time.Since(lastSampleAt))
			return nil
		}

		readBuf := buf
		if maxBytes > 0 {
			remaining := maxBytes - *totalBytes
			if remaining <= 0 {
				flushSpeedSample(samples, intervalBytes, time.Since(lastSampleAt))
				return nil
			}
			if remaining < int64(len(buf)) {
				readBuf = buf[:remaining]
			}
		}

		n, err := resp.Body.Read(readBuf)
		now := time.Now()
		if n > 0 {
			*totalBytes += int64(n)
			intervalBytes += int64(n)
		}
		if elapsed := now.Sub(lastSampleAt); elapsed >= speedSampleInterval {
			flushSpeedSample(samples, intervalBytes, elapsed)
			intervalBytes = 0
			lastSampleAt = now
		}
		if err == io.EOF {
			flushSpeedSample(samples, intervalBytes, time.Since(lastSampleAt))
			return nil
		}
		if err != nil {
			return err
		}
	}
}

type uploadPayloadReader struct {
	remaining      int64
	totalBytes     *int64
	samples        *[]float64
	intervalBytes  int64
	lastSampleAt   time.Time
}

func newUploadPayloadReader(size int64, totalBytes *int64, samples *[]float64) *uploadPayloadReader {
	return &uploadPayloadReader{
		remaining:    size,
		totalBytes:   totalBytes,
		samples:      samples,
		lastSampleAt: time.Now(),
	}
}

func (r *uploadPayloadReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = 0
	}
	n := len(p)
	r.remaining -= int64(n)
	r.intervalBytes += int64(n)
	if r.totalBytes != nil {
		*r.totalBytes += int64(n)
	}
	if elapsed := time.Since(r.lastSampleAt); elapsed >= speedSampleInterval {
		flushSpeedSample(r.samples, r.intervalBytes, elapsed)
		r.intervalBytes = 0
		r.lastSampleAt = time.Now()
	}
	return n, nil
}

func (r *uploadPayloadReader) flush() {
	flushSpeedSample(r.samples, r.intervalBytes, time.Since(r.lastSampleAt))
	r.intervalBytes = 0
}

func runUploadPass(client *http.Client, rawURL string, deadline time.Time, totalBytes *int64, samples *[]float64, maxBytes int64) error {
	if maxBytes <= 0 {
		return fmt.Errorf("upload test requires a positive size limit")
	}
	remaining := maxBytes
	if totalBytes != nil {
		remaining -= *totalBytes
	}
	if remaining <= 0 {
		return nil
	}

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	payload := newUploadPayloadReader(remaining, totalBytes, samples)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, payload)
	if err != nil {
		return err
	}
	req.ContentLength = remaining
	req.Header.Set("Content-Type", "application/octet-stream")
	setSpeedTestHeaders(req)

	resp, err := client.Do(req)
	payload.flush()
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if !isSuccessfulSpeedStatus(resp.StatusCode) {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}

func isSuccessfulSpeedStatus(statusCode int) bool {
	return statusCode >= http.StatusOK && statusCode < http.StatusBadRequest
}

func flushSpeedSample(samples *[]float64, bytes int64, elapsed time.Duration) {
	if samples == nil || elapsed <= 0 {
		return
	}
	if bytes < 0 {
		bytes = 0
	}
	*samples = append(*samples, float64(bytes)/elapsed.Seconds())
}

func measureLatencySeries(client *http.Client, rawURL string, runs int) []time.Duration {
	if runs < 1 {
		runs = 1
	}
	out := make([]time.Duration, 0, runs)
	for i := 0; i < runs; i++ {
		latency, err := measureLatency(client, rawURL)
		if err == nil {
			out = append(out, latency)
		}
		time.Sleep(150 * time.Millisecond)
	}
	return out
}

func measureLatency(client *http.Client, rawURL string) (time.Duration, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), latencyProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "HEAD", rawURL, nil)
	if err == nil {
		setSpeedTestHeaders(req)
		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 1))
			resp.Body.Close()
			if isSuccessfulSpeedStatus(resp.StatusCode) {
				return time.Since(start), nil
			}
		}
	}

	start = time.Now()
	req, err = http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return 0, err
	}
	setSpeedTestHeaders(req)
	req.Header.Set("Range", "bytes=0-0")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1))
	resp.Body.Close()
	if !isSuccessfulSpeedStatus(resp.StatusCode) {
		return 0, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return time.Since(start), nil
}

func averageDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	var total time.Duration
	for _, value := range values {
		total += value
	}
	return time.Duration(int64(total) / int64(len(values)))
}

func worstPercentileAverage(values []time.Duration, percentile float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	cp := append([]time.Duration(nil), values...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] > cp[j] })
	count := int(math.Ceil(float64(len(cp)) * percentile))
	if count < 1 {
		count = 1
	}
	return averageDuration(cp[:count])
}

func lowPercentileAverage(samples []float64, percentile float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	cp := append([]float64(nil), samples...)
	sort.Float64s(cp)
	count := int(math.Ceil(float64(len(cp)) * percentile))
	if count < 1 {
		count = 1
	}
	var total float64
	for _, sample := range cp[:count] {
		total += sample
	}
	return total / float64(count)
}

func peakSample(samples []float64) float64 {
	var peak float64
	for _, sample := range samples {
		if sample > peak {
			peak = sample
		}
	}
	return peak
}

func formatBitrate(bytesPerSecond float64) string {
	if bytesPerSecond <= 0 {
		return "N/A"
	}
	bitsPerSecond := bytesPerSecond * 8
	switch {
	case bitsPerSecond >= 1e9:
		return fmt.Sprintf("%.2f Gb/s", bitsPerSecond/1e9)
	case bitsPerSecond >= 1e6:
		return fmt.Sprintf("%.2f Mb/s", bitsPerSecond/1e6)
	case bitsPerSecond >= 1e3:
		return fmt.Sprintf("%.2f Kb/s", bitsPerSecond/1e3)
	default:
		return fmt.Sprintf("%.0f b/s", bitsPerSecond)
	}
}

func formatDecimalBytes(bytes int64) string {
	if bytes <= 0 {
		return "0 B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	value := float64(bytes)
	idx := 0
	for value >= 1000 && idx < len(units)-1 {
		value /= 1000
		idx++
	}
	return fmt.Sprintf("%.2f %s", value, units[idx])
}

func formatDurationMetric(d time.Duration) string {
	if d <= 0 {
		return "N/A"
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

var deleteOutboundCmd = &cobra.Command{
	Use:               "delete [alias]",
	Short:             "Remove a relay node from STAGING",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		newOutbounds := []config.CustomOutbound{}
		found := false
		for _, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				found = true
				continue
			}
			newOutbounds = append(newOutbounds, co)
		}
		if found {
			cfg.CustomOutbounds = newOutbounds
			if err := cfg.SaveEx(true); err == nil {
				fmt.Printf("✅ Deleted '%s' from STAGING.\n", alias)
				fmt.Println("🚀 Run 'apply' to commit changes.")
			}
		} else {
			fmt.Printf("❌ Relay '%s' not found.\n", alias)
		}
	},
}

var bindInterfaceCmd = &cobra.Command{
	Use:   "bind-interface [alias] [interface]",
	Short: "Create a direct relay bound to a local interface",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		alias, ifaceName := args[0], args[1]
		bindAddr, _ := cmd.Flags().GetString("addr")
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			cfg = &config.UserConfig{UUID: uuid.New().String(), Role: config.RoleServer}
		}
		if bindAddr == "" {
			iface, err := net.InterfaceByName(ifaceName)
			if err == nil {
				addrs, _ := iface.Addrs()
				for _, addr := range addrs {
					if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
						bindAddr = ipnet.IP.String()
						break
					}
				}
			}
		}
		out, err := xray.ParseInterfaceBind(ifaceName, bindAddr)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			return
		}
		newCO := config.CustomOutbound{Alias: alias, Enabled: true, UserUUID: uuid.New().String(), Config: out}
		cfg.CustomOutbounds = append(cfg.CustomOutbounds, newCO)
		if err := cfg.SaveEx(true); err == nil {
			fmt.Println("✅ Interface binding added to STAGING.")
			fmt.Println("🚀 Run 'apply' to commit changes.")
		}
	},
}

var setDNSRelayCmd = &cobra.Command{
	Use:   "set-dns [alias]",
	Short: "Configure DNS strategy for a relay (STAGING)",
	Long: strings.TrimSpace(`
Override the DNS behavior of a specific relay in the staging config.

You can set a DNS query strategy, provide dedicated upstream DNS servers, or
clear the relay-specific override with --reset. After reset, the relay falls
back to the global default DNS behavior generated from the active config.
`),
	Example: strings.TrimSpace(`
  xray-proxya outbound set-dns test1 --strategy UseIPv4
  xray-proxya outbound set-dns test1 --servers 1.1.1.1,8.8.8.8
  xray-proxya outbound set-dns test1 --strategy UseIP --servers https://dns.google/dns-query
  xray-proxya outbound set-dns test1 --reset
`),
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		strategy, _ := cmd.Flags().GetString("strategy")
		servers, _ := cmd.Flags().GetStringSlice("servers")
		reset, _ := cmd.Flags().GetBool("reset")
		normalizedStrategy, normalizedServers, err := normalizeDNSFlags(strategy, servers, reset)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			return
		}
		if normalizedStrategy == "" && len(normalizedServers) == 0 && !reset {
			fmt.Println("❌ Error: You must specify --strategy, --servers, or --reset")
			return
		}
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		for i, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				applyDNSConfigUpdate(&cfg.CustomOutbounds[i], normalizedStrategy, normalizedServers, reset)
				if err := cfg.SaveEx(true); err == nil {
					if reset {
						fmt.Printf("✅ DNS config reset for '%s'.\n", alias)
					} else {
						fmt.Printf("✅ DNS config updated for '%s'.\n", alias)
					}
					fmt.Println("🚀 Run 'apply' to commit changes.")
				}
				return
			}
		}
		fmt.Printf("❌ Relay '%s' not found.\n", alias)
	},
}

var setPrivateTargetsRelayCmd = &cobra.Command{
	Use:   "set-private-targets [alias] [true|false]",
	Short: "Allow or block relay access to next-hop private addresses (STAGING)",
	Long: strings.TrimSpace(`
Each relay link authenticates as the user associated with its outbound. By
default, that user cannot forward loopback or private-address requests to the
next hop: such requests stay direct on this server.

Set this to true only when the next hop intentionally exposes a private
service through this relay, such as a remote PathLink agent on 127.0.0.1.
`),
	Example: strings.TrimSpace(`
  xray-proxya outbound set-private-targets remote true
  xray-proxya outbound set-private-targets remote false
`),
	Args: cobra.ExactArgs(2),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 0 {
			return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
		}
		if len(args) == 1 {
			return []string{"true", "false"}, cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		allow, err := strconv.ParseBool(args[1])
		if err != nil {
			fmt.Println("❌ Value must be true or false.")
			return
		}
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			fmt.Println("❌", err)
			return
		}
		if !setRelayPrivateTargets(cfg, alias, allow) {
			fmt.Printf("❌ Relay '%s' not found.\n", alias)
			return
		}
		if err := cfg.SaveEx(true); err != nil {
			fmt.Println("❌", err)
			return
		}
		state := "blocked"
		if allow {
			state = "allowed"
		}
		fmt.Printf("✅ Private targets are %s for relay '%s' in STAGING.\n", state, alias)
		fmt.Println("🚀 Run 'apply' to commit changes.")
	},
}

func setRelayPrivateTargets(cfg *config.UserConfig, alias string, allow bool) bool {
	for i := range cfg.CustomOutbounds {
		if cfg.CustomOutbounds[i].Alias == alias {
			cfg.CustomOutbounds[i].AllowPrivateTargets = allow
			return true
		}
	}
	return false
}

func buildDNSProbeQuery() []byte {
	return []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
	}
}

func probeDNSViaTCP(dialer *utils.SOCKS5Dialer, servers []string) (time.Duration, error) {
	target := "8.8.8.8:53"
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		host := s
		if strings.Contains(s, "://") {
			if u, err := url.Parse(s); err == nil {
				host = u.Hostname()
			}
		} else if h, _, err := net.SplitHostPort(s); err == nil {
			host = h
		}
		if host != "" {
			target = net.JoinHostPort(host, "53")
			break
		}
	}

	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return 0, fmt.Errorf("tcp connect: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	query := buildDNSProbeQuery()
	// TCP DNS: 2-byte length prefix + query
	frame := make([]byte, 2+len(query))
	frame[0] = byte(len(query) >> 8)
	frame[1] = byte(len(query))
	copy(frame[2:], query)

	start := time.Now()
	if _, err := conn.Write(frame); err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}

	// Read 2-byte response length
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, fmt.Errorf("read length: %w", err)
	}
	respLen := int(header[0])<<8 | int(header[1])
	if respLen < 12 {
		return 0, fmt.Errorf("response too short: %d bytes", respLen)
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return 0, fmt.Errorf("read body: %w", err)
	}
	duration := time.Since(start)

	// Check ANCOUNT > 0 (bytes 6-7 of DNS response)
	ancount := int(resp[6])<<8 | int(resp[7])
	if ancount == 0 {
		return duration, fmt.Errorf("no answers in DNS response")
	}
	return duration, nil
}

func runIsolatedTest(cfg *config.UserConfig, co config.CustomOutbound) ProbeResult {
	results := ProbeResult{TCP: "FAIL", UDP: "FAIL", DNS: "FAIL", IPv4: "N/A", IPv6: "N/A"}
	client, socksAddr, cleanup, err := startIsolatedOutboundInstance(cfg, co.Alias)
	if err != nil {
		return results
	}
	defer cleanup()

	dialer, err := utils.NewSOCKS5Dialer(socksAddr)
	if err != nil {
		return results
	}
	httpClient := client

	// 1. Direct TCP Test (Bypass DNS)
	if conn, err := dialer.Dial("tcp", "8.8.8.8:443"); err == nil {
		results.TCP = "OK"
		conn.Close()
	} else {
		results.TCP = fmt.Sprintf("FAIL(443:%v)", err)
	}

	if results.TCP == "OK" {
		if conn, err := dialer.Dial("tcp", "8.8.8.8:80"); err == nil {
			conn.Close()
		} else {
			results.TCP = fmt.Sprintf("OK(443),FAIL(80:%v)", err)
		}
	}

	// 2. Fetch Exit IPs
	if wantIPv4() {
		if ip := fetchFamilyIP(httpClient, "4"); ip != "" {
			results.IPv4 = ip
		}
	}
	if wantIPv6() {
		if ip := fetchFamilyIP(httpClient, "6"); ip != "" {
			results.IPv6 = ip
		}
	}

	// 3. DNS Test (actual resolution via TCP)
	dnsDuration, dnsErr := probeDNSViaTCP(dialer, co.DNSServers)
	if dnsErr == nil {
		results.DNS = fmt.Sprintf("OK(%dms)", dnsDuration.Milliseconds())
	} else {
		results.DNS = fmt.Sprintf("FAIL(%v)", dnsErr)
	}
	udpDuration, udpErr := xray.TestUDP(socksAddr, "user-"+co.Alias, "test")
	if udpErr == nil {
		results.UDP = fmt.Sprintf("OK(%dms)", udpDuration.Milliseconds())
	} else {
		results.UDP = fmt.Sprintf("FAIL(%v)", udpErr)
	}

	return results
}

func init() {
	bindInterfaceCmd.Flags().StringP("addr", "a", "", "Specific IP address to bind")
	setDNSRelayCmd.Flags().StringP("strategy", "s", "", "DNS query strategy: UseIP, UseIPv4, or UseIPv6")
	setDNSRelayCmd.Flags().StringSliceP("servers", "v", []string{}, "DNS servers for this relay, e.g. https://dns.google/dns-query or 1.1.1.1")
	setDNSRelayCmd.Flags().BoolP("reset", "r", false, "Clear relay-specific DNS overrides and return to the default DNS config")
	testOutboundCmd.Flags().BoolVarP(&outboundIPv4, "ipv4", "4", false, "Probe IPv4")
	testOutboundCmd.Flags().BoolVarP(&outboundIPv6, "ipv6", "6", false, "Probe IPv6")
	infoOutboundCmd.Flags().BoolVarP(&outboundIPv4, "ipv4", "4", false, "Probe IPv4")
	infoOutboundCmd.Flags().BoolVarP(&outboundIPv6, "ipv6", "6", false, "Probe IPv6")
	probeLocalOutboundCmd.Flags().BoolVarP(&outboundIPv4, "ipv4", "4", false, "Probe IPv4")
	probeLocalOutboundCmd.Flags().BoolVarP(&outboundIPv6, "ipv6", "6", false, "Probe IPv6")
	speedOutboundCmd.Flags().StringVarP(&speedLink, "link", "l", "", "Speed test URL (applies to the selected direction, or both)")
	speedOutboundCmd.Flags().StringVar(&speedUploadLink, "link-upload", "", "Upload speed test URL (overrides --link for uploads)")
	speedOutboundCmd.Flags().StringVar(&speedDownloadLink, "link-download", "", "Download speed test URL (overrides --link for downloads)")
	speedOutboundCmd.Flags().IntVarP(&speedTime, "time", "t", 0, "Continuous test duration in seconds (max 3600)")
	speedOutboundCmd.Flags().StringVarP(&speedSize, "size", "s", "", "Maximum total transfer for the test session (e.g. 50MB, 10MB, 500KB, 50000000)")
	speedOutboundCmd.Flags().BoolVarP(&speedUpload, "upload", "u", false, "Run an upload speed test")
	speedOutboundCmd.Flags().BoolVarP(&speedDownload, "download", "d", false, "Run a download speed test")
	speedOutboundCmd.Flags().BoolVar(&speedBoth, "both", false, "Run download first, then upload, with separate reports")
	bindInterfaceCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		switch len(args) {
		case 0:
			return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
		case 1:
			ifaces, err := net.Interfaces()
			if err != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			var names []string
			for _, iface := range ifaces {
				if iface.Name != "" {
					names = append(names, iface.Name)
				}
			}
			return names, cobra.ShellCompDirectiveNoFileComp
		default:
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
	}
	setDNSRelayCmd.RegisterFlagCompletionFunc("strategy", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"UseIP", "UseIPv4", "UseIPv6"}, cobra.ShellCompDirectiveNoFileComp
	})
	outboundCmd.AddCommand(addOutboundCmd, listOutboundCmd, testOutboundCmd, infoOutboundCmd, speedOutboundCmd, deleteOutboundCmd, bindInterfaceCmd, setDNSRelayCmd, setPrivateTargetsRelayCmd, probeLocalOutboundCmd, resolveOutboundCmd)
	rootCmd.AddCommand(outboundCmd)
}
