package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/net/proxy"
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

var (
	outboundIPv4 bool
	outboundIPv6 bool
)

var outboundCmd = &cobra.Command{
	Use:     "outbound",
	Aliases: []string{"node", "relay"},
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
		fmt.Printf("\n%-3s | %-14s | %-5s | %-11s | %-30s | %-20s | %-18s | %-s\n", "ID", "ALIAS", "STATE", "PROTO", "REMOTE", "TRANSPORT", "INTERNAL", "DNS")
		fmt.Println("----------------------------------------------------------------------------------------------------------------------------------------")
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
			fmt.Printf(
				"%-3d | %-14s | %-5s | %-11s | %-30s | %-20s | %-18s | %-s\n",
				i+1,
				co.Alias,
				status,
				outboundProtocol(co),
				outboundRemoteSummary(co),
				outboundTransportSummary(co),
				internal,
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
	Use:   "test [alias]",
	Short: "Verify relay node connectivity",
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		target := ""
		if len(args) > 0 {
			target = args[0]
		}
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		for _, co := range cfg.CustomOutbounds {
			if target != "" && co.Alias != target {
				continue
			}
			results := runIsolatedTest(cfg, co)
			printProbeResults(co.Alias, results)
		}
	},
}

var infoOutboundCmd = &cobra.Command{
	Use:   "info [alias]",
	Short: "Fetch detailed landing profile and media unlock status",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	},
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
		testSocksPort, _ := xray.GetFreePort()
		apiPort, _ := xray.GetFreePort()
		dnsPort, _ := xray.GetFreePort()

		testCfg := *cfg
		testCfg.Role = config.RoleServer
		testCfg.Gateway = config.GatewayConfig{}

		// v0.2.4: Randomize all active presets to avoid "device busy" during info test
		overrides := map[string]int{"test-socks": testSocksPort, "api": apiPort, "dns-in": dnsPort}
		for _, m := range testCfg.ActiveModes {
			if m.Enabled {
				p, _ := xray.GetFreePort()
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
		time.Sleep(1 * time.Second)

		socksAddr := fmt.Sprintf("127.0.0.1:%d", testSocksPort)
		dialer, _ := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
		httpClient := &http.Client{
			Transport: &http.Transport{
				Dial:                  dialer.Dial,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
			},
			Timeout: 15 * time.Second,
		}
		profile := fetchProfile(httpClient)
		nf := testMedia(httpClient, "https://www.netflix.com/title/80018499")
		yt := testMedia(httpClient, "https://www.youtube.com/premium")
		ds := testMedia(httpClient, "https://www.disneyplus.com")
		fmt.Printf("\n✨ Landing Profile: %s\n   Exit IP: %s\n   Exit IPv4: %s\n   Exit IPv6: %s\n   ASN Type: %s (%s)\n   ASN: %s\n   Company: %s\n   Local: %s, %s, %s\n   Local Time: %s\n   Time Zone: %s\n\n   Media Unlock Tests:\n   Netflix: %s  YouTube: %s  Disney+: %s\n\n",
			alias, choosePrimaryIP(profile.IPv4, profile.IPv6), valueOrNA(profile.IPv4), valueOrNA(profile.IPv6), profile.ASNType, profile.Privacy, profile.ASN, profile.Org, profile.City, profile.Region, profile.Country, profile.LocalTime, profile.Timezone, nf, yt, ds)
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
	req.Header.Set("User-Agent", "xray-proxya/0.2.6")
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
	req.Header.Set("User-Agent", "xray-proxya/0.2.6")
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

func testMedia(client *http.Client, url string) string {
	resp, err := client.Get(url)
	if err != nil {
		return "🔴"
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return "🟢"
	}
	if resp.StatusCode == 403 {
		return "🚫"
	}
	return fmt.Sprintf("⚠️%d", resp.StatusCode)
}

var probeLocalOutboundCmd = &cobra.Command{
	Use:   "probe-local [alias]",
	Short: "Probe a relay's bound local socks/http listeners",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	},
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
				fmt.Printf("❌ Relay '%s' has no bound local proxy. Use 'outbound set-internal-proxy %s'.\n", alias, alias)
				return
			}
			printProxyProbe(alias, "SOCKS", probeBoundProxy("socks5h://127.0.0.1:"+fmt.Sprint(co.InternalProxyPort)))
			printProxyProbe(alias, "HTTP", probeBoundProxy("http://127.0.0.1:"+fmt.Sprint(co.InternalProxyPort+1)))
			return
		}
		fmt.Printf("❌ Relay '%s' not found.\n", alias)
	},
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

var deleteOutboundCmd = &cobra.Command{
	Use:   "delete [alias]",
	Short: "Remove a relay node from STAGING",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	},
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
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		strategy, _ := cmd.Flags().GetString("strategy")
		servers, _ := cmd.Flags().GetStringSlice("servers")
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		for i, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				if strategy != "" {
					cfg.CustomOutbounds[i].DNSStrategy = strategy
				}
				if len(servers) > 0 {
					cfg.CustomOutbounds[i].DNSServers = servers
				}
				if err := cfg.SaveEx(true); err == nil {
					fmt.Printf("✅ DNS strategy updated for '%s'.\n", alias)
					fmt.Println("🚀 Run 'apply' to commit changes.")
				}
				return
			}
		}
		fmt.Printf("❌ Relay '%s' not found.\n", alias)
	},
}

var setInternalProxyCmd = &cobra.Command{
	Use:   "set-internal-proxy [alias]",
	Short: "Provide local unauthenticated socks/http proxy for a relay (STAGING)",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		port, _ := cmd.Flags().GetInt("port")
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		for i, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				if port == 0 {
					for {
						p, _ := xray.GetFreePort()
						if utils.IsPortFree(p + 1) {
							port = p
							break
						}
					}
				} else if !utils.IsPortFree(port) || !utils.IsPortFree(port+1) {
					fmt.Printf("❌ Port %d or %d is in use.\n", port, port+1)
					return
				}
				cfg.CustomOutbounds[i].InternalProxyPort = port
				if err := cfg.SaveEx(true); err == nil {
					fmt.Printf("✅ Internal proxy for '%s' in STAGING -> Socks:%d, HTTP:%d\n", alias, port, port+1)
					fmt.Println("🚀 Run 'apply' to commit.")
				}
				return
			}
		}
		fmt.Printf("❌ Relay '%s' not found.\n", alias)
	},
}

func runIsolatedTest(cfg *config.UserConfig, co config.CustomOutbound) ProbeResult {
	results := ProbeResult{TCP: "FAIL", UDP: "FAIL", DNS: "FAIL", IPv4: "N/A", IPv6: "N/A"}
	testSocksPort, _ := xray.GetFreePort()
	apiPort, _ := xray.GetFreePort()
	dnsPort, _ := xray.GetFreePort()

	testCfg := *cfg
	testCfg.Role = config.RoleServer
	testCfg.Gateway = config.GatewayConfig{}

	// v0.2.4: Fully randomized overrides for test instance
	overrides := map[string]int{"test-socks": testSocksPort, "api": apiPort, "dns-in": dnsPort}
	for _, m := range testCfg.ActiveModes {
		if m.Enabled {
			p, _ := xray.GetFreePort()
			overrides[string(m.Mode)] = p
		}
	}

	jsonData, err := xray.GenerateXrayJSON(&testCfg, overrides, co.Alias)
	if err != nil {
		return results
	}

	cmd, cleanup, err := xray.StartXrayTemp(jsonData)
	if err != nil {
		return results
	}
	_ = cmd // explicitly ignore if we only need cleanup
	defer cleanup()

	// Wait a bit for Xray to start
	time.Sleep(1 * time.Second)

	socksAddr := fmt.Sprintf("127.0.0.1:%d", testSocksPort)
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return results
	}

	httpClient := &http.Client{Transport: &http.Transport{Dial: dialer.Dial}, Timeout: 10 * time.Second}

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

	// 3. DNS Test (via Outbound)
	conn, err := dialer.Dial("tcp", "8.8.8.8:53")
	if err == nil {
		results.DNS = "OK"
		conn.Close()
	}
	duration, err := xray.TestUDP(socksAddr, "user-"+co.Alias, "test")
	if err == nil {
		results.UDP = fmt.Sprintf("OK(%dms)", duration.Milliseconds())
	} else {
		results.UDP = fmt.Sprintf("FAIL(%v)", err)
	}

	return results
}

func init() {
	bindInterfaceCmd.Flags().StringP("addr", "a", "", "Specific IP address to bind")
	setDNSRelayCmd.Flags().StringP("strategy", "s", "", "Strategy: follow, direct, manual")
	setDNSRelayCmd.Flags().StringSliceP("servers", "v", []string{}, "Manual DNS Servers")
	setInternalProxyCmd.Flags().IntP("port", "p", 0, "Base port (0 for random)")
	testOutboundCmd.Flags().BoolVarP(&outboundIPv4, "ipv4", "4", false, "Probe IPv4")
	testOutboundCmd.Flags().BoolVarP(&outboundIPv6, "ipv6", "6", false, "Probe IPv6")
	infoOutboundCmd.Flags().BoolVarP(&outboundIPv4, "ipv4", "4", false, "Probe IPv4")
	infoOutboundCmd.Flags().BoolVarP(&outboundIPv6, "ipv6", "6", false, "Probe IPv6")
	probeLocalOutboundCmd.Flags().BoolVarP(&outboundIPv4, "ipv4", "4", false, "Probe IPv4")
	probeLocalOutboundCmd.Flags().BoolVarP(&outboundIPv6, "ipv6", "6", false, "Probe IPv6")
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
		return []string{"follow", "direct", "manual"}, cobra.ShellCompDirectiveNoFileComp
	})
	outboundCmd.AddCommand(addOutboundCmd, listOutboundCmd, testOutboundCmd, infoOutboundCmd, deleteOutboundCmd, bindInterfaceCmd, setDNSRelayCmd, setInternalProxyCmd, probeLocalOutboundCmd)
	rootCmd.AddCommand(outboundCmd)
}
