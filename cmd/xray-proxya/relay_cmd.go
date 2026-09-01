package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/relayinfo"
	"xray-proxya/internal/relayspeed"
	"xray-proxya/internal/relaytest"
	"xray-proxya/internal/xray"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var (
	relayTestFull        bool
	relayTestJSON        bool
	relayTestConcurrency int
	relayInfoFull        bool
	relayInfoJSON        bool
	relayInfoConcurrency int
	relayInfoIPv4        bool
	relayInfoIPv6        bool
	relayInfoNatural     bool
	outboundIPv4         bool
	outboundIPv6         bool
	relaySpeedProvider   string
	relaySpeedJSON       bool
	relaySpeedDownload   bool
	relaySpeedUpload     bool
	relaySpeedBoth       bool
	relaySpeedSize       string
	relaySpeedTime       int
	relaySpeedLink       string
	relaySpeedLinkDL     string
	relaySpeedLinkUL     string
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
		res, err := relaytest.RunTest(context.Background(), cfg, alias, relaytest.ModeSimple)
		if err != nil || res == nil {
			fmt.Printf("❌ Test failed: %v\n", err)
		} else {
			fmt.Print(relaytest.RenderTerminal([]*relaytest.TestResult{res}))
			fmt.Println()
		}
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
	Short:             "Verify relay node connectivity and protocol health",
	ValidArgsFunction: completeRelayAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}

		mode := relaytest.ModeSimple
		if relayTestFull {
			mode = relaytest.ModeFull
		}

		ctx := context.Background()

		if len(args) > 0 {
			target := args[0]
			found := false
			for _, co := range cfg.CustomOutbounds {
				if co.Alias == target {
					found = true
					break
				}
			}
			if !found {
				fmt.Printf("❌ Relay '%s' not found.\n", target)
				return
			}

			res, err := relaytest.RunTest(ctx, cfg, target, mode)
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
				return
			}
			if relayTestJSON {
				out, _ := relaytest.RenderJSON(res)
				fmt.Println(out)
			} else {
				fmt.Print(relaytest.RenderTerminal([]*relaytest.TestResult{res}))
				fmt.Println()
			}
			return
		}

		if len(cfg.CustomOutbounds) == 0 {
			fmt.Println("No custom relay nodes configured.")
			return
		}

		var aliases []string
		for _, co := range cfg.CustomOutbounds {
			aliases = append(aliases, co.Alias)
		}

		results, err := relaytest.RunTests(ctx, cfg, aliases, mode, relayTestConcurrency)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			return
		}

		if relayTestJSON {
			out, _ := relaytest.RenderJSON(results)
			fmt.Println(out)
		} else {
			fmt.Print(relaytest.RenderTerminal(results))
		}
	},
}

var infoOutboundCmd = &cobra.Command{
	Use:               "info [alias...]",
	Short:             "Fetch detailed landing profile and media unlock status",
	ValidArgsFunction: completeRelayAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}

		mode := relayinfo.ModeSimple
		if relayInfoFull {
			mode = relayinfo.ModeFull
		}

		family := relayinfo.IPFamilyAuto
		if relayInfoNatural {
			family = relayinfo.IPFamilyNatural
		} else if relayInfoIPv6 && !relayInfoIPv4 {
			family = relayinfo.IPFamilyIPv6
		} else if relayInfoIPv4 && !relayInfoIPv6 {
			family = relayinfo.IPFamilyIPv4
		}

		ctx := context.Background()

		if len(args) == 1 {
			target := args[0]
			found := false
			for _, co := range cfg.CustomOutbounds {
				if co.Alias == target {
					found = true
					break
				}
			}
			if !found {
				fmt.Printf("❌ Relay '%s' not found.\n", target)
				return
			}

			res, err := relayinfo.RunInfo(ctx, cfg, target, mode, family)
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
				return
			}
			if relayInfoJSON {
				out, _ := relayinfo.RenderJSON(res)
				fmt.Println(out)
			} else {
				fmt.Print(relayinfo.RenderTerminal([]*relayinfo.InfoResult{res}))
			}
			return
		}

		var targets []string
		if len(args) > 1 {
			for _, a := range args {
				found := false
				for _, co := range cfg.CustomOutbounds {
					if co.Alias == a {
						found = true
						break
					}
				}
				if !found {
					fmt.Printf("❌ Relay '%s' not found.\n", a)
					return
				}
				targets = append(targets, a)
			}
		} else {
			if len(cfg.CustomOutbounds) == 0 {
				fmt.Println("No custom relay nodes configured.")
				return
			}
			for _, co := range cfg.CustomOutbounds {
				targets = append(targets, co.Alias)
			}
		}

		results, err := relayinfo.RunInfos(ctx, cfg, targets, mode, family, relayInfoConcurrency)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			return
		}

		if relayInfoJSON {
			out, _ := relayinfo.RenderJSON(results)
			fmt.Println(out)
		} else {
			fmt.Print(relayinfo.RenderTerminal(results))
		}
	},
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
	Use:               "speed [alias...]",
	Short:             "Measure relay throughput and latency under load across providers with queue execution",
	ValidArgsFunction: completeRelayAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}

		sizeLimit := int64(25 * 1024 * 1024)
		if relaySpeedSize != "" {
			var err error
			sizeLimit, err = relayspeed.ParseSize(relaySpeedSize)
			if err != nil {
				fmt.Printf("❌ Invalid size: %v\n", err)
				return
			}
		}

		direction := relayspeed.DirectionDownload
		if relaySpeedBoth || (relaySpeedDownload && relaySpeedUpload) {
			direction = relayspeed.DirectionBoth
		} else if relaySpeedUpload {
			direction = relayspeed.DirectionUpload
		}

		customDL := relaySpeedLink
		if relaySpeedLinkDL != "" {
			customDL = relaySpeedLinkDL
		}
		customUL := relaySpeedLink
		if relaySpeedLinkUL != "" {
			customUL = relaySpeedLinkUL
		}

		opts := relayspeed.Options{
			Provider:          relaySpeedProvider,
			Direction:         direction,
			SizeBytes:         sizeLimit,
			DurationSeconds:   relaySpeedTime,
			CustomDownloadURL: customDL,
			CustomUploadURL:   customUL,
		}

		ctx := context.Background()

		// Single node test
		if len(args) == 1 {
			target := args[0]
			found := false
			for _, co := range cfg.CustomOutbounds {
				if co.Alias == target {
					found = true
					break
				}
			}
			if !found {
				fmt.Printf("❌ Relay '%s' not found.\n", target)
				return
			}

			if !relaySpeedJSON {
				providerName := opts.Provider
				if providerName == "" {
					providerName = "cloudflare"
				}
				fmt.Printf("🚀 Running speed test for [%s] (Provider: %s)...\n", target, providerName)
			}

			res, err := relayspeed.RunSpeed(ctx, cfg, target, opts, nil)
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
				return
			}

			if relaySpeedJSON {
				out, _ := relayspeed.RenderJSON(res)
				fmt.Println(out)
			} else {
				fmt.Print(relayspeed.RenderSingleCard(res))
			}
			return
		}

		// Multiple nodes / All nodes (Queue execution)
		var targets []string
		if len(args) > 1 {
			for _, a := range args {
				found := false
				for _, co := range cfg.CustomOutbounds {
					if co.Alias == a {
						found = true
						break
					}
				}
				if !found {
					fmt.Printf("❌ Relay '%s' not found.\n", a)
					return
				}
				targets = append(targets, a)
			}
		} else {
			if len(cfg.CustomOutbounds) == 0 {
				fmt.Println("No custom relay nodes configured.")
				return
			}
			for _, co := range cfg.CustomOutbounds {
				targets = append(targets, co.Alias)
			}
		}

		if !relaySpeedJSON {
			providerName := opts.Provider
			if providerName == "" {
				providerName = "cloudflare"
			}
			fmt.Printf("🚀 Starting sequential speed test queue (%d nodes, Provider: %s)...\n\n", len(targets), providerName)
		}

		results, err := relayspeed.RunSpeedQueue(ctx, cfg, targets, opts, nil)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			return
		}

		if relaySpeedJSON {
			out, _ := relayspeed.RenderJSON(results)
			fmt.Println(out)
		} else {
			fmt.Print(relayspeed.RenderTable(results))
		}
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

func init() {
	bindInterfaceCmd.Flags().StringP("addr", "a", "", "Specific IP address to bind")
	setDNSRelayCmd.Flags().StringP("strategy", "s", "", "DNS query strategy: UseIP, UseIPv4, or UseIPv6")
	setDNSRelayCmd.Flags().StringSliceP("servers", "v", []string{}, "DNS servers for this relay, e.g. https://dns.google/dns-query or 1.1.1.1")
	setDNSRelayCmd.Flags().BoolP("reset", "r", false, "Clear relay-specific DNS overrides and return to the default DNS config")
	testOutboundCmd.Flags().BoolVarP(&relayTestFull, "full", "f", false, "Run complete diagnostic mode including modern web protocols and UDP stack")
	testOutboundCmd.Flags().BoolVarP(&relayTestJSON, "json", "j", false, "Output test results in JSON format")
	testOutboundCmd.Flags().IntVar(&relayTestConcurrency, "concurrency", 4, "Number of concurrent relay tests")
	infoOutboundCmd.Flags().BoolVarP(&relayInfoFull, "full", "f", false, "Run complete profile and unlock mode including timezone and local time")
	infoOutboundCmd.Flags().BoolVarP(&relayInfoJSON, "json", "j", false, "Output info results in JSON format")
	infoOutboundCmd.Flags().IntVarP(&relayInfoConcurrency, "concurrency", "c", 4, "Number of concurrent relay info tests")
	infoOutboundCmd.Flags().BoolVarP(&relayInfoIPv4, "ipv4", "4", false, "Force IPv4 stack for unlock and profile testing")
	infoOutboundCmd.Flags().BoolVarP(&relayInfoIPv6, "ipv6", "6", false, "Force IPv6 stack for unlock and profile testing")
	infoOutboundCmd.Flags().BoolVarP(&relayInfoNatural, "natural", "n", false, "Use natural dual-stack DNS resolution and domain routing")
	probeLocalOutboundCmd.Flags().BoolVarP(&outboundIPv4, "ipv4", "4", false, "Probe IPv4")
	probeLocalOutboundCmd.Flags().BoolVarP(&outboundIPv6, "ipv6", "6", false, "Probe IPv6")
	speedOutboundCmd.Flags().StringVarP(&relaySpeedProvider, "provider", "p", "cloudflare", "Speed test provider (cloudflare, fast, mlab, ookla, custom)")
	speedOutboundCmd.Flags().BoolVarP(&relaySpeedJSON, "json", "j", false, "Output speed test results in JSON format")
	speedOutboundCmd.Flags().BoolVarP(&relaySpeedDownload, "download", "d", false, "Run a download speed test")
	speedOutboundCmd.Flags().BoolVarP(&relaySpeedUpload, "upload", "u", false, "Run an upload speed test")
	speedOutboundCmd.Flags().BoolVarP(&relaySpeedBoth, "both", "b", false, "Run both download and upload speed tests")
	speedOutboundCmd.Flags().StringVarP(&relaySpeedSize, "size", "s", "25MB", "Maximum total transfer size (e.g. 10MB, 25MB, 50MB, 100MB)")
	speedOutboundCmd.Flags().IntVarP(&relaySpeedTime, "time", "t", 0, "Speed test duration limit in seconds (0 = single pass)")
	speedOutboundCmd.Flags().StringVarP(&relaySpeedLink, "link", "l", "", "Custom speed test URL (for custom provider)")
	speedOutboundCmd.Flags().StringVar(&relaySpeedLinkDL, "link-download", "", "Custom download URL (for custom provider)")
	speedOutboundCmd.Flags().StringVar(&relaySpeedLinkUL, "link-upload", "", "Custom upload URL (for custom provider)")
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
