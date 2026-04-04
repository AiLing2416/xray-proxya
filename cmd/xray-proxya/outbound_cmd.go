package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
	"io"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/net/proxy"
)

var outboundCmd = &cobra.Command{
	Use:   "outbound",
	Short: "Manage relay nodes (Custom Outbounds) in STAGING area",
}

func getRelayAliases() []string {
	cfg, _ := config.LoadConfigEx(true)
	if cfg == nil { return nil }
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
		if cfg == nil { cfg = &config.UserConfig{UUID: uuid.New().String(), Role: config.RoleServer} }

		for _, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				fmt.Printf("❌ Alias '%s' already exists.\n", alias)
				return
			}
		}

		out, err := xray.ParseProxyLink(link)
		if err != nil { fmt.Printf("❌ Failed to parse link: %v\n", err); return }

		newCO := config.CustomOutbound{
			Alias:    alias,
			Enabled:  true,
			UserUUID: uuid.New().String(),
			Config:   out,
		}
		cfg.CustomOutbounds = append(cfg.CustomOutbounds, newCO)

		fmt.Printf("🔍 Testing node '%s' connectivity...\n", alias)
		results := runIsolatedTest(cfg, newCO)
		fmt.Printf("[%s] -> TCP: %s | UDP: %s | DNS: %s | IP: %s\n", 
			alias, results["TCP"], results["UDP"], results["DNS"], results["IP"])

		cfg.SaveEx(true)
		fmt.Println("✅ Added to STAGING. Run 'apply' to commit.")
	},
}

var listOutboundCmd = &cobra.Command{
	Use:   "list",
	Short: "List all relay nodes in staging",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil { return }
		
		fmt.Printf("\n%-3s | %-15s | %-10s | %-6s | %-12s | %-s\n", "ID", "ALIAS", "PROTO", "STATE", "INTERNAL", "DNS")
		fmt.Println("-------------------------------------------------------------------------------------")
		for i, co := range cfg.CustomOutbounds {
			status := "OFF"; if co.Enabled { status = "ON" }
			internal := "None"
			if co.InternalProxyPort > 0 { internal = fmt.Sprintf(":%d", co.InternalProxyPort) }
			strategy := co.DNSStrategy; if strategy == "" { strategy = "default" }
			fmt.Printf("%-3d | %-15s | %-10s | %-6s | %-12s | %-s\n", 
				i+1, co.Alias, co.Config["protocol"], status, internal, strategy)
		}
	},
}

var testOutboundCmd = &cobra.Command{
	Use:   "test [alias]",
	Short: "Verify relay node connectivity",
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 { return nil, cobra.ShellCompDirectiveNoFileComp }
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		target := ""; if len(args) > 0 { target = args[0] }
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }
		for _, co := range cfg.CustomOutbounds {
			if target != "" && co.Alias != target { continue }
			results := runIsolatedTest(cfg, co)
			fmt.Printf("[%s] -> TCP: %s | UDP: %s | DNS: %s | IP: %s\n", 
				co.Alias, results["TCP"], results["UDP"], results["DNS"], results["IP"])
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
		if cfg == nil { return }

		var target *config.CustomOutbound
		for _, co := range cfg.CustomOutbounds {
			if co.Alias == alias { target = &co; break }
		}
		if target == nil { fmt.Printf("❌ Relay '%s' not found.\n", alias); return }

		fmt.Printf("🔍 Fetching landing profile for '%s'...\n", alias)
		
		// 1. Prepare isolated test
		testSocksPort, _ := xray.GetFreePort()
		apiPort, _ := xray.GetFreePort()
		overrides := map[string]int{"test-socks": testSocksPort, "api": apiPort}
		jsonData, _ := xray.GenerateXrayJSON(cfg, overrides)
		_, cleanup, err := xray.StartXrayTemp(jsonData)
		if err != nil { fmt.Printf("❌ Failed to start test core: %v\n", err); return }
		defer cleanup()

		socksAddr := fmt.Sprintf("127.0.0.1:%d", testSocksPort)
		dialer, _ := proxy.SOCKS5("tcp", socksAddr, &proxy.Auth{User: "user-" + target.Alias, Password: "test"}, proxy.Direct)
		httpClient := &http.Client{Transport: &http.Transport{Dial: dialer.Dial}, Timeout: 10 * time.Second}

		// 2. Fetch GeoIP & ASN Data
		var geo struct {
			Query       string `json:"query"`
			Status      string `json:"status"`
			Country     string `json:"country"`
			CountryCode string `json:"countryCode"`
			RegionName  string `json:"regionName"`
			City        string `json:"city"`
			ISP         string `json:"isp"`
			Org         string `json:"org"`
			AS          string `json:"as"`
			Timezone    string `json:"timezone"`
			Hosting     bool   `json:"hosting"`
			Proxy       bool   `json:"proxy"`
		}
		
		resp, err := httpClient.Get("http://ip-api.com/json/?fields=66846719")
		if err != nil { fmt.Printf("❌ Failed to reach info API: %v\n", err); return }
		json.NewDecoder(resp.Body).Decode(&geo)
		resp.Body.Close()

		// 3. Media Unlock Tests
		nfStatus := testMedia(httpClient, "https://www.netflix.com/title/80018499")
		ytStatus := testMedia(httpClient, "https://www.youtube.com/premium")
		dsStatus := testMedia(httpClient, "https://www.disneyplus.com")

		// 4. Calculate Local Time
		loc, _ := time.LoadLocation(geo.Timezone)
		localTime := time.Now().In(loc).Format("2006-01-02 15:04:05")

		// 5. Display Card
		fmt.Printf("\n┏━━━━━━━━━━━━ Landing Profile: %s ━━━━━━━━━━━━┓\n", alias)
		fmt.Printf("┃ 🌐 Exit Address: %-36s ┃\n", geo.Query)
		
		asnType := "ISP/Consumer"
		if geo.Hosting { asnType = "DataCenter/Hosting" }
		fmt.Printf("┃ 🏷️  ASN Type:     %-36s ┃\n", asnType)
		fmt.Printf("┃ 🏢 ASN:          %-36s ┃\n", geo.AS)
		fmt.Printf("┃ 📡 Provider/Org: %-36s ┃\n", geo.Org)
		fmt.Printf("┃ 📍 Location:     %s, %s, %s ┃\n", geo.City, geo.RegionName, geo.CountryCode)
		fmt.Printf("┃ ⏰ Local Time:   %-36s ┃\n", localTime)
		fmt.Printf("┃ 🌐 Timezone:     %-36s ┃\n", geo.Timezone)
		
		privacy := "Clear (Residential/Corporate)"
		if geo.Proxy { privacy = "Flagged (VPN/Proxy/Tor)" }
		fmt.Printf("┃ 🛡️  Privacy:      %-36s ┃\n", privacy)
		
		fmt.Printf("┣━━━━━━━━━━━━ Media Unlock Tests ━━━━━━━━━━━━━┫\n")
		fmt.Printf("┃ 🎬 Netflix: %-38s ┃\n", nfStatus)
		fmt.Printf("┃ 📺 YouTube: %-38s ┃\n", ytStatus)
		fmt.Printf("┃ 🏰 Disney+: %-38s ┃\n", dsStatus)
		fmt.Printf("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n")
	},
}

func testMedia(client *http.Client, url string) string {
	start := time.Now()
	resp, err := client.Get(url)
	if err != nil { return "❌ Connection Error" }
	defer resp.Body.Close()
	
	duration := time.Since(start).Milliseconds()
	if resp.StatusCode == 200 {
		return fmt.Sprintf("✅ Unlocked (%dms)", duration)
	} else if resp.StatusCode == 403 {
		return "🚫 Blocked / Geo-Restricted"
	}
	return fmt.Sprintf("⚠️  Unexpected Status: %d", resp.StatusCode)
}

var deleteOutboundCmd = &cobra.Command{
	Use:   "delete [alias]",
	Short: "Remove a relay node from staging",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }
		newOutbounds := []config.CustomOutbound{}
		found := false
		for _, co := range cfg.CustomOutbounds {
			if co.Alias == alias { found = true; continue }
			newOutbounds = append(newOutbounds, co)
		}
		if found {
			cfg.CustomOutbounds = newOutbounds
			cfg.SaveEx(true)
			fmt.Printf("✅ Deleted '%s' from STAGING.\n", alias)
		} else {
			fmt.Printf("❌ Relay '%s' not found.\n", alias)
		}
	},
}

var bindInterfaceCmd = &cobra.Command{
	Use:   "bind-interface [alias] [interface]",
	Short: "Bind a relay to a local interface (freedom)",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		alias, ifaceName := args[0], args[1]
		bindAddr, _ := cmd.Flags().GetString("addr")
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil { cfg = &config.UserConfig{UUID: uuid.New().String(), Role: config.RoleServer} }

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
		if err != nil { fmt.Printf("❌ Error: %v\n", err); return }
		newCO := config.CustomOutbound{Alias: alias, Enabled: true, UserUUID: uuid.New().String(), Config: out}
		cfg.CustomOutbounds = append(cfg.CustomOutbounds, newCO)
		cfg.SaveEx(true)
		fmt.Println("✅ Interface binding added to STAGING.")
	},
}

var setDNSRelayCmd = &cobra.Command{
	Use:   "set-dns [alias]",
	Short: "Configure DNS strategy for a relay",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		strategy, _ := cmd.Flags().GetString("strategy")
		servers, _ := cmd.Flags().GetStringSlice("servers")
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }
		for i, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				if strategy != "" { cfg.CustomOutbounds[i].DNSStrategy = strategy }
				if len(servers) > 0 { cfg.CustomOutbounds[i].DNSServers = servers }
				cfg.SaveEx(true)
				fmt.Printf("✅ DNS strategy updated for '%s'.\n", alias)
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
		cfg, _ := config.LoadConfigEx(true); if cfg == nil { return }

		for i, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				if port == 0 {
					for {
						p, _ := xray.GetFreePort()
						if isPortFree(p + 1) { port = p; break }
					}
				} else if !isPortFree(port) || !isPortFree(port+1) {
					fmt.Printf("❌ Port %d or %d is in use.\n", port, port+1); return
				}
				cfg.CustomOutbounds[i].InternalProxyPort = port
				cfg.SaveEx(true)
				fmt.Printf("✅ Internal proxy for '%s' in STAGING -> Socks:%d, HTTP:%d\n", alias, port, port+1)
				fmt.Println("🚀 Run 'apply' to commit.")
				return
			}
		}
		fmt.Printf("❌ Relay '%s' not found.\n", alias)
	},
}

func isPortFree(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil { return false }
	ln.Close()
	return true
}

func runIsolatedTest(cfg *config.UserConfig, co config.CustomOutbound) map[string]string {
	results := map[string]string{"TCP": "FAIL", "UDP": "FAIL", "DNS": "FAIL", "IP": "Unknown"}
	testSocksPort, _ := xray.GetFreePort()
	apiPort, _ := xray.GetFreePort()
	overrides := map[string]int{"test-socks": testSocksPort, "api": apiPort}
	jsonData, err := xray.GenerateXrayJSON(cfg, overrides)
	if err != nil { return results }
	_, cleanup, err := xray.StartXrayTemp(jsonData)
	if err != nil { return results }
	defer cleanup()
	socksAddr := fmt.Sprintf("127.0.0.1:%d", testSocksPort)
	dialer, err := proxy.SOCKS5("tcp", socksAddr, &proxy.Auth{User: "user-" + co.Alias, Password: "test"}, proxy.Direct)
	if err != nil { return results }
	httpClient := &http.Client{Transport: &http.Transport{Dial: dialer.Dial}, Timeout: 5 * time.Second}
	resp, err := httpClient.Get("http://ip-api.com/json")
	if err == nil {
		defer resp.Body.Close()
		var geo struct { Query string `json:"query"` }
		data, _ := io.ReadAll(resp.Body)
		if err := json.Unmarshal(data, &geo); err == nil { results["TCP"], results["IP"] = "OK", geo.Query }
	}
	conn, err := dialer.Dial("tcp", "8.8.8.8:53")
	if err == nil { results["DNS"] = "OK"; conn.Close() }
	duration, err := xray.TestUDP(socksAddr, "user-"+co.Alias, "test")
	if err == nil { results["UDP"] = fmt.Sprintf("OK(%dms)", duration.Milliseconds()) }
	return results
}

func init() {
	bindInterfaceCmd.Flags().StringP("addr", "a", "", "Specific IP address to bind")
	setDNSRelayCmd.Flags().StringP("strategy", "s", "", "Strategy: follow, direct, manual")
	setDNSRelayCmd.Flags().StringSliceP("servers", "v", []string{}, "Manual DNS Servers")
	setInternalProxyCmd.Flags().IntP("port", "p", 0, "Base port (0 for random)")
	
	outboundCmd.AddCommand(addOutboundCmd, listOutboundCmd, testOutboundCmd, infoOutboundCmd, deleteOutboundCmd, bindInterfaceCmd, setDNSRelayCmd, setInternalProxyCmd)
	rootCmd.AddCommand(outboundCmd)
}
