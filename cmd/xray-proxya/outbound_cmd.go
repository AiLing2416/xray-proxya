package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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
	IP, ASN, Org, City, Region, Country, Timezone, LocalTime string
	ASNType, Privacy                                         string
}

var outboundCmd = &cobra.Command{
	Use:     "outbound",
	Aliases: []string{"node", "relay"},
	Short:   "Manage relay nodes (Custom Outbounds) in STAGING area",
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
		fmt.Printf("[%s] -> TCP: %s | UDP: %s | DNS: %s | IP: %s\n", alias, results["TCP"], results["UDP"], results["DNS"], results["IP"])
		if err := cfg.SaveEx(true); err == nil {
			fmt.Println("✅ Added to STAGING. Run 'apply' to commit.")
		}
	},
}

var listOutboundCmd = &cobra.Command{
	Use:   "list",
	Short: "List all relay nodes in staging",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		fmt.Printf("\n%-3s | %-15s | %-10s | %-6s | %-12s | %-s\n", "ID", "ALIAS", "PROTO", "STATE", "INTERNAL", "DNS")
		fmt.Println("-------------------------------------------------------------------------------------")
		for i, co := range cfg.CustomOutbounds {
			status := "OFF"
			if co.Enabled {
				status = "ON"
			}
			internal := "None"
			if co.InternalProxyPort > 0 {
				internal = fmt.Sprintf(":%d", co.InternalProxyPort)
			}
			strategy := co.DNSStrategy
			if strategy == "" {
				strategy = "default"
			}
			fmt.Printf("%-3d | %-15s | %-10s | %-6s | %-12s | %-s\n", i+1, co.Alias, co.Config["protocol"], status, internal, strategy)
		}
		fmt.Println()
	},
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
			fmt.Printf("[%s] -> TCP: %s | UDP: %s | DNS: %s | IP: %s\n", co.Alias, results["TCP"], results["UDP"], results["DNS"], results["IP"])
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
		
		// v0.2.4: Randomize all active presets to avoid "device busy" during info test
		overrides := map[string]int{"test-socks": testSocksPort, "api": apiPort, "dns-in": dnsPort}
		for _, m := range cfg.ActiveModes {
			if m.Enabled {
				p, _ := xray.GetFreePort()
				overrides[string(m.Mode)] = p
			}
		}

		jsonData, _ := xray.GenerateXrayJSON(cfg, overrides, alias)
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
		httpClient := &http.Client{Transport: &http.Transport{Dial: dialer.Dial}, Timeout: 10 * time.Second}
		profile := fetchProfile(httpClient)
		nf := testMedia(httpClient, "https://www.netflix.com/title/80018499")
		yt := testMedia(httpClient, "https://www.youtube.com/premium")
		ds := testMedia(httpClient, "https://www.disneyplus.com")
		fmt.Printf("\n✨ Landing Profile: %s\n   Exit IP: %s\n   ASN Type: %s (%s)\n   ASN: %s\n   Company: %s\n   Local: %s, %s, %s\n   Local Time: %s\n   Time Zone: %s\n\n   Media Unlock Tests:\n   Netflix: %s  YouTube: %s  Disney+: %s\n\n",
			alias, profile.IP, profile.ASNType, profile.Privacy, profile.ASN, profile.Org, profile.City, profile.Region, profile.Country, profile.LocalTime, profile.Timezone, nf, yt, ds)
	},
}

func fetchProfile(client *http.Client) Profile {
	p := Profile{IP: "Unknown", ASN: "N/A", Org: "N/A", City: "N/A", Region: "N/A", Country: "N/A", Timezone: "UTC", ASNType: "N/A", Privacy: "N/A"}
	resp, err := client.Get("http://ip-api.com/json/?fields=66846719")
	if err == nil {
		defer resp.Body.Close()
		var res struct {
			Query, Country, RegionName, City, Org, AS, Timezone string
			Hosting, Proxy                                      bool
		}
		if json.NewDecoder(resp.Body).Decode(&res) == nil && res.Query != "" {
			p.IP, p.Country, p.Region, p.City, p.Org, p.ASN, p.Timezone = res.Query, res.Country, res.RegionName, res.City, res.Org, res.AS, res.Timezone
			p.ASNType = "ISP"
			if res.Hosting {
				p.ASNType = "DataCenter"
			}
			p.Privacy = "Clear"
			if res.Proxy {
				p.Privacy = "Flagged"
			}
			p.LocalTime = getLocalTime(p.Timezone)
			return p
		}
	}
	resp, err = client.Get("https://ipinfo.io/json")
	if err == nil {
		defer resp.Body.Close()
		var res struct{ IP, Org, City, Region, Country, Timezone string }
		if json.NewDecoder(resp.Body).Decode(&res) == nil && res.IP != "" {
			p.IP, p.Org, p.City, p.Region, p.Country, p.Timezone = res.IP, res.Org, res.City, res.Region, res.Country, res.Timezone
			p.ASN, p.LocalTime = res.Org, getLocalTime(p.Timezone)
		}
	}
	return p
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

func runIsolatedTest(cfg *config.UserConfig, co config.CustomOutbound) map[string]string {
	results := map[string]string{"TCP": "FAIL", "UDP": "FAIL", "DNS": "FAIL", "IP": "Unknown"}
	testSocksPort, _ := xray.GetFreePort()
	apiPort, _ := xray.GetFreePort()
	dnsPort, _ := xray.GetFreePort()

	// v0.2.4: Fully randomized overrides for test instance
	overrides := map[string]int{"test-socks": testSocksPort, "api": apiPort, "dns-in": dnsPort}
	for _, m := range cfg.ActiveModes {
		if m.Enabled {
			p, _ := xray.GetFreePort()
			overrides[string(m.Mode)] = p
		}
	}

	jsonData, err := xray.GenerateXrayJSON(cfg, overrides, co.Alias)
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
		results["TCP"] = "OK"
		conn.Close()
	} else {
		results["TCP"] = fmt.Sprintf("FAIL(443:%v)", err)
	}

	if results["TCP"] == "OK" {
		if conn, err := dialer.Dial("tcp", "8.8.8.8:80"); err == nil {
			conn.Close()
		} else {
			results["TCP"] = fmt.Sprintf("OK(443),FAIL(80:%v)", err)
		}
	}

	// 2. Fetch Exit IP
	ipList := []string{"http://api.ip.sb/ip", "http://ifconfig.me/ip", "http://ident.me"}
	for _, url := range ipList {
		resp, err := httpClient.Get(url)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			results["IP"] = strings.TrimSpace(string(body))
			break
		} else {
			results["IP"] = fmt.Sprintf("Err:%v", err)
		}
	}

	// 3. DNS Test (via Outbound)
	conn, err := dialer.Dial("tcp", "8.8.8.8:53")
	if err == nil {
		results["DNS"] = "OK"
		conn.Close()
	}
	duration, err := xray.TestUDP(socksAddr, "user-"+co.Alias, "test")
	if err == nil {
		results["UDP"] = fmt.Sprintf("OK(%dms)", duration.Milliseconds())
	} else {
		results["UDP"] = fmt.Sprintf("FAIL(%v)", err)
	}

	return results
}

func init() {
	bindInterfaceCmd.Flags().StringP("addr", "a", "", "Specific IP address to bind")
	setDNSRelayCmd.Flags().StringP("strategy", "s", "", "Strategy: follow, direct, manual")
	setDNSRelayCmd.Flags().StringSliceP("servers", "v", []string{}, "Manual DNS Servers")
	setInternalProxyCmd.Flags().IntP("port", "p", 0, "Base port (0 for random)")
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

	outboundCmd.AddCommand(addOutboundCmd, listOutboundCmd, testOutboundCmd, infoOutboundCmd, deleteOutboundCmd, bindInterfaceCmd, setDNSRelayCmd, setInternalProxyCmd)
	rootCmd.AddCommand(outboundCmd)
}
