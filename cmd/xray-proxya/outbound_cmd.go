package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/net/proxy"
)

var outboundCmd = &cobra.Command{
	Use:   "outbound",
	Short: "Manage relay nodes (Custom Outbounds) in STAGING area",
	Long: `Manage your relay nodes. All changes are saved to the staging area 
and must be committed via the 'apply' command. Supports importing links, 
setting DNS strategies, and binding to local network interfaces.`,
}

var addOutboundCmd = &cobra.Command{
	Use:   "add [alias] [link]",
	Short: "Import a relay node from a link (vmess/vless/ss/http/socks)",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		alias, link := args[0], args[1]
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			cfg = &config.UserConfig{UUID: uuid.New().String(), Role: config.RoleServer}
		}

		for _, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				fmt.Printf("❌ Alias '%s' already exists in STAGING.\n", alias)
				return
			}
		}

		out, err := xray.ParseProxyLink(link)
		if err != nil {
			fmt.Printf("❌ Failed to parse link: %v\n", err)
			return
		}

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
		
		fmt.Printf("\n%-3s | %-15s | %-10s | %-6s | %-s\n", "ID", "ALIAS", "PROTO", "STATE", "DNS STRATEGY")
		fmt.Println("----------------------------------------------------------------------")
		for i, co := range cfg.CustomOutbounds {
			status := "OFF"
			if co.Enabled { status = "ON" }
			strategy := co.DNSStrategy
			if strategy == "" { strategy = "default" }
			fmt.Printf("%-3d | %-15s | %-10s | %-6s | %-s\n", 
				i+1, co.Alias, co.Config["protocol"], status, strategy)
		}
	},
}

var testOutboundCmd = &cobra.Command{
	Use:   "test [alias]",
	Short: "Verify relay node connectivity using an isolated process",
	Run: func(cmd *cobra.Command, args []string) {
		target := ""
		if len(args) > 0 { target = args[0] }
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil { return }

		for _, co := range cfg.CustomOutbounds {
			if target != "" && co.Alias != target { continue }
			results := runIsolatedTest(cfg, co)
			fmt.Printf("[%s] -> TCP: %s | UDP: %s | DNS: %s | IP: %s\n", 
				co.Alias, results["TCP"], results["UDP"], results["DNS"], results["IP"])
		}
	},
}

var deleteOutboundCmd = &cobra.Command{
	Use:   "delete [alias]",
	Short: "Remove a relay node from staging",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil { return }

		newOutbounds := []config.CustomOutbound{}
		found := false
		for _, co := range cfg.CustomOutbounds {
			if co.Alias == alias { found = true; continue }
			newOutbounds = append(newOutbounds, co)
		}
		
		if found {
			cfg.CustomOutbounds = newOutbounds
			cfg.SaveEx(true)
			fmt.Printf("✅ Deleted '%s' from STAGING. Run 'apply' to commit.\n", alias)
		} else {
			fmt.Printf("❌ Relay '%s' not found.\n", alias)
		}
	},
}

var bindInterfaceCmd = &cobra.Command{
	Use:   "bind-interface [alias] [interface]",
	Short: "Bind a relay to a specific local network interface (freedom protocol)",
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
					if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
						if ipnet.IP.To4() != nil {
							bindAddr = ipnet.IP.String()
							fmt.Printf("🔍 Auto-detected IPv4 for %s: %s\n", ifaceName, bindAddr)
							break
						}
					}
				}
			}
		}

		out, err := xray.ParseInterfaceBind(ifaceName, bindAddr)
		if err != nil { fmt.Printf("❌ Error: %v\n", err); return }

		newCO := config.CustomOutbound{
			Alias:    alias,
			Enabled:  true,
			UserUUID: uuid.New().String(),
			Config:   out,
		}

		cfg.CustomOutbounds = append(cfg.CustomOutbounds, newCO)
		cfg.SaveEx(true)
		fmt.Println("✅ Interface binding added to STAGING. Run 'apply' to commit.")
	},
}

var setDNSRelayCmd = &cobra.Command{
	Use:   "set-dns [alias]",
	Short: "Configure DNS strategy for a relay (follow, direct, manual)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		strategy, _ := cmd.Flags().GetString("strategy")
		servers, _ := cmd.Flags().GetStringSlice("servers")
		
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil { return }

		found := false
		for i, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				found = true
				if strategy != "" { cfg.CustomOutbounds[i].DNSStrategy = strategy }
				if len(servers) > 0 { cfg.CustomOutbounds[i].DNSServers = servers }
				cfg.SaveEx(true)
				fmt.Printf("✅ DNS strategy updated for '%s' in STAGING.\n", alias)
				break
			}
		}
		if !found { fmt.Printf("❌ Relay '%s' not found.\n", alias) }
	},
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

	// TCP & IP
	resp, err := httpClient.Get("http://ip-api.com/json")
	if err == nil {
		defer resp.Body.Close()
		var geo struct { Query string `json:"query"` }
		if err := json.NewDecoder(resp.Body).Decode(&geo); err == nil {
			results["TCP"] = "OK"
			results["IP"] = geo.Query
		}
	}

	// DNS
	conn, err := dialer.Dial("tcp", "8.8.8.8:53")
	if err == nil { results["DNS"] = "OK"; conn.Close() }

	// UDP
	duration, err := xray.TestUDP(socksAddr, "user-"+co.Alias, "test")
	if err == nil { results["UDP"] = fmt.Sprintf("OK(%dms)", duration.Milliseconds()) }

	return results
}

func init() {
	bindInterfaceCmd.Flags().StringP("addr", "a", "", "Specific IP address to bind (optional)")
	setDNSRelayCmd.Flags().StringP("strategy", "s", "", "Strategy: follow, direct, manual")
	setDNSRelayCmd.Flags().StringSliceP("servers", "v", []string{}, "DNS Servers for manual mode")
	
	outboundCmd.AddCommand(addOutboundCmd, listOutboundCmd, testOutboundCmd, deleteOutboundCmd, bindInterfaceCmd, setDNSRelayCmd)
	rootCmd.AddCommand(outboundCmd)
}
