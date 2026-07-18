package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	proxySocksPort int
	proxyHttpPort  int
	proxyListenIP  string
)

var proxyCmd = &cobra.Command{
	Use:     "proxy",
	Aliases: []string{"proxies", "localproxy"},
	Short:   "Manage and run local SOCKS/HTTP proxy listeners",
}

var proxyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configured local SOCKS/HTTP proxies",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			return
		}
		fmt.Printf("\n%-15s | %-8s | %-10s | %-10s | %-15s | %-s\n", "ALIAS", "STATE", "SOCKS PORT", "HTTP PORT", "LISTEN IP", "REMOTE ENDPOINT")
		fmt.Println("---------------------------------------------------------------------------------------------------------")
		for _, co := range cfg.CustomOutbounds {
			state := "OFF"
			socksPortStr := "-"
			httpPortStr := "-"
			listenIP := "-"

			if co.InternalProxyPort > 0 {
				if co.Enabled {
					state = "ON"
				} else {
					state = "DISABLED"
				}
				socksPortStr = fmt.Sprintf("%d", co.InternalProxyPort)
				httpPort := co.InternalHttpPort
				if httpPort <= 0 {
					httpPort = co.InternalProxyPort + 1
				}
				httpPortStr = fmt.Sprintf("%d", httpPort)

				listenIP = co.InternalListenAddr
				if listenIP == "" {
					listenIP = "127.0.0.1"
				}
			}

			fmt.Printf(
				"%-15s | %-8s | %-10s | %-10s | %-15s | %-s\n",
				co.Alias,
				state,
				socksPortStr,
				httpPortStr,
				listenIP,
				outboundRemoteSummary(co),
			)
		}
	},
}

var proxySetCmd = &cobra.Command{
	Use:   "set [alias]",
	Short: "Configure local SOCKS/HTTP proxy for a relay in STAGING",
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

		for i, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				socksPort := proxySocksPort
				httpPort := proxyHttpPort

				// Validate SOCKS port selection
				if socksPort == 0 {
					for {
						p, _ := xray.GetFreePort()
						if utils.IsPortFree(p + 1) {
							socksPort = p
							break
						}
					}
				}

				// Validate HTTP port selection
				if httpPort == 0 {
					httpPort = socksPort + 1
				}

				if !utils.IsPortFree(socksPort) {
					fmt.Printf("❌ SOCKS Port %d is in use.\n", socksPort)
					return
				}
				if !utils.IsPortFree(httpPort) {
					fmt.Printf("❌ HTTP Port %d is in use.\n", httpPort)
					return
				}

				// Validate IP address format if provided
				listenIP := proxyListenIP
				if listenIP != "" {
					if ip := net.ParseIP(listenIP); ip == nil {
						fmt.Printf("❌ Invalid listen IP address: %s\n", listenIP)
						return
					}
				} else {
					listenIP = "127.0.0.1"
				}

				cfg.CustomOutbounds[i].InternalProxyPort = socksPort
				cfg.CustomOutbounds[i].InternalHttpPort = httpPort
				cfg.CustomOutbounds[i].InternalListenAddr = listenIP

				if err := cfg.SaveEx(true); err == nil {
					fmt.Printf("✅ Configured local proxy for '%s' in STAGING:\n", alias)
					fmt.Printf("   SOCKS Port: %d\n", socksPort)
					fmt.Printf("   HTTP Port:  %d\n", httpPort)
					fmt.Printf("   Listen IP:  %s\n", listenIP)
					fmt.Println("🚀 Run 'apply' to commit changes.")
				}
				return
			}
		}
		fmt.Printf("❌ Relay '%s' not found.\n", alias)
	},
}

var proxyUnsetCmd = &cobra.Command{
	Use:   "unset [alias]",
	Short: "Disable local SOCKS/HTTP proxy for a relay in STAGING",
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
		for i, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				if co.InternalProxyPort <= 0 {
					fmt.Printf("ℹ️ Local proxy for '%s' was not configured.\n", alias)
					return
				}
				cfg.CustomOutbounds[i].InternalProxyPort = 0
				cfg.CustomOutbounds[i].InternalHttpPort = 0
				cfg.CustomOutbounds[i].InternalListenAddr = ""
				if err := cfg.SaveEx(true); err == nil {
					fmt.Printf("✅ Disabled local proxy for '%s' in STAGING.\n", alias)
					fmt.Println("🚀 Run 'apply' to commit changes.")
				}
				return
			}
		}
		fmt.Printf("❌ Relay '%s' not found.\n", alias)
	},
}

var proxyRunCmd = &cobra.Command{
	Use:   "run [alias]",
	Short: "Run a temporary standalone local SOCKS/HTTP proxy for a relay",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		alias := args[0]
		cfg, _ := config.LoadConfigEx(true)
		if cfg == nil {
			cfg, _ = config.LoadConfig()
		}
		if cfg == nil {
			fmt.Println("❌ Error: Configuration could not be loaded.")
			return
		}

		var targetCO *config.CustomOutbound
		for _, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				targetCO = &co
				break
			}
		}
		if targetCO == nil {
			fmt.Printf("❌ Relay '%s' not found.\n", alias)
			return
		}

		socksPort := proxySocksPort
		httpPort := proxyHttpPort
		listenIP := proxyListenIP

		// If flags aren't specified, try to fall back to configured values
		if socksPort == 0 {
			socksPort = targetCO.InternalProxyPort
		}
		if socksPort == 0 {
			for {
				p, _ := xray.GetFreePort()
				if utils.IsPortFree(p + 1) {
					socksPort = p
					break
				}
			}
		}
		if httpPort == 0 {
			httpPort = targetCO.InternalHttpPort
		}
		if httpPort == 0 {
			httpPort = socksPort + 1
		}
		if listenIP == "" {
			listenIP = targetCO.InternalListenAddr
		}
		if listenIP == "" {
			listenIP = "127.0.0.1"
		}

		if !utils.IsPortFree(socksPort) {
			fmt.Printf("❌ SOCKS Port %d is in use.\n", socksPort)
			return
		}
		if !utils.IsPortFree(httpPort) {
			fmt.Printf("❌ HTTP Port %d is in use.\n", httpPort)
			return
		}
		if ip := net.ParseIP(listenIP); ip == nil {
			fmt.Printf("❌ Invalid listen IP address: %s\n", listenIP)
			return
		}

		// Setup a temporary configuration copy with only our target node and configured proxy ports
		tempCfg := *cfg
		tempCfg.Role = config.RoleServer
		tempCfg.Gateway = config.GatewayConfig{}
		tempCfg.Presets = []config.ModeInfo{} // disable all presets to avoid port conflicts

		// Find and configure only the target outbound, ensuring it's enabled and has the right ports
		tempCfg.CustomOutbounds = []config.CustomOutbound{}
		coCopy := *targetCO
		coCopy.Enabled = true
		coCopy.InternalProxyPort = socksPort
		coCopy.InternalHttpPort = httpPort
		coCopy.InternalListenAddr = listenIP
		tempCfg.CustomOutbounds = append(tempCfg.CustomOutbounds, coCopy)

		// Build and start
		apiPort, _ := xray.GetFreePort()
		overrides := map[string]int{
			"api":        apiPort,
			"test-socks": 0, // Disable global test socks for clarity
		}
		jsonData, err := xray.GenerateXrayJSON(&tempCfg, overrides, "")
		if err != nil {
			fmt.Printf("❌ Failed to generate config: %v\n", err)
			return
		}

		_, cleanup, err := xray.StartXrayTemp(jsonData)
		if err != nil {
			fmt.Printf("❌ Failed to start temporary Xray instance: %v\n", err)
			return
		}
		defer cleanup()

		fmt.Printf("✅ Temporary SOCKS/HTTP proxy started successfully!\n")
		fmt.Printf("   👉 SOCKS5: %s:%d\n", listenIP, socksPort)
		fmt.Printf("   👉 HTTP:   %s:%d\n", listenIP, httpPort)
		fmt.Printf("   Target:    %s (%s)\n", alias, outboundRemoteSummary(coCopy))
		fmt.Println("\nPress Ctrl+C to terminate...")

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		fmt.Println("\nStopping proxy...")
	},
}

var proxyTestCmd = &cobra.Command{
	Use:   "test [alias]",
	Short: "Test connectivity of a configured local proxy",
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

		var targetCO *config.CustomOutbound
		for _, co := range cfg.CustomOutbounds {
			if co.Alias == alias {
				targetCO = &co
				break
			}
		}
		if targetCO == nil {
			fmt.Printf("❌ Relay '%s' not found.\n", alias)
			return
		}

		if targetCO.InternalProxyPort <= 0 {
			fmt.Printf("❌ Local proxy is not configured for '%s'. Configure it first with 'xray-proxya proxy set %s'.\n", alias, alias)
			return
		}

		socksPort := targetCO.InternalProxyPort
		listenIP := targetCO.InternalListenAddr
		if listenIP == "" {
			listenIP = "127.0.0.1"
		}

		socksAddr := fmt.Sprintf("%s:%d", listenIP, socksPort)
		dialer, err := utils.NewSOCKS5Dialer(socksAddr)
		if err != nil {
			fmt.Printf("❌ Failed to create SOCKS dialer: %v\n", err)
			return
		}

		fmt.Printf("🔍 Testing local proxy at %s...\n", socksAddr)

		// We'll test TCP connection to a public IP
		conn, err := dialer.Dial("tcp", "8.8.8.8:53")
		if err != nil {
			fmt.Printf("❌ TCP test failed: %v\n", err)
			return
		}
		conn.Close()
		fmt.Println("✅ TCP connectivity OK.")

		// Test UDP query/ping if supported
		duration, err := xray.TestUDP(socksAddr, "user-"+alias, "test")
		if err == nil {
			fmt.Printf("✅ UDP connectivity OK (%dms).\n", duration.Milliseconds())
		} else {
			fmt.Printf("⚠️  UDP test failed: %v\n", err)
		}
	},
}

func init() {
	proxySetCmd.Flags().IntVarP(&proxySocksPort, "port", "p", 0, "Base port (SOCKS port, HTTP port will be SOCKS+1)")
	proxySetCmd.Flags().IntVar(&proxySocksPort, "socks-port", 0, "Specific SOCKS port")
	proxySetCmd.Flags().IntVar(&proxyHttpPort, "http-port", 0, "Specific HTTP port")
	proxySetCmd.Flags().StringVarP(&proxyListenIP, "listen", "l", "127.0.0.1", "IP address to listen on")

	proxyRunCmd.Flags().IntVarP(&proxySocksPort, "port", "p", 0, "Base port (SOCKS port, HTTP port will be SOCKS+1)")
	proxyRunCmd.Flags().IntVar(&proxySocksPort, "socks-port", 0, "Specific SOCKS port")
	proxyRunCmd.Flags().IntVar(&proxyHttpPort, "http-port", 0, "Specific HTTP port")
	proxyRunCmd.Flags().StringVarP(&proxyListenIP, "listen", "l", "", "IP address to listen on")

	proxyCmd.AddCommand(proxyListCmd, proxySetCmd, proxyUnsetCmd, proxyRunCmd, proxyTestCmd)
	rootCmd.AddCommand(proxyCmd)
}
