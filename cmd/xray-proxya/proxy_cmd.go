package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	proxyListJSON bool
	proxyListAll  bool

	proxySocksPort int
	proxyHttpPort  int
	proxyListenIP  string

	proxySetSocksPort int
	proxySetHttpPort  int
	proxySetListenIP  string

	proxyRunSocksPort int
	proxyRunHttpPort  int
	proxyRunListenIP  string
)

var proxyCmd = &cobra.Command{
	Use:     "proxy",
	Aliases: []string{"proxies", "localproxy"},
	Short:   "Manage and run local SOCKS/HTTP proxy listeners",
	Long:    "Manage and run local SOCKS5 and HTTP proxy listeners for relays. Supports both persistent configuration via STAGING and temporary standalone foreground execution.",
	Example: `  # List all local proxy listeners
  xray-proxya proxy list

  # Configure local proxy for a relay in STAGING
  xray-proxya proxy set node-us -p 10808 -l 127.0.0.1
  xray-proxya apply

  # Test connectivity of configured local proxy
  xray-proxya proxy test node-us

  # Run temporary standalone proxy in foreground
  xray-proxya proxy run node-us -p 20808 -l 0.0.0.0`,
}

type ProxyListItemJSON struct {
	Alias          string `json:"alias"`
	State          string `json:"state"` // ON, DISABLED, OFF, PENDING
	SocksPort      int    `json:"socks_port"`
	HttpPort       int    `json:"http_port"`
	ListenIP       string `json:"listen_ip"`
	RemoteEndpoint string `json:"remote_endpoint"`
	Applied        bool   `json:"applied"`
}

func isProxyApplied(stagingCO config.CustomOutbound, activeCfg *config.UserConfig) bool {
	if !config.StagingExists() {
		return true
	}
	if activeCfg == nil {
		return false
	}
	var activeCO *config.CustomOutbound
	for _, aco := range activeCfg.CustomOutbounds {
		if aco.Alias == stagingCO.Alias {
			activeCO = &aco
			break
		}
	}
	if stagingCO.InternalProxyPort <= 0 {
		if activeCO != nil && activeCO.InternalProxyPort > 0 {
			return false
		}
		return true
	}
	if activeCO == nil || activeCO.InternalProxyPort != stagingCO.InternalProxyPort {
		return false
	}
	stagingHttp := stagingCO.InternalHttpPort
	if stagingHttp <= 0 {
		stagingHttp = stagingCO.InternalProxyPort + 1
	}
	activeHttp := activeCO.InternalHttpPort
	if activeHttp <= 0 {
		activeHttp = activeCO.InternalProxyPort + 1
	}
	if stagingHttp != activeHttp {
		return false
	}
	stagingListen := stagingCO.InternalListenAddr
	if stagingListen == "" {
		stagingListen = "127.0.0.1"
	}
	activeListen := activeCO.InternalListenAddr
	if activeListen == "" {
		activeListen = "127.0.0.1"
	}
	if stagingListen != activeListen {
		return false
	}
	if activeCO.Enabled != stagingCO.Enabled {
		return false
	}
	return true
}

func runProxyList(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config.")
	}

	var activeCfg *config.UserConfig
	if config.StagingExists() {
		activeCfg, _ = config.LoadConfigEx(false)
	} else {
		activeCfg = cfg
	}

	if proxyListJSON {
		items := make([]ProxyListItemJSON, 0)
		for _, co := range cfg.CustomOutbounds {
			if !proxyListAll && co.InternalProxyPort <= 0 {
				continue
			}
			applied := isProxyApplied(co, activeCfg)
			state := "OFF"
			socksPort := 0
			httpPort := 0
			listenIP := "-"

			if co.InternalProxyPort > 0 {
				if !applied {
					state = "PENDING"
				} else if co.Enabled {
					state = "ON"
				} else {
					state = "DISABLED"
				}
				socksPort = co.InternalProxyPort
				httpPort = co.InternalHttpPort
				if httpPort <= 0 {
					httpPort = co.InternalProxyPort + 1
				}
				listenIP = co.InternalListenAddr
				if listenIP == "" {
					listenIP = "127.0.0.1"
				}
			}

			items = append(items, ProxyListItemJSON{
				Alias:          co.Alias,
				State:          state,
				SocksPort:      socksPort,
				HttpPort:       httpPort,
				ListenIP:       listenIP,
				RemoteEndpoint: outboundRemoteSummary(co),
				Applied:        applied,
			})
		}
		data, err := json.MarshalIndent(items, "", "  ")
		if err != nil {
			return fmt.Errorf("❌ Failed to serialize proxy list JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	configuredCount := 0
	for _, co := range cfg.CustomOutbounds {
		if co.InternalProxyPort > 0 {
			configuredCount++
		}
	}

	if len(cfg.CustomOutbounds) == 0 || (!proxyListAll && configuredCount == 0) {
		fmt.Println("ℹ️ No local proxy listeners configured. Use 'xray-proxya proxy set <alias>' to configure one.")
		return nil
	}

	hasPending := false
	fmt.Printf("\n%-15s | %-8s | %-10s | %-10s | %-15s | %-s\n", "ALIAS", "STATE", "SOCKS PORT", "HTTP PORT", "LISTEN IP", "REMOTE ENDPOINT")
	fmt.Println("---------------------------------------------------------------------------------------------------------")
	for _, co := range cfg.CustomOutbounds {
		if !proxyListAll && co.InternalProxyPort <= 0 {
			continue
		}

		state := "OFF"
		socksPortStr := "-"
		httpPortStr := "-"
		listenIP := "-"

		applied := isProxyApplied(co, activeCfg)
		if !applied {
			hasPending = true
		}

		if co.InternalProxyPort > 0 {
			if !applied {
				state = "PENDING"
			} else if co.Enabled {
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

	if hasPending {
		fmt.Println("\n⚠️  Pending changes in STAGING. Run 'xray-proxya apply' to commit.")
	}
	return nil
}

var proxyListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all configured local SOCKS/HTTP proxies",
	Run: func(cmd *cobra.Command, args []string) {
		_ = runProxyList(cmd, args)
	},
	RunE: runProxyList,
}

func checkProxyPortConflict(cfg *config.UserConfig, alias string, listenIP string, socksPort, httpPort int) error {
	if socksPort == httpPort {
		return fmt.Errorf("SOCKS port and HTTP port cannot be the same (%d)", socksPort)
	}

	// 1. Check conflicts with other custom outbounds
	for _, co := range cfg.CustomOutbounds {
		if co.Alias == alias || co.InternalProxyPort <= 0 {
			continue
		}
		coSocks := co.InternalProxyPort
		coHttp := co.InternalHttpPort
		if coHttp <= 0 {
			coHttp = coSocks + 1
		}
		coListen := co.InternalListenAddr
		if coListen == "" {
			coListen = "127.0.0.1"
		}
		if utils.ListenAddressesOverlap(listenIP, coListen) {
			if socksPort == coSocks {
				return fmt.Errorf("SOCKS port %d conflicts with relay %q SOCKS proxy (%s:%d)", socksPort, co.Alias, coListen, coSocks)
			}
			if socksPort == coHttp {
				return fmt.Errorf("SOCKS port %d conflicts with relay %q HTTP proxy (%s:%d)", socksPort, co.Alias, coListen, coHttp)
			}
			if httpPort == coSocks {
				return fmt.Errorf("HTTP port %d conflicts with relay %q SOCKS proxy (%s:%d)", httpPort, co.Alias, coListen, coSocks)
			}
			if httpPort == coHttp {
				return fmt.Errorf("HTTP port %d conflicts with relay %q HTTP proxy (%s:%d)", httpPort, co.Alias, coListen, coHttp)
			}
		}
	}

	// 2. Check conflicts with presets
	for _, m := range cfg.Presets {
		if m.Enabled && m.Port > 0 {
			if socksPort == m.Port {
				return fmt.Errorf("SOCKS port %d conflicts with enabled preset %s (port %d)", socksPort, m.Mode, m.Port)
			}
			if httpPort == m.Port {
				return fmt.Errorf("HTTP port %d conflicts with enabled preset %s (port %d)", httpPort, m.Mode, m.Port)
			}
		}
	}

	// 3. Check conflicts with subscriptions
	if cfg.AdminSub.Port > 0 {
		if socksPort == cfg.AdminSub.Port {
			return fmt.Errorf("SOCKS port %d conflicts with Admin Subscription service (port %d)", socksPort, cfg.AdminSub.Port)
		}
		if httpPort == cfg.AdminSub.Port {
			return fmt.Errorf("HTTP port %d conflicts with Admin Subscription service (port %d)", httpPort, cfg.AdminSub.Port)
		}
	}
	if cfg.SubPort > 0 && cfg.SubPort != cfg.AdminSub.Port {
		if socksPort == cfg.SubPort {
			return fmt.Errorf("SOCKS port %d conflicts with Subscription service (port %d)", socksPort, cfg.SubPort)
		}
		if httpPort == cfg.SubPort {
			return fmt.Errorf("HTTP port %d conflicts with Subscription service (port %d)", httpPort, cfg.SubPort)
		}
	}
	if cfg.GuestSubPort > 0 {
		if socksPort == cfg.GuestSubPort {
			return fmt.Errorf("SOCKS port %d conflicts with Guest Subscription service (port %d)", socksPort, cfg.GuestSubPort)
		}
		if httpPort == cfg.GuestSubPort {
			return fmt.Errorf("HTTP port %d conflicts with Guest Subscription service (port %d)", httpPort, cfg.GuestSubPort)
		}
	}
	if cfg.SubscriptionInstances != nil {
		for name, inst := range cfg.SubscriptionInstances {
			if inst.Port > 0 {
				if socksPort == inst.Port {
					return fmt.Errorf("SOCKS port %d conflicts with subscription instance %q (port %d)", socksPort, name, inst.Port)
				}
				if httpPort == inst.Port {
					return fmt.Errorf("HTTP port %d conflicts with subscription instance %q (port %d)", httpPort, name, inst.Port)
				}
			}
		}
	}

	// 4. Check Internal API & Test Inbounds
	if cfg.APIInbound > 0 && utils.ListenAddressesOverlap(listenIP, "127.0.0.1") {
		if socksPort == cfg.APIInbound {
			return fmt.Errorf("SOCKS port %d conflicts with API inbound (port %d)", socksPort, cfg.APIInbound)
		}
		if httpPort == cfg.APIInbound {
			return fmt.Errorf("HTTP port %d conflicts with API inbound (port %d)", httpPort, cfg.APIInbound)
		}
	}
	if cfg.TestInbound > 0 && utils.ListenAddressesOverlap(listenIP, "127.0.0.1") {
		if socksPort == cfg.TestInbound {
			return fmt.Errorf("SOCKS port %d conflicts with Test inbound (port %d)", socksPort, cfg.TestInbound)
		}
		if httpPort == cfg.TestInbound {
			return fmt.Errorf("HTTP port %d conflicts with Test inbound (port %d)", httpPort, cfg.TestInbound)
		}
	}

	// 5. Check Web Camouflage Skin Port
	if cfg.SkinPort > 0 && utils.ListenAddressesOverlap(listenIP, "127.0.0.1") {
		if socksPort == cfg.SkinPort {
			return fmt.Errorf("SOCKS port %d conflicts with Web Camouflage Skin service (port %d)", socksPort, cfg.SkinPort)
		}
		if httpPort == cfg.SkinPort {
			return fmt.Errorf("HTTP port %d conflicts with Web Camouflage Skin service (port %d)", httpPort, cfg.SkinPort)
		}
	}

	return nil
}

func runProxySet(cmd *cobra.Command, args []string) error {
	alias := args[0]

	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config.")
	}

	for i, co := range cfg.CustomOutbounds {
		if co.Alias == alias {
			socksSpecified := cmd.Flags().Changed("port") || cmd.Flags().Changed("socks-port")
			socksPort := proxySetSocksPort
			if !socksSpecified && proxySocksPort != 0 {
				socksPort = proxySocksPort
				socksSpecified = true
			}

			httpSpecified := cmd.Flags().Changed("http-port")
			httpPort := proxySetHttpPort
			if !httpSpecified && proxyHttpPort != 0 {
				httpPort = proxyHttpPort
				httpSpecified = true
			}

			listenSpecified := cmd.Flags().Changed("listen")
			listenIP := proxySetListenIP
			if !listenSpecified && proxyListenIP != "" && proxyListenIP != "127.0.0.1" {
				listenIP = proxyListenIP
				listenSpecified = true
			}

			// 1. Determine listen address
			if listenSpecified {
				if ip := net.ParseIP(listenIP); ip == nil {
					return fmt.Errorf("❌ Invalid listen IP address: %s", listenIP)
				}
			} else {
				if co.InternalListenAddr != "" {
					listenIP = co.InternalListenAddr
				} else {
					listenIP = "127.0.0.1"
				}
			}

			// 2. Determine SOCKS port
			socksUpdated := false
			if socksSpecified {
				socksUpdated = true
			} else {
				if co.InternalProxyPort > 0 {
					socksPort = co.InternalProxyPort
				} else {
					// Allocate free port
					for {
						p, _ := xray.GetFreePort()
						if p > 0 && p < 65535 &&
							utils.IsPortFree(p) && utils.IsUDPPortFree(p) &&
							utils.IsPortFree(p+1) &&
							checkProxyPortConflict(cfg, alias, listenIP, p, p+1) == nil {
							socksPort = p
							socksUpdated = true
							break
						}
					}
				}
			}

			// 3. Determine HTTP port
			if !httpSpecified {
				if socksUpdated {
					httpPort = socksPort + 1
				} else if co.InternalHttpPort > 0 {
					httpPort = co.InternalHttpPort
				} else {
					httpPort = socksPort + 1
				}
			}

			if socksPort < 1 || socksPort > 65535 {
				return fmt.Errorf("❌ Invalid SOCKS port: %d (must be between 1 and 65535)", socksPort)
			}
			if httpPort < 1 || httpPort > 65535 {
				return fmt.Errorf("❌ Invalid HTTP port: %d (must be between 1 and 65535)", httpPort)
			}

			if err := checkProxyPortConflict(cfg, alias, listenIP, socksPort, httpPort); err != nil {
				return fmt.Errorf("❌ Port conflict: %w", err)
			}

			// Check if ports are already legitimately owned by this relay in active configuration
			socksOwnedBySelf := false
			httpOwnedBySelf := false
			if activeCfg, _ := config.LoadConfig(); activeCfg != nil {
				for _, aco := range activeCfg.CustomOutbounds {
					if aco.Alias == alias && aco.InternalProxyPort > 0 {
						activeSocks := aco.InternalProxyPort
						activeHttp := aco.InternalHttpPort
						if activeHttp <= 0 {
							activeHttp = activeSocks + 1
						}
						activeListen := aco.InternalListenAddr
						if activeListen == "" {
							activeListen = "127.0.0.1"
						}
						if utils.ListenAddressesOverlap(listenIP, activeListen) {
							if socksPort == activeSocks {
								socksOwnedBySelf = true
							}
							if httpPort == activeHttp {
								httpOwnedBySelf = true
							}
						}
						break
					}
				}
			}

			if !socksOwnedBySelf {
				if !utils.IsPortFree(socksPort) || !utils.IsUDPPortFree(socksPort) {
					return fmt.Errorf("❌ SOCKS Port %d is in use on the host.", socksPort)
				}
			}
			if !httpOwnedBySelf {
				if !utils.IsPortFree(httpPort) {
					return fmt.Errorf("❌ HTTP Port %d is in use on the host.", httpPort)
				}
			}

			cfg.CustomOutbounds[i].InternalProxyPort = socksPort
			cfg.CustomOutbounds[i].InternalHttpPort = httpPort
			cfg.CustomOutbounds[i].InternalListenAddr = listenIP

			if err := cfg.SaveEx(true); err != nil {
				return fmt.Errorf("❌ Failed to save staging config: %w", err)
			}
			fmt.Printf("✅ Configured local proxy for '%s' in STAGING:\n", alias)
			fmt.Printf("   SOCKS Port: %d\n", socksPort)
			fmt.Printf("   HTTP Port:  %d\n", httpPort)
			fmt.Printf("   Listen IP:  %s\n", listenIP)
			fmt.Println("🚀 Run 'apply' to commit changes.")
			return nil
		}
	}
	return fmt.Errorf("❌ Relay '%s' not found.", alias)
}

var proxySetCmd = &cobra.Command{
	Use:   "set [alias]",
	Short: "Configure local SOCKS/HTTP proxy for a relay in STAGING",
	Example: `  # Configure SOCKS (10808) and HTTP (10809) for localhost
  xray-proxya proxy set node-us -p 10808

  # Configure custom SOCKS and HTTP ports with LAN sharing
  xray-proxya proxy set node-hk --socks-port 10810 --http-port 10811 --listen 0.0.0.0`,
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		_ = runProxySet(cmd, args)
	},
	RunE: runProxySet,
}

func runProxyUnset(cmd *cobra.Command, args []string) error {
	alias := args[0]
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config.")
	}
	for i, co := range cfg.CustomOutbounds {
		if co.Alias == alias {
			if co.InternalProxyPort <= 0 {
				fmt.Printf("ℹ️ Local proxy for '%s' was not configured.\n", alias)
				return nil
			}
			cfg.CustomOutbounds[i].InternalProxyPort = 0
			cfg.CustomOutbounds[i].InternalHttpPort = 0
			cfg.CustomOutbounds[i].InternalListenAddr = ""
			if err := cfg.SaveEx(true); err != nil {
				return fmt.Errorf("❌ Failed to save staging config: %w", err)
			}
			fmt.Printf("✅ Disabled local proxy for '%s' in STAGING.\n", alias)
			fmt.Println("🚀 Run 'apply' to commit changes.")
			return nil
		}
	}
	return fmt.Errorf("❌ Relay '%s' not found.", alias)
}

var proxyUnsetCmd = &cobra.Command{
	Use:   "unset [alias]",
	Short: "Disable local SOCKS/HTTP proxy for a relay in STAGING",
	Example: `  # Disable local proxy for a relay in STAGING
  xray-proxya proxy unset node-us
  xray-proxya apply`,
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		_ = runProxyUnset(cmd, args)
	},
	RunE: runProxyUnset,
}

func runProxyRun(cmd *cobra.Command, args []string) error {
	alias := args[0]
	cfg, _ := config.LoadConfigEx(true)
	if cfg == nil {
		cfg, _ = config.LoadConfig()
	}
	if cfg == nil {
		return fmt.Errorf("❌ Configuration could not be loaded.")
	}

	var targetCO *config.CustomOutbound
	for _, co := range cfg.CustomOutbounds {
		if co.Alias == alias {
			targetCO = &co
			break
		}
	}
	if targetCO == nil {
		return fmt.Errorf("❌ Relay '%s' not found.", alias)
	}

	socksSpecified := cmd.Flags().Changed("port") || cmd.Flags().Changed("socks-port") || proxyRunSocksPort != 0
	httpSpecified := cmd.Flags().Changed("http-port") || proxyRunHttpPort != 0
	listenSpecified := cmd.Flags().Changed("listen") || proxyRunListenIP != ""

	socksPort := proxyRunSocksPort
	httpPort := proxyRunHttpPort
	listenIP := proxyRunListenIP

	// SOCKS port
	if !socksSpecified {
		if targetCO.InternalProxyPort > 0 {
			socksPort = targetCO.InternalProxyPort
		} else {
			for {
				p, _ := xray.GetFreePort()
				if p > 0 && p < 65535 &&
					utils.IsPortFree(p) && utils.IsUDPPortFree(p) &&
					utils.IsPortFree(p+1) {
					socksPort = p
					break
				}
			}
		}
	}

	// HTTP port: if socks is explicitly set and http is not, link http = socks + 1
	if httpSpecified {
		// Use explicitly specified httpPort
	} else if socksSpecified {
		httpPort = socksPort + 1
	} else if targetCO.InternalHttpPort > 0 {
		httpPort = targetCO.InternalHttpPort
	} else {
		httpPort = socksPort + 1
	}

	// Listen IP
	if !listenSpecified {
		if targetCO.InternalListenAddr != "" {
			listenIP = targetCO.InternalListenAddr
		} else {
			listenIP = "127.0.0.1"
		}
	}

	if socksPort < 1 || socksPort > 65535 {
		return fmt.Errorf("❌ Invalid SOCKS port: %d (must be between 1 and 65535)", socksPort)
	}
	if httpPort < 1 || httpPort > 65535 {
		return fmt.Errorf("❌ Invalid HTTP port: %d (must be between 1 and 65535)", httpPort)
	}
	if socksPort == httpPort {
		return fmt.Errorf("❌ SOCKS port and HTTP port cannot be the same (%d).", socksPort)
	}

	if !utils.IsPortFree(socksPort) || !utils.IsUDPPortFree(socksPort) {
		return fmt.Errorf("❌ SOCKS Port %d is in use on the host.", socksPort)
	}
	if !utils.IsPortFree(httpPort) {
		return fmt.Errorf("❌ HTTP Port %d is in use on the host.", httpPort)
	}
	if ip := net.ParseIP(listenIP); ip == nil {
		return fmt.Errorf("❌ Invalid listen IP address: %s", listenIP)
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
		return fmt.Errorf("❌ Failed to generate config: %w", err)
	}

	var stderrBuf bytes.Buffer
	cmdProc, cleanup, err := xray.StartXrayTempWithOutput(jsonData, &stderrBuf)
	if err != nil {
		return fmt.Errorf("❌ Failed to start temporary Xray instance: %w", err)
	}
	defer cleanup()

	// Wait for SOCKS listener to become ready
	dialAddr := net.JoinHostPort(listenIP, strconv.Itoa(socksPort))
	if utils.IsWildcardIP(listenIP) {
		dialAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := utils.WaitForTCPPort(ctx, dialAddr, 5*time.Second); err != nil {
		if cmdProc.Process != nil {
			if sigErr := cmdProc.Process.Signal(syscall.Signal(0)); sigErr != nil {
				out := strings.TrimSpace(stderrBuf.String())
				if out != "" {
					return fmt.Errorf("❌ Temporary Xray instance exited prematurely: %s", out)
				}
				return fmt.Errorf("❌ Temporary Xray instance exited prematurely: %w", sigErr)
			}
		}
		out := strings.TrimSpace(stderrBuf.String())
		if out != "" {
			return fmt.Errorf("❌ SOCKS listener %s not ready: %v (xray stderr: %s)", dialAddr, err, out)
		}
		return fmt.Errorf("❌ SOCKS listener %s not ready: %w", dialAddr, err)
	}

	fmt.Printf("✅ Temporary SOCKS/HTTP proxy started successfully!\n")
	fmt.Printf("   👉 SOCKS5: %s:%d\n", listenIP, socksPort)
	fmt.Printf("   👉 HTTP:   %s:%d\n", listenIP, httpPort)
	fmt.Printf("   Target:    %s (%s)\n", alias, outboundRemoteSummary(coCopy))
	fmt.Println("\nPress Ctrl+C to terminate...")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nStopping proxy...")
	return nil
}

var proxyRunCmd = &cobra.Command{
	Use:   "run [alias]",
	Short: "Run a temporary standalone local SOCKS/HTTP proxy for a relay",
	Example: `  # Run temporary proxy in foreground
  xray-proxya proxy run node-us -p 20808

  # Run temporary proxy with LAN sharing
  xray-proxya proxy run node-us -p 20808 -l 0.0.0.0`,
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	RunE:              runProxyRun,
}

func normalizeProbeListenIP(listenIP string) string {
	if listenIP == "" || listenIP == "0.0.0.0" {
		return "127.0.0.1"
	}
	if listenIP == "::" {
		return "::1"
	}
	return listenIP
}

func testHTTPProxy(proxyAddr string) error {
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		return err
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   8 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: 8 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   12 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	targets := []string{
		"http://cp.cloudflare.com/generate_204",
		"http://connectivitycheck.gstatic.com/generate_204",
		"http://1.1.1.1",
	}
	var lastErr error
	for _, target := range targets {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		cancel()
		if err == nil {
			resp.Body.Close()
			return nil
		}
		lastErr = err
	}
	return lastErr
}

func runProxyTest(cmd *cobra.Command, args []string) error {
	alias := args[0]
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config.")
	}

	var targetCO *config.CustomOutbound
	for _, co := range cfg.CustomOutbounds {
		if co.Alias == alias {
			targetCO = &co
			break
		}
	}
	if targetCO == nil {
		return fmt.Errorf("❌ Relay '%s' not found.", alias)
	}

	if targetCO.InternalProxyPort <= 0 {
		return fmt.Errorf("❌ Local proxy is not configured for '%s'. Configure it first with 'xray-proxya proxy set %s'.", alias, alias)
	}

	var activeCfg *config.UserConfig
	if config.StagingExists() {
		activeCfg, _ = config.LoadConfigEx(false)
	} else {
		activeCfg = cfg
	}
	applied := isProxyApplied(*targetCO, activeCfg)

	socksPort := targetCO.InternalProxyPort
	httpPort := targetCO.InternalHttpPort
	if httpPort <= 0 {
		httpPort = socksPort + 1
	}

	probeListenIP := normalizeProbeListenIP(targetCO.InternalListenAddr)
	socksAddr := net.JoinHostPort(probeListenIP, strconv.Itoa(socksPort))
	httpAddr := net.JoinHostPort(probeListenIP, strconv.Itoa(httpPort))

	dialer, err := utils.NewSOCKS5Dialer(socksAddr)
	if err != nil {
		if !applied {
			fmt.Printf("💡 Hint: Local proxy for '%s' is in STAGING but not yet active. Run 'xray-proxya apply' to start it.\n", alias)
		}
		return fmt.Errorf("❌ Failed to create SOCKS dialer: %w", err)
	}

	fmt.Printf("🔍 Testing local SOCKS5 proxy at %s...\n", socksAddr)

	socksTargets := []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}
	var lastTCPErr error
	tcpOK := false
	for _, target := range socksTargets {
		conn, err := dialer.Dial("tcp", target)
		if err == nil {
			conn.Close()
			tcpOK = true
			break
		}
		lastTCPErr = err
	}
	if !tcpOK {
		if !applied {
			fmt.Printf("💡 Hint: Local proxy for '%s' is in STAGING but not yet active. Run 'xray-proxya apply' to start it.\n", alias)
		}
		return fmt.Errorf("❌ TCP test failed: %w", lastTCPErr)
	}
	fmt.Println("✅ SOCKS5 TCP connectivity OK.")

	// Test UDP query/ping if supported
	duration, err := xray.TestUDP(socksAddr, "user-"+alias, "test")
	if err == nil {
		fmt.Printf("✅ SOCKS5 UDP connectivity OK (%dms).\n", duration.Milliseconds())
	} else {
		fmt.Printf("⚠️  SOCKS5 UDP test failed: %v\n", err)
	}

	// Test HTTP proxy
	fmt.Printf("🔍 Testing local HTTP proxy at %s...\n", httpAddr)
	if err := testHTTPProxy(httpAddr); err != nil {
		if !applied {
			fmt.Printf("💡 Hint: Local proxy for '%s' is in STAGING but not yet active. Run 'xray-proxya apply' to start it.\n", alias)
		}
		return fmt.Errorf("❌ HTTP proxy test failed: %w", err)
	}
	fmt.Println("✅ HTTP proxy connectivity OK.")

	if proxyTestProbe {
		fmt.Printf("\n🌐 Probing outbound IP via local proxy...\n")
		runProxyProbeTarget(alias, *targetCO)
	}

	return nil
}

var proxyTestProbe bool

var proxyTestCmd = &cobra.Command{
	Use:               "test [alias]",
	Short:             "Test connectivity of a configured local proxy",
	Example: `  # Test connectivity of configured local proxy
  xray-proxya proxy test node-us

  # Test connectivity and probe outbound public IP
  xray-proxya proxy test node-us --probe`,
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	Run: func(cmd *cobra.Command, args []string) {
		_ = runProxyTest(cmd, args)
	},
	RunE: runProxyTest,
}

func resolveProxyTargets(co config.CustomOutbound) (string, string) {
	listenHost := normalizeProbeListenIP(co.InternalListenAddr)
	httpPort := co.InternalHttpPort
	if httpPort <= 0 {
		httpPort = co.InternalProxyPort + 1
	}
	socksTarget := net.JoinHostPort(listenHost, strconv.Itoa(co.InternalProxyPort))
	httpTarget := net.JoinHostPort(listenHost, strconv.Itoa(httpPort))
	return socksTarget, httpTarget
}

func runProxyProbeTarget(alias string, co config.CustomOutbound) {
	socksTarget, httpTarget := resolveProxyTargets(co)
	printProxyProbe(alias, "SOCKS", probeBoundProxy("socks5h://"+socksTarget))
	printProxyProbe(alias, "HTTP", probeBoundProxy("http://"+httpTarget))
}

func runProxyProbe(cmd *cobra.Command, args []string) error {
	alias := args[0]
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config.")
	}

	var targetCO *config.CustomOutbound
	for _, co := range cfg.CustomOutbounds {
		if co.Alias == alias {
			targetCO = &co
			break
		}
	}
	if targetCO == nil {
		return fmt.Errorf("❌ Relay '%s' not found.", alias)
	}

	if targetCO.InternalProxyPort <= 0 {
		return fmt.Errorf("❌ Local proxy is not configured for '%s'. Configure it first with 'xray-proxya proxy set %s'.", alias, alias)
	}

	runProxyProbeTarget(alias, *targetCO)
	return nil
}

var proxyProbeCmd = &cobra.Command{
	Use:               "probe [alias]",
	Short:             "Probe outbound public IP addresses via configured local proxy",
	Example: `  # Probe outbound IPv4/IPv6 via configured local proxy
  xray-proxya proxy probe node-us`,
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	RunE:              runProxyProbe,
}

var proxyEnvUnset bool

func runProxyEnv(cmd *cobra.Command, args []string) error {
	if proxyEnvUnset {
		fmt.Println("unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY")
		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("❌ Please specify a relay alias (e.g. 'xray-proxya proxy env <alias>') or use --unset")
	}

	alias := args[0]
	cfg, err := config.LoadConfigEx(true)
	if err != nil || cfg == nil {
		return fmt.Errorf("❌ Failed to load staging config.")
	}

	var targetCO *config.CustomOutbound
	for _, co := range cfg.CustomOutbounds {
		if co.Alias == alias {
			targetCO = &co
			break
		}
	}
	if targetCO == nil {
		return fmt.Errorf("❌ Relay '%s' not found.", alias)
	}

	if targetCO.InternalProxyPort <= 0 {
		return fmt.Errorf("❌ Local proxy is not configured for '%s'. Configure it first with 'xray-proxya proxy set %s'.", alias, alias)
	}

	listenIP := normalizeProbeListenIP(targetCO.InternalListenAddr)
	if strings.Contains(listenIP, ":") && !strings.HasPrefix(listenIP, "[") {
		listenIP = "[" + listenIP + "]"
	}

	socksPort := targetCO.InternalProxyPort
	httpPort := targetCO.InternalHttpPort
	if httpPort <= 0 {
		httpPort = socksPort + 1
	}

	httpURL := fmt.Sprintf("http://%s:%d", listenIP, httpPort)
	socksURL := fmt.Sprintf("socks5h://%s:%d", listenIP, socksPort)

	fmt.Printf("export http_proxy=%q\n", httpURL)
	fmt.Printf("export https_proxy=%q\n", httpURL)
	fmt.Printf("export all_proxy=%q\n", socksURL)
	fmt.Printf("export HTTP_PROXY=%q\n", httpURL)
	fmt.Printf("export HTTPS_PROXY=%q\n", httpURL)
	fmt.Printf("export ALL_PROXY=%q\n", socksURL)
	return nil
}

var proxyEnvCmd = &cobra.Command{
	Use:   "env [alias]",
	Short: "Output shell export commands for local HTTP/SOCKS proxy",
	Long:  "Generate shell export/unset statements for http_proxy, https_proxy, and all_proxy. Can be used with 'eval $(xray-proxya proxy env <alias>)'.",
	Example: `  # Set proxy environment variables in current shell
  eval $(xray-proxya proxy env node-us)

  # Unset proxy environment variables
  eval $(xray-proxya proxy env --unset)`,
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	RunE:              runProxyEnv,
}

func init() {
	proxyListCmd.Flags().BoolVar(&proxyListJSON, "json", false, "Output local proxies in JSON format")
	proxyListCmd.Flags().BoolVarP(&proxyListAll, "all", "a", false, "List all relays including those without local proxy")

	proxySetCmd.Flags().IntVarP(&proxySetSocksPort, "port", "p", 0, "Base port (SOCKS port, HTTP port will be SOCKS+1)")
	proxySetCmd.Flags().IntVar(&proxySetSocksPort, "socks-port", 0, "Specific SOCKS port")
	proxySetCmd.Flags().IntVar(&proxySetHttpPort, "http-port", 0, "Specific HTTP port")
	proxySetCmd.Flags().StringVarP(&proxySetListenIP, "listen", "l", "127.0.0.1", "IP address to listen on")
	proxySetCmd.RegisterFlagCompletionFunc("listen", completeIPListenAddresses)

	proxyRunCmd.Flags().IntVarP(&proxyRunSocksPort, "port", "p", 0, "Base port (SOCKS port, HTTP port will be SOCKS+1)")
	proxyRunCmd.Flags().IntVar(&proxyRunSocksPort, "socks-port", 0, "Specific SOCKS port")
	proxyRunCmd.Flags().IntVar(&proxyRunHttpPort, "http-port", 0, "Specific HTTP port")
	proxyRunCmd.Flags().StringVarP(&proxyRunListenIP, "listen", "l", "", "IP address to listen on")
	proxyRunCmd.RegisterFlagCompletionFunc("listen", completeIPListenAddresses)

	proxyTestCmd.Flags().BoolVarP(&proxyTestProbe, "probe", "p", false, "Probe outbound IP address after connectivity tests")

	proxyEnvCmd.Flags().BoolVarP(&proxyEnvUnset, "unset", "u", false, "Output shell unset commands")

	proxyCmd.AddCommand(proxyListCmd, proxySetCmd, proxyUnsetCmd, proxyRunCmd, proxyTestCmd, proxyEnvCmd, proxyProbeCmd)
	rootCmd.AddCommand(proxyCmd)
}
