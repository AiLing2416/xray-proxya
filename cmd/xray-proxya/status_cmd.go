package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/trafficstats"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show unified systemd services, network state, and traffic overview",
	Run: func(cmd *cobra.Command, args []string) {
		if _, err := os.Stat(config.GetConfigPath()); os.IsNotExist(err) {
			fmt.Println("❌ Error: Xray-Proxya has not been initialized. Please run 'xray-proxya init' first.")
			os.Exit(1)
		}

		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("❌ Failed to load active config: %v\n", err)
			return
		}

		isRoot := os.Geteuid() == 0

		fmt.Printf("\n🛰️  XRAY-PROXYA RUNTIME OVERVIEW (Role: %s)\n", strings.ToUpper(string(cfg.Role)))
		fmt.Println("============================================================")

		// 1. Managed Services (systemd)
		fmt.Println("🧩 Managed Services (systemd):")
		printServiceUnitStatus(cfg, isRoot)

		// 2. User session lingering (if non-root)
		if !isRoot {
			user := currentLingerUser()
			enabled, err := checkLingerStatus(user)
			if err == nil && enabled {
				fmt.Printf("   👤 User Session Lingering:      [Enabled]  (User: %s, linger is enabled)\n", user)
			} else {
				fmt.Printf("   👤 User Session Lingering:      [Disabled] (User: %s, linger is disabled)\n", user)
			}
		}

		// 3. Network & Role Configuration
		fmt.Println("\n🌐 Network & Proxy State:")
		if cfg.Role == config.RoleGateway {
			gwState := cfg.Gateway.State
			if gwState == "" {
				gwState = "proxy"
			}
			localStr := "OFF"
			if cfg.Gateway.LocalEnabled {
				localStr = "ON"
			}
			lanStr := "OFF"
			if cfg.Gateway.LANEnabled {
				lanStr = fmt.Sprintf("ON (Iface: %s)", cfg.Gateway.LANInterface)
			}
			relayStr := cfg.Gateway.RelayAlias
			if relayStr == "" {
				relayStr = "direct"
			}
			fmt.Printf("   - Gateway State  : %s (Mode: %s)\n", gwState, cfg.Gateway.Mode)
			fmt.Printf("   - Local / LAN    : Local: %s | LAN: %s\n", localStr, lanStr)
			fmt.Printf("   - Active Relay   : %s\n", relayStr)
		} else {
			activePresets := 0
			for _, p := range cfg.Presets {
				if p.Enabled {
					activePresets++
				}
			}
			fmt.Printf("   - Active Presets : %d / %d\n", activePresets, len(cfg.Presets))
			fmt.Printf("   - Relays / Guests: %d relays | %d guests\n", len(cfg.CustomOutbounds), len(cfg.Guests))
		}

		if config.StagingExists() {
			fmt.Println("   - Staging Config : ⚠️ Pending changes in STAGING (Run 'apply' to commit)")
		} else {
			fmt.Println("   - Staging Config : Clean (In sync with active)")
		}

		// 4. Traffic Statistics
		mainActive, _, _ := querySystemdUnitState(xray.MainServiceUnit)
		if !mainActive {
			fmt.Println("\n📊 Traffic Statistics (gRPC API):")
			fmt.Println("   (Xray Core service is inactive; traffic statistics unavailable)")
			fmt.Println("============================================================")
			return
		}

		allStats, err := xray.GetXrayStats(cfg.APIInbound)
		if err != nil {
			fmt.Println("\n📊 Traffic Statistics (gRPC API):")
			fmt.Printf("   ⚠️ Failed to query API traffic stats (port %d): %v\n", cfg.APIInbound, err)
			fmt.Println("============================================================")
			return
		}

		fmt.Println("\n📊 Traffic Statistics (gRPC API):")
		summary := trafficstats.Summarize(allStats)

		fmt.Printf("   🌐 Total Direct: %s | Total Relay: %s\n",
			utils.FormatBytes(summary.Direct), utils.FormatBytes(summary.Relay))

		printNamedStats("\n   📥 Service Inbounds:", summary.InboundStats)
		printNamedStats("\n   🧭 Direct / Service Usage:", summary.ServiceStats)
		printNamedStats("\n   🔁 Relay Usage:", summary.RelayStats)
		printGuestStatsWithDetails(summary.GuestStats, cfg.Guests)

		fmt.Println("============================================================")
	},
}

func querySystemdUnitState(unit string) (bool, int, string) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, 0, "[N/A (systemctl missing)]"
	}
	args := append(xray.SystemdScopeArgs(), "is-active", unit)
	cmd := exec.Command("systemctl", args...)
	if err := cmd.Run(); err != nil {
		showArgs := append(xray.SystemdScopeArgs(), "show", "-p", "ActiveState,LoadState", "--value", unit)
		out, err2 := exec.Command("systemctl", showArgs...).Output()
		if err2 == nil {
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			if len(lines) >= 2 && lines[1] == "not-found" {
				return false, 0, "[Not Installed]"
			}
			if len(lines) >= 1 && lines[0] == "failed" {
				return false, 0, "[Failed]"
			}
		}
		return false, 0, "[Inactive]"
	}
	showPIDArgs := append(xray.SystemdScopeArgs(), "show", "-p", "MainPID", "--value", unit)
	out, err := exec.Command("systemctl", showPIDArgs...).Output()
	pid := 0
	if err == nil {
		pid, _ = strconv.Atoi(strings.TrimSpace(string(out)))
	}
	return true, pid, "[Active]"
}

func printServiceUnitStatus(cfg *config.UserConfig, isRoot bool) {
	// Main service
	mainRootOnly := (cfg.Role == config.RoleGateway)
	if !isRoot && mainRootOnly {
		fmt.Printf("   ○ %-30s [Unavailable] (root only)\n", xray.MainServiceUnit)
	} else {
		active, pid, status := querySystemdUnitState(xray.MainServiceUnit)
		icon := "●"
		if !active {
			icon = "○"
		}
		if active && pid > 0 {
			fmt.Printf("   %s %-30s %-12s PID: %-7d\n", icon, xray.MainServiceUnit, status, pid)
		} else {
			fmt.Printf("   %s %-30s %s\n", icon, xray.MainServiceUnit, status)
		}
	}

	// Pathd service
	if !isRoot {
		fmt.Printf("   ○ %-30s [Unavailable] (root only)\n", pathdServiceUnit)
	} else if cfg.Role != config.RoleServer {
		fmt.Printf("   ○ %-30s [N/A] (Server role only)\n", pathdServiceUnit)
	} else {
		active, pid, status := querySystemdUnitState(pathdServiceUnit)
		icon := "●"
		if !active {
			icon = "○"
		}
		if active && pid > 0 {
			fmt.Printf("   %s %-30s %-12s PID: %-7d (ICMP Probe)\n", icon, pathdServiceUnit, status, pid)
		} else {
			fmt.Printf("   %s %-30s %s\n", icon, pathdServiceUnit, status)
		}
	}

	// Sub instances
	subInstances := make(map[string]config.AdminSubConfig)
	if cfg.SubscriptionInstances != nil && len(cfg.SubscriptionInstances) > 0 {
		subInstances = cfg.SubscriptionInstances
	} else if cfg.AdminSub.Token != "" {
		subInstances["default"] = cfg.AdminSub
	}

	if len(subInstances) == 0 {
		fmt.Printf("   ○ %-30s [Inactive] (Not configured)\n", "xray-proxya-sub@default")
	} else {
		instNames := make([]string, 0, len(subInstances))
		for name := range subInstances {
			instNames = append(instNames, name)
		}
		sort.Strings(instNames)
		for _, inst := range instNames {
			entry := subInstances[inst]
			unitName := fmt.Sprintf("xray-proxya-sub@%s.service", inst)
			subRootOnly := (entry.IPv6Rotation != "" || entry.Port <= 1024)
			if !isRoot && subRootOnly {
				fmt.Printf("   ○ %-30s [Unavailable] (root only)\n", unitName)
			} else {
				active, pid, status := querySystemdUnitState(unitName)
				icon := "●"
				if !active {
					icon = "○"
				}
				if active {
					fmt.Printf("   %s %-30s %-12s Port: %-5d PID: %-7d\n", icon, unitName, status, entry.Port, pid)
				} else {
					fmt.Printf("   %s %-30s %s (Port: %d)\n", icon, unitName, status, entry.Port)
				}
			}
		}
	}

	// IPv6 rotate service
	if !isRoot {
		fmt.Printf("   ○ %-30s [Unavailable] (root only)\n", rotateServiceUnit)
	} else {
		hasIPv6Config := cfg.IPv6Rotation.Subnet != "" || (cfg.IPv6Rotations != nil && cfg.IPv6Rotations["default"].Subnet != "")
		if !hasIPv6Config {
			fmt.Printf("   ○ %-30s [Inactive] (Not configured)\n", rotateServiceUnit)
		} else {
			active, pid, status := querySystemdUnitState(rotateServiceUnit)
			icon := "●"
			if !active {
				icon = "○"
			}
			if active && pid > 0 {
				fmt.Printf("   %s %-30s %-12s PID: %-7d\n", icon, rotateServiceUnit, status, pid)
			} else {
				fmt.Printf("   %s %-30s %s\n", icon, rotateServiceUnit, status)
			}
		}
	}
}

func printNamedStats(title string, stats map[string]int64) {
	if len(stats) == 0 {
		return
	}
	fmt.Println(title)
	keys := make([]string, 0, len(stats))
	for key := range stats {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Printf("      - %-25s: %s\n", key, utils.FormatBytes(stats[key]))
	}
}

func printGuestStatsWithDetails(guestStats map[string]int64, guests []config.GuestConfig) {
	if len(guests) == 0 && len(guestStats) == 0 {
		return
	}
	fmt.Println("\n   👥 Guest Usage:")
	guestMap := make(map[string]config.GuestConfig)
	for _, g := range guests {
		guestMap[g.Alias] = g
	}

	seen := make(map[string]bool)
	var allAliases []string
	for alias := range guestStats {
		if !seen[alias] {
			seen[alias] = true
			allAliases = append(allAliases, alias)
		}
	}
	for _, g := range guests {
		if !seen[g.Alias] {
			seen[g.Alias] = true
			allAliases = append(allAliases, g.Alias)
		}
	}
	sort.Strings(allAliases)

	for _, alias := range allAliases {
		trafficBytes := guestStats[alias]
		trafficFormatted := utils.FormatBytes(trafficBytes)
		if g, ok := guestMap[alias]; ok {
			state := guestStateLabel(g)
			quotaFormatted := formatGuestQuota(g.QuotaGB)
			fmt.Printf("      - %-15s: %s (Quota: %s) [%s]\n", alias, trafficFormatted, quotaFormatted, state)
		} else {
			fmt.Printf("      - %-15s: %s\n", alias, trafficFormatted)
		}
	}
}

func summarizeStats(allStats map[string]int64) (int64, int64, map[string]int64, map[string]int64, map[string]int64, map[string]int64) {
	summary := trafficstats.Summarize(allStats)
	return summary.Direct, summary.Relay, summary.ServiceStats, summary.RelayStats, summary.GuestStats, summary.InboundStats
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
