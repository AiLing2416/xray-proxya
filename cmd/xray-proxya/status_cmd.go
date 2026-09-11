package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/quota"
	"xray-proxya/internal/service"
	"xray-proxya/internal/trafficstats"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var statusJSON bool

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show unified systemd services, network state, and traffic overview",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := os.Stat(config.GetConfigPath()); os.IsNotExist(err) {
			return fmt.Errorf("❌ Error: Xray-Proxya has not been initialized. Please run 'xray-proxya init' first.")
		}

		cfg, err := config.LoadConfig()
		if err != nil {
			return fmt.Errorf("❌ Failed to load active config: %w", err)
		}

		isRoot := os.Geteuid() == 0

		if statusJSON {
			return outputStatusJSON(cfg, isRoot)
		}

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
			return nil
		}

		allStats, err := xray.GetXrayStats(cfg.APIInbound)
		if err != nil {
			fmt.Println("\n📊 Traffic Statistics (gRPC API):")
			fmt.Printf("   ⚠️ Failed to query API traffic stats (port %d): %v\n", cfg.APIInbound, err)
			fmt.Println("============================================================")
			return nil
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
		return nil
	},
}

func querySystemdUnitState(unit string) (bool, int, string) {
	st := service.GetUnitStatus(unit)
	statusStr := "[" + st.State + "]"
	if st.Active {
		statusStr = "[Active]"
	} else if st.State == "Stopped" {
		statusStr = "[Inactive]"
	}
	return st.Active, st.PID, statusStr
}

func printServiceUnitStatus(cfg *config.UserConfig, isRoot bool) {
	// 1. Main service
	mainLabel := fmt.Sprintf("%s (%s)", service.UnitDisplayName(xray.MainServiceUnit), xray.MainServiceUnit)
	mainRootOnly := (cfg.Role == config.RoleGateway)
	if !isRoot && mainRootOnly {
		fmt.Printf("   ○ %-40s [Unavailable] (root only)\n", mainLabel)
	} else {
		active, pid, status := querySystemdUnitState(xray.MainServiceUnit)
		icon := "●"
		if !active {
			icon = "○"
		}
		if active && pid > 0 {
			fmt.Printf("   %s %-40s %-12s PID: %-7d\n", icon, mainLabel, status, pid)
		} else {
			fmt.Printf("   %s %-40s %s\n", icon, mainLabel, status)
		}
	}

	// 2. Subscription service
	port := cfg.SubPort
	if port <= 0 {
		port = cfg.AdminSub.Port
	}
	subConfigured := cfg.AdminSub.Token != "" || port > 0
	subLabel := fmt.Sprintf("%s (%s)", service.UnitDisplayName(subServiceUnit), subServiceUnit)
	if !subConfigured {
		fmt.Printf("   ○ %-40s [Inactive] (Not configured)\n", subLabel)
	} else {
		subRootOnly := port <= 1024
		if !isRoot && subRootOnly {
			fmt.Printf("   ○ %-40s [Unavailable] (root only)\n", subLabel)
		} else {
			active, pid, status := querySystemdUnitState(subServiceUnit)
			icon := "●"
			if !active {
				icon = "○"
			}
			if active && pid > 0 {
				fmt.Printf("   %s %-40s %-12s Port: %-5d PID: %-7d\n", icon, subLabel, status, port, pid)
			} else {
				fmt.Printf("   %s %-40s %s (Port: %d)\n", icon, subLabel, status, port)
			}
		}
	}

	// 3. Pathd service
	pathdLabel := fmt.Sprintf("%s (%s)", service.UnitDisplayName(pathdServiceUnit), pathdServiceUnit)
	if !isRoot {
		fmt.Printf("   ○ %-40s [Unavailable] (root only)\n", pathdLabel)
	} else if cfg.Role != config.RoleServer {
		fmt.Printf("   ○ %-40s [N/A] (Server role only)\n", pathdLabel)
	} else {
		active, pid, status := querySystemdUnitState(pathdServiceUnit)
		icon := "●"
		if !active {
			icon = "○"
		}
		if active && pid > 0 {
			fmt.Printf("   %s %-40s %-12s PID: %-7d (ICMP Probe)\n", icon, pathdLabel, status, pid)
		} else {
			fmt.Printf("   %s %-40s %s\n", icon, pathdLabel, status)
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
		if g, ok := guestMap[alias]; ok {
			v := quota.BuildGuestView(g, time.Now())
			fmt.Printf("      - %-15s: %s (Quota: %s) [%s]\n", alias, utils.FormatBytes(trafficBytes), v.QuotaFormatted, v.StateLabel)
		} else {
			fmt.Printf("      - %-15s: %s\n", alias, utils.FormatBytes(trafficBytes))
		}
	}
}

func summarizeStats(allStats map[string]int64) (int64, int64, map[string]int64, map[string]int64, map[string]int64, map[string]int64) {
	summary := trafficstats.Summarize(allStats)
	return summary.Direct, summary.Relay, summary.ServiceStats, summary.RelayStats, summary.GuestStats, summary.InboundStats
}

type StatusJSONOutput struct {
	Role            string                 `json:"role"`
	ManagedServices []service.Status       `json:"managed_services"`
	NetworkState    map[string]interface{} `json:"network_state"`
	Traffic         *TrafficJSONOutput     `json:"traffic,omitempty"`
	StagingClean    bool                   `json:"staging_clean"`
}

type TrafficJSONOutput struct {
	Direct       int64                       `json:"direct_bytes"`
	Relay        int64                       `json:"relay_bytes"`
	Inbounds     map[string]int64            `json:"inbounds"`
	ServiceUsage map[string]int64            `json:"service_usage"`
	RelayUsage   map[string]int64            `json:"relay_usage"`
	Guests       map[string]GuestTrafficJSON `json:"guests"`
}

type GuestTrafficJSON struct {
	UsedBytes  int64   `json:"used_bytes"`
	LimitBytes int64   `json:"limit_bytes"`
	QuotaGB    float64 `json:"quota_gb"`
	State      string  `json:"state"`
	Reason     string  `json:"reason"`
}

func outputStatusJSON(cfg *config.UserConfig, isRoot bool) error {
	managedServices, _ := service.ListManagedServices(cfg)
	if len(managedServices) == 0 {
		managedServices = []service.Status{
			service.GetUnitStatus(service.MainUnit),
			service.GetUnitStatus(service.PathdUnit),
			service.GetUnitStatus(service.SubUnit),
		}
	}

	networkState := make(map[string]interface{})
	if cfg.Role == config.RoleGateway {
		gwState := cfg.Gateway.State
		if gwState == "" {
			gwState = "proxy"
		}
		relayStr := cfg.Gateway.RelayAlias
		if relayStr == "" {
			relayStr = "direct"
		}
		networkState["gateway_state"] = gwState
		networkState["gateway_mode"] = cfg.Gateway.Mode
		networkState["local_enabled"] = cfg.Gateway.LocalEnabled
		networkState["lan_enabled"] = cfg.Gateway.LANEnabled
		networkState["lan_interface"] = cfg.Gateway.LANInterface
		networkState["active_relay"] = relayStr
	} else {
		networkState["sub_port"] = cfg.SubPort
		networkState["guest_sub_port"] = cfg.GuestSubPort
		networkState["guest_sub_bind"] = cfg.GuestSubBind
	}

	activePresets := 0
	for _, p := range cfg.Presets {
		if p.Enabled {
			activePresets++
		}
	}
	networkState["active_presets"] = activePresets
	networkState["total_presets"] = len(cfg.Presets)
	networkState["relays_count"] = len(cfg.CustomOutbounds)
	networkState["guests_count"] = len(cfg.Guests)

	var trafficOutput *TrafficJSONOutput
	allStats, err := xray.GetXrayStats(cfg.APIInbound)
	if err == nil && allStats != nil {
		summary := trafficstats.Summarize(allStats)
		guestTrafficMap := make(map[string]GuestTrafficJSON)
		now := time.Now()
		for _, g := range cfg.Guests {
			used := summary.GuestStats[g.Alias]
			view := quota.BuildGuestView(g, now)
			guestTrafficMap[g.Alias] = GuestTrafficJSON{
				UsedBytes:  used,
				LimitBytes: g.EffectiveLimitBytes(),
				QuotaGB:    g.QuotaGB,
				State:      view.StateLabel,
				Reason:     view.ReasonLabel,
			}
		}
		trafficOutput = &TrafficJSONOutput{
			Direct:       summary.Direct,
			Relay:        summary.Relay,
			Inbounds:     summary.InboundStats,
			ServiceUsage: summary.ServiceStats,
			RelayUsage:   summary.RelayStats,
			Guests:       guestTrafficMap,
		}
	}

	output := StatusJSONOutput{
		Role:            string(cfg.Role),
		ManagedServices: managedServices,
		NetworkState:    networkState,
		Traffic:         trafficOutput,
		StagingClean:    !config.StagingExists(),
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("❌ Failed to serialize status JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func init() {
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "Output status in JSON format")
	rootCmd.AddCommand(statusCmd)
}
