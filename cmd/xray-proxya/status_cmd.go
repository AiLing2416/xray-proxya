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
	"xray-proxya/internal/ui"
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

		colorEnabled := ui.IsColorEnabled()
		user := "root"
		if !isRoot {
			user = currentLingerUser()
		}

		fmt.Printf("\n🛰️  XRAY-PROXYA RUNTIME OVERVIEW (Role: %s, User: %s)\n\n", strings.ToUpper(string(cfg.Role)), user)

		// 1. Managed Services (systemd)
		fmt.Println("● SERVICES (systemd)")
		printServiceUnitStatus(cfg, isRoot)

		// 2. Network & Role Configuration
		fmt.Println("\n🌐 NETWORK & PROXY")
		if cfg.Role == config.RoleGateway {
			gwState := cfg.Gateway.State
			if gwState == "" {
				gwState = "proxy"
			}
			localStr := ui.Gray("OFF", colorEnabled)
			if cfg.Gateway.LocalEnabled {
				localStr = ui.Green("ON", colorEnabled)
			}
			lanStr := ui.Gray("OFF", colorEnabled)
			if cfg.Gateway.LANEnabled {
				lanStr = fmt.Sprintf("%s (Iface: %s)", ui.Green("ON", colorEnabled), cfg.Gateway.LANInterface)
			}
			relayStr := cfg.Gateway.RelayAlias
			if relayStr == "" {
				relayStr = "direct"
			}
			fmt.Printf("  Gateway State      : %s (Mode: %s)\n", gwState, cfg.Gateway.Mode)
			fmt.Printf("  Interception       : Local: %s │ LAN: %s\n", localStr, lanStr)
			fmt.Printf("  Active Outbound    : %s\n", relayStr)
			fmt.Printf("  Managed Resources  : %d relays │ %d guest tenants │ %d certificates\n",
				len(cfg.CustomOutbounds), len(cfg.Guests), len(cfg.Certs))
		} else {
			activePresets := 0
			for _, p := range cfg.Presets {
				if p.Enabled {
					activePresets++
				}
			}
			fmt.Printf("  Active Presets     : %d / %d enabled\n", activePresets, len(cfg.Presets))
			fmt.Printf("  Managed Resources  : %d relays │ %d guest tenants │ %d certificates\n",
				len(cfg.CustomOutbounds), len(cfg.Guests), len(cfg.Certs))
		}

		// 3. Traffic Statistics
		mainActive, _, _ := querySystemdUnitState(xray.MainServiceUnit)
		if !mainActive {
			fmt.Println("\n📊 TRAFFIC & USAGE")
			fmt.Println("  (Xray Core service is inactive; traffic statistics unavailable)")
		} else {
			allStats, err := xray.GetXrayStats(cfg.APIInbound)
			if err != nil {
				fmt.Println("\n📊 TRAFFIC & USAGE")
				fmt.Printf("  ⚠️ Failed to query API traffic stats (port %d): %v\n", cfg.APIInbound, err)
			} else {
				fmt.Println("\n📊 TRAFFIC & USAGE")
				summary := trafficstats.Summarize(allStats)
				fmt.Printf("  Throughput Total   : Direct: %s │ Relay: %s\n",
					utils.FormatBytes(summary.Direct), utils.FormatBytes(summary.Relay))
				printNamedStats("\n  📥 Service Inbounds:", summary.InboundStats)
				printNamedStats("\n  🧭 Direct / Service Usage:", summary.ServiceStats)
				printNamedStats("\n  🔁 Relay Usage:", summary.RelayStats)
				printGuestStatsWithDetails(summary.GuestStats, cfg.Guests)
			}
		}

		// 4. Staging Status Banner
		if config.StagingExists() {
			fmt.Printf("\n%s\n\n", ui.Warning("Pending changes in STAGING. Run 'xray-proxya apply' to commit."))
		} else {
			fmt.Printf("\n%s\n\n", ui.Success("Staging configuration is clean and in sync with active."))
		}
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

func formatServiceUnitLine(displayName, unitName, stateStr string, active bool, detail string, colorEnabled bool) string {
	icon := ui.Gray(ui.SymHollow, colorEnabled)
	stateColored := ui.Gray(stateStr, colorEnabled)
	if active {
		icon = ui.Green(ui.SymBullet, colorEnabled)
		stateColored = ui.Green(stateStr, colorEnabled)
	} else if strings.EqualFold(stateStr, "failed") || strings.EqualFold(stateStr, "error") {
		icon = ui.Red(ui.SymBullet, colorEnabled)
		stateColored = ui.Red(stateStr, colorEnabled)
	}

	detailStr := detail
	if detailStr == "" {
		detailStr = ui.Gray("-", colorEnabled)
	}

	return fmt.Sprintf("  %-18s │ %s %-10s │ %-12s │ %s\n",
		displayName,
		icon,
		stateColored,
		detailStr,
		unitName,
	)
}

func printServiceUnitStatus(cfg *config.UserConfig, isRoot bool) {
	colorEnabled := ui.IsColorEnabled()

	// 1. Main service
	mainRootOnly := (cfg.Role == config.RoleGateway)
	if !isRoot && mainRootOnly {
		fmt.Print(formatServiceUnitLine("Main Core", xray.MainServiceUnit, "Unavailable", false, "root only", colorEnabled))
	} else {
		active, pid, _ := querySystemdUnitState(xray.MainServiceUnit)
		stateStr := "Inactive"
		detail := "-"
		if active {
			stateStr = "Active"
			if pid > 0 {
				detail = fmt.Sprintf("PID: %d", pid)
			}
		}
		fmt.Print(formatServiceUnitLine("Main Core", xray.MainServiceUnit, stateStr, active, detail, colorEnabled))
	}

	// 2. Subscription service
	port := cfg.SubPort
	if port <= 0 {
		port = cfg.AdminSub.Port
	}
	subConfigured := cfg.AdminSub.Token != "" || port > 0
	if !subConfigured {
		fmt.Print(formatServiceUnitLine("Subscription Dist", subServiceUnit, "Inactive", false, "Not configured", colorEnabled))
	} else {
		subRootOnly := port <= 1024
		if !isRoot && subRootOnly {
			fmt.Print(formatServiceUnitLine("Subscription Dist", subServiceUnit, "Unavailable", false, "root only", colorEnabled))
		} else {
			active, pid, _ := querySystemdUnitState(subServiceUnit)
			stateStr := "Inactive"
			detail := fmt.Sprintf("Port: %d", port)
			if active {
				stateStr = "Active"
				if pid > 0 {
					detail = fmt.Sprintf("PID: %d", pid)
				}
			}
			fmt.Print(formatServiceUnitLine("Subscription Dist", subServiceUnit, stateStr, active, detail, colorEnabled))
		}
	}

	// 3. Pathd service
	if !isRoot {
		fmt.Print(formatServiceUnitLine("Pathd Daemon", pathdServiceUnit, "Unavailable", false, "root only", colorEnabled))
	} else if cfg.Role != config.RoleServer {
		fmt.Print(formatServiceUnitLine("Pathd Daemon", pathdServiceUnit, "N/A", false, "Server only", colorEnabled))
	} else {
		active, pid, _ := querySystemdUnitState(pathdServiceUnit)
		stateStr := "Inactive"
		detail := "-"
		if active {
			stateStr = "Active"
			if pid > 0 {
				detail = fmt.Sprintf("PID: %d", pid)
			}
		}
		fmt.Print(formatServiceUnitLine("Pathd Daemon", pathdServiceUnit, stateStr, active, detail, colorEnabled))
	}

	// 4. Session linger (if non-root)
	if !isRoot {
		user := currentLingerUser()
		enabled, err := checkLingerStatus(user)
		lingerState := "Disabled"
		detail := "User: " + user
		if err == nil && enabled {
			lingerState = "Enabled"
		}
		fmt.Print(formatServiceUnitLine("User Session Linger", "systemd --user", lingerState, enabled, detail, colorEnabled))
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
		guestMap[config.SanitizeGuestAlias(g.Alias)] = g
	}

	seen := make(map[string]bool)
	var allKeys []string
	for key := range guestStats {
		if !seen[key] {
			seen[key] = true
			allKeys = append(allKeys, key)
		}
	}
	for _, g := range guests {
		key := config.SanitizeGuestAlias(g.Alias)
		if !seen[key] {
			seen[key] = true
			allKeys = append(allKeys, key)
		}
	}
	sort.Strings(allKeys)

	for _, key := range allKeys {
		trafficBytes := guestStats[key]
		if g, ok := guestMap[key]; ok {
			v := quota.BuildGuestView(g, time.Now())
			fmt.Printf("      - %-15s: %s (Quota: %s) [%s]\n", g.Alias, utils.FormatBytes(trafficBytes), v.QuotaFormatted, v.StateLabel)
		} else {
			fmt.Printf("      - %-15s: %s\n", key, utils.FormatBytes(trafficBytes))
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
			used := summary.GuestStats[config.SanitizeGuestAlias(g.Alias)]
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
