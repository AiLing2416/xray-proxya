package main

import (
	"fmt"
	"sort"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show Xray core status and detailed traffic stats",
	Run: func(cmd *cobra.Command, args []string) {
		active, pid := xray.GetXrayStatus()
		if !active {
			fmt.Println("❌ Xray Core: Inactive")
			return
		}

		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("❌ Failed to load config: %v\n", err)
			return
		}

		uptime := xray.GetXrayUptime(pid)
		allStats, _ := xray.GetXrayStats(cfg.APIInbound)

		fmt.Printf("🟢 Xray Core: Active (PID %d)\n", pid)
		fmt.Printf("⏱️  UpTime: %s\n", uptime)
		fmt.Println("------------------------------------------------------------")

		direct, relay, serviceStats, relayStats, guestStats, inboundStats := summarizeStats(allStats)

		fmt.Printf("🌐 Total Traffic:\n")
		fmt.Printf("   Direct Outbound: %s\n", utils.FormatBytes(direct))
		fmt.Printf("   Relay Outbound:  %s\n", utils.FormatBytes(relay))

		printNamedStats("\n📥 Service Inbounds:", inboundStats)
		printNamedStats("\n🧭 Direct / Service Usage:", serviceStats)
		printNamedStats("\n🔁 Relay Usage:", relayStats)
		printNamedStats("\n👥 Guest Usage:", guestStats)
		fmt.Println("------------------------------------------------------------")
	},
}

func summarizeStats(allStats map[string]int64) (int64, int64, map[string]int64, map[string]int64, map[string]int64, map[string]int64) {
	var direct, relay int64
	serviceStats := make(map[string]int64)
	relayStats := make(map[string]int64)
	guestStats := make(map[string]int64)
	inboundStats := make(map[string]int64)

	for name, val := range allStats {
		switch {
		case strings.HasPrefix(name, "outbound>>>direct>>>"):
			direct += val
		case strings.HasPrefix(name, "outbound>>>outbound-") && !strings.Contains(name, ">>>blocked>>>"):
			relay += val
		case strings.HasPrefix(name, "user>>>"):
			parts := strings.Split(name, ">>>")
			if len(parts) < 2 {
				continue
			}
			email := parts[1]
			switch {
			case email == "service-user":
				serviceStats["service-user"] += val
			case strings.HasPrefix(email, "relay-"):
				relayStats[strings.TrimPrefix(email, "relay-")] += val
			case strings.HasPrefix(email, "guest-"):
				guestStats[strings.TrimPrefix(email, "guest-")] += val
			default:
				serviceStats[email] += val
			}
		case strings.HasPrefix(name, "inbound>>>") && !strings.Contains(name, ">>>api>>>"):
			parts := strings.Split(name, ">>>")
			if len(parts) >= 2 {
				inboundStats[parts[1]] += val
			}
		}
	}

	return direct, relay, serviceStats, relayStats, guestStats, inboundStats
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
		fmt.Printf("   %-25s: %s\n", key, utils.FormatBytes(stats[key]))
	}
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
