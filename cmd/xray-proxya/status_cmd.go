package main

import (
	"fmt"
	"os"
	"sort"
	"xray-proxya/internal/config"
	"xray-proxya/internal/trafficstats"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show Xray core status and detailed traffic stats",
	Run: func(cmd *cobra.Command, args []string) {
		if _, err := os.Stat(config.GetConfigPath()); os.IsNotExist(err) {
			fmt.Println("❌ Error: Xray-Proxya has not been initialized. Please run 'xray-proxya init' first.")
			os.Exit(1)
		}

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

		summary := trafficstats.Summarize(allStats)

		fmt.Printf("🌐 Total Traffic:\n")
		fmt.Printf("   Direct Outbound: %s\n", utils.FormatBytes(summary.Direct))
		fmt.Printf("   Relay Outbound:  %s\n", utils.FormatBytes(summary.Relay))

		printNamedStats("\n📥 Service Inbounds:", summary.InboundStats)
		printNamedStats("\n🧭 Direct / Service Usage:", summary.ServiceStats)
		printNamedStats("\n🔁 Relay Usage:", summary.RelayStats)
		printNamedStats("\n👥 Guest Usage:", summary.GuestStats)
		fmt.Println("------------------------------------------------------------")
	},
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

func summarizeStats(allStats map[string]int64) (int64, int64, map[string]int64, map[string]int64, map[string]int64, map[string]int64) {
	summary := trafficstats.Summarize(allStats)
	return summary.Direct, summary.Relay, summary.ServiceStats, summary.RelayStats, summary.GuestStats, summary.InboundStats
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
