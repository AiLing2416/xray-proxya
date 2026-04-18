package main

import (
	"fmt"
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

		var direct, relay int64
		guestStats := make(map[string]int64)
		inboundStats := make(map[string]int64)

		for name, val := range allStats {
			if strings.HasPrefix(name, "outbound>>>direct") {
				direct += val
			} else if strings.HasPrefix(name, "outbound>>>outbound-") {
				relay += val
			} else if strings.HasPrefix(name, "user>>>") {
				parts := strings.Split(name, ">>>")
				if len(parts) >= 2 {
					email := parts[1]
					guestStats[email] += val
				}
			} else if strings.HasPrefix(name, "inbound>>>") && !strings.Contains(name, "api") {
				parts := strings.Split(name, ">>>")
				if len(parts) >= 2 {
					tag := parts[1]
					inboundStats[tag] += val
				}
			}
		}

		fmt.Printf("🌐 Total Traffic:\n")
		fmt.Printf("   Direct Outbound: %s\n", utils.FormatBytes(direct))
		fmt.Printf("   Relay Outbound:  %s\n", utils.FormatBytes(relay))

		if len(inboundStats) > 0 {
			fmt.Println("\n📥 Service Inbounds:")
			for tag, val := range inboundStats {
				fmt.Printf("   %-25s: %s\n", tag, utils.FormatBytes(val))
			}
		}

		if len(guestStats) > 0 {
			fmt.Println("\n👥 Guest Usage:")
			for email, val := range guestStats {
				alias := strings.Split(email, "@")[0]
				fmt.Printf("   %-25s: %s\n", alias, utils.FormatBytes(val))
			}
		}
		fmt.Println("------------------------------------------------------------")
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
