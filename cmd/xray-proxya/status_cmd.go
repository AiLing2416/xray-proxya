package main

import (
	"fmt"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show Xray core status and traffic overview",
	Run: func(cmd *cobra.Command, args []string) {
		active, pid := xray.GetXrayStatus()
		if !active {
			fmt.Println("Xray Core: Inactive")
			return
		}

		cfg, _ := config.LoadConfig()
		uptime := xray.GetXrayUptime(pid)
		allStats, _ := xray.GetXrayStats(cfg.APIInbound)

		var direct, relay int64
		for name, val := range allStats {
			if strings.Contains(name, "direct") {
				direct += val
			} else if strings.Contains(name, "outbound") && !strings.Contains(name, "direct") && !strings.Contains(name, "blocked") {
				relay += val
			}
		}

		fmt.Printf("PID %d | UpTime: %s | Direct: %d B | Relay: %d B\n", 
			pid, uptime, direct, relay)
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
