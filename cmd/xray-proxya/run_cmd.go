package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	runAudit bool
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run Xray core in foreground",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Println("❌ Failed to load config. Please run 'init' first.")
			return
		}

		// v0.2.4 Port Policy:
		// By default (especially as a service), we are STRICT.
		// We only allow port drift if --audit is explicitly provided.
		changed := false
		auditPort := func(label string, current *int) {
			if *current <= 0 { return }
			if !utils.IsPortFree(*current) {
				if runAudit {
					newP, _ := xray.GetFreePort()
					fmt.Printf("⚠️  Warning: %s Port %d occupied, switched to %d\n", label, *current, newP)
					*current = newP
					changed = true
				} else {
					fmt.Printf("❌ Error: %s Port %d is occupied. Use --audit to allow dynamic port selection.\n", label, *current)
					os.Exit(1)
				}
			}
		}

		auditPort("API", &cfg.APIInbound)
		for i := range cfg.ActiveModes {
			if cfg.ActiveModes[i].Enabled {
				auditPort(string(cfg.ActiveModes[i].Mode), &cfg.ActiveModes[i].Port)
			}
		}

		if changed { cfg.Save() }

		fmt.Println("🔍 Generating configuration...")
		jsonData, err := xray.GenerateXrayJSON(cfg, nil, "")
		if err != nil {
			fmt.Printf("❌ Failed to generate config: %v\n", err)
			return
		}

		confPath := filepath.Join(config.GetConfigDir(), "config.active.json")
		os.WriteFile(confPath, jsonData, 0644)

		fmt.Println("🚀 Starting Xray core in foreground...")
		process, err := xray.StartXray(confPath)
		if err != nil {
			fmt.Printf("❌ Failed to start Xray: %v\n", err)
			return
		}

		pidPath := filepath.Join(config.GetConfigDir(), "xray.pid")
		os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", process.Process.Pid)), 0600)
		defer os.Remove(pidPath)

		if cfg.Gateway.LocalEnabled || cfg.Gateway.LANEnabled {
			time.Sleep(1 * time.Second)
			fmt.Println("🛡️  Synchronizing transparent gateway rules...")
			gateway.SyncFirewall(cfg)
		}

		// Handle signals
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		fmt.Println("\n🛑 Stopping Xray...")
		process.Process.Signal(syscall.SIGTERM)
		
		if cfg.Gateway.LocalEnabled || cfg.Gateway.LANEnabled {
			gateway.CleanupFirewall()
		}
	},
}

func init() {
	runCmd.Flags().BoolVar(&runAudit, "audit", false, "Enable dynamic port negotiation if configured ports are occupied")
	rootCmd.AddCommand(runCmd)
}
