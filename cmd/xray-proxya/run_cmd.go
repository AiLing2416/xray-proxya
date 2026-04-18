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

	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start Xray core in foreground (For service/daemon use)",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Println("❌ Failed to load config. Please run 'init' first.")
			return
		}

		fmt.Println("🔍 Generating configuration...")
		jsonData, err := xray.GenerateXrayJSON(cfg, nil, "")
		if err != nil {
			fmt.Printf("❌ Failed to generate config: %v\n", err)
			return
		}


		confPath := filepath.Join(config.GetConfigDir(), "config.active.json")
		os.WriteFile(confPath, jsonData, 0644)

		if cfg.Gateway.LocalEnabled || cfg.Gateway.LANEnabled {
			fmt.Println("🛡️  Synchronizing transparent gateway rules...")
			gateway.SyncFirewall(cfg)
		}

		fmt.Println("🚀 Starting Xray core in foreground...")
		process, err := xray.StartXray(confPath)
		if err != nil {
			fmt.Printf("❌ Failed to start Xray: %v\n", err)
			return
		}

		// Handle signals for graceful shutdown
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			<-sigChan
			fmt.Println("\n🛑 Stopping Xray core...")
			process.Process.Kill()
			os.Remove(confPath)
			os.Exit(0)
		}()

		// Start Quota Maintenance Loop
		if cfg.Role == config.RoleServer {
			go maintainQuota(cfg.APIInbound)
		}

		err = process.Wait()
		if err != nil {
			fmt.Printf("❌ Xray exited with error: %v\n", err)
		}
	},
}

func maintainQuota(apiPort int) {
	fmt.Printf("🚀 Quota maintenance loop started on port %d\n", apiPort)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats, err := xray.GetXrayStats(apiPort)
		if err != nil {
			fmt.Printf("❌ Quota loop: failed to get stats: %v\n", err)
			continue
		}

		cfg, err := config.LoadConfig()
		if err != nil {
			continue
		}

		changed := false
		for i, g := range cfg.Guests {
			// user>>>Alias@xray-proxya.com>>>traffic>>>downlink
			name := fmt.Sprintf("user>>>%s@xray-proxya.com>>>traffic>>>downlink", g.Alias)
			if val, ok := stats[name]; ok {
				fmt.Printf("📊 Stat: %s = %d bytes\n", name, val)
				cfg.Guests[i].UsedBytes = val
				// Check Quota
				if g.QuotaGB > 0 {
					limitBytes := int64(g.QuotaGB * 1024 * 1024 * 1024)
					if val >= limitBytes && g.Enabled {
						fmt.Printf("⚠️ Quota exceeded for guest '%s' (%d >= %d). Disabling via API.\n", g.Alias, val, limitBytes)
						cfg.Guests[i].Enabled = false
						changed = true
						// Attempt to remove from all standard inbounds
						tags := []string{"vless-vision-reality-tcp-in", "vless-reality-xhttp-in", "vless-xhttp-kem768-in", "vmess-ws-in"}
						for _, tag := range tags {
							err := xray.RemoveUserAPI(apiPort, tag, g.Alias+"@xray-proxya.com")
							if err != nil {
								fmt.Printf("❌ Failed to remove user %s from %s: %v\n", g.Alias, tag, err)
							}
						}
					}
				}
			}
		}

		if changed {
			cfg.Save()
		}
	}
}

func init() {
	rootCmd.AddCommand(runCmd)
}
