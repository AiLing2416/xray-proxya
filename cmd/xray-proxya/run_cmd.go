package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
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
		jsonData, err := xray.GenerateXrayJSON(cfg, nil)
		if err != nil {
			fmt.Printf("❌ Failed to generate Xray JSON: %v\n", err)
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

		err = process.Wait()
		if err != nil {
			fmt.Printf("❌ Xray exited with error: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}
