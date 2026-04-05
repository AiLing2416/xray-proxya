package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start Xray core in foreground (For service/daemon use)",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("❌ Failed to load config: %v\n", err)
			return
		}

		if cfg.Role == config.RoleGateway {
			fmt.Println("⚙️ [Gateway Mode] Auto-configuring environment...")
			exec.Command(xray.GetXrayProxyaPath(), "gateway", "setup-kernel").Run()
			exec.Command(xray.GetXrayProxyaPath(), "gateway", "sync-firewall").Run()
		}

		fmt.Println("🔍 Generating configuration...")
		jsonData, err := xray.GenerateXrayJSON(cfg, nil)
		if err != nil {
			fmt.Printf("❌ Failed to generate config: %v\n", err)
			return
		}

		// Use normalized config directory
		dir := config.GetConfigDir()
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Printf("❌ Failed to create config dir %s: %v\n", dir, err)
			return
		}
		xrayConfigPath := filepath.Join(dir, "xray_config.json")
		if err := os.WriteFile(xrayConfigPath, jsonData, 0644); err != nil {
			fmt.Printf("❌ Failed to write config file: %v\n", err)
			return
		}

		fmt.Println("🚀 Starting Xray core in foreground...")
		// StartXrayRaw executes Xray core directly and blocks
		if err := xray.StartXrayRaw(xrayConfigPath); err != nil {
			fmt.Printf("❌ Xray exited with error: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}
