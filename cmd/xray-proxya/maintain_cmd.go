package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var maintainCmd = &cobra.Command{
	Use:   "maintain",
	Short: "System maintenance and cleanup tasks",
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update Xray core binary to the pinned tested version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🔄 Checking for Xray core updates...")
		xrayPath := xray.GetXrayBinaryPath()
		os.Rename(xrayPath, xrayPath+".bak")
		fmt.Println("✅ Update command initialized. Run 'init' or 'apply' to trigger auto-download.")
	},
}

var purgeCmd = &cobra.Command{
	Use:   "purge",
	Short: "Completely remove xray-proxya, services, and all data (requires root shell)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := utils.RequireRootShell("purge"); err != nil {
			return err
		}
		fmt.Println("🧨 STARTING FULL PURGE...")
		bringGatewayDown()
		exec.Command(xray.GetXrayProxyaPath(), "service", "uninstall").Run()
		_ = xray.ManageSystemdUnit("stop", xray.MainServiceUnit)
		home := config.GetHomeDir()
		confDir := filepath.Join(home, ".config", "xray-proxya")
		os.RemoveAll(confDir)
		fmt.Printf("✨ Purge complete. Manually remove the binary to finish.\n")
		return nil
	},
}

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Wipe all configurations but keep the program and Xray core",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🧹 Resetting configuration files...")
		bringGatewayDown()
		_ = xray.ManageSystemdUnit("stop", xray.MainServiceUnit)
		home := config.GetHomeDir()
		confDir := filepath.Join(home, ".config", "xray-proxya")
		files, _ := filepath.Glob(filepath.Join(confDir, "*.json*"))
		for _, f := range files {
			os.Remove(f)
		}
		fmt.Println("✅ Reset successful. You can now run 'init' to reconfigure.")
	},
}

func bringGatewayDown() {
	if os.Geteuid() != 0 {
		return
	}
	cfg, err := config.LoadConfig()
	if err != nil || cfg == nil || cfg.Role != config.RoleGateway {
		if cleanupErr := gateway.CleanupFirewall(); cleanupErr != nil {
			fmt.Printf("⚠️ Failed to clean gateway runtime: %v\n", cleanupErr)
		}
		return
	}
	if err := gateway.Down(); err != nil {
		fmt.Printf("⚠️ Failed to bring gateway down: %v\n", err)
	}
}

func init() {
	rootCmd.AddCommand(updateCmd, purgeCmd, resetCmd)
}
