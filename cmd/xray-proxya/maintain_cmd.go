package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

var maintainCmd = &cobra.Command{
	Use:   "maintain",
	Short: "System maintenance and cleanup tasks",
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update Xray core binary to the latest version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🔄 Checking for Xray core updates...")
		xrayPath := xray.GetXrayBinaryPath()
		os.Rename(xrayPath, xrayPath+".bak")
		fmt.Println("✅ Update command initialized. Run 'init' or 'apply' to trigger auto-download.")
	},
}

var purgeCmd = &cobra.Command{
	Use:   "purge",
	Short: "Completely remove xray-proxya, services, and all data (requires sudo)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🧨 STARTING FULL PURGE...")
		exec.Command(xray.GetXrayProxyaPath(), "service", "uninstall").Run()
		xray.StopXray()
		exec.Command("sudo", "nft", "delete", "table", "inet", "xray_gateway").Run()
		exec.Command("sudo", "nft", "delete", "table", "inet", "xray_tproxy").Run()
		home, _ := os.UserHomeDir()
		if os.Geteuid() == 0 { home = "/root" }
		confDir := filepath.Join(home, ".config", "xray-proxya")
		os.RemoveAll(confDir)
		fmt.Printf("✨ Purge complete. Manually remove the binary to finish.\n")
	},
}

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Wipe all configurations but keep the program and Xray core",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🧹 Resetting configuration files...")
		xray.StopXray()
		home, _ := os.UserHomeDir()
		if os.Geteuid() == 0 { home = "/root" }
		confDir := filepath.Join(home, ".config", "xray-proxya")
		files, _ := filepath.Glob(filepath.Join(confDir, "*.json*"))
		for _, f := range files { os.Remove(f) }
		fmt.Println("✅ Reset successful. You can now run 'init' to reconfigure.")
	},
}

func init() {
	rootCmd.AddCommand(updateCmd, purgeCmd, resetCmd)
}
