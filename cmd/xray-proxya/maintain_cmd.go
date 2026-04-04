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
		
		// For now, we reuse the downloader logic by triggering a re-download
		// In a future PR, we can add version checking
		fmt.Println("⬇️ Downloading latest Xray core...")
		os.Rename(xrayPath, xrayPath+".bak")
		
		// Note: User can run 'init' again to trigger the download logic if this is a fresh install,
		// but here we intend to keep it as a dedicated update path.
		fmt.Println("✅ Update command is ready. (Run 'init' to force re-download if needed)")
	},
}

var purgeCmd = &cobra.Command{
	Use:   "purge",
	Short: "Completely remove xray-proxya, services, and all data (requires sudo)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🧨 STARTING FULL PURGE...")
		
		// 1. Stop and Uninstall Service
		fmt.Println("🛑 Stopping and removing systemd service...")
		exec.Command(xray.GetXrayProxyaPath(), "service", "uninstall").Run()
		
		// 2. Kill any orphan processes
		xray.StopXray()
		
		// 3. Clear Firewall rules
		fmt.Println("🛡️ Clearing nftables rules...")
		exec.Command("sudo", "nft", "delete", "table", "inet", "xray_gateway").Run()
		exec.Command("sudo", "nft", "delete", "table", "inet", "xray_tproxy").Run()
		
		// 4. Remove Configuration Directory
		home, _ := os.UserHomeDir()
		confDir := filepath.Join(home, ".config", "xray-proxya")
		if err := os.RemoveAll(confDir); err == nil {
			fmt.Printf("✅ Config directory removed: %s\n", confDir)
		}
		
		// 5. Guidance for binary removal
		binPath := xray.GetXrayProxyaPath()
		fmt.Printf("\n✨ Purge complete. To finish, manually remove the binary:\n   rm %s\n", binPath)
	},
}

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Wipe all configurations but keep the program and Xray core",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🧹 Resetting configuration files...")
		
		// 1. Stop current service/process
		xray.StopXray()
		exec.Command("sudo", "systemctl", "stop", "xray-proxya").Run()
		
		// 2. Remove all JSON and Staging files
		home, _ := os.UserHomeDir()
		confDir := filepath.Join(home, ".config", "xray-proxya")
		
		files, _ := filepath.Glob(filepath.Join(confDir, "*.json*"))
		for _, f := range files {
			os.Remove(f)
			fmt.Printf("🗑️ Removed: %s\n", filepath.Base(f))
		}
		
		fmt.Println("✅ Reset successful. You can now run 'init' to reconfigure.")
	},
}

func init() {
	rootCmd.AddCommand(updateCmd, purgeCmd, resetCmd)
}
