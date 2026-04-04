package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage systemd service for xray-proxya",
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install and enable systemd service (requires sudo)",
	Run: func(cmd *cobra.Command, args []string) {
		user := os.Getenv("USER")
		if user == "" { user = "gemini" }
		
		binPath := xray.GetXrayProxyaPath()
		
		unitContent := fmt.Sprintf(`[Unit]
Description=Xray-Proxya Service
After=network.target nss-lookup.target

[Service]
User=%s
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=false
ExecStart=%s run
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
`, user, binPath)

		tmpFile := "/tmp/xray-proxya.service"
		os.WriteFile(tmpFile, []byte(unitContent), 0644)
		
		fmt.Println("🚀 Installing systemd service...")
		exec.Command("sudo", "cp", tmpFile, "/etc/systemd/system/xray-proxya.service").Run()
		exec.Command("sudo", "systemctl", "daemon-reload").Run()
		exec.Command("sudo", "systemctl", "enable", "xray-proxya").Run()
		exec.Command("sudo", "systemctl", "start", "xray-proxya").Run()
		
		fmt.Println("✅ Service installed and started.")
	},
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop and remove systemd service (requires sudo)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🛑 Uninstalling systemd service...")
		exec.Command("sudo", "systemctl", "stop", "xray-proxya").Run()
		exec.Command("sudo", "systemctl", "disable", "xray-proxya").Run()
		exec.Command("sudo", "rm", "-f", "/etc/systemd/system/xray-proxya.service").Run()
		exec.Command("sudo", "systemctl", "daemon-reload").Run()
		fmt.Println("✅ Service uninstalled.")
	},
}

var serviceLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Tail service logs",
	Run: func(cmd *cobra.Command, args []string) {
		home, _ := os.UserHomeDir()
		logPath := filepath.Join(home, ".config", "xray-proxya", "xray.log")
		
		c := exec.Command("tail", "-f", logPath)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		c.Run()
	},
}

func init() {
	serviceCmd.AddCommand(serviceInstallCmd, serviceUninstallCmd, serviceLogsCmd)
	rootCmd.AddCommand(serviceCmd)
}
