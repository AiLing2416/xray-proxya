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
	Short: "Manage background service (Requires Root)",
}

func checkRoot() bool {
	if os.Geteuid() != 0 {
		fmt.Println("❌ This command must be run as root (or with sudo).")
		return false
	}
	return true
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install and enable service (Root only)",
	Run: func(cmd *cobra.Command, args []string) {
		if !checkRoot() { return }
		
		user := "root" // Default to root for service since we are root
		binPath := xray.GetXrayProxyaPath()

		if _, err := exec.LookPath("systemctl"); err == nil {
			installSystemd(user, binPath)
		} else if _, err := exec.LookPath("rc-service"); err == nil {
			installOpenRC(user, binPath)
		} else {
			fmt.Println("❌ No supported service manager found.")
		}
	},
}

func installSystemd(user string, binPath string) {
	fmt.Println("🚀 Installing systemd service...")
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

	tmpFile := "/etc/systemd/system/xray-proxya.service"
	os.WriteFile(tmpFile, []byte(unitContent), 0644)
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "xray-proxya").Run()
	exec.Command("systemctl", "start", "xray-proxya").Run()
	fmt.Println("✅ Systemd service installed and started.")
}

func installOpenRC(user string, binPath string) {
	fmt.Println("🚀 Installing OpenRC service...")
	scriptContent := fmt.Sprintf(`#!/sbin/openrc-run
description="Xray-Proxya Service"
command="%s"
command_args="run"
command_user="%s"
command_background="yes"
pidfile="/run/xray-proxya.pid"

depend() {
	need net
	after firewall
}
`, binPath, user)

	initFile := "/etc/init.d/xray-proxya"
	os.WriteFile(initFile, []byte(scriptContent), 0755)
	exec.Command("rc-update", "add", "xray-proxya", "default").Run()
	exec.Command("rc-service", "xray-proxya", "start").Run()
	fmt.Println("✅ OpenRC service installed and started.")
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop and remove service (Root only)",
	Run: func(cmd *cobra.Command, args []string) {
		if !checkRoot() { return }

		if _, err := exec.LookPath("systemctl"); err == nil {
			fmt.Println("🛑 Uninstalling systemd service...")
			exec.Command("systemctl", "stop", "xray-proxya").Run()
			exec.Command("systemctl", "disable", "xray-proxya").Run()
			os.Remove("/etc/systemd/system/xray-proxya.service")
			exec.Command("systemctl", "daemon-reload").Run()
		} else if _, err := exec.LookPath("rc-service"); err == nil {
			fmt.Println("🛑 Uninstalling OpenRC service...")
			exec.Command("rc-service", "xray-proxya", "stop").Run()
			exec.Command("rc-update", "del", "xray-proxya").Run()
			os.Remove("/etc/init.d/xray-proxya")
		}
		fmt.Println("✅ Service uninstalled.")
	},
}

var serviceLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Tail service logs",
	Run: func(cmd *cobra.Command, args []string) {
		home, _ := os.UserHomeDir()
		logPath := filepath.Join(home, ".config", "xray-proxya", "xray.log")
		exec.Command("tail", "-f", logPath).Run()
	},
}

func init() {
	serviceCmd.AddCommand(serviceInstallCmd, serviceUninstallCmd, serviceLogsCmd)
	rootCmd.AddCommand(serviceCmd)
}
