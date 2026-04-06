package main

import (
	"fmt"
	"os"
	"os/exec"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage background service (Requires Root)",
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install xray-proxya as a system service (Systemd/OpenRC)",
	Run: func(cmd *cobra.Command, args []string) {
		if os.Geteuid() != 0 { fmt.Println("❌ This command requires sudo/root."); return }
		// Detect init system
		if _, err := exec.LookPath("systemctl"); err == nil {
			installSystemd()
		} else if _, err := exec.LookPath("rc-service"); err == nil {
			installOpenRC()
		} else {
			fmt.Println("❌ Unsupported init system.")
		}
	},
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove the system service",
	Run: func(cmd *cobra.Command, args []string) {
		if os.Geteuid() != 0 { fmt.Println("❌ Requires root."); return }
		if _, err := exec.LookPath("systemctl"); err == nil {
			exec.Command("systemctl", "stop", "xray-proxya").Run()
			exec.Command("systemctl", "disable", "xray-proxya").Run()
			os.Remove("/etc/systemd/system/xray-proxya.service")
			exec.Command("systemctl", "daemon-reload").Run()
		}
		fmt.Println("✅ Service uninstalled.")
	},
}

func installSystemd() {
	binPath := xray.GetXrayProxyaPath()
	content := fmt.Sprintf(`[Unit]
Description=Xray-Proxya Service
After=network.target

[Service]
Type=simple
ExecStart=%s run
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
`, binPath)
	os.WriteFile("/etc/systemd/system/xray-proxya.service", []byte(content), 0644)
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "xray-proxya").Run()
	fmt.Println("✅ Systemd service installed and enabled.")
}

func installOpenRC() {
	// Simple OpenRC stub
	fmt.Println("ℹ️ OpenRC installation is partially implemented. Manual config might be needed.")
}

func init() {
	serviceCmd.AddCommand(serviceInstallCmd, serviceUninstallCmd)
	rootCmd.AddCommand(serviceCmd)
}
