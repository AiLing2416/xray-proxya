package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage background service (Systemd/OpenRC for Root, Nohup for Rootless)",
}

func getSystemdPath() string {
	return "/etc/systemd/system/xray-proxya.service"
}

func buildSystemdServiceContent(binPath string, workDir string, assetDir string, logPath string) string {
	return fmt.Sprintf(`[Unit]
Description=Xray-Proxya Service
After=network.target

[Service]
Type=simple
ExecStart=%s run
Restart=on-failure
WorkingDirectory=%s
Environment=XRAY_LOCATION_ASSET=%s
StandardOutput=append:%s
StandardError=append:%s

[Install]
WantedBy=multi-user.target
`, binPath, workDir, assetDir, logPath, logPath)
}

func buildOpenRCServiceContent(binPath string, assetDir string, logPath string) string {
	return fmt.Sprintf(`#!/sbin/openrc-run
description="Xray-Proxya Service"
command="%s"
command_args="run"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
output_log="%s"
error_log="%s"
export XRAY_LOCATION_ASSET="%s"
depend() {
	need net
}
`, binPath, logPath, logPath, assetDir)
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install as a system service (Requires Root)",
	Run: func(cmd *cobra.Command, args []string) {
		if !utils.IsRoot() {
			fmt.Println("ℹ️ Rootless mode uses 'nohup' automatically. No installation required.")
			fmt.Println("🚀 Use 'service start' to run in background.")
			return
		}

		binPath := xray.GetXrayProxyaPath()
		// Security Check: Ensure binary is not in a world-writable directory
		if info, err := os.Stat(filepath.Dir(binPath)); err == nil {
			if info.Mode()&0002 != 0 {
				fmt.Printf("⚠️  SECURITY WARNING: Binary is in a world-writable directory (%s).\n", filepath.Dir(binPath))
				fmt.Println("   This could allow other users to replace the binary and gain root privileges.")
				fmt.Println("   Consider moving it to /usr/local/bin or a root-owned directory.")
			}
		}

		home, _ := os.UserHomeDir()
		if os.Geteuid() == 0 {
			home = "/root"
		}
		workDir := filepath.Join(home, ".local", "share", "xray-proxya")
		assetDir := filepath.Join(workDir, "bin")
		logPath := xray.GetXrayLogPath()
		os.MkdirAll(workDir, 0700)
		os.MkdirAll(filepath.Dir(logPath), 0700)
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
			f.Close()
		} else {
			fmt.Printf("❌ Failed to prepare log file: %v\n", err)
			return
		}

		if _, err := exec.LookPath("systemctl"); err == nil {
			content := buildSystemdServiceContent(binPath, workDir, assetDir, logPath)

			err := os.WriteFile(getSystemdPath(), []byte(content), 0644)
			if err != nil {
				fmt.Printf("❌ Failed to write service file: %v\n", err)
				return
			}
			exec.Command("systemctl", "daemon-reload").Run()
			fmt.Println("✅ System (Root) service unit installed (Disabled by default).")
			fmt.Println("🚀 Use 'service start' to run manually.")
		} else if _, err := exec.LookPath("rc-service"); err == nil {
			installOpenRC(true)
		}
	},
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the system service (Requires Root)",
	Run: func(cmd *cobra.Command, args []string) {
		if !utils.IsRoot() {
			fmt.Println("❌ This command is for system service removal and requires root.")
			return
		}
		if _, err := exec.LookPath("systemctl"); err == nil {
			exec.Command("systemctl", "stop", "xray-proxya").Run()
			exec.Command("systemctl", "disable", "xray-proxya").Run()
			os.Remove(getSystemdPath())
			exec.Command("systemctl", "daemon-reload").Run()
			fmt.Println("✅ Systemd service uninstalled.")
		} else if _, err := exec.LookPath("rc-service"); err == nil {
			os.Remove("/etc/init.d/xray-proxya")
			fmt.Println("✅ OpenRC service uninstalled.")
		}
	},
}

var serviceStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the service",
	Run: func(cmd *cobra.Command, args []string) {
		if err := xray.StartService(); err != nil {
			fmt.Printf("❌ Failed to start: %v\n", err)
		}
	},
}

var serviceStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the service",
	Run: func(cmd *cobra.Command, args []string) {
		xray.StopService()
		fmt.Println("✅ Stop command executed.")
	},
}

var serviceRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the service",
	Run: func(cmd *cobra.Command, args []string) {
		if err := xray.RestartXrayService(); err != nil {
			fmt.Printf("❌ Restart failed: %v\n", err)
		}
	},
}

var serviceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check service status",
	Run: func(cmd *cobra.Command, args []string) {
		// Just delegate to the main status logic for consistent output
		statusCmd.Run(cmd, args)
	},
}

func installOpenRC(isRoot bool) {
	binPath := xray.GetXrayProxyaPath()
	home, _ := os.UserHomeDir()
	if os.Geteuid() == 0 {
		home = "/root"
	}
	assetDir := filepath.Join(home, ".local", "share", "xray-proxya", "bin")
	logPath := xray.GetXrayLogPath()
	os.MkdirAll(filepath.Dir(logPath), 0700)
	if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
		f.Close()
	}

	content := buildOpenRCServiceContent(binPath, assetDir, logPath)
	os.WriteFile("/etc/init.d/xray-proxya", []byte(content), 0755)
	fmt.Println("✅ OpenRC service installed (Disabled by default).")
}

func init() {
	serviceCmd.AddCommand(serviceInstallCmd, serviceUninstallCmd, serviceStartCmd, serviceStopCmd, serviceRestartCmd, serviceStatusCmd)
	rootCmd.AddCommand(serviceCmd)
}
