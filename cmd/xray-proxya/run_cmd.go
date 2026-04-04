package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start Xray in foreground (service mode)",
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

		fmt.Println("🔍 Validating configuration...")
		jsonData, err := xray.GenerateXrayJSON(cfg, nil)
		if err != nil {
			fmt.Printf("❌ Failed to generate Xray JSON: %v\n", err)
			return
		}

		if err := xray.ValidateConfig(jsonData); err != nil {
			fmt.Printf("❌ Config validation failed: %v\n", err)
			return
		}

		home, _ := os.UserHomeDir()
		confDir := filepath.Join(home, ".config", "xray-proxya")
		xrayJSONPath := filepath.Join(confDir, "xray_config.json")
		os.WriteFile(xrayJSONPath, jsonData, 0600)

		fmt.Println("🚀 Starting Xray core...")
		xrayCmd := exec.Command(xray.GetXrayBinaryPath(), "run", "-c", xrayJSONPath)
		
		logFile, _ := os.OpenFile(filepath.Join(confDir, "xray.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		xrayCmd.Stdout = logFile
		xrayCmd.Stderr = logFile

		if err := xrayCmd.Start(); err != nil {
			fmt.Printf("❌ Failed to start Xray: %v\n", err)
			return
		}

		pidPath := filepath.Join(confDir, "xray.pid")
		os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", xrayCmd.Process.Pid)), 0600)
		fmt.Printf("✅ Running (PID: %d). Press Ctrl+C to stop.\n", xrayCmd.Process.Pid)

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		go func() {
			<-sigChan
			fmt.Println("\n🛑 Stopping Xray service...")
			xrayCmd.Process.Kill()
		}()

		xrayCmd.Wait()
		fmt.Println("👋 Service exited.")
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}
