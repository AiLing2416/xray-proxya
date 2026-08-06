package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

const pathdUnit = "xray-proxya-pathd"

var (
	pathListen string
	pathToken  string
	pathIdle   int
)

func pathdConfigPath() string { return filepath.Join(config.GetConfigDir(), "pathd.json") }
func pathdBinaryPath() string {
	return filepath.Join(filepath.Dir(xray.GetXrayProxyaPath()), "xray-proxya-pathd")
}
func pathdUnitPath() string { return "/etc/systemd/system/" + pathdUnit + ".service" }

func writePathdConfig(cfg *config.UserConfig) error {
	if cfg.Path.Listen == "" {
		cfg.Path.Listen = "127.0.0.1:39091"
	}
	if cfg.Path.IdleSeconds <= 0 {
		cfg.Path.IdleSeconds = 20
	}
	data, err := json.MarshalIndent(struct {
		Listen      string `json:"listen"`
		Token       string `json:"token"`
		IdleSeconds int    `json:"idle_seconds"`
	}{cfg.Path.Listen, cfg.Path.Token, cfg.Path.IdleSeconds}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(pathdConfigPath(), data, 0600)
}

var pathCmd = &cobra.Command{Use: "path", Short: "Manage the loopback-only PathLink ICMP agent", PersistentPreRun: func(cmd *cobra.Command, args []string) {
	if _, err := os.Stat(config.GetConfigPath()); err != nil {
		fmt.Println("❌ Initialize xray-proxya first.")
		os.Exit(1)
	}
}}

var pathEnableCmd = &cobra.Command{Use: "enable", Short: "Enable PathLink in staging and create its private configuration", Run: func(cmd *cobra.Command, args []string) {
	cfg, err := config.LoadConfigEx(true)
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	if pathListen != "" {
		cfg.Path.Listen = pathListen
	}
	if pathIdle > 0 {
		cfg.Path.IdleSeconds = pathIdle
	}
	if pathToken != "" {
		cfg.Path.Token = pathToken
	}
	if cfg.Path.Listen == "" {
		cfg.Path.Listen = "127.0.0.1:39091"
	}
	if cfg.Path.Token == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			fmt.Println("❌ Generate token:", err)
			return
		}
		cfg.Path.Token = hex.EncodeToString(b)
	}
	cfg.Path.Enabled = true
	if err := cfg.SaveEx(true); err != nil {
		fmt.Println("❌", err)
		return
	}
	if err := writePathdConfig(cfg); err != nil {
		fmt.Println("❌ Write private pathd configuration:", err)
		return
	}
	fmt.Printf("✅ PathLink enabled in STAGING (%s). Run 'apply', then 'path install' and 'path start'.\n", cfg.Path.Listen)
	if cfg.Role == config.RoleServer {
		fmt.Println("ℹ️ Copy this same PathLink token to the paired Gateway with: path enable --token <token>")
	}
}}

var pathDisableCmd = &cobra.Command{Use: "disable", Short: "Disable PathLink in staging and stop its local agent", Run: func(cmd *cobra.Command, args []string) {
	cfg, err := config.LoadConfigEx(true)
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	cfg.Path.Enabled = false
	if err := cfg.SaveEx(true); err != nil {
		fmt.Println("❌", err)
		return
	}
	if os.Geteuid() == 0 {
		_ = exec.Command("systemctl", "stop", pathdUnit).Run()
	}
	fmt.Println("✅ PathLink disabled in STAGING.")
}}

var pathInstallCmd = &cobra.Command{Use: "install", Short: "Install pathd as a root systemd service", Run: func(cmd *cobra.Command, args []string) {
	if os.Geteuid() != 0 {
		fmt.Println("❌ pathd service installation requires root.")
		return
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	if cfg.Role != config.RoleServer || !cfg.Path.Enabled {
		fmt.Println("❌ pathd can be installed only on a Server after 'path enable' and 'apply'.")
		return
	}
	if _, err := os.Stat(pathdBinaryPath()); err != nil {
		fmt.Printf("❌ pathd binary missing at %s\n", pathdBinaryPath())
		return
	}
	if err := writePathdConfig(cfg); err != nil {
		fmt.Println("❌", err)
		return
	}
	content := fmt.Sprintf("[Unit]\nDescription=Xray-Proxya PathLink Agent\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=root\nExecStart=%s serve --config %s\nRestart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n", pathdBinaryPath(), pathdConfigPath())
	if err := os.WriteFile(pathdUnitPath(), []byte(content), 0644); err != nil {
		fmt.Println("❌", err)
		return
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("✅ pathd system service installed.")
}}

func pathSystemctl(action string) {
	if os.Geteuid() != 0 {
		fmt.Println("❌ pathd service control requires root.")
		return
	}
	if err := exec.Command("systemctl", action, pathdUnit).Run(); err != nil {
		fmt.Printf("❌ pathd %s failed: %v\n", action, err)
		return
	}
	fmt.Printf("✅ pathd %s.\n", action)
}

var pathStartCmd = &cobra.Command{Use: "start", Short: "Start pathd", Run: func(cmd *cobra.Command, args []string) { pathSystemctl("start") }}
var pathStopCmd = &cobra.Command{Use: "stop", Short: "Stop pathd", Run: func(cmd *cobra.Command, args []string) { pathSystemctl("stop") }}
var pathRestartCmd = &cobra.Command{Use: "restart", Short: "Restart pathd", Run: func(cmd *cobra.Command, args []string) { pathSystemctl("restart") }}
var pathStatusCmd = &cobra.Command{Use: "status", Short: "Show pathd service state", Run: func(cmd *cobra.Command, args []string) {
	if os.Geteuid() != 0 {
		fmt.Println("❌ pathd service status requires root.")
		return
	}
	command := exec.Command("systemctl", "--no-pager", "status", pathdUnit)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	_ = command.Run()
}}

func init() {
	pathEnableCmd.Flags().StringVar(&pathListen, "listen", "", "loopback pathd listen address")
	pathEnableCmd.Flags().StringVar(&pathToken, "token", "", "shared 32-byte PathLink token")
	pathEnableCmd.Flags().IntVar(&pathIdle, "idle", 20, "pathd connection idle timeout in seconds")
	pathCmd.AddCommand(pathEnableCmd, pathDisableCmd, pathInstallCmd, pathStartCmd, pathStopCmd, pathRestartCmd, pathStatusCmd)
	rootCmd.AddCommand(pathCmd)
}
