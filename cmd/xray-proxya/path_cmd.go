package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/pathd"
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

func buildPathdSystemdServiceContent(binaryPath, configPath string) string {
	return fmt.Sprintf(`[Unit]
Description=Xray-Proxya PathLink Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# pathd needs only raw ICMP; it never changes routing, firewall, or files.
User=root
ExecStart=%s serve --config %s
Restart=on-failure
RestartSec=2
UMask=0077
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
`, binaryPath, configPath)
}

func writePathdConfig(cfg *config.UserConfig) error {
	if cfg.Path.Listen == "" {
		cfg.Path.Listen = "127.0.0.1:39091"
	}
	if err := pathd.ValidateListenAddress(cfg.Path.Listen); err != nil {
		return err
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
	if err := pathd.ValidateListenAddress(cfg.Path.Listen); err != nil {
		fmt.Println("❌", err)
		return
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
	content := buildPathdSystemdServiceContent(pathdBinaryPath(), pathdConfigPath())
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
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	serviceState := "unknown"
	if os.Geteuid() == 0 && exec.Command("systemctl", "is-active", "--quiet", pathdUnit).Run() == nil {
		serviceState = "active"
	} else if os.Geteuid() == 0 {
		serviceState = "inactive"
	}
	fmt.Printf("PathLink: %s\n", map[bool]string{true: "enabled", false: "disabled"}[cfg.Path.Enabled])
	fmt.Printf("Role: %s\n", cfg.Role)
	if cfg.Role == config.RoleServer {
		fmt.Printf("Agent: %s (%s)\n", serviceState, cfg.Path.Listen)
		return
	}
	if cfg.Role != config.RoleGateway {
		return
	}
	fmt.Printf("Relay: %s\n", cfg.Gateway.RelayAlias)
	if state, err := readPathRuntime(); err == nil {
		connection := "idle/disconnected"
		if state.Connected {
			connection = "connected"
		}
		fmt.Printf("PathLink connection: %s; in-flight: %d\n", connection, state.InFlight)
		if !state.LastActivity.IsZero() {
			fmt.Printf("Last activity: %s ago\n", time.Since(state.LastActivity).Round(time.Second))
		}
		if state.LastRTTMs > 0 {
			fmt.Printf("Last remote ICMP RTT: %dms\n", state.LastRTTMs)
		}
		if state.LastError != "" {
			fmt.Printf("Last error: %s\n", state.LastError)
		}
		return
	}
	fmt.Println("PathLink runtime: unavailable (run gateway up with --synthetic-ping and path enabled)")
}}

var pathPingCmd = &cobra.Command{Use: "ping <hostname-or-ip>", Short: "Send one real ICMP echo through the selected relay", Args: cobra.ExactArgs(1), Run: func(cmd *cobra.Command, args []string) {
	if os.Geteuid() != 0 {
		fmt.Println("❌ path ping requires root on the Gateway.")
		return
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	if cfg.Role != config.RoleGateway || !cfg.Path.Enabled || cfg.Path.Token == "" || cfg.Gateway.State != "proxy" || !cfg.Gateway.SyntheticPing || cfg.Gateway.RelayAlias == "" {
		fmt.Println("❌ path ping requires an enabled Gateway PathLink, synthetic ping, and selected proxy relay.")
		return
	}
	ip, err := resolvePublicTarget(args[0])
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	socks, err := activePathdSOCKSAddress()
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	target := cfg.Path.Listen
	if target == "" {
		target = "127.0.0.1:39091"
	}
	client := pathd.NewIdleClient(socks, target, cfg.Path.Token, 15*time.Second)
	defer client.Close()
	started := time.Now()
	remoteRTT, err := client.Ping(ip)
	if err != nil {
		fmt.Printf("❌ %s through %s: %v\n", ip, cfg.Gateway.RelayAlias, err)
		return
	}
	fmt.Printf("✅ %s through %s\nPathLink end-to-end: %s\nRemote ICMP RTT: %s\n", ip, cfg.Gateway.RelayAlias, time.Since(started).Round(time.Millisecond), remoteRTT.Round(time.Millisecond))
}}

func resolvePublicTarget(value string) (net.IP, error) {
	if ip := net.ParseIP(value); ip != nil {
		if err := pathd.ValidateProbeTarget(ip); err != nil {
			return nil, err
		}
		return ip, nil
	}
	addresses, err := net.LookupIP(value)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", value, err)
	}
	for _, ip := range addresses {
		if pathd.IsPublicTarget(ip) {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("%q has no public A or AAAA record", value)
}

func activePathdSOCKSAddress() (string, error) {
	data, err := os.ReadFile(filepath.Join(config.GetConfigDir(), "config.active.json"))
	if err != nil {
		return "", err
	}
	var runtime struct {
		Inbounds []struct {
			Tag    string `json:"tag"`
			Listen string `json:"listen"`
			Port   int    `json:"port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &runtime); err != nil {
		return "", err
	}
	for _, inbound := range runtime.Inbounds {
		if inbound.Tag == "pathd-socks" && inbound.Port > 0 {
			listen := inbound.Listen
			if listen == "" {
				listen = "127.0.0.1"
			}
			return net.JoinHostPort(listen, fmt.Sprint(inbound.Port)), nil
		}
	}
	return "", fmt.Errorf("PathLink SOCKS inbound is unavailable; run gateway up")
}

func init() {
	pathEnableCmd.Flags().StringVar(&pathListen, "listen", "", "loopback pathd listen address")
	pathEnableCmd.Flags().StringVar(&pathToken, "token", "", "shared 32-byte PathLink token")
	pathEnableCmd.Flags().IntVar(&pathIdle, "idle", 20, "pathd connection idle timeout in seconds")
	pathCmd.AddCommand(pathEnableCmd, pathDisableCmd, pathInstallCmd, pathStartCmd, pathStopCmd, pathRestartCmd, pathStatusCmd, pathPingCmd)
	rootCmd.AddCommand(pathCmd)
}
