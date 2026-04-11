package gateway

import (
	"fmt"
	"os/exec"
	"strings"
	"xray-proxya/internal/config"
)

func GetSSHPorts() []string {
	ports := []string{"22"}
	out, err := exec.Command("sh", "-c", "ss -tlnp | grep sshd").Output()
	if err != nil { return ports }
	lines := strings.Split(string(out), "\n")
	found := make(map[string]bool)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 { continue }
		parts := strings.Split(fields[3], ":")
		if len(parts) > 1 {
			port := parts[len(parts)-1]
			if port != "" { found[port] = true }
		}
	}
	if len(found) > 0 {
		ports = []string{}
		for p := range found { ports = append(ports, p) }
	}
	return ports
}

func SyncFirewall(cfg *config.UserConfig) error {
	CleanupFirewall() // Always start fresh

	if !cfg.Gateway.LocalEnabled && !cfg.Gateway.LANEnabled {
		return nil
	}

	// 0. Auto-configure Kernel Parameters (Non-persistent)
	fmt.Println("🔧  Auto-configuring kernel parameters for Dual-Stack Gateway...")
	kernelParams := [][]string{
		{"net.ipv4.ip_forward", "1"},
		{"net.ipv6.conf.all.forwarding", "1"},
		{"net.ipv4.conf.all.rp_filter", "0"},
		{"net.ipv4.conf.default.rp_filter", "0"},
	}
	for _, param := range kernelParams {
		exec.Command("sudo", "sysctl", "-w", fmt.Sprintf("%s=%s", param[0], param[1])).Run()
	}

	fmt.Println("🛡️  Synchronizing firewall rules using NFTables (Dual-Stack)...")
	sshPorts := GetSSHPorts()
	tproxyPort := "12345"

	// 1. Setup Policy Routing (IPv4 & IPv6)
	// IPv4
	exec.Command("sudo", "ip", "rule", "add", "fwmark", "1", "table", "100").Run()
	exec.Command("sudo", "ip", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()
	// IPv6
	exec.Command("sudo", "ip", "-6", "rule", "add", "fwmark", "1", "table", "100").Run()
	exec.Command("sudo", "ip", "-6", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()

	// 2. NFTables Commands
	commands := []string{
		"add table inet xray_tproxy",
		"add chain inet xray_tproxy prerouting { type filter hook prerouting priority -100; policy accept; }",
		"add chain inet xray_tproxy output { type filter hook output priority -100; policy accept; }",
	}

	// Exclude Reserved/Private Networks
	commands = append(commands, "add rule inet xray_tproxy prerouting ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept")
	commands = append(commands, "add rule inet xray_tproxy prerouting ip6 daddr { ::1/128, fc00::/7, fe80::/10 } accept")

	// Exclude SSH Ports
	for _, port := range sshPorts {
		commands = append(commands, fmt.Sprintf("add rule inet xray_tproxy prerouting tcp dport %s accept", port))
		commands = append(commands, fmt.Sprintf("add rule inet xray_tproxy output tcp dport %s accept", port))
	}

	// LAN Redirection (Dual-Stack TProxy)
	if cfg.Gateway.LANEnabled && cfg.Gateway.LANInterface != "" {
		fmt.Printf("🛡️  Redirecting LAN traffic (v4/v6) from %s to TProxy:%s\n", cfg.Gateway.LANInterface, tproxyPort)
		commands = append(commands, fmt.Sprintf("add rule inet xray_tproxy prerouting iifname %s meta l4proto { tcp, udp } tproxy to :%s meta mark set 1 accept", cfg.Gateway.LANInterface, tproxyPort))
	}

	// Local Redirection (Only if not using TUN autoRoute)
	if cfg.Gateway.LocalEnabled {
		if cfg.Gateway.Mode == "tun" {
			fmt.Println("🚀  Local traffic handled by Xray TUN (autoRoute).")
		} else {
			fmt.Println("🛡️  Redirecting local traffic to TProxy...")
			commands = append(commands, "add rule inet xray_tproxy output ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept")
			commands = append(commands, "add rule inet xray_tproxy output meta mark set 1 accept")
			commands = append(commands, fmt.Sprintf("add rule inet xray_tproxy prerouting iifname lo meta mark 1 tproxy to :%s accept", tproxyPort))
		}
	}

	nftPath := "nft"
	if _, err := exec.LookPath("nft"); err != nil { nftPath = "/usr/sbin/nft" }

	for _, cmd := range commands {
		args := append([]string{nftPath}, strings.Fields(cmd)...)
		if err := exec.Command("sudo", args...).Run(); err != nil {
			// Some errors might occur if nftables is not perfectly clean, we ignore for basic implementation
		}
	}

	return nil
}

func CleanupFirewall() error {
	fmt.Println("🧹 Cleaning up NFTables and IP Rules (Dual-Stack)...")
	nftPath := "nft"
	if _, err := exec.LookPath("nft"); err != nil { nftPath = "/usr/sbin/nft" }

	exec.Command("sudo", nftPath, "delete", "table", "inet", "xray_tproxy").Run()
	// IPv4 Cleanup
	exec.Command("sudo", "ip", "rule", "del", "fwmark", "1", "table", "100").Run()
	exec.Command("sudo", "ip", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
	// IPv6 Cleanup
	exec.Command("sudo", "ip", "-6", "rule", "del", "fwmark", "1", "table", "100").Run()
	exec.Command("sudo", "ip", "-6", "route", "del", "local", "default", "dev", "lo", "table", "100").Run()
	return nil
}
