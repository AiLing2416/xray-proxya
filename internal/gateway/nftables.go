package gateway

import (
	"fmt"
	"os/exec"
	"strings"
	"xray-proxya/internal/config"
)

// GetSSHPorts detects ports that sshd is listening on
func GetSSHPorts() []string {
	ports := []string{"22"} // Default
	out, err := exec.Command("sh", "-c", "ss -tlnp | grep sshd").Output()
	if err != nil { return ports }

	lines := strings.Split(string(out), "\n")
	found := make(map[string]bool)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 { continue }
		addr := fields[3]
		parts := strings.Split(addr, ":")
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
	if !cfg.Gateway.LocalEnabled && !cfg.Gateway.LANEnabled {
		return CleanupFirewall()
	}

	// In TUN mode, Xray with autoRoute: true handles the local machine routing and firewall rules
	// We only need nftables if we are in TProxy mode or doing LAN redirection manually
	if cfg.Gateway.Mode == "tun" {
		fmt.Println("🚀  TUN mode detected. Xray will handle routing via autoRoute.")
		// We still need to cleanup any leftover TProxy rules
		CleanupFirewall()
		return nil
	}

	fmt.Println("🛡️  Detecting SSH ports to prevent lockout...")
	sshPorts := GetSSHPorts()
	fmt.Printf("🛡️  Excluding SSH ports: %s\n", strings.Join(sshPorts, ", "))

	// 1. Setup Policy Routing (Temporary)
	// We don't check for existence, just try to add. 'ip' will return error if exists, which we ignore for simplicity in this POC
	exec.Command("sudo", "ip", "rule", "add", "fwmark", "1", "table", "100").Run()
	exec.Command("sudo", "ip", "route", "add", "local", "default", "dev", "lo", "table", "100").Run()

	// 2. NFTables Rules
	commands := []string{
		"add table inet xray_tproxy",
		"flush table inet xray_tproxy",
		"add chain inet xray_tproxy prerouting { type filter hook prerouting priority -100; policy accept; }",
		"add chain inet xray_tproxy output { type filter hook output priority -100; policy accept; }",
	}

	// Exclusions
	for _, port := range sshPorts {
		commands = append(commands, fmt.Sprintf("add rule inet xray_tproxy prerouting tcp dport %s accept", port))
		commands = append(commands, fmt.Sprintf("add rule inet xray_tproxy prerouting udp dport %s accept", port))
	}

	// Private Network Exclusions
	commands = append(commands, "add rule inet xray_tproxy prerouting ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept")

	// Blacklist IPs
	if len(cfg.Gateway.BlacklistIPs) > 0 {
		ipList := strings.Join(cfg.Gateway.BlacklistIPs, ", ")
		commands = append(commands, fmt.Sprintf("add rule inet xray_tproxy prerouting ip daddr { %s } drop", ipList))
	}

	// TProxy Redirection (Port 12345 hardcoded for now or fetched from config)
	tproxyPort := "12345" 
	
	// LAN Gateway Logic
	if cfg.Gateway.LANEnabled && cfg.Gateway.LANInterface != "" {
		commands = append(commands, fmt.Sprintf("add rule inet xray_tproxy prerouting iifname %s meta l4proto tcp meta mark set 1 tproxy to :%s accept", cfg.Gateway.LANInterface, tproxyPort))
		commands = append(commands, fmt.Sprintf("add rule inet xray_tproxy prerouting iifname %s meta l4proto udp meta mark set 1 tproxy to :%s accept", cfg.Gateway.LANInterface, tproxyPort))
	}

	// Local Machine Logic (Output Chain)
	if cfg.Gateway.LocalEnabled {
		// Rule: Skip SSH and local traffic, mark everything else
		for _, port := range sshPorts {
			commands = append(commands, fmt.Sprintf("add rule inet xray_tproxy output tcp dport %s accept", port))
			commands = append(commands, fmt.Sprintf("add rule inet xray_tproxy output udp dport %s accept", port))
		}
		commands = append(commands, "add rule inet xray_tproxy output ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept")
		commands = append(commands, "add rule inet xray_tproxy output meta mark set 1 accept")
		
		// To make local traffic work with TProxy, it must be routed to lo and then caught in prerouting
		commands = append(commands, "add rule inet xray_tproxy prerouting iifname lo meta mark 1 tproxy to :12345 accept")
	}

	for _, cmd := range commands {
		if err := exec.Command("sudo", "nft", cmd).Run(); err != nil {
			fmt.Printf("⚠️  NFT Command Failed: nft %s (%v)\n", cmd, err)
		}
	}

	return nil
}

func CleanupFirewall() error {
	fmt.Println("🧹 Cleaning up temporary firewall rules...")
	// Use sh -c to allow redirection of stderr
	exec.Command("sh", "-c", "sudo nft delete table inet xray_tproxy 2>/dev/null || true").Run()
	exec.Command("sh", "-c", "sudo ip rule del fwmark 1 table 100 2>/dev/null || true").Run()
	exec.Command("sh", "-c", "sudo ip route del local default dev lo table 100 2>/dev/null || true").Run()
	return nil
}
