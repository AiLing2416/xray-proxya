package gateway

import (
	"os"
	"os/exec"
	"path/filepath"
	"xray-proxya/internal/config"
)

func SyncFirewall(cfg *config.UserConfig) {
	// 1. Cleanup all possible tables
	exec.Command("sudo", "nft", "delete", "table", "inet", "xray_proxya").Run()
	exec.Command("sudo", "nft", "delete", "table", "inet", "xray_proxya_tun").Run()
	
	if cfg.Gateway.Mode == "tun" {
		SyncTun(cfg)
		return
	}
}

func SyncTun(cfg *config.UserConfig) {
	xrayMark := "255"

	// 2. Policy Routing
	exec.Command("sudo", "ip", "rule", "del", "pref", "10").Run()
	exec.Command("sudo", "ip", "rule", "del", "pref", "149").Run()
	exec.Command("sudo", "ip", "rule", "del", "pref", "150").Run()
	exec.Command("sudo", "ip", "rule", "del", "pref", "151").Run()
	exec.Command("sudo", "ip", "rule", "del", "pref", "200").Run()
	
	exec.Command("sudo", "ip", "-6", "rule", "del", "pref", "10").Run()
	exec.Command("sudo", "ip", "-6", "rule", "del", "pref", "149").Run()
	exec.Command("sudo", "ip", "-6", "rule", "del", "pref", "150").Run()
	exec.Command("sudo", "ip", "-6", "rule", "del", "pref", "151").Run()
	exec.Command("sudo", "ip", "-6", "rule", "del", "pref", "200").Run()

	SetupKernel()

	exec.Command("sudo", "ip", "rule", "add", "fwmark", xrayMark, "table", "main", "pref", "10").Run()
	exec.Command("sudo", "ip", "-6", "rule", "add", "fwmark", xrayMark, "table", "main", "pref", "10").Run()

	exec.Command("sudo", "ip", "rule", "add", "to", "10.47.0.102", "table", "main", "pref", "149").Run()
	exec.Command("sudo", "ip", "rule", "add", "to", "10.47.0.0/24", "table", "main", "pref", "150").Run()
	exec.Command("sudo", "ip", "-6", "rule", "add", "to", "fd47::102", "table", "main", "pref", "149").Run()
	exec.Command("sudo", "ip", "-6", "rule", "add", "to", "fd47::/64", "table", "main", "pref", "150").Run()

	if cfg.Gateway.LocalEnabled || cfg.Gateway.LANEnabled {
		exec.Command("sudo", "ip", "route", "flush", "table", "100").Run()
		exec.Command("sudo", "ip", "route", "add", "default", "dev", "proxya-tun", "table", "100").Run()
		exec.Command("sudo", "ip", "-6", "route", "flush", "table", "100").Run()
		exec.Command("sudo", "ip", "-6", "route", "add", "default", "dev", "proxya-tun", "table", "100").Run()
		
		exec.Command("sudo", "ip", "rule", "add", "table", "100", "pref", "200").Run()
		exec.Command("sudo", "ip", "-6", "rule", "add", "table", "100", "pref", "200").Run()
	}

	// 3. DNS Hijack via NAT REDIRECT (Most Reliable for IPv4)
	// and TProxy for IPv6 in the same table
	sb := "table inet xray_proxya {\n"
	sb += "    chain prerouting {\n"
	sb += "        type filter hook prerouting priority mangle; policy accept;\n"
	sb += "        iifname != \"eth0\" accept\n"
	sb += "        udp dport 53 tproxy ip to 127.0.0.1:53 accept\n"
	sb += "        tcp dport 53 tproxy ip to 127.0.0.1:53 accept\n"
	sb += "        udp dport 53 tproxy ip6 to [::1]:53 accept\n"
	sb += "        tcp dport 53 tproxy ip6 to [::1]:53 accept\n"
	sb += "    }\n"
	sb += "    chain forward { type filter hook forward priority 0; policy accept; }\n"
	sb += "    chain postrouting { type nat hook postrouting priority 100; policy accept; oifname != \"proxya-tun\" meta mark != 255 masquerade }\n"
	sb += "}\n"

	tmpFile := filepath.Join(os.TempDir(), "proxya.nft")
	os.WriteFile(tmpFile, []byte("add table inet xray_proxya\nflush table inet xray_proxya\n"+sb), 0600)
	exec.Command("sudo", "nft", "-f", tmpFile).Run()
	os.Remove(tmpFile)
}

func CleanupFirewall() {
	exec.Command("sudo", "nft", "delete", "table", "inet", "xray_proxya").Run()
}

func SetupKernel() {
	exec.Command("sudo", "sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	exec.Command("sudo", "sysctl", "-w", "net.ipv6.conf.all.forwarding=1").Run()
	exec.Command("sudo", "sysctl", "-w", "net.ipv4.conf.all.rp_filter=0").Run()
	exec.Command("sudo", "sysctl", "-w", "net.ipv4.conf.default.rp_filter=0").Run()
	
	// Temporary fix for DNS conflict (non-permanent)
	exec.Command("sudo", "systemctl", "stop", "systemd-resolved").Run()
	exec.Command("sudo", "systemctl", "stop", "dnsmasq").Run()
}
