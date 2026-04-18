package gateway

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"xray-proxya/internal/config"
)

const (
	tableName = "xray_proxya"
	tunName   = "proxya-tun"
	xrayMark  = "255"
	tunMark   = "1"
)

func SyncFirewall(cfg *config.UserConfig) {
	CleanupFirewall()

	if cfg == nil || cfg.Role != config.RoleGateway {
		return
	}
	if cfg.Gateway.Mode != "tun" {
		return
	}
	if !cfg.Gateway.LocalEnabled && !cfg.Gateway.LANEnabled {
		return
	}

	lanIface := cfg.Gateway.LANInterface
	if lanIface == "" {
		lanIface = "eth0"
	}

	lanCIDR, err := getInterfaceCIDR(lanIface)
	if err != nil {
		fmt.Printf("❌ Failed to detect LAN subnet for %s: %v\n", lanIface, err)
		return
	}

	SetupKernel()

	run("sudo", "ip", "rule", "add", "fwmark", tunMark, "table", "100", "pref", "100")
	run("sudo", "ip", "rule", "add", "fwmark", xrayMark, "table", "main", "pref", "10")
	run("sudo", "ip", "rule", "add", "to", lanCIDR, "table", "main", "pref", "50")
	run("sudo", "ip", "rule", "add", "to", "127.0.0.0/8", "table", "main", "pref", "51")
	run("sudo", "ip", "route", "replace", "default", "dev", tunName, "table", "100")

	tmpFile := filepath.Join(os.TempDir(), "xray-proxya.nft")
	rules := buildNFT(cfg, lanIface, lanCIDR)
	if err := os.WriteFile(tmpFile, []byte(rules), 0600); err != nil {
		fmt.Printf("❌ Failed to write nft rules: %v\n", err)
		return
	}
	defer os.Remove(tmpFile)

	run("sudo", "nft", "-f", tmpFile)
}

func CleanupFirewall() {
	run("sudo", "nft", "delete", "table", "inet", tableName)
	run("sudo", "ip", "rule", "del", "pref", "5")
	run("sudo", "ip", "rule", "del", "pref", "10")
	run("sudo", "ip", "rule", "del", "pref", "50")
	run("sudo", "ip", "rule", "del", "pref", "51")
	run("sudo", "ip", "rule", "del", "pref", "100")
	run("sudo", "ip", "rule", "del", "pref", "149")
	run("sudo", "ip", "rule", "del", "pref", "150")
	run("sudo", "ip", "rule", "del", "pref", "200")
	run("sudo", "ip", "rule", "del", "pref", "201")
	run("sudo", "ip", "route", "flush", "table", "100")
	run("sudo", "ip", "-6", "rule", "del", "pref", "10")
	run("sudo", "ip", "-6", "rule", "del", "pref", "50")
	run("sudo", "ip", "-6", "rule", "del", "pref", "100")
	run("sudo", "ip", "-6", "rule", "del", "pref", "149")
	run("sudo", "ip", "-6", "rule", "del", "pref", "150")
	run("sudo", "ip", "-6", "rule", "del", "pref", "200")
	run("sudo", "ip", "-6", "route", "flush", "table", "100")
}

func SetupKernel() {
	run("sudo", "sysctl", "-w", "net.ipv4.ip_forward=1")
	run("sudo", "sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
	run("sudo", "sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
	run("sudo", "sysctl", "-w", "net.ipv4.conf.default.rp_filter=0")
	run("sudo", "systemctl", "stop", "systemd-resolved")
}

func buildNFT(cfg *config.UserConfig, lanIface, lanCIDR string) string {
	var b strings.Builder
	b.WriteString("table inet " + tableName + " {\n")
	b.WriteString("    chain prerouting {\n")
	b.WriteString("        type filter hook prerouting priority mangle; policy accept;\n")
	b.WriteString("        meta mark " + xrayMark + " return\n")
	b.WriteString("        iifname != \"" + lanIface + "\" return\n")
	b.WriteString("        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return\n")
	b.WriteString("        ip daddr " + lanCIDR + " return\n")
	for _, ip := range outboundIPs(cfg) {
		b.WriteString("        ip daddr " + ip + " return\n")
	}
	b.WriteString("        meta l4proto { tcp, udp } meta mark set " + tunMark + "\n")
	b.WriteString("    }\n")

	if cfg.Gateway.LocalEnabled {
		b.WriteString("    chain output {\n")
		b.WriteString("        type route hook output priority mangle; policy accept;\n")
		b.WriteString("        meta mark " + xrayMark + " return\n")
		b.WriteString("        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return\n")
		b.WriteString("        ip daddr " + lanCIDR + " return\n")
		for _, ip := range outboundIPs(cfg) {
			b.WriteString("        ip daddr " + ip + " return\n")
		}
		for _, port := range getSSHPorts() {
			b.WriteString("        tcp dport " + port + " return\n")
		}
		b.WriteString("        meta l4proto { tcp, udp } meta mark set " + tunMark + "\n")
		b.WriteString("    }\n")
	}

	b.WriteString("}\n")
	return b.String()
}

func getInterfaceCIDR(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil || ipNet.IP.To4() == nil {
			continue
		}
		networkIP := ipNet.IP.Mask(ipNet.Mask)
		return (&net.IPNet{IP: networkIP, Mask: ipNet.Mask}).String(), nil
	}
	return "", fmt.Errorf("no IPv4 subnet found on %s", name)
}

func outboundIPs(cfg *config.UserConfig) []string {
	var ips []string
	seen := map[string]bool{}
	for _, co := range cfg.CustomOutbounds {
		if !co.Enabled {
			continue
		}
		settings, _ := co.Config["settings"].(map[string]interface{})
		vnextList, _ := settings["vnext"].([]interface{})
		for _, item := range vnextList {
			vnext, _ := item.(map[string]interface{})
			addr, _ := vnext["address"].(string)
			ip := net.ParseIP(addr)
			if ip == nil {
				continue
			}
			if seen[ip.String()] {
				continue
			}
			seen[ip.String()] = true
			ips = append(ips, ip.String())
		}
	}
	return ips
}

func getSSHPorts() []string {
	ports := []string{"22"}
	out, err := exec.Command("sh", "-c", "ss -tlnp | grep sshd").Output()
	if err != nil {
		return ports
	}
	found := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		hostPort := fields[3]
		idx := strings.LastIndex(hostPort, ":")
		if idx < 0 || idx+1 >= len(hostPort) {
			continue
		}
		port := hostPort[idx+1:]
		if port != "" {
			found[port] = true
		}
	}
	if len(found) == 0 {
		return ports
	}
	ports = ports[:0]
	for port := range found {
		ports = append(ports, port)
	}
	return ports
}

func run(name string, args ...string) {
	exec.Command(name, args...).Run()
}
