package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"xray-proxya/internal/endpoint"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

// HETunnelSpec represents the parsed configuration for a Hurricane Electric 6in4 tunnel.
type HETunnelSpec struct {
	Interface    string `json:"interface"`
	ServerIPv4   string `json:"server_ipv4"`
	ClientIPv4   string `json:"client_ipv4"`
	ClientIPv6   string `json:"client_ipv6"`
	PrefixLen    int    `json:"prefix_len"`
	GatewayIPv6  string `json:"gateway_ipv6"`
	RoutedSubnet string `json:"routed_subnet"`
}

// ParseHETunnelConfig parses Debian/interfaces format or key-value format for an HE tunnel.
func ParseHETunnelConfig(content string) (*HETunnelSpec, error) {
	spec := &HETunnelSpec{
		Interface: "he-ipv6",
		PrefixLen: 64,
	}

	lines := strings.Split(content, "\n")
	var explicitRouted string

	routedRegex := regexp.MustCompile(`(?i)(?:routed\s*/?(?:64|48)[:\s]+|routed(?:64|48|-subnet)?[:\s]+)([0-9a-fA-F:]+/(?:48|64))`)

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		if matches := routedRegex.FindStringSubmatch(line); len(matches) > 1 {
			explicitRouted = strings.TrimSpace(matches[1])
		}

		if strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := strings.ToLower(fields[0])
		val := fields[1]

		switch key {
		case "iface":
			spec.Interface = val
		case "auto":
			if spec.Interface == "he-ipv6" || spec.Interface == "" {
				spec.Interface = val
			}
		case "endpoint":
			spec.ServerIPv4 = val
		case "local":
			spec.ClientIPv4 = val
		case "gateway":
			spec.GatewayIPv6 = val
		case "address":
			if strings.Contains(val, "/") {
				parts := strings.Split(val, "/")
				spec.ClientIPv6 = parts[0]
				if plen, err := strconv.Atoi(parts[1]); err == nil {
					spec.PrefixLen = plen
				}
			} else {
				spec.ClientIPv6 = val
			}
		case "netmask":
			if plen, err := strconv.Atoi(val); err == nil {
				spec.PrefixLen = plen
			}
		case "routed", "routed-subnet", "routed64", "routed48":
			explicitRouted = val
		}
	}

	if spec.ServerIPv4 == "" {
		return nil, fmt.Errorf("missing ServerIPv4 ('endpoint') in HE tunnel config")
	}
	if net.ParseIP(spec.ServerIPv4) == nil || net.ParseIP(spec.ServerIPv4).To4() == nil {
		return nil, fmt.Errorf("invalid ServerIPv4 address: %s", spec.ServerIPv4)
	}

	if spec.ClientIPv4 == "" {
		return nil, fmt.Errorf("missing ClientIPv4 ('local') in HE tunnel config")
	}
	if net.ParseIP(spec.ClientIPv4) == nil || net.ParseIP(spec.ClientIPv4).To4() == nil {
		return nil, fmt.Errorf("invalid ClientIPv4 address: %s", spec.ClientIPv4)
	}

	if spec.ClientIPv6 == "" {
		return nil, fmt.Errorf("missing ClientIPv6 ('address') in HE tunnel config")
	}
	ip6 := net.ParseIP(spec.ClientIPv6)
	if ip6 == nil || ip6.To4() != nil {
		return nil, fmt.Errorf("invalid ClientIPv6 address: %s", spec.ClientIPv6)
	}

	if spec.PrefixLen <= 0 || spec.PrefixLen > 128 {
		spec.PrefixLen = 64
	}

	if spec.GatewayIPv6 != "" {
		gw := net.ParseIP(spec.GatewayIPv6)
		if gw == nil || gw.To4() != nil {
			return nil, fmt.Errorf("invalid GatewayIPv6 address: %s", spec.GatewayIPv6)
		}
	}

	if explicitRouted != "" {
		if _, _, err := net.ParseCIDR(explicitRouted); err == nil {
			spec.RoutedSubnet = explicitRouted
		}
	}

	if spec.RoutedSubnet == "" {
		mask := net.CIDRMask(spec.PrefixLen, 128)
		netIP := ip6.Mask(mask)
		spec.RoutedSubnet = fmt.Sprintf("%s/%d", netIP.String(), spec.PrefixLen)
	}

	return spec, nil
}

// getHostIPv4Addresses returns all non-loopback IPv4 addresses bound to host interfaces.
func getHostIPv4Addresses() (map[string]string, error) {
	res := make(map[string]string)
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipNet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
					res[ip4.String()] = iface.Name
				}
			}
		}
	}
	return res, nil
}

// DetectAndFixNAT inspects host interfaces. If ClientIPv4 is not bound to any local interface,
// it determines the default outgoing interface and private IPv4, auto-correcting ClientIPv4.
func DetectAndFixNAT(spec *HETunnelSpec) (fixed bool, ifaceName string, originalIP string) {
	hostIPv4s, err := getHostIPv4Addresses()
	if err != nil {
		return false, "", ""
	}

	if _, exists := hostIPv4s[spec.ClientIPv4]; exists {
		return false, "", ""
	}

	// ClientIPv4 not found locally, machine is in a NAT / private IP environment.
	originalIP = spec.ClientIPv4

	// Try using 'ip -4 route get <ServerIPv4>' to find egress interface and source IP
	if out, err := exec.Command("ip", "-4", "route", "get", spec.ServerIPv4).CombinedOutput(); err == nil {
		outStr := string(out)
		fields := strings.Fields(outStr)
		var dev, src string
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				dev = fields[i+1]
			} else if fields[i] == "src" {
				src = fields[i+1]
			}
		}
		if src != "" && net.ParseIP(src) != nil && net.ParseIP(src).To4() != nil {
			spec.ClientIPv4 = src
			ifaceName = dev
			return true, ifaceName, originalIP
		}
	}

	// Fallback to first available host IPv4
	for ip, dev := range hostIPv4s {
		spec.ClientIPv4 = ip
		ifaceName = dev
		return true, ifaceName, originalIP
	}

	return false, "", ""
}

func findIPBinary() string {
	for _, p := range []string{"/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("ip"); err == nil {
		return p
	}
	return "/sbin/ip"
}

func testTunnelReachability(sourceIPv6 string, timeout time.Duration) (bool, time.Duration, error) {
	return endpoint.TestIPv6Reachability(sourceIPv6, timeout)
}

var doctorTunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Hurricane Electric (HE) 6in4 tunnel management, NAT auto-fix and systemd persistence",
	Long: `Safely parse Hurricane Electric IPv6 tunnel configuration, automatically detect and fix NAT private IP bindings,
incrementally configure 6in4 SIT tunnels without network restarts, and persist via systemd.`,
}

var doctorTunnelUpCmd = &cobra.Command{
	Use:   "up [config-path]",
	Short: "Deploy or update Hurricane Electric 6in4 tunnel",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := utils.RequireRootShell("doctor tunnel"); err != nil {
			return err
		}

		cfgPath := "/root/interfaces-he"
		if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
			cfgPath = strings.TrimSpace(args[0])
		}

		content, err := os.ReadFile(cfgPath)
		if err != nil {
			return fmt.Errorf("failed to read tunnel configuration (%s): %w", cfgPath, err)
		}

		spec, err := ParseHETunnelConfig(string(content))
		if err != nil {
			return fmt.Errorf("failed to parse tunnel configuration: %w", err)
		}

		if fixed, ifaceName, orig := DetectAndFixNAT(spec); fixed {
			fmt.Fprintf(cmd.OutOrStdout(), "💡 Auto-Fix: Detected NAT private interface (%s). Using local IP %s for tunnel binding (was %s).\n", ifaceName, spec.ClientIPv4, orig)
		}

		ipBin := findIPBinary()

		// 1. Teardown existing tunnel if present
		_ = exec.Command(ipBin, "link", "set", spec.Interface, "down").Run()
		_ = exec.Command(ipBin, "tunnel", "del", spec.Interface).Run()

		// 2. Add SIT tunnel
		if out, err := exec.Command(ipBin, "tunnel", "add", spec.Interface, "mode", "sit", "remote", spec.ServerIPv4, "local", spec.ClientIPv4, "ttl", "255").CombinedOutput(); err != nil {
			return fmt.Errorf("failed to create SIT tunnel: %w (%s)", err, strings.TrimSpace(string(out)))
		}

		// 3. Set MTU and bring up
		if out, err := exec.Command(ipBin, "link", "set", spec.Interface, "up", "mtu", "1480").CombinedOutput(); err != nil {
			return fmt.Errorf("failed to bring up tunnel interface: %w (%s)", err, strings.TrimSpace(string(out)))
		}

		// 4. Bind client IPv6
		clientCIDR := fmt.Sprintf("%s/%d", spec.ClientIPv6, spec.PrefixLen)
		if out, err := exec.Command(ipBin, "-6", "addr", "replace", clientCIDR, "dev", spec.Interface, "nodad").CombinedOutput(); err != nil {
			return fmt.Errorf("failed to bind client IPv6 address: %w (%s)", err, strings.TrimSpace(string(out)))
		}

		// 5. Default route
		if out, err := exec.Command(ipBin, "-6", "route", "replace", "default", "dev", spec.Interface).CombinedOutput(); err != nil {
			return fmt.Errorf("failed to set default IPv6 route: %w (%s)", err, strings.TrimSpace(string(out)))
		}

		// 6. Generate systemd persistence unit
		systemdIpPath := "/sbin/ip"
		if _, err := os.Stat(systemdIpPath); err != nil {
			systemdIpPath = ipBin
		}

		serviceUnit := fmt.Sprintf(`[Unit]
Description=Hurricane Electric 6in4 IPv6 Tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%s tunnel add %s mode sit remote %s local %s ttl 255
ExecStart=%s link set %s up mtu 1480
ExecStart=%s -6 addr replace %s/%d dev %s nodad
ExecStart=%s -6 route replace default dev %s
ExecStop=%s -6 route del default dev %s
ExecStop=%s link set %s down
ExecStop=%s tunnel del %s

[Install]
WantedBy=multi-user.target
`, systemdIpPath, spec.Interface, spec.ServerIPv4, spec.ClientIPv4,
			systemdIpPath, spec.Interface,
			systemdIpPath, spec.ClientIPv6, spec.PrefixLen, spec.Interface,
			systemdIpPath, spec.Interface,
			systemdIpPath, spec.Interface,
			systemdIpPath, spec.Interface,
			systemdIpPath, spec.Interface)

		unitPath := "/etc/systemd/system/he-tunnel.service"
		if err := os.WriteFile(unitPath, []byte(serviceUnit), 0644); err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "⚠️  Failed to write systemd unit (%s): %v\n", unitPath, err)
		} else {
			_ = exec.Command("systemctl", "daemon-reload").Run()
			_ = exec.Command("systemctl", "enable", "he-tunnel.service").Run()
		}

		// 7. Automated reachability probe
		ok, rtt, probeErr := testTunnelReachability(spec.ClientIPv6, 5*time.Second)

		fmt.Fprintln(cmd.OutOrStdout(), "")
		fmt.Fprintf(cmd.OutOrStdout(), "✅ Hurricane Electric IPv6 tunnel '%s' deployed successfully!\n", spec.Interface)
		fmt.Fprintf(cmd.OutOrStdout(), "   - Interface:    %s (MTU 1480)\n", spec.Interface)
		fmt.Fprintf(cmd.OutOrStdout(), "   - Local IPv4:   %s\n", spec.ClientIPv4)
		fmt.Fprintf(cmd.OutOrStdout(), "   - Remote IPv4:  %s\n", spec.ServerIPv4)
		fmt.Fprintf(cmd.OutOrStdout(), "   - Client IPv6:  %s/%d\n", spec.ClientIPv6, spec.PrefixLen)
		if spec.GatewayIPv6 != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "   - Gateway:      %s\n", spec.GatewayIPv6)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "   - Routed /64:   %s\n", spec.RoutedSubnet)
		fmt.Fprintf(cmd.OutOrStdout(), "   - Persistence:  he-tunnel.service (enabled)\n")
		if ok {
			fmt.Fprintf(cmd.OutOrStdout(), "   - Connectivity: OK (RTT: %v)\n", rtt.Round(time.Millisecond))
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "   - Connectivity: ⚠️  Probe failed (%v)\n", probeErr)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "")

		return nil
	},
}

var doctorTunnelDownCmd = &cobra.Command{
	Use:   "down [interface]",
	Short: "Tear down Hurricane Electric 6in4 tunnel and disable persistence",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := utils.RequireRootShell("doctor tunnel"); err != nil {
			return err
		}

		iface := "he-ipv6"
		if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
			iface = strings.TrimSpace(args[0])
		}

		ipBin := findIPBinary()

		_ = exec.Command("systemctl", "disable", "--now", "he-tunnel.service").Run()
		_ = exec.Command(ipBin, "-6", "route", "del", "default", "dev", iface).Run()
		_ = exec.Command(ipBin, "link", "set", iface, "down").Run()
		_ = exec.Command(ipBin, "tunnel", "del", iface).Run()

		fmt.Fprintf(cmd.OutOrStdout(), "✅ HE tunnel '%s' brought down and he-tunnel.service disabled.\n", iface)
		return nil
	},
}

var doctorTunnelStatusCmd = &cobra.Command{
	Use:   "status [interface]",
	Short: "Check Hurricane Electric 6in4 tunnel status and traffic",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ifaceName := "he-ipv6"
		if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
			ifaceName = strings.TrimSpace(args[0])
		}

		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return fmt.Errorf("tunnel interface '%s' not found or inactive: %w", ifaceName, err)
		}

		isUp := (iface.Flags & net.FlagUp) != 0
		stateStr := "DOWN"
		if isUp {
			stateStr = "UP"
		}

		addrs, _ := iface.Addrs()
		var ipAddrs []string
		var clientV6 string
		for _, a := range addrs {
			ipAddrs = append(ipAddrs, a.String())
			if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.To4() == nil && !ipNet.IP.IsLinkLocalUnicast() {
				clientV6 = ipNet.IP.String()
			}
		}

		readStat := func(name string) string {
			p := filepath.Join("/sys/class/net", ifaceName, "statistics", name)
			b, err := os.ReadFile(p)
			if err != nil {
				return "0"
			}
			return strings.TrimSpace(string(b))
		}

		rxBytes := readStat("rx_bytes")
		txBytes := readStat("tx_bytes")
		rxPackets := readStat("rx_packets")
		txPackets := readStat("tx_packets")

		fmt.Printf("\n--- Hurricane Electric Tunnel: %s ---\n", ifaceName)
		fmt.Printf("State:       %s\n", stateStr)
		fmt.Printf("MTU:         %d\n", iface.MTU)
		fmt.Printf("Addresses:   %s\n", strings.Join(ipAddrs, ", "))
		fmt.Printf("Packets:     RX %s | TX %s\n", rxPackets, txPackets)
		fmt.Printf("Bytes:       RX %s | TX %s\n", rxBytes, txBytes)

		if isUp && clientV6 != "" {
			ok, rtt, err := testTunnelReachability(clientV6, 3*time.Second)
			if ok {
				fmt.Printf("Probe:       OK (RTT: %v)\n", rtt.Round(time.Millisecond))
			} else {
				fmt.Printf("Probe:       FAIL (%v)\n", err)
			}
		}
		fmt.Println()

		return nil
	},
}

func init() {
	doctorTunnelCmd.AddCommand(doctorTunnelUpCmd, doctorTunnelDownCmd, doctorTunnelStatusCmd)
}
