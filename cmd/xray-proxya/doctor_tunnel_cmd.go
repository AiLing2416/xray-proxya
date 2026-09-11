package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"xray-proxya/internal/endpoint"
	"xray-proxya/pkg/units"
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

// ManagedServiceInfo holds parsed metadata from a systemd tunnel service file.
type ManagedServiceInfo struct {
	ServiceName string
	Interface   string
	RemoteIPv4  string
	LocalIPv4   string
	IPv6Address string
	Active      string
	Enabled     string
}

// TunnelTrafficStats records RX and TX packet and byte counters.
type TunnelTrafficStats struct {
	RXPackets uint64 `json:"rx_packets"`
	TXPackets uint64 `json:"tx_packets"`
	RXBytes   uint64 `json:"rx_bytes"`
	TXBytes   uint64 `json:"tx_bytes"`
}

// TunnelProbeReport records reachability probe for an IPv6 address.
type TunnelProbeReport struct {
	SourceIP string `json:"source_ip"`
	Pass     bool   `json:"pass"`
	RTTMs    int64  `json:"rtt_ms"`
	Error    string `json:"error,omitempty"`
}

// TunnelStatusReportItem represents the state of a single tunnel interface.
type TunnelStatusReportItem struct {
	Interface      string              `json:"interface"`
	Managed        bool                `json:"managed"`
	ManagedBy      string              `json:"managed_by,omitempty"`
	ServiceActive  string              `json:"service_active,omitempty"`
	ServiceEnabled string              `json:"service_enabled,omitempty"`
	State          string              `json:"state"` // "UP", "DOWN", "ABSENT"
	MTU            int                 `json:"mtu"`
	LocalIPv4      string              `json:"local_ipv4,omitempty"`
	RemoteIPv4     string              `json:"remote_ipv4,omitempty"`
	GlobalIPv6     []string            `json:"global_ipv6"`
	LinkLocalIPv6  []string            `json:"link_local_ipv6"`
	Traffic        TunnelTrafficStats  `json:"traffic"`
	Probes         []TunnelProbeReport `json:"probes"`
	Diagnostics    []string            `json:"diagnostics,omitempty"`
}

// TunnelStatusReport is the root struct when formatting as JSON.
type TunnelStatusReport struct {
	Tunnels []TunnelStatusReportItem `json:"tunnels"`
}

var (
	systemdDir        = "/etc/systemd/system"
	sysfsNetDir       = "/sys/class/net"
	tunnelRequireRoot = func(op string) error {
		return utils.RequireRootShell(op)
	}
	tunnelCmdRunner = func(name string, arg ...string) ([]byte, error) {
		return exec.Command(name, arg...).CombinedOutput()
	}
	findVerifiedTunnelConfigFunc = findVerifiedTunnelConfig
	tunnelInterfacesLister       = net.Interfaces
	tunnelAddrsLister            = func(iface net.Interface) ([]net.Addr, error) {
		return iface.Addrs()
	}
	tunnelProbeRunner      = testTunnelReachability
	doctorTunnelStatusJSON bool
)

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

func findVerifiedTunnelConfig(iface string) (bool, string) {
	// 1. Search systemd units in systemdDir
	files, _ := filepath.Glob(filepath.Join(systemdDir, "he-tunnel*.service"))
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		str := string(content)
		if strings.Contains(str, "tunnel add "+iface+" ") ||
			strings.Contains(str, "dev "+iface) ||
			strings.Contains(str, "he-tunnel-"+iface+".service") {
			return true, fmt.Sprintf("systemd service (%s)", filepath.Base(f))
		}
	}

	// 2. Search /etc/network/interfaces and /etc/network/interfaces.d/*
	checkDebianFile := func(path string) bool {
		content, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		lines := strings.Split(string(content), "\n")
		inIface := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "iface ") {
				parts := strings.Fields(trimmed)
				if len(parts) >= 2 && parts[1] == iface {
					inIface = true
					if strings.Contains(trimmed, "v4tunnel") || strings.Contains(trimmed, "sit") {
						return true
					}
				} else {
					inIface = false
				}
			} else if inIface {
				if strings.HasPrefix(trimmed, "endpoint ") || strings.HasPrefix(trimmed, "local ") {
					return true
				}
			}
		}
		return false
	}

	if checkDebianFile("/etc/network/interfaces") {
		return true, "/etc/network/interfaces"
	}
	if dFiles, _ := filepath.Glob("/etc/network/interfaces.d/*"); len(dFiles) > 0 {
		for _, df := range dFiles {
			if checkDebianFile(df) {
				return true, df
			}
		}
	}

	// 3. Search /etc/netplan/*.yaml and *.yml
	for _, pattern := range []string{"/etc/netplan/*.yaml", "/etc/netplan/*.yml"} {
		if npFiles, _ := filepath.Glob(pattern); len(npFiles) > 0 {
			for _, npf := range npFiles {
				content, err := os.ReadFile(npf)
				if err != nil {
					continue
				}
				str := string(content)
				if strings.Contains(str, iface+":") && (strings.Contains(str, "sit") || strings.Contains(str, "mode: sit") || strings.Contains(str, "remote:") || strings.Contains(str, "local:")) {
					return true, npf
				}
			}
		}
	}

	// 4. Search /etc/systemd/network/*
	if snFiles, _ := filepath.Glob("/etc/systemd/network/*"); len(snFiles) > 0 {
		for _, snf := range snFiles {
			content, err := os.ReadFile(snf)
			if err != nil {
				continue
			}
			str := string(content)
			if strings.Contains(str, iface) && (strings.Contains(str, "sit") || strings.Contains(str, "Kind=sit")) {
				return true, snf
			}
		}
	}

	return false, ""
}

var doctorTunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Hurricane Electric (HE) 6in4 tunnel declarative deployment, diagnostics, and management",
	Long: `Declarative provisioner and diagnostic tools for Hurricane Electric 6in4 IPv6 tunnels.
Operates on explicit configuration files, automatically detects NAT bindings,
incrementally configures SIT tunnels, and integrates with systemd.`,
}

var doctorTunnelUpCmd = &cobra.Command{
	Use:   "up <config-path>",
	Short: "Deploy or update Hurricane Electric 6in4 tunnel from a configuration file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := tunnelRequireRoot("doctor tunnel up"); err != nil {
			return err
		}

		cfgPath := strings.TrimSpace(args[0])
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

		// 1. Idempotent cleanup before re-creation
		_, _ = tunnelCmdRunner(ipBin, "-6", "route", "del", "default", "dev", spec.Interface)
		_, _ = tunnelCmdRunner(ipBin, "link", "set", spec.Interface, "down")
		_, _ = tunnelCmdRunner(ipBin, "tunnel", "del", spec.Interface)

		// 2. Add SIT tunnel
		if out, err := tunnelCmdRunner(ipBin, "tunnel", "add", spec.Interface, "mode", "sit", "remote", spec.ServerIPv4, "local", spec.ClientIPv4, "ttl", "255"); err != nil {
			return fmt.Errorf("failed to create SIT tunnel: %w (%s)", err, strings.TrimSpace(string(out)))
		}

		// 3. Set MTU and bring up
		if out, err := tunnelCmdRunner(ipBin, "link", "set", spec.Interface, "up", "mtu", "1480"); err != nil {
			return fmt.Errorf("failed to bring up tunnel interface: %w (%s)", err, strings.TrimSpace(string(out)))
		}

		// 4. Bind client IPv6
		clientCIDR := fmt.Sprintf("%s/%d", spec.ClientIPv6, spec.PrefixLen)
		if out, err := tunnelCmdRunner(ipBin, "-6", "addr", "replace", clientCIDR, "dev", spec.Interface, "nodad"); err != nil {
			return fmt.Errorf("failed to bind client IPv6 address: %w (%s)", err, strings.TrimSpace(string(out)))
		}

		// 5. Default route
		if out, err := tunnelCmdRunner(ipBin, "-6", "route", "replace", "default", "dev", spec.Interface); err != nil {
			return fmt.Errorf("failed to set default IPv6 route: %w (%s)", err, strings.TrimSpace(string(out)))
		}

		// 6. Generate dynamically named systemd persistence unit
		systemdIpPath := "/sbin/ip"
		if _, err := os.Stat(systemdIpPath); err != nil {
			systemdIpPath = ipBin
		}

		serviceName := fmt.Sprintf("he-tunnel-%s.service", spec.Interface)
		serviceUnit := fmt.Sprintf(`[Unit]
Description=Hurricane Electric 6in4 IPv6 Tunnel (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-%s tunnel del %s
ExecStart=%s tunnel add %s mode sit remote %s local %s ttl 255
ExecStart=%s link set %s up mtu 1480
ExecStart=%s -6 addr replace %s/%d dev %s nodad
ExecStart=%s -6 route replace default dev %s
ExecStop=%s -6 route del default dev %s
ExecStop=%s link set %s down
ExecStop=%s tunnel del %s

[Install]
WantedBy=multi-user.target
`, spec.Interface,
			systemdIpPath, spec.Interface,
			systemdIpPath, spec.Interface, spec.ServerIPv4, spec.ClientIPv4,
			systemdIpPath, spec.Interface,
			systemdIpPath, spec.ClientIPv6, spec.PrefixLen, spec.Interface,
			systemdIpPath, spec.Interface,
			systemdIpPath, spec.Interface,
			systemdIpPath, spec.Interface,
			systemdIpPath, spec.Interface)

		unitPath := filepath.Join(systemdDir, serviceName)
		_ = os.MkdirAll(systemdDir, 0755)
		if err := os.WriteFile(unitPath, []byte(serviceUnit), 0644); err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "⚠️  Failed to write systemd unit (%s): %v\n", unitPath, err)
		} else {
			// Clean legacy generic unit if it existed and is different
			if serviceName != "he-tunnel.service" {
				_ = os.Remove(filepath.Join(systemdDir, "he-tunnel.service"))
			}
			_, _ = tunnelCmdRunner("systemctl", "daemon-reload")
			_, _ = tunnelCmdRunner("systemctl", "enable", "--now", serviceName)
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
		fmt.Fprintf(cmd.OutOrStdout(), "   - Persistence:  %s (enabled & active)\n", serviceName)
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
	Use:   "down <config-path | interface>",
	Short: "Tear down Hurricane Electric 6in4 tunnel and remove systemd persistence",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := tunnelRequireRoot("doctor tunnel down"); err != nil {
			return err
		}

		target := strings.TrimSpace(args[0])
		iface := target

		// Branch A: input is an existing configuration file
		if fi, err := os.Stat(target); err == nil && !fi.IsDir() {
			content, err := os.ReadFile(target)
			if err != nil {
				return fmt.Errorf("failed to read tunnel configuration file (%s): %w", target, err)
			}
			spec, err := ParseHETunnelConfig(string(content))
			if err != nil {
				return fmt.Errorf("failed to parse tunnel configuration file (%s): %w", target, err)
			}
			iface = spec.Interface
		} else {
			// Branch B: input is an interface name -> require verified configuration source
			verified, source := findVerifiedTunnelConfigFunc(iface)
			if !verified {
				return fmt.Errorf("❌ Error: Cannot safely tear down interface '%s': No verified configuration found in active network configs or systemd services. Please specify the configuration file explicitly.", iface)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "ℹ️ Verified tunnel interface '%s' via %s.\n", iface, source)
		}

		ipBin := findIPBinary()

		// 1. Disable and stop systemd service(s)
		svcName := fmt.Sprintf("he-tunnel-%s.service", iface)
		_, _ = tunnelCmdRunner("systemctl", "disable", "--now", svcName)
		_, _ = tunnelCmdRunner("systemctl", "disable", "--now", "he-tunnel.service")

		// 2. Remove systemd service files
		_ = os.Remove(filepath.Join(systemdDir, svcName))
		_ = os.Remove(filepath.Join(systemdDir, "he-tunnel.service"))
		_, _ = tunnelCmdRunner("systemctl", "daemon-reload")

		// 3. Teardown kernel network
		_, _ = tunnelCmdRunner(ipBin, "-6", "route", "del", "default", "dev", iface)
		_, _ = tunnelCmdRunner(ipBin, "link", "set", iface, "down")
		_, _ = tunnelCmdRunner(ipBin, "tunnel", "del", iface)

		fmt.Fprintf(cmd.OutOrStdout(), "✅ HE tunnel '%s' brought down and systemd persistence removed.\n", iface)
		return nil
	},
}

func readIfaceStatFromSysfs(ifaceName, statName string) uint64 {
	p := filepath.Join(sysfsNetDir, ifaceName, "statistics", statName)
	b, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func readIfaceTypeFromSysfs(ifaceName string) int {
	p := filepath.Join(sysfsNetDir, ifaceName, "type")
	b, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0
	}
	return v
}

func isTunnelDevice(iface net.Interface) bool {
	lower := strings.ToLower(iface.Name)
	if strings.HasPrefix(lower, "he-") || strings.HasPrefix(lower, "sit") || strings.HasPrefix(lower, "tun") || strings.HasPrefix(lower, "ip6tnl") {
		return true
	}
	t := readIfaceTypeFromSysfs(iface.Name)
	// ARPHRD_SIT = 776, ARPHRD_TUNNEL = 768, ARPHRD_TUNNEL6 = 769, ARPHRD_IPGRE = 772, ARPHRD_NONE = 65534
	return t == 776 || t == 768 || t == 769 || t == 772 || t == 65534
}

func parseManagedTunnelServices(dir string) map[string]ManagedServiceInfo {
	res := make(map[string]ManagedServiceInfo)
	files, _ := filepath.Glob(filepath.Join(dir, "he-tunnel*.service"))

	ifaceRegex := regexp.MustCompile(`(?:tunnel\s+(?:add|del)\s+|dev\s+)([a-zA-Z0-9_-]+)`)
	remoteRegex := regexp.MustCompile(`remote\s+([0-9.]+)`)
	localRegex := regexp.MustCompile(`local\s+([0-9.]+)`)
	addrRegex := regexp.MustCompile(`addr\s+replace\s+([0-9a-fA-F:]+(?:/\d+)?)`)

	for _, f := range files {
		svcName := filepath.Base(f)
		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		str := string(content)

		var ifaceName string
		if matches := ifaceRegex.FindStringSubmatch(str); len(matches) > 1 {
			ifaceName = matches[1]
		} else if strings.HasPrefix(svcName, "he-tunnel-") && strings.HasSuffix(svcName, ".service") {
			ifaceName = strings.TrimSuffix(strings.TrimPrefix(svcName, "he-tunnel-"), ".service")
		} else if svcName == "he-tunnel.service" {
			ifaceName = "he-ipv6"
		}

		if ifaceName == "" {
			continue
		}

		info := ManagedServiceInfo{
			ServiceName: svcName,
			Interface:   ifaceName,
		}

		if m := remoteRegex.FindStringSubmatch(str); len(m) > 1 {
			info.RemoteIPv4 = m[1]
		}
		if m := localRegex.FindStringSubmatch(str); len(m) > 1 {
			info.LocalIPv4 = m[1]
		}
		if m := addrRegex.FindStringSubmatch(str); len(m) > 1 {
			info.IPv6Address = m[1]
		}

		activeOut, _ := tunnelCmdRunner("systemctl", "is-active", svcName)
		info.Active = strings.TrimSpace(string(activeOut))
		if info.Active == "" {
			info.Active = "unknown"
		}

		enabledOut, _ := tunnelCmdRunner("systemctl", "is-enabled", svcName)
		info.Enabled = strings.TrimSpace(string(enabledOut))
		if info.Enabled == "" {
			info.Enabled = "unknown"
		}

		res[ifaceName] = info
	}

	return res
}

var doctorTunnelStatusCmd = &cobra.Command{
	Use:   "status [interface]",
	Short: "Check Hurricane Electric 6in4 tunnel status and traffic",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		servicesMap := parseManagedTunnelServices(systemdDir)

		allIfaces, _ := tunnelInterfacesLister()
		kernelIfaces := make(map[string]net.Interface)
		for _, ifc := range allIfaces {
			if isTunnelDevice(ifc) {
				kernelIfaces[ifc.Name] = ifc
			}
		}

		var targetIfaces []string
		if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
			target := strings.TrimSpace(args[0])
			if _, inKernel := kernelIfaces[target]; !inKernel {
				for _, ifc := range allIfaces {
					if ifc.Name == target {
						kernelIfaces[target] = ifc
						break
					}
				}
			}
			_, inTier1 := servicesMap[target]
			_, inTier2 := kernelIfaces[target]
			if !inTier1 && !inTier2 {
				return fmt.Errorf("tunnel interface '%s' not found in systemd services or kernel network devices", target)
			}
			targetIfaces = []string{target}
		} else {
			nameSet := make(map[string]struct{})
			for name := range servicesMap {
				nameSet[name] = struct{}{}
			}
			for name := range kernelIfaces {
				nameSet[name] = struct{}{}
			}
			for name := range nameSet {
				targetIfaces = append(targetIfaces, name)
			}
			sort.Strings(targetIfaces)
		}

		report := TunnelStatusReport{
			Tunnels: make([]TunnelStatusReportItem, 0, len(targetIfaces)),
		}

		for _, ifaceName := range targetIfaces {
			item := TunnelStatusReportItem{
				Interface:     ifaceName,
				GlobalIPv6:    []string{},
				LinkLocalIPv6: []string{},
				Probes:        []TunnelProbeReport{},
				Diagnostics:   []string{},
			}

			if svc, ok := servicesMap[ifaceName]; ok {
				item.Managed = true
				item.ManagedBy = svc.ServiceName
				item.ServiceActive = svc.Active
				item.ServiceEnabled = svc.Enabled
				item.LocalIPv4 = svc.LocalIPv4
				item.RemoteIPv4 = svc.RemoteIPv4
			} else {
				item.Managed = false
				item.Diagnostics = append(item.Diagnostics, "Detected manual or external tunnel interface. Not managed by Xray-Proxya systemd service.")
			}

			if kIface, ok := kernelIfaces[ifaceName]; ok {
				if (kIface.Flags & net.FlagUp) != 0 {
					item.State = "UP"
				} else {
					item.State = "DOWN"
				}
				item.MTU = kIface.MTU

				addrs, _ := tunnelAddrsLister(kIface)
				for _, a := range addrs {
					if ipNet, ok := a.(*net.IPNet); ok {
						if ipNet.IP.To4() == nil {
							if ipNet.IP.IsLinkLocalUnicast() {
								item.LinkLocalIPv6 = append(item.LinkLocalIPv6, ipNet.String())
							} else if !ipNet.IP.IsLoopback() {
								item.GlobalIPv6 = append(item.GlobalIPv6, ipNet.String())
							}
						}
					}
				}

				item.Traffic.RXBytes = readIfaceStatFromSysfs(ifaceName, "rx_bytes")
				item.Traffic.TXBytes = readIfaceStatFromSysfs(ifaceName, "tx_bytes")
				item.Traffic.RXPackets = readIfaceStatFromSysfs(ifaceName, "rx_packets")
				item.Traffic.TXPackets = readIfaceStatFromSysfs(ifaceName, "tx_packets")
			} else {
				item.State = "ABSENT"
				item.MTU = 0
				item.Diagnostics = append(item.Diagnostics, "Interface is absent in the kernel.")
				if svc, ok := servicesMap[ifaceName]; ok && svc.IPv6Address != "" {
					item.GlobalIPv6 = append(item.GlobalIPv6, svc.IPv6Address)
				}
			}

			for _, gIP := range item.GlobalIPv6 {
				ipOnly := strings.Split(gIP, "/")[0]
				if item.State == "UP" {
					ok, rtt, pErr := tunnelProbeRunner(ipOnly, 3*time.Second)
					rttMs := int64(0)
					errStr := ""
					if ok {
						rttMs = rtt.Milliseconds()
					}
					if pErr != nil {
						errStr = pErr.Error()
					}
					item.Probes = append(item.Probes, TunnelProbeReport{
						SourceIP: gIP,
						Pass:     ok,
						RTTMs:    rttMs,
						Error:    errStr,
					})
					if !ok {
						item.Diagnostics = append(item.Diagnostics, fmt.Sprintf("Reachability probe failed for %s: %s", gIP, errStr))
					}
				} else {
					item.Probes = append(item.Probes, TunnelProbeReport{
						SourceIP: gIP,
						Pass:     false,
						RTTMs:    0,
						Error:    "interface is not UP",
					})
				}
			}

			if item.Managed && item.ServiceActive != "" && item.ServiceActive != "active" {
				item.Diagnostics = append(item.Diagnostics, fmt.Sprintf("Systemd service '%s' is not active (state: %s).", item.ManagedBy, item.ServiceActive))
			}
			if item.State == "DOWN" {
				item.Diagnostics = append(item.Diagnostics, "Link state is DOWN.")
			}

			report.Tunnels = append(report.Tunnels, item)
		}

		if doctorTunnelStatusJSON {
			data, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to encode JSON status: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(data))
			return nil
		}

		if len(report.Tunnels) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No Hurricane Electric or tunnel interfaces detected on this system.")
			return nil
		}

		for _, tun := range report.Tunnels {
			fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("=", 80))
			fmt.Fprintf(cmd.OutOrStdout(), "Tunnel Interface: %s [%s]\n", tun.Interface, tun.State)
			fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("=", 80))

			if tun.Managed {
				fmt.Fprintf(cmd.OutOrStdout(), "Managed:        YES (via %s, %s, %s)\n", tun.ManagedBy, tun.ServiceActive, tun.ServiceEnabled)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "Managed:        NO (external/manual configuration)")
			}

			if tun.MTU > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "MTU:            %d\n", tun.MTU)
			}
			if tun.LocalIPv4 != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "Local IPv4:     %s\n", tun.LocalIPv4)
			}
			if tun.RemoteIPv4 != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "Remote IPv4:    %s\n", tun.RemoteIPv4)
			}
			if len(tun.GlobalIPv6) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "IPv6 (Global):  %s\n", strings.Join(tun.GlobalIPv6, ", "))
			}
			if len(tun.LinkLocalIPv6) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "IPv6 (Local):   %s\n", strings.Join(tun.LinkLocalIPv6, ", "))
			}

			if tun.State != "ABSENT" {
				fmt.Fprintf(cmd.OutOrStdout(), "Traffic:        RX %s (%d pkts) | TX %s (%d pkts)\n",
					units.FormatBytes(int64(tun.Traffic.RXBytes)), tun.Traffic.RXPackets,
					units.FormatBytes(int64(tun.Traffic.TXBytes)), tun.Traffic.TXPackets)
			}

			if len(tun.Probes) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "Probes:")
				for _, probe := range tun.Probes {
					if probe.Pass {
						fmt.Fprintf(cmd.OutOrStdout(), "  * %s: PASS (%dms)\n", probe.SourceIP, probe.RTTMs)
					} else {
						fmt.Fprintf(cmd.OutOrStdout(), "  * %s: FAIL (%s)\n", probe.SourceIP, probe.Error)
					}
				}
			}

			if len(tun.Diagnostics) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "Diagnostics:")
				for _, diag := range tun.Diagnostics {
					fmt.Fprintf(cmd.OutOrStdout(), "  ⚠️  %s\n", diag)
				}
			}
			fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", 80))
			fmt.Fprintln(cmd.OutOrStdout(), "")
		}

		return nil
	},
}

func init() {
	doctorTunnelStatusCmd.Flags().BoolVar(&doctorTunnelStatusJSON, "json", false, "Output status report in JSON format")
	doctorTunnelCmd.AddCommand(doctorTunnelUpCmd, doctorTunnelDownCmd, doctorTunnelStatusCmd)
}
