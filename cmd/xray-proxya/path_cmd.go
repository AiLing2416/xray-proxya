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
	"strings"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/pathd"

	"github.com/spf13/cobra"
)

const pathdUnit = "xray-proxya-pathd"

var (
	pathListen    string
	pathToken     string
	pathIdle      int
	pathRelay     string
	pathGenerate  bool
	pathPingTTL   int
	pathTraceHops int
	pathMTUMin    int
	pathMTUMax    int
)

func pathdConfigPath() string { return filepath.Join(config.GetConfigDir(), "pathd.json") }
func pathdBinaryPath() string {
	return filepath.Join(config.GetHomeDir(), ".local", "share", "xray-proxya", "bin", "pathd")
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
	if cfg == nil || cfg.Role != config.RoleServer {
		return fmt.Errorf("pathd configuration is available only on a Server")
	}
	if cfg.Path.Listen == "" {
		return fmt.Errorf("pathd listen address is not configured; run 'path set --listen <address>'")
	}
	if err := pathd.ValidateListenAddress(cfg.Path.Listen); err != nil {
		return err
	}
	if cfg.Path.IdleSeconds <= 0 {
		return fmt.Errorf("pathd idle timeout is invalid")
	}
	if cfg.Path.Token == "" {
		return fmt.Errorf("pathd token is not configured; run 'path set --token <token>'")
	}
	data, err := json.MarshalIndent(struct {
		Listen      string `json:"listen"`
		Token       string `json:"token"`
		IdleSeconds int    `json:"idle_seconds"`
	}{cfg.Path.Listen, cfg.Path.Token, cfg.Path.IdleSeconds}, "", "  ")
	if err != nil {
		return err
	}
	path := pathdConfigPath()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pathd.json-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

var pathCmd = &cobra.Command{Use: "path", Short: "Manage the root-only loopback PathLink ICMP agent", PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
	if err := pathRootOnlyError(os.Geteuid(), os.Getenv("SUDO_USER"), os.Getenv("SUDO_UID")); err != nil {
		return err
	}
	if _, err := os.Stat(config.GetConfigPath()); err != nil {
		return fmt.Errorf("initialize xray-proxya first")
	}
	return nil
}}

// PathLink has one root-owned configuration and service lifecycle. Rejecting
// sudo prevents a caller from accidentally mixing an unprivileged shell's
// configuration expectations with root's system service.
func pathRootOnlyError(euid int, sudoUser, sudoUID string) error {
	if sudoUser != "" || sudoUID != "" {
		return fmt.Errorf("path commands must run from a direct root shell; sudo is not supported (use 'su -' or log in as root)")
	}
	if euid != 0 {
		return fmt.Errorf("path commands require a direct root shell (use 'su -' or log in as root)")
	}
	return nil
}

func setPathEndpoint(cmd *cobra.Command, endpoint *config.PathConfig, requireToken bool) (string, error) {
	if pathGenerate && cmd.Flags().Changed("token") {
		return "", fmt.Errorf("--generate-token cannot be combined with --token")
	}
	if !cmd.Flags().Changed("token") && !cmd.Flags().Changed("listen") && !cmd.Flags().Changed("idle") && !pathGenerate {
		return "", fmt.Errorf("specify --token, --listen, --idle, or --generate-token")
	}
	generated := ""
	if cmd.Flags().Changed("listen") {
		endpoint.Listen = pathListen
	}
	if cmd.Flags().Changed("idle") {
		endpoint.IdleSeconds = pathIdle
	}
	if cmd.Flags().Changed("token") {
		endpoint.Token = pathToken
	}
	if pathGenerate {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			return "", fmt.Errorf("generate token: %w", err)
		}
		generated = hex.EncodeToString(bytes)
		endpoint.Token = generated
	}
	if endpoint.Listen == "" {
		endpoint.Listen = "127.0.0.1:39091"
	}
	if endpoint.IdleSeconds <= 0 {
		endpoint.IdleSeconds = 20
	}
	if err := pathd.ValidateListenAddress(endpoint.Listen); err != nil {
		return "", err
	}
	if requireToken && endpoint.Token == "" {
		return "", fmt.Errorf("a token is required for a new relay PathLink binding")
	}
	if endpoint.Token == "" {
		return "", fmt.Errorf("pathd token is not configured; pass --token or --generate-token")
	}
	return generated, nil
}

func validatePathRole(role config.AppRole, relay string) error {
	switch role {
	case config.RoleServer:
		if relay != "" {
			return fmt.Errorf("Server Pathd is local; --relay is only valid on a Gateway")
		}
	case config.RoleGateway:
		if relay == "" {
			return fmt.Errorf("Gateway PathLink configuration requires --relay")
		}
	default:
		return fmt.Errorf("unsupported role %q", role)
	}
	return nil
}

var pathSetCmd = &cobra.Command{Use: "set", Short: "Configure Pathd or a relay PathLink credential in STAGING", Run: func(cmd *cobra.Command, args []string) {
	cfg, err := config.LoadConfigEx(true)
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	switch cfg.Role {
	case config.RoleServer:
		if err := validatePathRole(cfg.Role, pathRelay); err != nil {
			fmt.Println("❌", err)
			return
		}
		generated, err := setPathEndpoint(cmd, &cfg.Path, false)
		if err != nil {
			fmt.Println("❌", err)
			return
		}
		if err := cfg.SaveEx(true); err != nil {
			fmt.Println("❌", err)
			return
		}
		fmt.Printf("✅ Server Pathd configured in STAGING (%s). Run 'apply', then manage it with 'service enable --now xray-proxya-pathd'.\n", cfg.Path.Listen)
		if generated != "" {
			fmt.Printf("🔐 Generated token (save it now): %s\n", generated)
		}
	case config.RoleGateway:
		if err := validatePathRole(cfg.Role, pathRelay); err != nil {
			fmt.Println("❌", err)
			return
		}
		if pathGenerate {
			fmt.Println("❌ Gateway credentials must match the remote Pathd; pass --token instead of --generate-token.")
			return
		}
		for i := range cfg.CustomOutbounds {
			outbound := &cfg.CustomOutbounds[i]
			if outbound.Alias != pathRelay {
				continue
			}
			if outbound.Path == nil {
				outbound.Path = &config.PathConfig{}
			}
			if _, err := setPathEndpoint(cmd, outbound.Path, outbound.Path.Token == ""); err != nil {
				fmt.Println("❌", err)
				return
			}
			if err := cfg.SaveEx(true); err != nil {
				fmt.Println("❌", err)
				return
			}
			fmt.Printf("✅ PathLink credentials for relay '%s' saved in STAGING. Run 'apply'.\n", pathRelay)
			return
		}
		fmt.Printf("❌ Relay '%s' not found.\n", pathRelay)
	default:
		fmt.Printf("❌ Unsupported role %q.\n", cfg.Role)
	}
}}

var pathUnsetCmd = &cobra.Command{Use: "unset", Short: "Remove a relay PathLink credential from STAGING", Run: func(cmd *cobra.Command, args []string) {
	cfg, err := config.LoadConfigEx(true)
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	if cfg.Role == config.RoleServer {
		if err := validatePathRole(cfg.Role, pathRelay); err != nil {
			fmt.Println("❌", err)
			return
		}
		if exec.Command("systemctl", "is-active", "--quiet", pathdUnit).Run() == nil {
			fmt.Println("❌ Stop or disable xray-proxya-pathd with the service command before removing its configuration.")
			return
		}
		cfg.Path = config.PathConfig{}
	} else if cfg.Role == config.RoleGateway {
		if err := validatePathRole(cfg.Role, pathRelay); err != nil {
			fmt.Println("❌", err)
			return
		}
		found := false
		for i := range cfg.CustomOutbounds {
			if cfg.CustomOutbounds[i].Alias == pathRelay {
				cfg.CustomOutbounds[i].Path = nil
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("❌ Relay '%s' not found.\n", pathRelay)
			return
		}
	} else {
		fmt.Printf("❌ Unsupported role %q.\n", cfg.Role)
		return
	}
	if err := cfg.SaveEx(true); err != nil {
		fmt.Println("❌", err)
		return
	}
	fmt.Println("✅ PathLink configuration removed from STAGING. Run 'apply'.")
}}
var pathStatusCmd = &cobra.Command{Use: "status", Short: "Show pathd service state", Run: func(cmd *cobra.Command, args []string) {
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	serviceState := "unknown"
	serviceEnabled := "unknown"
	if os.Geteuid() == 0 && exec.Command("systemctl", "is-active", "--quiet", pathdUnit).Run() == nil {
		serviceState = "active"
	} else if os.Geteuid() == 0 {
		serviceState = "inactive"
	}
	if os.Geteuid() == 0 {
		if exec.Command("systemctl", "is-enabled", "--quiet", pathdUnit).Run() == nil {
			serviceEnabled = "enabled"
		} else {
			serviceEnabled = "disabled"
		}
	}
	fmt.Printf("Role: %s\n", cfg.Role)
	if cfg.Role == config.RoleServer {
		if cfg.Path.Token == "" {
			fmt.Printf("Agent: %s (%s); configuration: missing\n", serviceState, serviceEnabled)
			return
		}
		fmt.Printf("Agent: %s (%s), %s\n", serviceState, serviceEnabled, cfg.Path.Listen)
		return
	}
	if cfg.Role != config.RoleGateway {
		return
	}
	fmt.Printf("Relay: %s\n", cfg.Gateway.RelayAlias)
	if endpoint, relay, err := selectedGatewayPath(cfg); err != nil {
		fmt.Printf("PathLink credentials: unavailable (%v)\n", err)
		return
	} else {
		fmt.Printf("PathLink credentials: configured for %s (%s)\n", relay, endpoint.Listen)
	}
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
	fmt.Println("PathLink runtime: unavailable (run gateway up with PathLink credentials configured)")
}}

func selectedGatewayPath(cfg *config.UserConfig) (*config.PathConfig, string, error) {
	if cfg == nil || cfg.Role != config.RoleGateway {
		return nil, "", fmt.Errorf("PathLink is available only on a Gateway")
	}
	if cfg.Gateway.State != "proxy" || !(cfg.Gateway.LocalEnabled || cfg.Gateway.LANEnabled) {
		return nil, "", fmt.Errorf("Gateway proxy mode is not enabled")
	}
	if cfg.Gateway.RelayAlias == "" {
		return nil, "", fmt.Errorf("no Gateway relay is selected")
	}
	for i := range cfg.CustomOutbounds {
		outbound := &cfg.CustomOutbounds[i]
		if outbound.Alias != cfg.Gateway.RelayAlias {
			continue
		}
		if !outbound.Enabled {
			return nil, "", fmt.Errorf("selected relay %q is disabled", outbound.Alias)
		}
		if outbound.Path == nil || outbound.Path.Token == "" {
			return nil, "", fmt.Errorf("selected relay %q has no PathLink credentials", outbound.Alias)
		}
		endpoint := *outbound.Path
		if endpoint.Listen == "" {
			endpoint.Listen = "127.0.0.1:39091"
		}
		if endpoint.IdleSeconds <= 0 {
			endpoint.IdleSeconds = 20
		}
		if err := pathd.ValidateListenAddress(endpoint.Listen); err != nil {
			return nil, "", err
		}
		return &endpoint, outbound.Alias, nil
	}
	return nil, "", fmt.Errorf("selected relay %q does not exist", cfg.Gateway.RelayAlias)
}

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
	endpoint, relay, err := selectedGatewayPath(cfg)
	if err != nil {
		fmt.Printf("❌ path ping requires Gateway PathLink credentials: %v\n", err)
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
	client := pathd.NewIdleClient(socks, endpoint.Listen, endpoint.Token, time.Duration(endpoint.IdleSeconds)*time.Second)
	defer client.Close()
	started := time.Now()
	probe, err := client.ProbeTTL(ip, pathPingTTL)
	if err != nil {
		fmt.Printf("❌ %s through %s: %v\n", ip, relay, err)
		return
	}
	if !probe.Echo {
		fmt.Printf("⚠️ %s through %s\nPathLink end-to-end: %s\nRemote diagnostic: %v\n", ip, relay, time.Since(started).Round(time.Millisecond), probe.Error())
		return
	}
	fmt.Printf("✅ %s through %s\nPathLink end-to-end: %s\nRemote ICMP RTT: %s\n", ip, relay, time.Since(started).Round(time.Millisecond), probe.RTT.Round(time.Millisecond))
}}

var pathTraceCmd = &cobra.Command{Use: "trace <hostname-or-ip>", Short: "Trace remote ICMP hops through the selected relay", Args: cobra.ExactArgs(1), Run: func(cmd *cobra.Command, args []string) {
	if os.Geteuid() != 0 {
		fmt.Println("❌ path trace requires root on the Gateway.")
		return
	}
	if pathTraceHops < 1 || pathTraceHops > 255 {
		fmt.Println("❌ --max-hops must be between 1 and 255.")
		return
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	endpoint, relay, err := selectedGatewayPath(cfg)
	if err != nil {
		fmt.Printf("❌ path trace requires Gateway PathLink credentials: %v\n", err)
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
	client := pathd.NewIdleClient(socks, endpoint.Listen, endpoint.Token, time.Duration(endpoint.IdleSeconds)*time.Second)
	defer client.Close()
	fmt.Printf("Path trace to %s through %s (max %d hops)\n", ip, relay, pathTraceHops)
	for ttl := 1; ttl <= pathTraceHops; ttl++ {
		probe, err := client.ProbeTTL(ip, ttl)
		if err != nil {
			fmt.Printf("%2d  *  %v\n", ttl, err)
			continue
		}
		responder := "unknown"
		if probe.Responder != nil {
			responder = probe.Responder.String()
		}
		if probe.Echo {
			fmt.Printf("%2d  %-39s  %s  echo reply\n", ttl, responder, probe.RTT.Round(time.Millisecond))
			return
		}
		fmt.Printf("%2d  %-39s  %s  %s\n", ttl, responder, probe.RTT.Round(time.Millisecond), pathDiagnosticLabel(probe))
	}
	fmt.Printf("Trace stopped after %d hops without an echo reply.\n", pathTraceHops)
}}

func pathDiagnosticLabel(probe pathd.ProbeResult) string {
	if probe.ICMPType == 11 && probe.ICMPCode == 0 {
		return "TTL exceeded"
	}
	if probe.ICMPType == 3 && probe.ICMPCode == 0 {
		return "hop limit exceeded"
	}
	return probe.Error().Error()
}

var pathMTUCmd = &cobra.Command{Use: "mtu <hostname-or-ip>", Short: "Actively discover path MTU through the selected relay", Args: cobra.ExactArgs(1), Run: func(cmd *cobra.Command, args []string) {
	if os.Geteuid() != 0 {
		fmt.Println("❌ path mtu requires root on the Gateway.")
		return
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	endpoint, relay, err := selectedGatewayPath(cfg)
	if err != nil {
		fmt.Printf("❌ path mtu requires Gateway PathLink credentials: %v\n", err)
		return
	}
	ip, err := resolvePublicTarget(args[0])
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	minimum := pathMTUMin
	if minimum == 0 {
		minimum = 1280
		if ip.To4() != nil {
			minimum = 576
		}
	}
	if pathMTUMax < minimum || minimum < 28 || pathMTUMax > 65535 {
		fmt.Println("❌ invalid --min/--max MTU range.")
		return
	}
	socks, err := activePathdSOCKSAddress()
	if err != nil {
		fmt.Println("❌", err)
		return
	}
	client := pathd.NewIdleClient(socks, endpoint.Listen, endpoint.Token, time.Duration(endpoint.IdleSeconds)*time.Second)
	defer client.Close()
	ipHeader := 40
	if ip.To4() != nil {
		ipHeader = 20
	}
	const icmpHeader = 8
	if minimum < ipHeader+icmpHeader {
		minimum = ipHeader + icmpHeader
	}
	fmt.Printf("Active PMTU to %s through %s (%d–%d bytes)\n", ip, relay, minimum, pathMTUMax)
	low, high, best := minimum, pathMTUMax, 0
	for low <= high {
		candidate := low + (high-low)/2
		probe, probeErr := client.ProbeWithOptions(ip, pathd.ProbeOptions{TTL: 64, PayloadSize: candidate - ipHeader - icmpHeader, DontFragment: ip.To4() != nil})
		if probeErr != nil {
			if strings.Contains(strings.ToLower(probeErr.Error()), "message too long") {
				fmt.Printf("  %d bytes: too large\n", candidate)
				high = candidate - 1
				continue
			}
			fmt.Printf("❌ probe at %d bytes failed: %v\n", candidate, probeErr)
			return
		}
		if probe.Echo {
			fmt.Printf("  %d bytes: reply (%s)\n", candidate, probe.RTT.Round(time.Millisecond))
			best = candidate
			low = candidate + 1
			continue
		}
		if probe.IsPacketTooBig(ip) {
			fmt.Printf("  %d bytes: packet too big%s\n", candidate, pathReportedMTU(probe))
			if probe.MTU > 0 && probe.MTU < candidate {
				high = probe.MTU
			} else {
				high = candidate - 1
			}
			continue
		}
		fmt.Printf("❌ probe at %d bytes returned %s\n", candidate, pathDiagnosticLabel(probe))
		return
	}
	if best == 0 {
		fmt.Printf("❌ no successful probe in %d–%d bytes.\n", minimum, pathMTUMax)
		return
	}
	probeKind := map[bool]string{true: "IPv4 DF", false: "IPv6"}[ip.To4() != nil]
	if best == pathMTUMax {
		fmt.Printf("✅ Path MTU: at least %d bytes (no limit found in the requested range; active %s probe)\n", best, probeKind)
		return
	}
	fmt.Printf("✅ Path MTU: %d bytes (active %s probe)\n", best, probeKind)
}}

func pathReportedMTU(probe pathd.ProbeResult) string {
	if probe.MTU > 0 {
		return fmt.Sprintf(" (reported MTU %d)", probe.MTU)
	}
	return ""
}

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
	pathSetCmd.Flags().StringVarP(&pathRelay, "relay", "r", "", "relay to bind PathLink credentials to (Gateway only)")
	pathSetCmd.Flags().StringVarP(&pathListen, "listen", "l", "", "numeric loopback Pathd listen address")
	pathSetCmd.Flags().StringVarP(&pathToken, "token", "t", "", "shared PathLink token")
	pathSetCmd.Flags().IntVar(&pathIdle, "idle", 20, "Pathd connection idle timeout in seconds")
	pathSetCmd.Flags().BoolVar(&pathGenerate, "generate-token", false, "generate a new Server Pathd token")
	pathSetCmd.RegisterFlagCompletionFunc("relay", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	})

	pathUnsetCmd.Flags().StringVarP(&pathRelay, "relay", "r", "", "relay whose PathLink credentials to remove (Gateway only)")
	pathUnsetCmd.RegisterFlagCompletionFunc("relay", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	})

	noFileComp := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	pathPingCmd.Flags().IntVar(&pathPingTTL, "ttl", 64, "outgoing ICMP TTL/hop limit (1-255)")
	pathPingCmd.ValidArgsFunction = noFileComp
	pathTraceCmd.Flags().IntVarP(&pathTraceHops, "max-hops", "m", 16, "maximum TTL/hop limit to probe (1-255)")
	pathTraceCmd.ValidArgsFunction = noFileComp
	pathMTUCmd.Flags().IntVar(&pathMTUMin, "min", 0, "smallest IP packet MTU to probe (default: IPv4 576, IPv6 1280)")
	pathMTUCmd.Flags().IntVar(&pathMTUMax, "max", 2000, "largest IP packet MTU to probe")
	pathMTUCmd.ValidArgsFunction = noFileComp

	pathCmd.AddCommand(pathSetCmd, pathUnsetCmd, pathStatusCmd, pathPingCmd, pathTraceCmd, pathMTUCmd)
	rootCmd.AddCommand(pathCmd)
}
