package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/pathd"
	"xray-proxya/internal/service"
	"xray-proxya/internal/ui"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

const pathdUnit = "xray-proxya-pathd"

var (
	pathListen       string
	pathToken        string
	pathIdle         int
	pathRelay        string
	pathGenerate     bool
	pathPingTTL      int
	pathPingCount    int
	pathPingInterval time.Duration
	pathPingSize     int
	pathPingTimeout  time.Duration
	pathTraceHops    int
	pathTraceTimeout time.Duration
	pathMTUMin       int
	pathMTUMax       int
	pathMTUTimeout   time.Duration
	pathListJSON     bool
	pathStatusJSON   bool
	pathPingJSON     bool
	pathTraceJSON    bool
	pathMTUJSON      bool
)

type PathListItemJSON struct {
	Alias           string `json:"alias"`
	PathLink        string `json:"pathlink"`
	Listen          string `json:"listen,omitempty"`
	IdleSeconds     int    `json:"idle_seconds,omitempty"`
	TokenConfigured bool   `json:"token_configured"`
	IsActiveRelay   bool   `json:"is_active_relay"`
	Pending         bool   `json:"pending"`
}

type PathStatusJSON struct {
	Role            string `json:"role"`
	ServiceState    string `json:"service_state,omitempty"`
	ServiceEnabled  string `json:"service_enabled,omitempty"`
	Listen          string `json:"listen,omitempty"`
	Relay           string `json:"relay,omitempty"`
	TunInterface    string `json:"tun_interface,omitempty"`
	SocksInbound    string `json:"socks_inbound,omitempty"`
	IsActiveRelay   bool   `json:"is_active_relay,omitempty"`
	TokenConfigured bool   `json:"token_configured,omitempty"`
	IdleSeconds     int    `json:"idle_seconds,omitempty"`
	Connected       bool   `json:"connected"`
	InFlight        int    `json:"in_flight"`
	LastActivity    string `json:"last_activity,omitempty"`
	LastRTTMs       int64  `json:"last_rtt_ms,omitempty"`
	LastError       string `json:"last_error,omitempty"`
}

type PathPingResultJSON struct {
	Seq        int    `json:"seq"`
	Success    bool   `json:"success"`
	Echo       bool   `json:"echo"`
	RTTMs      int64  `json:"rtt_ms"`
	DurationMs int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

type PathPingSummaryJSON struct {
	Transmitted int     `json:"transmitted"`
	Received    int     `json:"received"`
	LossPercent float64 `json:"loss_percent"`
	MinRTTMs    float64 `json:"min_rtt_ms,omitempty"`
	AvgRTTMs    float64 `json:"avg_rtt_ms,omitempty"`
	MaxRTTMs    float64 `json:"max_rtt_ms,omitempty"`
	MdevRTTMs   float64 `json:"mdev_rtt_ms,omitempty"`
}

type PathPingJSON struct {
	TargetIP   string               `json:"target_ip"`
	Relay      string               `json:"relay"`
	Success    bool                 `json:"success"`
	Echo       bool                 `json:"echo"`
	RTTMs      int64                `json:"rtt_ms"`
	DurationMs int64                `json:"duration_ms"`
	Error      string               `json:"error,omitempty"`
	Probes     []PathPingResultJSON `json:"probes,omitempty"`
	Summary    *PathPingSummaryJSON `json:"summary,omitempty"`
}

type PathTraceHopJSON struct {
	TTL       int    `json:"ttl"`
	Responder string `json:"responder"`
	RTTMs     int64  `json:"rtt_ms"`
	Echo      bool   `json:"echo"`
	Status    string `json:"status"`
}

type PathTraceJSON struct {
	TargetIP string             `json:"target_ip"`
	Relay    string             `json:"relay"`
	MaxHops  int                `json:"max_hops"`
	Reached  bool               `json:"reached"`
	Hops     []PathTraceHopJSON `json:"hops"`
}

type PathMTUJSON struct {
	TargetIP      string `json:"target_ip"`
	Relay         string `json:"relay"`
	MinMTU        int    `json:"min_mtu"`
	MaxMTU        int    `json:"max_mtu"`
	DiscoveredMTU int    `json:"discovered_mtu"`
	ProbeKind     string `json:"probe_kind"`
	Success       bool   `json:"success"`
}

func pathdConfigPath() string { return filepath.Join(config.GetConfigDir(), "pathd.json") }
func pathdBinaryPath() string {
	return filepath.Join(config.GetHomeDir(), ".local", "share", "xray-proxya", "bin", "pathd")
}
func pathdUnitPath() string { return "/etc/systemd/system/" + pathdUnit + ".service" }

func buildPathdSystemdServiceContent(binaryPath, configPath string) string {
	return service.BuildPathdServiceContent(binaryPath, configPath)
}

func writePathdConfig(cfg *config.UserConfig) error {
	return service.WritePathdConfig(cfg)
}

var pathCmd = &cobra.Command{Use: "path", Short: "Manage the root-only loopback PathLink ICMP agent", PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
	if err := pathRootOnlyError(os.Geteuid(), os.Getenv("SUDO_USER"), os.Getenv("SUDO_UID"), os.Getenv("SUDO_COMMAND")); err != nil {
		return err
	}
	if _, err := os.Stat(config.GetConfigPath()); err != nil {
		return fmt.Errorf("initialize xray-proxya first")
	}
	return nil
}}

// PathLink has one root-owned configuration and service lifecycle. Rejecting
// single-command sudo prevents a caller from accidentally mixing an unprivileged shell's
// configuration expectations with root's system service.
func pathRootOnlyError(euid int, sudoUser, sudoUID, sudoCommand string) error {
	return utils.RequireRootShellFor(euid, sudoUser, sudoUID, sudoCommand, "path")
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
		generated = utils.GenerateAlphanumericToken(16)
		endpoint.Token = generated
	}
	if endpoint.Listen == "" {
		endpoint.Listen = pathd.DefaultListenAddress
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

func resolvePathRelay(cmd *cobra.Command, args []string) (string, error) {
	relay := pathRelay
	if len(args) > 0 {
		pos := strings.TrimSpace(args[0])
		if cmd.Flags().Changed("relay") && pathRelay != "" && pathRelay != pos {
			return "", fmt.Errorf("conflicting relay specified: '%s' and --relay '%s'", pos, pathRelay)
		}
		relay = pos
	}
	return relay, nil
}

var pathListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List PathLink credential bindings for all relays",
	Args:    cobra.NoArgs,
	RunE:    runPathList,
}

func runPathList(cmd *cobra.Command, args []string) error {
	activeCfg, _ := config.LoadConfig()
	stagingCfg, err := config.LoadConfigEx(true)
	if err != nil {
		if activeCfg != nil {
			stagingCfg = activeCfg
		} else {
			return fmt.Errorf("❌ %w", err)
		}
	}
	if stagingCfg.Role == config.RoleServer {
		if pathListJSON {
			data, err := json.MarshalIndent(map[string]interface{}{
				"role":             "server",
				"listen":           stagingCfg.Path.Listen,
				"idle_seconds":     stagingCfg.Path.IdleSeconds,
				"token_configured": stagingCfg.Path.Token != "",
			}, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		}
		fmt.Println("Server role uses local Pathd responder daemon.")
		fmt.Println("Use 'xray-proxya path status' to view service state.")
		return nil
	}
	if stagingCfg.Role != config.RoleGateway {
		return fmt.Errorf("❌ Unsupported role %q", stagingCfg.Role)
	}

	if len(stagingCfg.CustomOutbounds) == 0 {
		if pathListJSON {
			fmt.Println("[]")
			return nil
		}
		fmt.Println("No custom relays configured.")
		return nil
	}

	var activeByAlias map[string]*config.PathConfig
	if activeCfg != nil {
		activeByAlias = make(map[string]*config.PathConfig, len(activeCfg.CustomOutbounds))
		for i := range activeCfg.CustomOutbounds {
			activeByAlias[activeCfg.CustomOutbounds[i].Alias] = activeCfg.CustomOutbounds[i].Path
		}
	}

	hasPending := false
	items := make([]PathListItemJSON, 0, len(stagingCfg.CustomOutbounds))
	for _, co := range stagingCfg.CustomOutbounds {
		activePath, hadInActive := activeByAlias[co.Alias]
		pending := false
		if activeCfg != nil {
			if !hadInActive {
				pending = true
			} else if !reflect.DeepEqual(activePath, co.Path) {
				pending = true
			}
		}
		if pending {
			hasPending = true
		}

		state := "DISABLED"
		listenAddr := ""
		tokenConfigured := false
		idleSec := 0

		if co.Path != nil && co.Path.Token != "" {
			tokenConfigured = true
			listenAddr = co.Path.Listen
			if listenAddr == "" {
				listenAddr = pathd.DefaultListenAddress
			}
			idleSec = co.Path.IdleSeconds
			if idleSec <= 0 {
				idleSec = 20
			}

			if pending {
				state = "PENDING"
			} else if co.Enabled {
				state = "ENABLED"
			} else {
				state = "DISABLED"
			}
		} else if pending && activePath != nil && activePath.Token != "" {
			state = "PENDING"
		}

		isActive := (co.Alias == stagingCfg.Gateway.RelayAlias)
		items = append(items, PathListItemJSON{
			Alias:           co.Alias,
			PathLink:        state,
			Listen:          listenAddr,
			IdleSeconds:     idleSec,
			TokenConfigured: tokenConfigured,
			IsActiveRelay:   isActive,
			Pending:         pending,
		})
	}

	if pathListJSON {
		data, err := json.MarshalIndent(items, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	colorEnabled := ui.IsColorEnabled()
	t := ui.NewTable("ALIAS", "PATHLINK", "LISTEN", "IDLE", "TOKEN", "ACTIVE")
	t.SetAlignment(3, ui.AlignRight)
	t.SetAlignment(4, ui.AlignCenter)

	for _, item := range items {
		activeMarker := ui.Gray("-", colorEnabled)
		if item.IsActiveRelay {
			activeMarker = ui.Green("*active", colorEnabled)
		}
		listen := item.Listen
		if listen == "" {
			listen = ui.Gray("-", colorEnabled)
		}
		idle := ui.Gray("-", colorEnabled)
		if item.IdleSeconds > 0 {
			idle = fmt.Sprintf("%ds", item.IdleSeconds)
		}
		token := ui.Gray("NOT SET", colorEnabled)
		if item.TokenConfigured {
			token = ui.Green("SET", colorEnabled)
		}
		t.AddRow(item.Alias, item.PathLink, listen, idle, token, activeMarker)
	}

	fmt.Println()
	fmt.Print(t.Render())
	if hasPending {
		fmt.Println("\n⚠️  Pending changes in STAGING. Run 'xray-proxya apply' to commit.")
	} else {
		fmt.Println()
	}
	return nil
}

var pathSetCmd = &cobra.Command{
	Use:               "set [relay]",
	Short:             "Configure Pathd or a relay PathLink credential in STAGING",
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		relay, err := resolvePathRelay(cmd, args)
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		switch cfg.Role {
		case config.RoleServer:
			if err := validatePathRole(cfg.Role, relay); err != nil {
				return fmt.Errorf("❌ %w", err)
			}
			generated, err := setPathEndpoint(cmd, &cfg.Path, false)
			if err != nil {
				return fmt.Errorf("❌ %w", err)
			}
			if err := cfg.SaveEx(true); err != nil {
				return fmt.Errorf("❌ %w", err)
			}
			fmt.Printf("✅ Server Pathd configured in STAGING (%s). Run 'apply', then manage it with 'service enable --now xray-proxya-pathd'.\n", cfg.Path.Listen)
			if generated != "" {
				fmt.Printf("🔐 Generated token (save it now): %s\n", generated)
			}
			return nil
		case config.RoleGateway:
			if err := validatePathRole(cfg.Role, relay); err != nil {
				return fmt.Errorf("❌ %w", err)
			}
			if pathGenerate {
				return fmt.Errorf("❌ Gateway credentials must match the remote Pathd; pass --token instead of --generate-token.")
			}
			for i := range cfg.CustomOutbounds {
				outbound := &cfg.CustomOutbounds[i]
				if outbound.Alias != relay {
					continue
				}
				if outbound.Path == nil {
					outbound.Path = &config.PathConfig{}
				}
				if _, err := setPathEndpoint(cmd, outbound.Path, outbound.Path.Token == ""); err != nil {
					return fmt.Errorf("❌ %w", err)
				}
				if err := cfg.SaveEx(true); err != nil {
					return fmt.Errorf("❌ %w", err)
				}
				fmt.Printf("✅ PathLink credentials for relay '%s' saved in STAGING. Run 'apply'.\n", relay)
				return nil
			}
			return fmt.Errorf("❌ Relay '%s' not found.", relay)
		default:
			return fmt.Errorf("❌ Unsupported role %q.", cfg.Role)
		}
	},
}

var pathUnsetCmd = &cobra.Command{
	Use:               "unset [relay]",
	Short:             "Remove a relay PathLink credential from STAGING",
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		relay, err := resolvePathRelay(cmd, args)
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		if cfg.Role == config.RoleServer {
			if err := validatePathRole(cfg.Role, relay); err != nil {
				return fmt.Errorf("❌ %w", err)
			}
			if service.IsUnitActive(service.PathdUnit) {
				return fmt.Errorf("❌ Stop or disable xray-proxya-pathd with the service command before removing its configuration.")
			}
			cfg.Path = config.PathConfig{}
			if err := cfg.SaveEx(true); err != nil {
				return fmt.Errorf("❌ %w", err)
			}
			fmt.Println("✅ Server Pathd configuration removed from STAGING. Run 'apply'.")
			return nil
		} else if cfg.Role == config.RoleGateway {
			if err := validatePathRole(cfg.Role, relay); err != nil {
				return fmt.Errorf("❌ %w", err)
			}
			found := false
			for i := range cfg.CustomOutbounds {
				if cfg.CustomOutbounds[i].Alias == relay {
					cfg.CustomOutbounds[i].Path = nil
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("❌ Relay '%s' not found.", relay)
			}
			if err := cfg.SaveEx(true); err != nil {
				return fmt.Errorf("❌ %w", err)
			}
			fmt.Printf("✅ PathLink credentials for relay '%s' removed from STAGING. Run 'apply'.\n", relay)
			return nil
		}
		return fmt.Errorf("❌ Unsupported role %q.", cfg.Role)
	},
}
var pathStatusCmd = &cobra.Command{
	Use:               "status [relay]",
	Short:             "Show pathd service state or relay PathLink parameters",
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeRelayAliasesArg,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfig()
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		targetRelay, err := resolvePathRelay(cmd, args)
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		if cfg.Role == config.RoleServer {
			if targetRelay != "" {
				return fmt.Errorf("❌ Server Pathd is local; --relay is only valid on a Gateway")
			}
			serviceState := "unknown"
			serviceEnabled := "unknown"
			if os.Geteuid() == 0 {
				if service.IsUnitActive(service.PathdUnit) {
					serviceState = "active"
				} else {
					serviceState = "inactive"
				}
				if service.IsUnitEnabled(service.PathdUnit) {
					serviceEnabled = "enabled"
				} else {
					serviceEnabled = "disabled"
				}
			}
			var statusJSON PathStatusJSON
			statusJSON.Role = string(cfg.Role)
			statusJSON.ServiceState = serviceState
			statusJSON.ServiceEnabled = serviceEnabled
			statusJSON.Listen = cfg.Path.Listen
			statusJSON.IdleSeconds = cfg.Path.IdleSeconds
			statusJSON.TokenConfigured = cfg.Path.Token != ""

			if pathStatusJSON {
				data, err := json.MarshalIndent(statusJSON, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(data))
				return nil
			}
			fmt.Printf("Role: %s\n", cfg.Role)
			if cfg.Path.Token == "" {
				fmt.Printf("Agent: %s (%s); configuration: missing\n", serviceState, serviceEnabled)
				return nil
			}
			fmt.Printf("Agent: %s (%s), %s\n", serviceState, serviceEnabled, cfg.Path.Listen)
			return nil
		}
		if cfg.Role != config.RoleGateway {
			var statusJSON PathStatusJSON
			statusJSON.Role = string(cfg.Role)
			if pathStatusJSON {
				data, _ := json.MarshalIndent(statusJSON, "", "  ")
				fmt.Println(string(data))
				return nil
			}
			fmt.Printf("Role: %s\n", cfg.Role)
			return nil
		}

		// Gateway role: specific relay requested
		if targetRelay != "" {
			var targetCO *config.CustomOutbound
			for i := range cfg.CustomOutbounds {
				if cfg.CustomOutbounds[i].Alias == targetRelay {
					targetCO = &cfg.CustomOutbounds[i]
					break
				}
			}
			if targetCO == nil {
				return fmt.Errorf("❌ Relay '%s' not found.", targetRelay)
			}

			isActive := (targetCO.Alias == cfg.Gateway.RelayAlias)
			tokenSet := targetCO.Path != nil && targetCO.Path.Token != ""
			listenAddr := pathd.DefaultListenAddress
			idleSec := 20
			if targetCO.Path != nil {
				if targetCO.Path.Listen != "" {
					listenAddr = targetCO.Path.Listen
				}
				if targetCO.Path.IdleSeconds > 0 {
					idleSec = targetCO.Path.IdleSeconds
				}
			}

			if pathStatusJSON {
				out := PathStatusJSON{
					Role:            string(cfg.Role),
					Relay:           targetCO.Alias,
					Listen:          listenAddr,
					IdleSeconds:     idleSec,
					TokenConfigured: tokenSet,
					IsActiveRelay:   isActive,
				}
				if isActive {
					state, runtimeErr := readPathRuntime()
					if runtimeErr == nil {
						out.Connected = state.Connected
						out.InFlight = state.InFlight
						if !state.LastActivity.IsZero() {
							out.LastActivity = time.Since(state.LastActivity).Round(time.Second).String()
						}
						out.LastRTTMs = state.LastRTTMs
						out.LastError = state.LastError
					}
				}
				data, _ := json.MarshalIndent(out, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			fmt.Printf("Role: %s\n", cfg.Role)
			standby := "standby"
			if isActive {
				standby = "active"
			}
			fmt.Printf("Target Relay: %s (%s)\n", targetCO.Alias, standby)
			if !tokenSet {
				fmt.Println("PathLink Status: not configured")
				fmt.Printf("ℹ️  Configure PathLink credentials with: xray-proxya path set %s --token <token>\n", targetCO.Alias)
				return nil
			}
			fmt.Printf("PathLink Status: configured (%s, idle %ds)\n", listenAddr, idleSec)
			fmt.Println("Token: configured [SET]")
			if !isActive {
				fmt.Printf("\nℹ️  Relay '%s' is currently standby. To route gateway ICMP via this node:\n", targetCO.Alias)
				fmt.Printf("   xray-proxya gateway set --relay %s && xray-proxya apply\n", targetCO.Alias)
			} else {
				state, runtimeErr := readPathRuntime()
				if runtimeErr == nil {
					connection := "idle/disconnected"
					if state.Connected {
						connection = "connected"
					}
					fmt.Printf("\nPathLink connection: %s; in-flight: %d\n", connection, state.InFlight)
					if !state.LastActivity.IsZero() {
						fmt.Printf("Last activity: %s ago\n", time.Since(state.LastActivity).Round(time.Second))
					}
					if state.LastRTTMs > 0 {
						fmt.Printf("Last remote ICMP RTT: %dms\n", state.LastRTTMs)
					}
					if state.LastError != "" {
						fmt.Printf("Last error: %s\n", state.LastError)
					}
				}
			}
			return nil
		}

		// Gateway role: global/active status
		var statusJSON PathStatusJSON
		statusJSON.Role = string(cfg.Role)
		statusJSON.Relay = cfg.Gateway.RelayAlias
		endpoint, relay, pathErr := selectedGatewayPath(cfg)
		if pathErr == nil && endpoint != nil {
			statusJSON.Listen = endpoint.Listen
			statusJSON.IdleSeconds = endpoint.IdleSeconds
			statusJSON.TokenConfigured = true
			statusJSON.IsActiveRelay = true
		}

		tunStatus := "not active"
		if iface, err := net.InterfaceByName("path-tun"); err == nil {
			tunStatus = fmt.Sprintf("UP (path-tun, MTU: %d)", iface.MTU)
		} else if config.GatewayTunDisabled() {
			tunStatus = "disabled (gateway-tun-disabled)"
		}
		statusJSON.TunInterface = tunStatus

		socksAddr, _ := activePathdSOCKSAddress()
		statusJSON.SocksInbound = socksAddr

		state, runtimeErr := readPathRuntime()
		if runtimeErr == nil {
			statusJSON.Connected = state.Connected
			statusJSON.InFlight = state.InFlight
			if !state.LastActivity.IsZero() {
				statusJSON.LastActivity = time.Since(state.LastActivity).Round(time.Second).String()
			}
			statusJSON.LastRTTMs = state.LastRTTMs
			statusJSON.LastError = state.LastError
		}

		if pathStatusJSON {
			data, err := json.MarshalIndent(statusJSON, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("Role: %s\n", cfg.Role)
		fmt.Printf("Relay: %s\n", cfg.Gateway.RelayAlias)
		if pathErr != nil {
			fmt.Printf("PathLink credentials: unavailable (%v)\n", pathErr)
			return nil
		}
		fmt.Printf("PathLink credentials: configured for %s (%s, idle %ds)\n", relay, endpoint.Listen, endpoint.IdleSeconds)
		fmt.Printf("Path-TUN Interface: %s\n", tunStatus)
		if socksAddr != "" {
			fmt.Printf("Inbound SOCKS Port: %s (pathd-socks)\n", socksAddr)
		}

		if runtimeErr == nil {
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
			return nil
		}
		fmt.Println("PathLink runtime: unavailable (run gateway up with PathLink credentials configured)")
		return nil
	},
}

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
			endpoint.Listen = pathd.DefaultListenAddress
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

var pathPingCmd = &cobra.Command{
	Use:   "ping <hostname-or-ip>",
	Short: "Send ICMP echo requests through the selected relay",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfig()
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		if cfg.Role == config.RoleServer {
			return fmt.Errorf("❌ Error: ICMP probing commands (ping, trace, mtu) are only supported on Gateway nodes. Server nodes run the 'xray-proxya-pathd' responder daemon.")
		}
		if pathPingCount < 1 {
			return fmt.Errorf("❌ --count must be at least 1")
		}
		if pathPingTTL < 1 || pathPingTTL > 255 {
			return fmt.Errorf("❌ --ttl must be between 1 and 255")
		}
		if pathPingSize < 8 || pathPingSize > 1024 {
			return fmt.Errorf("❌ --size must be between 8 and 1024 bytes")
		}
		if pathPingTimeout < 100*time.Millisecond || pathPingTimeout > 15*time.Second {
			return fmt.Errorf("❌ --timeout must be between 100ms and 15s")
		}
		if os.Geteuid() != 0 {
			return fmt.Errorf("❌ path ping requires root on the Gateway.")
		}

		endpoint, relay, err := selectedGatewayPath(cfg)
		if err != nil {
			return fmt.Errorf("❌ path ping requires Gateway PathLink credentials: %w", err)
		}
		ip, err := resolvePublicTarget(args[0])
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		socks, err := activePathdSOCKSAddress()
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		client := pathd.NewIdleClient(socks, endpoint.Listen, endpoint.Token, time.Duration(endpoint.IdleSeconds)*time.Second)
		defer client.Close()

		timeoutMS := int(pathPingTimeout.Milliseconds())
		probeOpts := pathd.ProbeOptions{
			TTL:         pathPingTTL,
			PayloadSize: pathPingSize,
			TimeoutMS:   timeoutMS,
		}

		if pathPingCount > 1 && !pathPingJSON {
			fmt.Printf("PING %s (%s) via relay %s: %d data bytes\n", args[0], ip, relay, pathPingSize)
		}

		var (
			probes    []PathPingResultJSON
			rttFloats []float64
			received  int
			lastProbe pathd.ProbeResult
			lastErr   error
			lastDur   time.Duration
		)

		for seq := 1; seq <= pathPingCount; seq++ {
			if seq > 1 && pathPingInterval > 0 {
				time.Sleep(pathPingInterval)
			}
			started := time.Now()
			probe, probeErr := client.ProbeWithOptions(ip, probeOpts)
			duration := time.Since(started)
			lastProbe = probe
			lastErr = probeErr
			lastDur = duration

			res := PathPingResultJSON{
				Seq:        seq,
				DurationMs: duration.Milliseconds(),
			}

			if probeErr != nil {
				res.Success = false
				res.Error = probeErr.Error()
				if pathPingCount > 1 && !pathPingJSON {
					fmt.Printf("Request timeout for icmp_seq %d: %v\n", seq, probeErr)
				}
			} else if !probe.Echo {
				res.Success = false
				if probe.Error() != nil {
					res.Error = probe.Error().Error()
				} else {
					res.Error = "no echo reply received"
				}
				if pathPingCount > 1 && !pathPingJSON {
					fmt.Printf("From %s icmp_seq=%d %s\n", ip, seq, res.Error)
				}
			} else {
				res.Success = true
				res.Echo = true
				res.RTTMs = probe.RTT.Milliseconds()
				received++
				rttMs := float64(probe.RTT.Nanoseconds()) / 1e6
				rttFloats = append(rttFloats, rttMs)
				if pathPingCount > 1 && !pathPingJSON {
					fmt.Printf("%d bytes from %s: icmp_seq=%d time=%.1f ms (PathLink: %.1f ms)\n",
						pathPingSize, ip, seq, rttMs, float64(duration.Nanoseconds())/1e6)
				}
			}
			probes = append(probes, res)
		}

		lossPercent := float64(pathPingCount-received) / float64(pathPingCount) * 100.0
		var summary *PathPingSummaryJSON
		if pathPingCount > 1 || len(rttFloats) > 0 {
			summary = &PathPingSummaryJSON{
				Transmitted: pathPingCount,
				Received:    received,
				LossPercent: lossPercent,
			}
			if len(rttFloats) > 0 {
				minRTT := rttFloats[0]
				maxRTT := rttFloats[0]
				sum := 0.0
				for _, r := range rttFloats {
					if r < minRTT {
						minRTT = r
					}
					if r > maxRTT {
						maxRTT = r
					}
					sum += r
				}
				avgRTT := sum / float64(len(rttFloats))
				var sumDiff float64
				for _, r := range rttFloats {
					sumDiff += math.Abs(r - avgRTT)
				}
				mdevRTT := sumDiff / float64(len(rttFloats))
				summary.MinRTTMs = math.Round(minRTT*100) / 100
				summary.AvgRTTMs = math.Round(avgRTT*100) / 100
				summary.MaxRTTMs = math.Round(maxRTT*100) / 100
				summary.MdevRTTMs = math.Round(mdevRTT*100) / 100
			}
		}

		if pathPingJSON {
			out := PathPingJSON{
				TargetIP:   ip.String(),
				Relay:      relay,
				DurationMs: lastDur.Milliseconds(),
			}
			if pathPingCount == 1 {
				out.Success = probes[0].Success
				out.Echo = probes[0].Echo
				out.RTTMs = probes[0].RTTMs
				out.Error = probes[0].Error
			} else {
				out.Success = received > 0
				out.Echo = received > 0
				out.Probes = probes
				out.Summary = summary
			}
			data, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(data))
			if pathPingCount == 1 && !out.Success {
				if lastErr != nil {
					return fmt.Errorf("probe failed: %w", lastErr)
				}
				return fmt.Errorf("probe did not receive echo reply: %s", out.Error)
			}
			if pathPingCount > 1 && received == 0 {
				return fmt.Errorf("all %d probes failed (100%% packet loss)", pathPingCount)
			}
			return nil
		}

		// Text mode
		if pathPingCount == 1 {
			if lastErr != nil {
				return fmt.Errorf("❌ %s through %s: %w", ip, relay, lastErr)
			}
			if !lastProbe.Echo {
				fmt.Printf("⚠️ %s through %s\nPathLink end-to-end: %s\nRemote diagnostic: %v\n", ip, relay, lastDur.Round(time.Millisecond), lastProbe.Error())
				return fmt.Errorf("probe did not receive echo reply: %v", lastProbe.Error())
			}
			fmt.Printf("✅ %s through %s\nPathLink end-to-end: %s\nRemote ICMP RTT: %s\n", ip, relay, lastDur.Round(time.Millisecond), lastProbe.RTT.Round(time.Millisecond))
			return nil
		}

		// Count > 1: Print summary statistics
		fmt.Printf("\n--- %s ping statistics through %s ---\n", ip, relay)
		fmt.Printf("%d packets transmitted, %d received, %.1f%% packet loss\n", pathPingCount, received, lossPercent)
		if len(rttFloats) > 0 && summary != nil {
			fmt.Printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", summary.MinRTTMs, summary.AvgRTTMs, summary.MaxRTTMs, summary.MdevRTTMs)
		}
		if received == 0 {
			return fmt.Errorf("all %d probes failed (100%% packet loss)", pathPingCount)
		}
		return nil
	},
}

var pathTraceCmd = &cobra.Command{Use: "trace <hostname-or-ip>", Short: "Trace remote ICMP hops through the selected relay", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("❌ %w", err)
	}
	if cfg.Role == config.RoleServer {
		return fmt.Errorf("❌ Error: ICMP probing commands (ping, trace, mtu) are only supported on Gateway nodes. Server nodes run the 'xray-proxya-pathd' responder daemon.")
	}
	if pathTraceHops < 1 || pathTraceHops > 255 {
		return fmt.Errorf("❌ --max-hops must be between 1 and 255.")
	}
	if pathTraceTimeout < 100*time.Millisecond || pathTraceTimeout > 15*time.Second {
		return fmt.Errorf("❌ --timeout must be between 100ms and 15s")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("❌ path trace requires root on the Gateway.")
	}
	endpoint, relay, err := selectedGatewayPath(cfg)
	if err != nil {
		return fmt.Errorf("❌ path trace requires Gateway PathLink credentials: %w", err)
	}
	ip, err := resolvePublicTarget(args[0])
	if err != nil {
		return fmt.Errorf("❌ %w", err)
	}
	socks, err := activePathdSOCKSAddress()
	if err != nil {
		return fmt.Errorf("❌ %w", err)
	}
	client := pathd.NewIdleClient(socks, endpoint.Listen, endpoint.Token, time.Duration(endpoint.IdleSeconds)*time.Second)
	defer client.Close()

	timeoutMS := int(pathTraceTimeout.Milliseconds())
	probeOpts := pathd.ProbeOptions{
		PayloadSize: 8,
		TimeoutMS:   timeoutMS,
	}

	if pathTraceJSON {
		traceJSON := PathTraceJSON{
			TargetIP: ip.String(),
			Relay:    relay,
			MaxHops:  pathTraceHops,
			Hops:     []PathTraceHopJSON{},
		}
		for ttl := 1; ttl <= pathTraceHops; ttl++ {
			probeOpts.TTL = ttl
			probe, probeErr := client.ProbeWithOptions(ip, probeOpts)
			hop := PathTraceHopJSON{
				TTL: ttl,
			}
			if probeErr != nil {
				if strings.Contains(strings.ToLower(probeErr.Error()), "timeout") || strings.Contains(strings.ToLower(probeErr.Error()), "timed out") {
					hop.Status = "request timed out"
				} else {
					hop.Status = probeErr.Error()
				}
				traceJSON.Hops = append(traceJSON.Hops, hop)
				continue
			}
			if probe.Responder != nil {
				hop.Responder = probe.Responder.String()
			}
			hop.Echo = probe.Echo
			hop.RTTMs = probe.RTT.Milliseconds()
			if probe.Echo {
				hop.Status = "echo reply"
				traceJSON.Reached = true
				traceJSON.Hops = append(traceJSON.Hops, hop)
				break
			}
			hop.Status = pathDiagnosticLabel(probe)
			traceJSON.Hops = append(traceJSON.Hops, hop)
		}
		data, _ := json.MarshalIndent(traceJSON, "", "  ")
		fmt.Println(string(data))
		if !traceJSON.Reached {
			return fmt.Errorf("trace stopped after %d hops without an echo reply", pathTraceHops)
		}
		return nil
	}

	fmt.Printf("Path trace to %s through %s (max %d hops)\n", ip, relay, pathTraceHops)
	for ttl := 1; ttl <= pathTraceHops; ttl++ {
		probeOpts.TTL = ttl
		probe, probeErr := client.ProbeWithOptions(ip, probeOpts)
		if probeErr != nil {
			if strings.Contains(strings.ToLower(probeErr.Error()), "timeout") || strings.Contains(strings.ToLower(probeErr.Error()), "timed out") {
				fmt.Printf("%2d  %-39s  *  request timed out\n", ttl, "*")
			} else {
				fmt.Printf("%2d  *  %v\n", ttl, probeErr)
			}
			continue
		}
		responder := "unknown"
		if probe.Responder != nil {
			responder = probe.Responder.String()
		}
		if probe.Echo {
			fmt.Printf("%2d  %-39s  %s  echo reply\n", ttl, responder, probe.RTT.Round(time.Millisecond))
			return nil
		}
		fmt.Printf("%2d  %-39s  %s  %s\n", ttl, responder, probe.RTT.Round(time.Millisecond), pathDiagnosticLabel(probe))
	}
	fmt.Printf("Trace stopped after %d hops without an echo reply.\n", pathTraceHops)
	return fmt.Errorf("trace stopped after %d hops without an echo reply", pathTraceHops)
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

var pathMTUCmd = &cobra.Command{Use: "mtu <hostname-or-ip>", Short: "Actively discover path MTU through the selected relay", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("❌ %w", err)
	}
	if cfg.Role == config.RoleServer {
		return fmt.Errorf("❌ Error: ICMP probing commands (ping, trace, mtu) are only supported on Gateway nodes. Server nodes run the 'xray-proxya-pathd' responder daemon.")
	}
	if pathMTUTimeout < 100*time.Millisecond || pathMTUTimeout > 15*time.Second {
		return fmt.Errorf("❌ --timeout must be between 100ms and 15s")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("❌ path mtu requires root on the Gateway.")
	}
	endpoint, relay, err := selectedGatewayPath(cfg)
	if err != nil {
		return fmt.Errorf("❌ path mtu requires Gateway PathLink credentials: %w", err)
	}
	ip, err := resolvePublicTarget(args[0])
	if err != nil {
		return fmt.Errorf("❌ %w", err)
	}
	minimum := pathMTUMin
	if minimum == 0 {
		minimum = 1280
		if ip.To4() != nil {
			minimum = 576
		}
	}
	if pathMTUMax < minimum || minimum < 28 || pathMTUMax > 65535 {
		return fmt.Errorf("❌ invalid --min/--max MTU range.")
	}
	socks, err := activePathdSOCKSAddress()
	if err != nil {
		return fmt.Errorf("❌ %w", err)
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
	probeKind := map[bool]string{true: "IPv4 DF", false: "IPv6"}[ip.To4() != nil]
	timeoutMS := int(pathMTUTimeout.Milliseconds())

	if !pathMTUJSON {
		fmt.Printf("Active PMTU to %s through %s (%d–%d bytes)\n", ip, relay, minimum, pathMTUMax)
	}
	low, high, best := minimum, pathMTUMax, 0
	for low <= high {
		candidate := low + (high-low)/2
		probe, probeErr := client.ProbeWithOptions(ip, pathd.ProbeOptions{
			TTL:          64,
			PayloadSize:  candidate - ipHeader - icmpHeader,
			DontFragment: ip.To4() != nil,
			TimeoutMS:    timeoutMS,
		})
		if probeErr != nil {
			if strings.Contains(strings.ToLower(probeErr.Error()), "message too long") {
				if !pathMTUJSON {
					fmt.Printf("  %d bytes: too large\n", candidate)
				}
				high = candidate - 1
				continue
			}
			if strings.Contains(strings.ToLower(probeErr.Error()), "timeout") || strings.Contains(strings.ToLower(probeErr.Error()), "timed out") {
				if !pathMTUJSON {
					fmt.Printf("  %d bytes: timeout (potential black hole, packet dropped)\n", candidate)
				}
				high = candidate - 1
				continue
			}
			if pathMTUJSON {
				out := PathMTUJSON{
					TargetIP:      ip.String(),
					Relay:         relay,
					MinMTU:        minimum,
					MaxMTU:        pathMTUMax,
					DiscoveredMTU: best,
					ProbeKind:     probeKind,
					Success:       false,
				}
				data, _ := json.MarshalIndent(out, "", "  ")
				fmt.Println(string(data))
			}
			return fmt.Errorf("❌ probe at %d bytes failed: %w", candidate, probeErr)
		}
		if probe.Echo {
			if !pathMTUJSON {
				fmt.Printf("  %d bytes: reply (%s)\n", candidate, probe.RTT.Round(time.Millisecond))
			}
			best = candidate
			low = candidate + 1
			continue
		}
		if probe.IsPacketTooBig(ip) {
			if !pathMTUJSON {
				fmt.Printf("  %d bytes: packet too big%s\n", candidate, pathReportedMTU(probe))
			}
			if probe.MTU > 0 && probe.MTU < candidate {
				high = probe.MTU
			} else {
				high = candidate - 1
			}
			continue
		}
		if pathMTUJSON {
			out := PathMTUJSON{
				TargetIP:      ip.String(),
				Relay:         relay,
				MinMTU:        minimum,
				MaxMTU:        pathMTUMax,
				DiscoveredMTU: best,
				ProbeKind:     probeKind,
				Success:       false,
			}
			data, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(data))
		}
		return fmt.Errorf("❌ probe at %d bytes returned %s", candidate, pathDiagnosticLabel(probe))
	}

	if best == 0 {
		if pathMTUJSON {
			out := PathMTUJSON{
				TargetIP:      ip.String(),
				Relay:         relay,
				MinMTU:        minimum,
				MaxMTU:        pathMTUMax,
				DiscoveredMTU: 0,
				ProbeKind:     probeKind,
				Success:       false,
			}
			data, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(data))
		}
		return fmt.Errorf("❌ no successful probe in %d–%d bytes", minimum, pathMTUMax)
	}

	if pathMTUJSON {
		out := PathMTUJSON{
			TargetIP:      ip.String(),
			Relay:         relay,
			MinMTU:        minimum,
			MaxMTU:        pathMTUMax,
			DiscoveredMTU: best,
			ProbeKind:     probeKind,
			Success:       true,
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	if best == pathMTUMax {
		fmt.Printf("✅ Path MTU: at least %d bytes (no limit found in the requested range; active %s probe)\n", best, probeKind)
		return nil
	}
	fmt.Printf("✅ Path MTU: %d bytes (active %s probe)\n", best, probeKind)
	return nil
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
	pathListCmd.Flags().BoolVar(&pathListJSON, "json", false, "output in JSON format")
	pathListCmd.ValidArgsFunction = noFileComp
	pathStatusCmd.Flags().StringVarP(&pathRelay, "relay", "r", "", "relay whose PathLink status to inspect (Gateway only)")
	pathStatusCmd.RegisterFlagCompletionFunc("relay", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getRelayAliases(), cobra.ShellCompDirectiveNoFileComp
	})
	pathStatusCmd.Flags().BoolVar(&pathStatusJSON, "json", false, "output in JSON format")
	pathPingCmd.Flags().IntVar(&pathPingTTL, "ttl", 64, "outgoing ICMP TTL/hop limit (1-255)")
	pathPingCmd.Flags().IntVarP(&pathPingCount, "count", "c", 1, "number of ICMP echo requests to send")
	pathPingCmd.Flags().DurationVarP(&pathPingInterval, "interval", "i", time.Second, "wait interval between packets")
	pathPingCmd.Flags().IntVarP(&pathPingSize, "size", "s", 8, "ICMP payload size in bytes (8-1024)")
	pathPingCmd.Flags().DurationVarP(&pathPingTimeout, "timeout", "W", 2*time.Second, "timeout per ICMP probe")
	pathPingCmd.Flags().BoolVar(&pathPingJSON, "json", false, "output in JSON format")
	pathPingCmd.ValidArgsFunction = noFileComp
	pathTraceCmd.Flags().IntVarP(&pathTraceHops, "max-hops", "m", 16, "maximum TTL/hop limit to probe (1-255)")
	pathTraceCmd.Flags().DurationVarP(&pathTraceTimeout, "timeout", "W", 2*time.Second, "timeout per hop probe")
	pathTraceCmd.Flags().BoolVar(&pathTraceJSON, "json", false, "output in JSON format")
	pathTraceCmd.ValidArgsFunction = noFileComp
	pathMTUCmd.Flags().IntVar(&pathMTUMin, "min", 0, "smallest IP packet MTU to probe (default: IPv4 576, IPv6 1280)")
	pathMTUCmd.Flags().IntVar(&pathMTUMax, "max", 2000, "largest IP packet MTU to probe")
	pathMTUCmd.Flags().DurationVarP(&pathMTUTimeout, "timeout", "W", 2*time.Second, "timeout per MTU probe")
	pathMTUCmd.Flags().BoolVar(&pathMTUJSON, "json", false, "output in JSON format")
	pathMTUCmd.ValidArgsFunction = noFileComp

	pathCmd.AddCommand(pathListCmd, pathSetCmd, pathUnsetCmd, pathStatusCmd, pathPingCmd, pathTraceCmd, pathMTUCmd)
	rootCmd.AddCommand(pathCmd)
}
