package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type AppRole string

const (
	RoleServer  AppRole = "server"
	RoleGateway AppRole = "gateway"
)

type PresetMode string

const (
	ModeVLESSReality   PresetMode = "vless-reality-xhttp"
	ModeVLESSVision    PresetMode = "vless-vision-reality-tcp"
	ModeVLESSXHTTP     PresetMode = "vless-xhttp-kem768"
	ModeVMessWS        PresetMode = "vmess-ws"
	ModeShadowsocksTCP PresetMode = "shadowsocks-tcp"
)

var PresetOrder = []PresetMode{
	ModeVLESSVision,
	ModeVLESSReality,
	ModeVLESSXHTTP,
	ModeVMessWS,
	ModeShadowsocksTCP,
}

type UserConfig struct {
	Role            AppRole          `json:"role"`
	UUID            string           `json:"uuid"`
	APIInbound      int              `json:"api_inbound"`
	TestInbound     int              `json:"test_inbound"`
	Presets         []ModeInfo       `json:"presets"`
	CustomOutbounds []CustomOutbound `json:"custom_outbounds"`
	Guests          []GuestConfig    `json:"guests"`
	Gateway         GatewayConfig    `json:"gateway"`
	// Path is the local Pathd daemon endpoint. It is meaningful only on a
	// Server. Gateway-side PathLink credentials live on the relay that uses
	// them (CustomOutbound.Path).
	Path     PathConfig     `json:"path,omitempty"`
	AdminSub AdminSubConfig `json:"admin_sub,omitempty"`
	// SubscriptionInstances contains named multi-instance subscription configurations.
	SubscriptionInstances map[string]AdminSubConfig `json:"subscription_instances,omitempty"`
	// IPv6Rotation contains the privileged address allocator used by
	// subscription services.
	IPv6Rotation IPv6Config `json:"ipv6_rotation,omitempty"`
	// IPv6Rotations is preserved for backwards compatibility with multi-instance schema.
	IPv6Rotations map[string]IPv6Config `json:"ipv6_rotations,omitempty"`
	Subscriptions []Subscription        `json:"subscriptions"`
	SubPort       int                   `json:"sub_port"`
	GuestSubPort  int                   `json:"guest_sub_port,omitempty"`
	GuestSubBind  string                `json:"guest_sub_bind,omitempty"`
	IPv6Pool      IPv6Config            `json:"ipv6_pool"`

	// legacyPath* are populated only while decoding the pre-relay PathLink
	// schema. They are intentionally not persisted.
	legacyPathEnabled *bool
	legacyPathSeen    bool
}

// PathConfig configures one loopback-only Pathd endpoint.  On a Server it is
// the local daemon configuration; on a Gateway it is attached to a relay.
// Service enablement deliberately belongs to systemd, not this config.
type PathConfig struct {
	Listen      string `json:"listen,omitempty"`
	Token       string `json:"token,omitempty"`
	IdleSeconds int    `json:"idle_seconds,omitempty"`
	// LegacyEnabled is retained only for an enabled legacy Gateway config whose
	// selected relay no longer exists. It is cleared as soon as migration can
	// attach the credential; new code never reads it for enablement.
	LegacyEnabled bool `json:"enabled,omitempty"`
}

func (cfg *UserConfig) UnmarshalJSON(data []byte) error {
	type Alias UserConfig
	aux := &struct {
		ActiveModes []ModeInfo      `json:"active_modes"`
		Path        json.RawMessage `json:"path"`
		*Alias
	}{
		Alias: (*Alias)(cfg),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(aux.ActiveModes) > 0 && len(cfg.Presets) == 0 {
		cfg.Presets = aux.ActiveModes
	}
	if len(aux.Path) > 0 && string(aux.Path) != "null" {
		if err := json.Unmarshal(aux.Path, &cfg.Path); err != nil {
			return err
		}
		var legacy struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.Unmarshal(aux.Path, &legacy); err != nil {
			return err
		}
		cfg.legacyPathEnabled = legacy.Enabled
		cfg.legacyPathSeen = legacy.Enabled != nil
		if legacy.Enabled != nil && *legacy.Enabled {
			cfg.Path.LegacyEnabled = true
		}
	}
	return nil
}

type AdminSubConfig struct {
	Listen       string `json:"listen,omitempty"`
	Token        string `json:"token,omitempty"`
	Address      string `json:"address,omitempty"`
	Port         int    `json:"port,omitempty"`
	TargetType   string `json:"target_type,omitempty"`
	TargetAlias  string `json:"target_alias,omitempty"`
	IPv6Rotation string `json:"ipv6_rotation,omitempty"`

	legacyEnabled    *bool
	legacyMode       string
	legacyIPv6Rotate IPv6Config
}

// SubscriptionServiceConfig is the private, per-instance runtime
// configuration consumed by xray-proxya-sub@<instance>.service. Link content
// is still generated from the active application configuration, while every
// listener, token and target selection has an independently owned file.
type SubscriptionServiceConfig struct {
	Listen    string         `json:"listen"`
	Port      int            `json:"port"`
	GuestBind string         `json:"guest_bind,omitempty"`
	GuestPort int            `json:"guest_port,omitempty"`
	AdminSub  AdminSubConfig `json:"admin_sub"`
}

type IPv6Config struct {
	Subnet       string `json:"subnet"`        // e.g., 2001:db8::/64
	Interface    string `json:"interface"`     // e.g., eth0
	MaxAddresses int    `json:"max_addresses"` // Max addresses to keep active (rotation limit)
	EnableNDP    bool   `json:"enable_ndp"`    // Whether to auto-configure NDP

	legacyEnabled *bool
}

// UnmarshalJSON accepts the pre-service schema but intentionally never
// serializes its enablement/mode switches again.
func (a *AdminSubConfig) UnmarshalJSON(data []byte) error {
	type wire struct {
		Listen       string     `json:"listen"`
		Token        string     `json:"token"`
		Address      string     `json:"address"`
		Port         int        `json:"port"`
		TargetType   string     `json:"target_type"`
		TargetAlias  string     `json:"target_alias"`
		IPv6Rotation string     `json:"ipv6_rotation"`
		Enabled      *bool      `json:"enabled"`
		Mode         string     `json:"mode"`
		IPv6Rotate   IPv6Config `json:"ipv6_rotate"`
	}
	var v wire
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*a = AdminSubConfig{Listen: v.Listen, Token: v.Token, Address: v.Address, Port: v.Port, TargetType: v.TargetType, TargetAlias: v.TargetAlias, IPv6Rotation: v.IPv6Rotation, legacyEnabled: v.Enabled, legacyMode: v.Mode, legacyIPv6Rotate: v.IPv6Rotate}
	return nil
}

func (v *IPv6Config) UnmarshalJSON(data []byte) error {
	type wire struct {
		Subnet       string `json:"subnet"`
		Interface    string `json:"interface"`
		MaxAddresses int    `json:"max_addresses"`
		EnableNDP    bool   `json:"enable_ndp"`
		Enabled      *bool  `json:"enabled"`
	}
	var raw wire
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*v = IPv6Config{Subnet: raw.Subnet, Interface: raw.Interface, MaxAddresses: raw.MaxAddresses, EnableNDP: raw.EnableNDP, legacyEnabled: raw.Enabled}
	return nil
}

type Subscription struct {
	Alias       string `json:"alias"`        // "" for the default direct outbound
	TargetType  string `json:"target_type"`  // "direct", "outbound", "guest"
	TargetAlias string `json:"target_alias"` // specific alias for outbound/guest
	Address     string `json:"address"`      // custom address or hostname
	Token       string `json:"token"`        // random URL path token
}

type GuestDisabledReason string

const (
	GuestDisabledNone         GuestDisabledReason = ""
	GuestDisabledManual       GuestDisabledReason = "manual"
	GuestDisabledQuotaReached GuestDisabledReason = "quota_reached"
	GuestDisabledQuotaZero    GuestDisabledReason = "quota_zero"
)

type GuestConfig struct {
	Alias          string                 `json:"alias"`
	UUID           string                 `json:"uuid"`
	Enabled        bool                   `json:"enabled"`
	DisabledReason GuestDisabledReason    `json:"disabled_reason,omitempty"`
	QuotaGB        float64                `json:"quota_gb"` // -1 for unlimited, 0 for paused
	UsedBytes      int64                  `json:"used_bytes"`
	ResetDay       int                    `json:"reset_day"`               // 1-31
	LastResetYM    string                 `json:"last_reset_ym,omitempty"` // YYYY-MM of the last quota reset
	SubToken       string                 `json:"sub_token,omitempty"`
	OutboundLink   string                 `json:"outbound_link,omitempty"` // For custom routing
	OutboundConf   map[string]interface{} `json:"outbound_conf,omitempty"` // Parsed version
}

type GatewayConfig struct {
	LocalEnabled    bool     `json:"local_enabled"`
	LANEnabled      bool     `json:"lan_enabled"`
	Mode            string   `json:"mode"` // "tun" or "tproxy"
	RelayAlias      string   `json:"relay_alias"`
	LANInterface    string   `json:"lan_interface"`
	BypassDNS       []string `json:"bypass_dns,omitempty"`
	State           string   `json:"state,omitempty"` // "disabled", "forward-only", "proxy"
	BypassCountries []string `json:"bypass_countries,omitempty"`
}

type CustomOutbound struct {
	Alias    string `json:"alias"`
	Enabled  bool   `json:"enabled"`
	UserUUID string `json:"user_uuid"`
	// AllowPrivateTargets permits the relay identity generated for this
	// outbound to forward RFC1918 and loopback destinations to its next hop.
	// It is false by default so relay users cannot reach a next-hop private
	// network unless an operator explicitly opts in.
	AllowPrivateTargets bool     `json:"allow_private_targets"`
	DNSStrategy         string   `json:"dns_strategy,omitempty"`
	DNSServers          []string `json:"dns_servers,omitempty"`
	InternalProxyPort   int      `json:"internal_proxy_port,omitempty"`
	InternalHttpPort    int      `json:"internal_http_port,omitempty"`
	InternalListenAddr  string   `json:"internal_listen_addr,omitempty"`
	// Path holds the remote loopback Pathd credentials used when this outbound
	// is selected as the Gateway relay. It is not rendered into share links.
	Path   *PathConfig            `json:"path,omitempty"`
	Config map[string]interface{} `json:"config"`
}

type ModeInfo struct {
	Mode      PresetMode `json:"mode"`
	Enabled   bool       `json:"enabled"`
	Port      int        `json:"port"`
	SNI       string     `json:"sni,omitempty"`
	Dest      string     `json:"dest,omitempty"`
	Path      string     `json:"path,omitempty"`
	Settings  Settings   `json:"settings"`
	Skin      bool       `json:"skin,omitempty"`
	RegenFlag bool       `json:"regen_flag,omitempty"`
}

type Settings struct {
	PrivateKey string `json:"privateKey,omitempty"`
	PublicKey  string `json:"publicKey,omitempty"`
	ShortID    string `json:"shortId,omitempty"`
	Password   string `json:"password,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
}

func (cfg *UserConfig) Normalize() {
	if cfg.Role != RoleServer {
		return
	}
	newModes := make([]ModeInfo, 0, len(PresetOrder))
	for _, target := range PresetOrder {
		found := false
		for _, m := range cfg.Presets {
			if m.Mode == target {
				newModes = append(newModes, m)
				found = true
				break
			}
		}
		if !found {
			newModes = append(newModes, ModeInfo{Mode: target, Enabled: false})
		}
	}
	cfg.Presets = newModes
}

func randomHexString(length int) string {
	if length <= 0 {
		return ""
	}
	buf := make([]byte, (length+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("0", length)
	}
	return hex.EncodeToString(buf)[:length]
}

func normalizeStringSlice(values []string) ([]string, bool) {
	if values == nil {
		return nil, false
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	changed := false
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != value {
			changed = true
		}
		if trimmed == "" {
			changed = true
			continue
		}
		if _, ok := seen[trimmed]; ok {
			changed = true
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) != len(values) {
		changed = true
	}
	return out, changed
}

func normalizeDNSStrategyValue(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "", strings.TrimSpace(value) != ""
	case "useip":
		return "UseIP", value != "UseIP"
	case "useipv4":
		return "UseIPv4", value != "UseIPv4"
	case "useipv6":
		return "UseIPv6", value != "UseIPv6"
	default:
		return value, false
	}
}

func (cfg *UserConfig) BackfillDefaults() []string {
	if cfg == nil {
		return nil
	}
	changes := []string{}

	if cfg.Role == "" {
		cfg.Role = RoleServer
		changes = append(changes, "set missing role=server")
	}
	changes = append(changes, cfg.migrateLegacyPath()...)
	if cfg.Role == RoleServer && cfg.Path.Token != "" {
		if cfg.Path.Listen == "" {
			cfg.Path.Listen = "127.0.0.1:39091"
			changes = append(changes, "set missing pathd.listen=127.0.0.1:39091")
		}
		if cfg.Path.IdleSeconds <= 0 {
			cfg.Path.IdleSeconds = 20
			changes = append(changes, "set missing pathd.idle_seconds=20")
		}
	}
	if cfg.UUID == "" {
		cfg.UUID = randomHexString(32)
		changes = append(changes, "generated missing service UUID")
	}
	if cfg.Presets == nil {
		cfg.Presets = []ModeInfo{}
		changes = append(changes, "initialized presets")
	}
	if cfg.CustomOutbounds == nil {
		cfg.CustomOutbounds = []CustomOutbound{}
		changes = append(changes, "initialized custom_outbounds")
	}
	if cfg.Guests == nil {
		cfg.Guests = []GuestConfig{}
		changes = append(changes, "initialized guests")
	}
	if cfg.Subscriptions == nil {
		cfg.Subscriptions = []Subscription{}
		changes = append(changes, "initialized subscriptions")
	}
	if cfg.IPv6Rotations == nil {
		cfg.IPv6Rotations = map[string]IPv6Config{}
	}
	if cfg.Role == RoleGateway {
		if cfg.Gateway.Mode == "" {
			cfg.Gateway.Mode = "tun"
			changes = append(changes, "set missing gateway.mode=tun")
		}
		if cfg.Gateway.State == "" {
			if cfg.Gateway.LocalEnabled || cfg.Gateway.LANEnabled {
				cfg.Gateway.State = "proxy"
				changes = append(changes, "initialized gateway.state to proxy")
			} else {
				cfg.Gateway.State = "disabled"
				changes = append(changes, "initialized gateway.state to disabled")
			}
		} else {
			state := strings.ToLower(strings.TrimSpace(cfg.Gateway.State))
			switch state {
			case "disabled", "forward-only", "proxy":
				if state != cfg.Gateway.State {
					cfg.Gateway.State = state
					changes = append(changes, "normalized gateway.state")
				}
			default:
				cfg.Gateway.State = "disabled"
				changes = append(changes, "reset invalid gateway.state to disabled")
			}
		}
	}
	if cfg.Gateway.BypassDNS != nil {
		normalized, changed := normalizeStringSlice(cfg.Gateway.BypassDNS)
		if changed {
			cfg.Gateway.BypassDNS = normalized
			changes = append(changes, "normalized gateway.bypass_dns")
		}
	}
	if cfg.Gateway.BypassCountries != nil {
		normalized, changed := normalizeStringSlice(cfg.Gateway.BypassCountries)
		if changed {
			cfg.Gateway.BypassCountries = normalized
			changes = append(changes, "normalized gateway.bypass_countries")
		}
	}
	if strings.TrimSpace(cfg.GuestSubBind) == "" {
		cfg.GuestSubBind = "127.0.0.1"
		changes = append(changes, "set missing guest_sub_bind=127.0.0.1")
	}

	legacyAdminIdx := -1
	for i := range cfg.Subscriptions {
		if cfg.Subscriptions[i].Alias == "admin" {
			legacyAdminIdx = i
			break
		}
	}
	if legacyAdminIdx >= 0 {
		legacyAdmin := cfg.Subscriptions[legacyAdminIdx]
		if cfg.AdminSub.Token == "" {
			cfg.AdminSub.Token = legacyAdmin.Token
			changes = append(changes, "migrated legacy admin subscription token")
		}
		if cfg.AdminSub.Address == "" {
			cfg.AdminSub.Address = legacyAdmin.Address
			changes = append(changes, "migrated legacy admin subscription address")
		}
		if cfg.AdminSub.TargetType == "direct" && legacyAdmin.TargetType != "" {
			cfg.AdminSub.TargetType = legacyAdmin.TargetType
			cfg.AdminSub.TargetAlias = legacyAdmin.TargetAlias
			changes = append(changes, "migrated legacy admin subscription target")
		}
	}
	if cfg.AdminSub.Port == 0 && cfg.SubPort > 0 {
		cfg.AdminSub.Port = cfg.SubPort
		changes = append(changes, "migrated legacy sub_port to admin_sub.port")
	}
	// In the new schema an endpoint exists when it has a token; systemd owns
	// whether it serves requests. A deliberately disabled legacy endpoint is
	// therefore removed rather than accidentally exposed after migration.
	if cfg.AdminSub.legacyEnabled != nil && !*cfg.AdminSub.legacyEnabled {
		cfg.AdminSub = AdminSubConfig{}
		changes = append(changes, "removed disabled legacy admin subscription")
	}
	if cfg.AdminSub.Token != "" && cfg.AdminSub.TargetType == "" {
		cfg.AdminSub.TargetType = "direct"
		changes = append(changes, "set missing admin_sub.target_type=direct")
	}
	if cfg.AdminSub.Token != "" && cfg.AdminSub.Port == 0 && cfg.SubPort > 0 {
		cfg.AdminSub.Port = cfg.SubPort
	}
	legacyRotate := cfg.AdminSub.legacyMode == "ipv6-rotate" ||
		(cfg.AdminSub.legacyIPv6Rotate.legacyEnabled != nil && *cfg.AdminSub.legacyIPv6Rotate.legacyEnabled) ||
		(cfg.IPv6Pool.legacyEnabled != nil && *cfg.IPv6Pool.legacyEnabled)
	if legacyRotate && cfg.AdminSub.Token != "" && cfg.AdminSub.IPv6Rotation == "" {
		rotation := cfg.AdminSub.legacyIPv6Rotate
		if rotation.Subnet == "" {
			rotation.Subnet = cfg.IPv6Pool.Subnet
		}
		if rotation.Interface == "" {
			rotation.Interface = cfg.IPv6Pool.Interface
		}
		if rotation.MaxAddresses == 0 {
			rotation.MaxAddresses = cfg.IPv6Pool.MaxAddresses
		}
		if !rotation.EnableNDP {
			rotation.EnableNDP = cfg.IPv6Pool.EnableNDP
		}
		cfg.IPv6Rotation = IPv6Config{Subnet: rotation.Subnet, Interface: rotation.Interface, MaxAddresses: rotation.MaxAddresses, EnableNDP: rotation.EnableNDP}
		cfg.IPv6Rotations["default"] = cfg.IPv6Rotation
		cfg.AdminSub.IPv6Rotation = "default"
		changes = append(changes, "migrated legacy IPv6 rotation to ipv6_rotation")
	}
	if cfg.IPv6Rotation.Subnet == "" && cfg.IPv6Rotations != nil && cfg.IPv6Rotations["default"].Subnet != "" {
		cfg.IPv6Rotation = cfg.IPv6Rotations["default"]
	}
	if cfg.IPv6Rotation.Subnet != "" {
		if cfg.IPv6Rotations == nil {
			cfg.IPv6Rotations = make(map[string]IPv6Config)
		}
		cfg.IPv6Rotations["default"] = cfg.IPv6Rotation
	}
	if cfg.SubscriptionInstances == nil {
		cfg.SubscriptionInstances = make(map[string]AdminSubConfig)
	}
	if cfg.AdminSub.Token != "" {
		cfg.SubscriptionInstances["default"] = cfg.AdminSub
	} else if defaultSub, ok := cfg.SubscriptionInstances["default"]; ok && defaultSub.Token != "" {
		cfg.AdminSub = defaultSub
	}
	if cfg.AdminSub.Port > 0 && cfg.SubPort != cfg.AdminSub.Port {
		cfg.SubPort = cfg.AdminSub.Port
		changes = append(changes, "synced legacy sub_port from admin_sub.port")
	}
	if cfg.IPv6Pool.Subnet != "" || cfg.IPv6Pool.Interface != "" || cfg.IPv6Pool.MaxAddresses != 0 || cfg.IPv6Pool.EnableNDP {
		cfg.IPv6Pool = IPv6Config{}
		changes = append(changes, "removed migrated legacy ipv6_pool")
	}
	if legacyAdminIdx >= 0 {
		newSubs := make([]Subscription, 0, len(cfg.Subscriptions)-1)
		for _, sub := range cfg.Subscriptions {
			if sub.Alias == "admin" {
				continue
			}
			newSubs = append(newSubs, sub)
		}
		cfg.Subscriptions = newSubs
		changes = append(changes, "removed managed admin alias from legacy subscriptions")
	}

	for i := range cfg.CustomOutbounds {
		co := &cfg.CustomOutbounds[i]
		if co.UserUUID == "" {
			co.UserUUID = randomHexString(32)
			changes = append(changes, "generated missing user_uuid for outbound "+co.Alias)
		}
		if co.Config == nil {
			co.Config = map[string]interface{}{}
			changes = append(changes, "initialized config for outbound "+co.Alias)
		}
		if normalizedStrategy, changed := normalizeDNSStrategyValue(co.DNSStrategy); changed {
			co.DNSStrategy = normalizedStrategy
			changes = append(changes, "normalized dns_strategy for outbound "+co.Alias)
		}
		if normalizedServers, changed := normalizeStringSlice(co.DNSServers); changed {
			co.DNSServers = normalizedServers
			changes = append(changes, "normalized dns_servers for outbound "+co.Alias)
		}
	}

	for i := range cfg.Guests {
		guest := &cfg.Guests[i]
		if guest.UUID == "" {
			guest.UUID = randomHexString(32)
			changes = append(changes, "generated missing UUID for guest "+guest.Alias)
		}
		if guest.UsedBytes < 0 && guest.UsedBytes != -1 {
			guest.UsedBytes = 0
			changes = append(changes, "normalized negative used_bytes for guest "+guest.Alias)
		}
		switch guest.DisabledReason {
		case GuestDisabledQuotaZero, GuestDisabledQuotaReached, GuestDisabledManual, GuestDisabledNone:
		default:
			guest.DisabledReason = GuestDisabledNone
			changes = append(changes, "cleared invalid disabled_reason for guest "+guest.Alias)
		}
		if guest.Enabled && guest.DisabledReason != GuestDisabledNone {
			guest.DisabledReason = GuestDisabledNone
			changes = append(changes, "cleared stale disabled_reason for enabled guest "+guest.Alias)
		}
		if !guest.Enabled && guest.DisabledReason == GuestDisabledNone {
			if guest.QuotaGB == 0 {
				guest.DisabledReason = GuestDisabledQuotaZero
				changes = append(changes, "backfilled disabled_reason=quota_zero for guest "+guest.Alias)
			} else {
				guest.DisabledReason = GuestDisabledManual
				changes = append(changes, "backfilled disabled_reason=manual for guest "+guest.Alias)
			}
		}
		if guest.ResetDay < 1 || guest.ResetDay > 31 {
			guest.ResetDay = 1
			changes = append(changes, "normalized invalid reset_day for guest "+guest.Alias)
		}
	}

	for i := range cfg.Presets {
		m := &cfg.Presets[i]
		if m.Mode == ModeVLESSVision || m.Mode == ModeVLESSReality {
			if m.Skin {
				m.Skin = false
				changes = append(changes, "cleared legacy skin flag for preset "+string(m.Mode))
			}
			if m.SNI != "" {
				normSNI := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(m.SNI)), ".")
				if normSNI != m.SNI {
					m.SNI = normSNI
					changes = append(changes, "normalized SNI for preset "+string(m.Mode))
				}
				if m.Dest == "" {
					m.Dest = net.JoinHostPort(normSNI, "443")
					changes = append(changes, "backfilled default dest for preset "+string(m.Mode))
				} else {
					destHost, _, normDest, err := NormalizeRealityTarget(m.Dest)
					if err != nil || destHost != normSNI {
						m.Dest = net.JoinHostPort(normSNI, "443")
						changes = append(changes, "aligned mismatched dest with SNI for preset "+string(m.Mode))
					} else if normDest != m.Dest {
						m.Dest = normDest
						changes = append(changes, "normalized dest for preset "+string(m.Mode))
					}
				}
			}
		}
	}

	beforeModes := len(cfg.Presets)
	cfg.Normalize()
	if cfg.Role == RoleServer && len(cfg.Presets) != beforeModes {
		changes = append(changes, "completed presets to current preset set")
	}

	return changes
}

// migrateLegacyPath moves the former global, enabled Gateway PathLink
// credentials onto the relay selected by that configuration. Server Pathd
// configuration stays top-level because it describes the local daemon.
// The migration is idempotent and is persisted on the next normal config save.
func (cfg *UserConfig) migrateLegacyPath() []string {
	if cfg == nil || !cfg.legacyPathSeen {
		return nil
	}
	changes := []string{}
	legacyEnabled := cfg.legacyPathEnabled != nil && *cfg.legacyPathEnabled
	if cfg.Role == RoleServer {
		cfg.Path.LegacyEnabled = false
		cfg.legacyPathSeen = false
		return append(changes, "migrated legacy Server path configuration")
	}
	if cfg.Role != RoleGateway {
		return nil
	}
	if legacyEnabled && cfg.Path.Token != "" && cfg.Gateway.RelayAlias != "" {
		for i := range cfg.CustomOutbounds {
			outbound := &cfg.CustomOutbounds[i]
			if outbound.Alias != cfg.Gateway.RelayAlias {
				continue
			}
			if outbound.Path == nil || outbound.Path.Token == "" {
				endpoint := cfg.Path
				endpoint.LegacyEnabled = false
				if endpoint.Listen == "" {
					endpoint.Listen = "127.0.0.1:39091"
				}
				if endpoint.IdleSeconds <= 0 {
					endpoint.IdleSeconds = 20
				}
				outbound.Path = &endpoint
				changes = append(changes, "migrated legacy enabled path credentials to relay "+outbound.Alias)
			} else {
				changes = append(changes, "kept existing relay path credentials for "+outbound.Alias)
			}
			cfg.Path = PathConfig{}
			cfg.legacyPathSeen = false
			return changes
		}
	}
	if !legacyEnabled {
		cfg.Path = PathConfig{}
		cfg.legacyPathSeen = false
		return append(changes, "removed disabled legacy gateway path configuration")
	}
	// Keep an enabled legacy value in memory until its selected relay exists;
	// LegacyEnabled causes it to remain durable until a later config operation
	// supplies that relay, avoiding silent credential loss during an upgrade.
	return changes
}

func GetHomeDir() string {
	if os.Geteuid() == 0 {
		return "/root"
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "/root"
	}
	return home
}

func GetConfigDir() string {
	// System services must never inherit a caller-controlled configuration
	// directory. In particular, sudo preserves enough environment state on some
	// systems to otherwise make a root service consume an unprivileged tree.
	if os.Geteuid() == 0 {
		const rootConfigDir = "/root/.config/xray-proxya"
		_ = os.MkdirAll(rootConfigDir, 0700)
		return rootConfigDir
	}
	if envDir := os.Getenv("XRAY_PROXYA_CONFIG_DIR"); envDir != "" {
		os.MkdirAll(envDir, 0700)
		return envDir
	}
	dir := filepath.Join(GetHomeDir(), ".config", "xray-proxya")
	os.MkdirAll(dir, 0700)
	return dir
}

func GetConfigPath() string {
	return filepath.Join(GetConfigDir(), "config.json")
}

func GetConfigPathEx(staging bool) string {
	path := GetConfigPath()
	if staging {
		path += ".staging"
	}
	return path
}

// GatewayTunDisabledPath is a runtime-only marker. It lets a gateway be
// brought down without mutating the active, staged configuration; the next
// gateway up removes it before restarting Xray with its TUN inbound enabled.
func GatewayTunDisabledPath() string {
	return filepath.Join(GetConfigDir(), "gateway.tun.disabled")
}

func GatewayTunDisabled() bool {
	_, err := os.Stat(GatewayTunDisabledPath())
	return err == nil
}

func SetGatewayTunDisabled(disabled bool) error {
	path := GatewayTunDisabledPath()
	if disabled {
		return os.WriteFile(path, []byte("disabled\n"), 0600)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// PathTunDisabledPath records that the optional PathLink TUN could not be
// created for the current service runtime.  It is deliberately separate from
// the desired configuration: a PathLink failure must not prevent the main
// transparent gateway from coming up.
func PathTunDisabledPath() string {
	return filepath.Join(GetConfigDir(), "gateway.path-tun.disabled")
}

func PathTunDisabled() bool {
	_, err := os.Stat(PathTunDisabledPath())
	return err == nil
}

func SetPathTunDisabled(disabled bool) error {
	path := PathTunDisabledPath()
	if disabled {
		return os.WriteFile(path, []byte("disabled\n"), 0600)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func StagingExists() bool {
	_, err := os.Stat(GetConfigPathEx(true))
	return err == nil
}

func LoadConfig() (*UserConfig, error) {
	// If a staging config exists, we should generally be aware of it to avoid split-brain.
	// However, for 'run' and 'status', we want the active one.
	cfg, err := LoadConfigEx(false)
	if err == nil {
		cfg.Normalize()
	}
	return cfg, err
}

func LoadConfigEx(staging bool) (*UserConfig, error) {
	path := GetConfigPathEx(staging)
	if staging {
		// If requesting staging but it doesn't exist, fallback to official
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return LoadConfigEx(false)
		}
	}
	return LoadConfigFile(path, true)
}

func LoadConfigFile(path string, backfill bool) (*UserConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg *UserConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if backfill {
		cfg.BackfillDefaults()
	}
	return cfg, nil
}

func (cfg *UserConfig) Save() error {
	// Safety check: if we are saving to official but a staging file exists,
	// we might be overwriting a pending change with stale data.
	// For background tasks like quota, we should ideally merge, but for now
	// we'll just ensure we save to the right place.
	return cfg.SaveEx(false)
}

func (cfg *UserConfig) SaveEx(staging bool) error {
	path := GetConfigPathEx(staging)
	os.MkdirAll(filepath.Dir(path), 0700)
	cfg.BackfillDefaults()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func CommitStaging() error {
	src := GetConfigPath() + ".staging"
	dst := GetConfigPath()
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return nil
	}

	stagingCfg, err := LoadConfigFile(src, false)
	if err != nil {
		return err
	}

	// Try to load the active config to merge background runtime updates
	if activeCfg, err := LoadConfigFile(dst, false); err == nil {
		// Merge background-mutable fields of guests
		for i := range stagingCfg.Guests {
			sg := &stagingCfg.Guests[i]
			// Find corresponding guest in active config
			var activeG *GuestConfig
			for j := range activeCfg.Guests {
				if activeCfg.Guests[j].Alias == sg.Alias {
					activeG = &activeCfg.Guests[j]
					break
				}
			}
			if activeG == nil {
				if sg.UsedBytes < 0 {
					sg.UsedBytes = 0
				}
				continue
			}

			// 1. Merge UsedBytes and LastResetYM (unless explicitly reset to -1 by admin)
			if sg.UsedBytes < 0 {
				sg.UsedBytes = 0
			} else {
				sg.UsedBytes = activeG.UsedBytes
				sg.LastResetYM = activeG.LastResetYM
			}

			// 2. Merge Enabled and DisabledReason (unless explicitly changed by admin)
			adminChangedEnablement := false
			if sg.UsedBytes == 0 && activeG.UsedBytes > 0 && activeG.DisabledReason == GuestDisabledQuotaReached {
				// Admin reset the usage via -1 which we just set to 0 above
				adminChangedEnablement = true
			} else if sg.QuotaGB != activeG.QuotaGB {
				adminChangedEnablement = true
			} else if sg.DisabledReason == GuestDisabledManual && activeG.DisabledReason != GuestDisabledManual {
				// Admin manually paused
				adminChangedEnablement = true
			} else if sg.DisabledReason == GuestDisabledNone && activeG.DisabledReason == GuestDisabledManual {
				// Admin manually resumed
				adminChangedEnablement = true
			}

			if !adminChangedEnablement {
				sg.Enabled = activeG.Enabled
				sg.DisabledReason = activeG.DisabledReason
			}
		}
	}

	// Normalize any remaining -1 values before saving to config.json
	for i := range stagingCfg.Guests {
		if stagingCfg.Guests[i].UsedBytes < 0 {
			stagingCfg.Guests[i].UsedBytes = 0
		}
	}

	// Save the merged configuration directly to active config path
	if err := stagingCfg.SaveEx(false); err != nil {
		return err
	}

	return os.Remove(src)
}

func ClearStaging() error {
	path := GetConfigPath() + ".staging"
	if _, err := os.Stat(path); err == nil {
		return os.Remove(path)
	}
	return nil
}
