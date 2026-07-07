package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	Presets     []ModeInfo       `json:"presets"`
	CustomOutbounds []CustomOutbound `json:"custom_outbounds"`
	Guests          []GuestConfig    `json:"guests"`
	Gateway         GatewayConfig    `json:"gateway"`
	AdminSub        AdminSubConfig   `json:"admin_sub,omitempty"`
	Subscriptions   []Subscription   `json:"subscriptions"`
	SubPort         int              `json:"sub_port"`
	GuestSubPort    int              `json:"guest_sub_port,omitempty"`
	GuestSubBind    string           `json:"guest_sub_bind,omitempty"`
	IPv6Pool        IPv6Config       `json:"ipv6_pool"`
}

func (cfg *UserConfig) UnmarshalJSON(data []byte) error {
	type Alias UserConfig
	aux := &struct {
		ActiveModes []ModeInfo `json:"active_modes"`
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
	return nil
}

type AdminSubMode string

const (
	AdminSubModeFixed      AdminSubMode = "fixed"
	AdminSubModeIPv6Rotate AdminSubMode = "ipv6-rotate"
)

type AdminSubConfig struct {
	Enabled     bool         `json:"enabled,omitempty"`
	Token       string       `json:"token,omitempty"`
	Address     string       `json:"address,omitempty"`
	Port        int          `json:"port,omitempty"`
	Mode        AdminSubMode `json:"mode,omitempty"`
	TargetType  string       `json:"target_type,omitempty"`
	TargetAlias string       `json:"target_alias,omitempty"`
	IPv6Rotate  IPv6Config   `json:"ipv6_rotate,omitempty"`
}

type IPv6Config struct {
	Enabled      bool   `json:"enabled"`
	Subnet       string `json:"subnet"`        // e.g., 2001:db8::/64
	Interface    string `json:"interface"`     // e.g., eth0
	MaxAddresses int    `json:"max_addresses"` // Max addresses to keep active (rotation limit)
	EnableNDP    bool   `json:"enable_ndp"`    // Whether to auto-configure NDP
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
	Alias             string                 `json:"alias"`
	Enabled           bool                   `json:"enabled"`
	UserUUID          string                 `json:"user_uuid"`
	DNSStrategy       string                 `json:"dns_strategy,omitempty"`
	DNSServers        []string               `json:"dns_servers,omitempty"`
	InternalProxyPort int                    `json:"internal_proxy_port,omitempty"`
	Config            map[string]interface{} `json:"config"`
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
	if cfg.AdminSub.TargetType == "" {
		cfg.AdminSub.TargetType = "direct"
		changes = append(changes, "set missing admin_sub.target_type=direct")
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
		if !cfg.AdminSub.Enabled {
			cfg.AdminSub.Enabled = true
			changes = append(changes, "migrated legacy admin subscription enablement")
		}
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
	switch cfg.AdminSub.Mode {
	case AdminSubModeFixed, AdminSubModeIPv6Rotate:
	default:
		if cfg.AdminSub.IPv6Rotate.Enabled || cfg.IPv6Pool.Enabled {
			cfg.AdminSub.Mode = AdminSubModeIPv6Rotate
		} else {
			cfg.AdminSub.Mode = AdminSubModeFixed
		}
		changes = append(changes, "normalized admin_sub.mode")
	}
	if cfg.AdminSub.Mode == AdminSubModeIPv6Rotate {
		if cfg.AdminSub.IPv6Rotate.Subnet == "" && cfg.IPv6Pool.Subnet != "" {
			cfg.AdminSub.IPv6Rotate.Subnet = cfg.IPv6Pool.Subnet
			changes = append(changes, "migrated legacy ipv6_pool.subnet to admin_sub")
		}
		if cfg.AdminSub.IPv6Rotate.Interface == "" && cfg.IPv6Pool.Interface != "" {
			cfg.AdminSub.IPv6Rotate.Interface = cfg.IPv6Pool.Interface
			changes = append(changes, "migrated legacy ipv6_pool.interface to admin_sub")
		}
		if cfg.AdminSub.IPv6Rotate.MaxAddresses == 0 && cfg.IPv6Pool.MaxAddresses != 0 {
			cfg.AdminSub.IPv6Rotate.MaxAddresses = cfg.IPv6Pool.MaxAddresses
			changes = append(changes, "migrated legacy ipv6_pool.max_addresses to admin_sub")
		}
		if !cfg.AdminSub.IPv6Rotate.EnableNDP && cfg.IPv6Pool.EnableNDP {
			cfg.AdminSub.IPv6Rotate.EnableNDP = true
			changes = append(changes, "migrated legacy ipv6_pool.ndp to admin_sub")
		}
		cfg.AdminSub.IPv6Rotate.Enabled = true
	}
	if cfg.AdminSub.Token != "" && !cfg.AdminSub.Enabled {
		cfg.AdminSub.Enabled = true
		changes = append(changes, "enabled admin_sub because token is present")
	}
	if cfg.AdminSub.Enabled && cfg.AdminSub.Token == "" {
		cfg.AdminSub.Token = randomHexString(24)
		changes = append(changes, "generated missing admin_sub token")
	}
	if cfg.AdminSub.Enabled && cfg.AdminSub.Port == 0 && cfg.SubPort > 0 {
		cfg.AdminSub.Port = cfg.SubPort
	}
	if cfg.AdminSub.Port > 0 && cfg.SubPort != cfg.AdminSub.Port {
		cfg.SubPort = cfg.AdminSub.Port
		changes = append(changes, "synced legacy sub_port from admin_sub.port")
	}
	legacyRotate := cfg.AdminSub.IPv6Rotate
	legacyRotate.Enabled = cfg.AdminSub.Mode == AdminSubModeIPv6Rotate
	if cfg.IPv6Pool != legacyRotate {
		cfg.IPv6Pool = legacyRotate
		changes = append(changes, "synced legacy ipv6_pool from admin_sub")
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
		if guest.UsedBytes < 0 {
			guest.UsedBytes = 0
			changes = append(changes, "normalized negative used_bytes for guest "+guest.Alias)
		}
		switch guest.DisabledReason {
		case GuestDisabledNone, GuestDisabledManual, GuestDisabledQuotaReached, GuestDisabledQuotaZero:
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
			changes = append(changes, "reset invalid reset_day for guest "+guest.Alias+" to 1")
		}
	}

	beforeModes := len(cfg.Presets)
	cfg.Normalize()
	if cfg.Role == RoleServer && len(cfg.Presets) != beforeModes {
		changes = append(changes, "completed presets to current preset set")
	}

	return changes
}

func GetConfigDir() string {
	if envDir := os.Getenv("XRAY_PROXYA_CONFIG_DIR"); envDir != "" {
		os.MkdirAll(envDir, 0700)
		return envDir
	}
	home, _ := os.UserHomeDir()
	if os.Geteuid() == 0 && (home == "" || home == "/root") {
		home = "/root"
	}
	dir := filepath.Join(home, ".config", "xray-proxya")
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
