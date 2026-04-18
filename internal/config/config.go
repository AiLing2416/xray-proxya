package config

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	ActiveModes     []ModeInfo       `json:"active_modes"`
	CustomOutbounds []CustomOutbound `json:"custom_outbounds"`
	Guests          []GuestConfig    `json:"guests"`
	Gateway         GatewayConfig    `json:"gateway"`
	Subscriptions   []Subscription   `json:"subscriptions"`
	SubPort         int              `json:"sub_port"`
	IPv6Pool        IPv6Config       `json:"ipv6_pool"`
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

type GuestConfig struct {
	Alias        string                 `json:"alias"`
	UUID         string                 `json:"uuid"`
	Enabled      bool                   `json:"enabled"`
	QuotaGB      float64                `json:"quota_gb"` // -1 for unlimited, 0 for paused
	UsedBytes    int64                  `json:"used_bytes"`
	ResetDay     int                    `json:"reset_day"` // 1-31
	OutboundLink string                 `json:"outbound_link,omitempty"` // For custom routing
	OutboundConf map[string]interface{} `json:"outbound_conf,omitempty"` // Parsed version
}

type GatewayConfig struct {
	LocalEnabled bool     `json:"local_enabled"`
	LANEnabled   bool     `json:"lan_enabled"`
	Mode         string   `json:"mode"` // "tun" or "tproxy"
	RelayAlias   string   `json:"relay_alias"`
	Blacklist    []string `json:"blacklist"`
	BlacklistIPs []string `json:"blacklist_ips"`
	LANInterface string   `json:"lan_interface"`
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
	if cfg.Role != RoleServer { return }
	newModes := make([]ModeInfo, 0, len(PresetOrder))
	for _, target := range PresetOrder {
		found := false
		for _, m := range cfg.ActiveModes {
			if m.Mode == target {
				newModes = append(newModes, m)
				found = true; break
			}
		}
		if !found {
			newModes = append(newModes, ModeInfo{Mode: target, Enabled: false})
		}
	}
	cfg.ActiveModes = newModes
}

func GetConfigDir() string {
	home, _ := os.UserHomeDir()
	// Fallback for some environments where UserHomeDir might fail for root
	if os.Geteuid() == 0 && home == "" {
		home = "/root"
	}
	dir := filepath.Join(home, ".config", "xray-proxya")
	os.MkdirAll(dir, 0700)
	return dir
}

func GetConfigPath() string {
	return filepath.Join(GetConfigDir(), "config.json")
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
	path := GetConfigPath()
	if staging {
		stagingPath := path + ".staging"
		// If requesting staging but it doesn't exist, fallback to official
		if _, err := os.Stat(stagingPath); os.IsNotExist(err) {
			return LoadConfigEx(false)
		}
		path = stagingPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg *UserConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.Normalize()
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
	path := GetConfigPath()
	if staging { path += ".staging" }
	os.MkdirAll(filepath.Dir(path), 0700)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil { return err }
	return os.WriteFile(path, data, 0600)
}

func CommitStaging() error {
	src := GetConfigPath() + ".staging"
	dst := GetConfigPath()
	if _, err := os.Stat(src); os.IsNotExist(err) { return nil }
	data, err := os.ReadFile(src)
	if err != nil { return err }
	if err := os.WriteFile(dst, data, 0600); err != nil { return err }
	return os.Remove(src)
}

func ClearStaging() error {
	path := GetConfigPath() + ".staging"
	if _, err := os.Stat(path); err == nil { return os.Remove(path) }
	return nil
}
