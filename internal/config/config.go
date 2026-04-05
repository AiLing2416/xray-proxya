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

// PresetOrder defines the canonical order of inbounds for v0.1.3+
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
	Gateway         GatewayConfig    `json:"gateway"`
}

type GatewayConfig struct {
	Enabled      bool     `json:"enabled"`
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
	if cfg.Role != RoleServer {
		return
	}
	newModes := make([]ModeInfo, 0, len(PresetOrder))
	for _, target := range PresetOrder {
		found := false
		for _, m := range cfg.ActiveModes {
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
	cfg.ActiveModes = newModes
}

func GetConfigDir() string {
	home, _ := os.UserHomeDir()
	if os.Geteuid() == 0 {
		home = "/root"
	}
	return filepath.Join(home, ".config", "xray-proxya")
}

func GetConfigPath() string {
	return filepath.Join(GetConfigDir(), "config.json")
}

func LoadConfig() (*UserConfig, error) {
	cfg, err := LoadConfigEx(false)
	if err == nil { cfg.Normalize() }
	return cfg, err
}

func LoadConfigEx(staging bool) (*UserConfig, error) {
	path := GetConfigPath()
	if staging {
		path += ".staging"
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		if staging {
			cfg, err := LoadConfigEx(false)
			if err == nil { cfg.Normalize() }
			return cfg, err
		}
		return nil, err
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

func ClearStaging() error {
	path := GetConfigPath() + ".staging"
	if _, err := os.Stat(path); err == nil {
		return os.Remove(path)
	}
	return nil
}

func (cfg *UserConfig) Save() error {
	return cfg.SaveEx(false)
}

func (cfg *UserConfig) SaveEx(staging bool) error {
	path := GetConfigPath()
	if staging {
		path += ".staging"
	}
	os.MkdirAll(filepath.Dir(path), 0755)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func CommitStaging() error {
	src := GetConfigPath() + ".staging"
	dst := GetConfigPath()
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		return err
	}
	return os.Remove(src)
}
