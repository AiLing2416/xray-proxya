package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type PresetMode string

type AppRole string

const (
	RoleServer  AppRole = "server"
	RoleGateway AppRole = "gateway"
)

const (
	ModeVLESSReality   PresetMode = "vless-reality"
	ModeVLESSVision    PresetMode = "vless-vision"
	ModeVLESSXHTTP     PresetMode = "vless-xhttp"
	ModeVMessWS        PresetMode = "vmess-ws"
	ModeShadowsocksTCP PresetMode = "shadowsocks-tcp"
)

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
	Alias       string                 `json:"alias"`
	Enabled     bool                   `json:"enabled"`
	UserUUID    string                 `json:"user_uuid"`
	DNSStrategy string                 `json:"dns_strategy,omitempty"` // "follow", "direct", "manual"
	DNSServers  []string               `json:"dns_servers,omitempty"`  // e.g. ["https://8.8.8.8/dns-query"]
	Config      map[string]interface{} `json:"config"`
}

type ModeInfo struct {
	Mode      PresetMode `json:"mode"`
	Enabled   bool       `json:"enabled"`
	Port      int        `json:"port"`
	Path      string     `json:"path"`
	SNI       string     `json:"sni"`
	Dest      string     `json:"dest"`
	RegenFlag bool       `json:"regen_flag,omitempty"`
	Settings  struct {
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
		ShortID    string `json:"short_id"`
		Password   string `json:"password"`
		Cipher     string `json:"cipher"`
	} `json:"settings"`
}

func GetConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "xray-proxya", "config.json")
}

func GetStagingPath() string {
	return GetConfigPath() + ".staging"
}

func (c *UserConfig) Save() error {
	return c.SaveEx(false)
}

func (c *UserConfig) SaveEx(staging bool) error {
	path := GetConfigPath()
	if staging {
		path = GetStagingPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func LoadConfig() (*UserConfig, error) {
	return LoadConfigEx(false)
}

func LoadConfigEx(preferStaging bool) (*UserConfig, error) {
	path := GetConfigPath()
	if preferStaging {
		if _, err := os.Stat(GetStagingPath()); err == nil {
			path = GetStagingPath()
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c UserConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.Role == "" {
		c.Role = RoleServer
	}
	return &c, nil
}

func ClearStaging() error {
	return os.Remove(GetStagingPath())
}

func CommitStaging() error {
	staging := GetStagingPath()
	if _, err := os.Stat(staging); err != nil {
		return nil
	}
	return os.Rename(staging, GetConfigPath())
}
