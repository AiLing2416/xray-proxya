package xray

import (
	"encoding/json"
	"fmt"
	"xray-proxya/internal/config"
	"xray-proxya/pkg/utils"
)

type XrayConfig struct {
	Log       LogConfig        `json:"log"`
	Api       *APIConfig       `json:"api,omitempty"`
	Dns       *DNSConfig       `json:"dns,omitempty"`
	FakeDns   interface{}      `json:"fakedns,omitempty"`
	Stats     struct{}         `json:"stats"`
	Policy    PolicyConfig     `json:"policy"`
	Inbounds  []InboundConfig  `json:"inbounds"`
	Outbounds []interface{}    `json:"outbounds"`
	Routing   RoutingConfig    `json:"routing"`
}

type LogConfig struct {
	LogLevel string `json:"loglevel"`
}

type APIConfig struct {
	Tag      string   `json:"tag"`
	Listen   string   `json:"listen"`
	Services []string `json:"services"`
}

type DNSConfig struct {
	Servers []interface{}     `json:"servers"`
	Hosts   map[string]string `json:"hosts,omitempty"`
}

type PolicyConfig struct {
	Levels map[string]interface{} `json:"levels"`
	System map[string]interface{} `json:"system"`
}

type InboundConfig struct {
	Tag            string          `json:"tag"`
	Port           int             `json:"port"`
	Protocol       string          `json:"protocol"`
	Settings       interface{}     `json:"settings"`
	StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
	Listen         string          `json:"listen,omitempty"`
	Sniffing       *SniffingConfig `json:"sniffing,omitempty"`
}

type SniffingConfig struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
}

type StreamSettings struct {
	Network       string      `json:"network,omitempty"`
	Security      string      `json:"security,omitempty"`
	Reality       *RealitySet `json:"realitySettings,omitempty"`
	XHTTPSettings *XHTTPSet              `json:"xhttpSettings,omitempty"`
	WSSettings    *WSSet                 `json:"wsSettings,omitempty"`
	Sockopt       map[string]interface{} `json:"sockopt,omitempty"`
}

type RealitySet struct {
	Show        bool     `json:"show"`
	Dest        string   `json:"dest"`
	Xver        int      `json:"xver"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIds    []string `json:"shortIds"`
}

type XHTTPSet struct {
	Mode string `json:"mode"`
	Path string `json:"path"`
	Host string `json:"host,omitempty"`
}

type WSSet struct {
	Path string `json:"path"`
}

type RoutingConfig struct {
	DomainStrategy string        `json:"domainStrategy"`
	Rules          []RoutingRule `json:"rules"`
}

type RoutingRule struct {
	Type        string        `json:"type"`
	InboundTag  []string      `json:"inboundTag,omitempty"`
	User        []string      `json:"user,omitempty"`
	Domain      []string      `json:"domain,omitempty"`
	IP          []string      `json:"ip,omitempty"`
	Port        string        `json:"port,omitempty"`
	OutboundTag string        `json:"outboundTag"`
}

func GenerateXrayJSON(userCfg *config.UserConfig, overridePorts map[string]int) ([]byte, error) {
	xc := XrayConfig{}
	xc.Log.LogLevel = "debug"
	xc.Policy.Levels = map[string]interface{}{
		"0": map[string]interface{}{"statsUserUplink": true, "statsUserDownlink": true},
	}
	xc.Policy.System = map[string]interface{}{
		"statsInboundDownlink": true, "statsInboundUplink": true,
		"statsOutboundUplink": true, "statsOutboundDownlink": true,
	}

	// 1. DNS Setup
	isGateway := userCfg.Gateway.LocalEnabled || userCfg.Gateway.LANEnabled
	if isGateway || len(userCfg.CustomOutbounds) > 0 {
		hosts := make(map[string]string)
		if isGateway {
			for _, d := range userCfg.Gateway.Blacklist {
				hosts[d] = "127.0.0.1"
				hosts["*."+d] = "127.0.0.1"
			}
		}

		dnsServers := []interface{}{
			"https://8.8.8.8/dns-query",
			"https://1.1.1.1/dns-query",
			"localhost",
		}

		if isGateway {
			xc.FakeDns = []interface{}{map[string]interface{}{"ipPool": "198.18.0.0/16", "poolSize": 65535}}
			dnsServers = append([]interface{}{map[string]interface{}{"address": "fakedns", "domains": []string{"regexp:.*"}}}, dnsServers...)
		}

		xc.Dns = &DNSConfig{ Servers: dnsServers, Hosts: hosts }
	}

	apiPort := userCfg.APIInbound
	if p, ok := overridePorts["api"]; ok { apiPort = p }

	if apiPort > 0 {
		xc.Api = &APIConfig{
			Tag: "api",
			Listen: fmt.Sprintf("127.0.0.1:%d", apiPort),
			Services: []string{"HandlerService", "LoggerService", "StatsService"},
		}
	}

	getInboundUsers := func(flow string) []map[string]interface{} {
		// 1. Main user
		users := []map[string]interface{}{{"id": userCfg.UUID, "email": "main-user", "level": 0}}
		if flow != "" { users[0]["flow"] = flow }
		
		// 2. Relay users (Internal API use)
		for _, co := range userCfg.CustomOutbounds {
			if !co.Enabled { continue }
			u := map[string]interface{}{"id": co.UserUUID, "email": "user-" + co.Alias, "level": 0}
			if flow != "" { u["flow"] = flow }
			users = append(users, u)
		}

		// 3. Guests
		for _, g := range userCfg.Guests {
			if !g.Enabled { continue }
			u := map[string]interface{}{"id": g.UUID, "email": "guest-" + g.Alias, "level": 0}
			if flow != "" { u["flow"] = flow }
			users = append(users, u)
		}
		return users
	}

	for _, mode := range userCfg.ActiveModes {
		if !mode.Enabled { continue }
		port := mode.Port
		if p, ok := overridePorts[string(mode.Mode)]; ok { port = p }

		in := InboundConfig{
			Tag:      string(mode.Mode) + "-in",
			Port:     port,
			Protocol: getProtocolForMode(mode.Mode),
			Sniffing: &SniffingConfig{Enabled: true, DestOverride: []string{"http", "tls", "quic"}},
		}

		switch mode.Mode {
		case config.ModeVLESSReality:
			in.Settings = map[string]interface{}{"clients": getInboundUsers(""), "decryption": "none", "network": "tcp,udp"}
			in.StreamSettings = &StreamSettings{
				Network:  "xhttp",
				Security: "reality",
				Reality: &RealitySet{
					ServerNames: []string{mode.SNI},
					PrivateKey:  mode.Settings.PrivateKey,
					ShortIds:    []string{mode.Settings.ShortID},
					Dest:        mode.Dest,
					Xver:        0,
				},
				XHTTPSettings: &XHTTPSet{Mode: "stream-up", Path: mode.Path, Host: mode.SNI},
			}
		case config.ModeVLESSVision:
			in.Settings = map[string]interface{}{"clients": getInboundUsers("xtls-rprx-vision"), "decryption": "none", "network": "tcp,udp"}
			in.StreamSettings = &StreamSettings{
				Network:  "tcp",
				Security: "reality",
				Reality: &RealitySet{
					ServerNames: []string{mode.SNI},
					PrivateKey:  mode.Settings.PrivateKey,
					ShortIds:    []string{mode.Settings.ShortID},
					Dest:        mode.Dest,
					Xver:        0,
				},
			}
		case config.ModeVLESSXHTTP:
			in.Settings = map[string]interface{}{"clients": getInboundUsers(""), "decryption": mode.Settings.PrivateKey, "network": "tcp,udp"}
			in.StreamSettings = &StreamSettings{
				Network: "xhttp",
				XHTTPSettings: &XHTTPSet{Mode: "stream-up", Path: mode.Path},
			}
		case config.ModeVMessWS:
			in.Settings = map[string]interface{}{"clients": getInboundUsers(""), "network": "tcp,udp"}
			in.StreamSettings = &StreamSettings{Network: "ws", WSSettings: &WSSet{Path: mode.Path}}
		case config.ModeShadowsocksTCP:
			in.Settings = map[string]interface{}{"method": mode.Settings.Cipher, "password": mode.Settings.Password, "network": "tcp,udp"}
		}
		xc.Inbounds = append(xc.Inbounds, in)
	}

	// Internal Proxies...
	privateIPs := utils.GetLocalPrivateIPs()
	for _, co := range userCfg.CustomOutbounds {
		if !co.Enabled || co.InternalProxyPort == 0 { continue }
		for _, lip := range privateIPs {
			xc.Inbounds = append(xc.Inbounds, InboundConfig{
				Tag: fmt.Sprintf("internal-socks-%s-%s", co.Alias, lip),
				Listen: lip, Port: co.InternalProxyPort, Protocol: "socks",
				Settings: map[string]interface{}{"auth": "noauth", "udp": true},
				Sniffing: &SniffingConfig{Enabled: true, DestOverride: []string{"http", "tls", "quic", "fakedns"}},
			})
			xc.Inbounds = append(xc.Inbounds, InboundConfig{
				Tag: fmt.Sprintf("internal-http-%s-%s", co.Alias, lip),
				Listen: lip, Port: co.InternalProxyPort + 1, Protocol: "http",
				Settings: map[string]interface{}{"auth": "noauth"},
				Sniffing: &SniffingConfig{Enabled: true, DestOverride: []string{"http", "tls", "quic", "fakedns"}},
			})
		}
	}

	// Gateway Inbounds...
	if isGateway {
		dnsPort := 53; if p, ok := overridePorts["dns-in"]; ok { dnsPort = p }
		xc.Inbounds = append(xc.Inbounds, InboundConfig{
			Tag: "dns-in", Port: dnsPort, Protocol: "dokodemo-door",
			Settings: map[string]interface{}{"network": "tcp,udp", "address": "1.1.1.1", "port": 53},
		})
		
		// 1. Local TUN Inbound (Modern approach for local proxy)
		if userCfg.Gateway.LocalEnabled && userCfg.Gateway.Mode == "tun" {
			xc.Inbounds = append(xc.Inbounds, InboundConfig{
				Tag: "tun-local-in", Protocol: "tun",
				Settings: map[string]interface{}{
					"name": "proxya-tun", 
					"address": []string{"172.16.1.1/30"}, 
					"mtu": 1500, 
					"stack": "gvisor", 
					"autoRoute": true, 
					"strictRoute": true,
				},
				Sniffing: &SniffingConfig{Enabled: true, DestOverride: []string{"http", "tls", "quic", "fakedns"}},
			})
		}

		// 2. LAN Gateway Inbound (Always TProxy for better reliability)
		if userCfg.Gateway.LANEnabled {
			tpPort := 12345; if p, ok := overridePorts["tproxy-in"]; ok { tpPort = p }
			xc.Inbounds = append(xc.Inbounds, InboundConfig{
				Tag: "tproxy-in", Port: tpPort, Protocol: "dokodemo-door",
				Settings: map[string]interface{}{"network": "tcp,udp", "followRedirect": true},
				StreamSettings: &StreamSettings{Sockopt: map[string]interface{}{"tproxy": "tproxy", "mark": 255}},
				Sniffing: &SniffingConfig{Enabled: true, DestOverride: []string{"http", "tls", "quic", "fakedns"}},
			})
		}
	}

	// 1. Relay Outbounds (Specific Nodes)
	for _, co := range userCfg.CustomOutbounds {
		if !co.Enabled { continue }
		out := deepCopyMap(co.Config); out["tag"] = "outbound-" + co.Alias
		xc.Outbounds = append(xc.Outbounds, out)
	}

	// 2. Guest Dedicated Outbounds
	for _, g := range userCfg.Guests {
		if !g.Enabled || g.OutboundConf == nil { continue }
		out := deepCopyMap(g.OutboundConf); out["tag"] = "guest-outbound-" + g.Alias
		xc.Outbounds = append(xc.Outbounds, out)
	}

	// 3. System Outbounds (Low Priority)
	xc.Outbounds = append(xc.Outbounds, map[string]interface{}{"protocol": "freedom", "tag": "direct"})
	xc.Outbounds = append(xc.Outbounds, map[string]interface{}{"protocol": "blackhole", "tag": "blocked"})
	if isGateway {
		xc.Outbounds = append(xc.Outbounds, map[string]interface{}{"protocol": "dns", "tag": "dns-out"})
	}

	// Test Inbound
	testPort := userCfg.TestInbound; if p, ok := overridePorts["test-socks"]; ok { testPort = p }
	testAccounts := []map[string]interface{}{{"user": "direct", "pass": "test"}}
	for _, co := range userCfg.CustomOutbounds {
		if !co.Enabled { continue }
		testAccounts = append(testAccounts, map[string]interface{}{"user": "user-" + co.Alias, "pass": "test"})
	}
	for _, g := range userCfg.Guests {
		if !g.Enabled { continue }
		testAccounts = append(testAccounts, map[string]interface{}{"user": "test-" + g.Alias, "pass": "test"})
	}
	xc.Inbounds = append(xc.Inbounds, InboundConfig{
		Tag: "test-socks", Listen: "127.0.0.1", Port: testPort, Protocol: "socks",
		Settings: map[string]interface{}{"auth": "password", "accounts": testAccounts, "udp": true},
		Sniffing: &SniffingConfig{Enabled: true, DestOverride: []string{"http", "tls", "quic"}},
	})

	xc.Routing.DomainStrategy = "AsIs"
	var rules []RoutingRule

	// 1. Mandatory routing for isolated tests (test-socks)
	for _, co := range userCfg.CustomOutbounds {
		if !co.Enabled { continue }
		rules = append(rules, RoutingRule{
			Type: "field", 
			InboundTag: []string{"test-socks"}, 
			OutboundTag: "outbound-" + co.Alias,
		})
	}

	// 2. Standard System Inbounds (API & DNS)
	rules = append(rules, RoutingRule{Type: "field", InboundTag: []string{"api"}, OutboundTag: "api"})
	rules = append(rules, RoutingRule{Type: "field", InboundTag: []string{"tun-local-in", "tun-lan-in", "tproxy-in", "dns-in"}, Port: "53", OutboundTag: "dns-out"})

	// 3. Transparent Gateway Redirection
	if isGateway && userCfg.Gateway.RelayAlias != "" {
		rules = append(rules, RoutingRule{Type: "field", InboundTag: []string{"tun-local-in", "tun-lan-in", "tproxy-in"}, OutboundTag: "outbound-" + userCfg.Gateway.RelayAlias})
	}

	// 4. Internal Proxy Routing (SOCKS/HTTP provided for each custom outbound)
	for _, co := range userCfg.CustomOutbounds {
		if !co.Enabled || co.InternalProxyPort == 0 { continue }
		var tags []string
		for _, lip := range privateIPs {
			tags = append(tags, fmt.Sprintf("internal-socks-%s-%s", co.Alias, lip), fmt.Sprintf("internal-http-%s-%s", co.Alias, lip))
		}
		rules = append(rules, RoutingRule{Type: "field", InboundTag: tags, OutboundTag: "outbound-" + co.Alias})
	}

	// 5. Guest & Relay User Identity-based Routing (Low Priority)
	for _, g := range userCfg.Guests {
		if !g.Enabled { continue }
		outTag := "direct"; if g.OutboundConf != nil { outTag = "guest-outbound-" + g.Alias }
		rules = append(rules, RoutingRule{Type: "field", User: []string{"guest-" + g.Alias, "test-" + g.Alias}, OutboundTag: outTag})
	}

	for _, co := range userCfg.CustomOutbounds {
		if !co.Enabled { continue }
		rules = append(rules, RoutingRule{Type: "field", User: []string{"user-" + co.Alias, "test-" + co.Alias}, OutboundTag: "outbound-" + co.Alias})
	}

	// 6. Default Fallback
	rules = append(rules, RoutingRule{Type: "field", User: []string{"main-user", "direct"}, OutboundTag: "direct"})
	rules = append(rules, RoutingRule{Type: "field", InboundTag: []string{"test-socks"}, OutboundTag: "blocked"}) // Block leaked test-socks
	xc.Routing.Rules = rules

	return json.MarshalIndent(xc, "", "  ")
}

func getProtocolForMode(m config.PresetMode) string {
	switch m {
	case config.ModeVLESSReality, config.ModeVLESSVision, config.ModeVLESSXHTTP: return "vless"
	case config.ModeVMessWS: return "vmess"
	case config.ModeShadowsocksTCP: return "shadowsocks"
	}
	return ""
}

func deepCopyMap(m map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{})
	for k, v := range m {
		switch vm := v.(type) {
		case map[string]interface{}: cp[k] = deepCopyMap(vm)
		case []interface{}: cp[k] = deepCopySlice(vm)
		default: cp[k] = v
		}
	}
	return cp
}

func deepCopySlice(s []interface{}) []interface{} {
	cp := make([]interface{}, len(s))
	for i, v := range s {
		switch vm := v.(type) {
		case map[string]interface{}: cp[i] = deepCopyMap(vm)
		case []interface{}: cp[i] = deepCopySlice(vm)
		default: cp[i] = v
		}
	}
	return cp
}
