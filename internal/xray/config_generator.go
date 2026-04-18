package xray

import (
	"encoding/json"
	"fmt"
	"xray-proxya/internal/config"
	"xray-proxya/pkg/utils"
)

func GenerateXrayJSON(userCfg *config.UserConfig, overridePorts map[string]int, testTarget string) ([]byte, error) {
	isGateway := userCfg.Role == config.RoleGateway
	relayAlias := ""
	if isGateway { relayAlias = userCfg.Gateway.RelayAlias }

	xc := make(map[string]interface{})
	xc["log"] = map[string]interface{}{"loglevel": "warning"}

	// 1. DNS
	xc["dns"] = map[string]interface{}{
		"servers": []interface{}{"https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query", "localhost"},
		"tag": "dns-internal", "queryStrategy": "UseIP",
	}
	xc["policy"] = map[string]interface{}{
		"levels": map[string]interface{}{"0": map[string]interface{}{"statsUserUplink": true, "statsUserDownlink": true}},
		"system": map[string]interface{}{"statsInboundUplink": true, "statsInboundDownlink": true},
	}

	// 2. Port Management & Audit
	// Rule: Test Port is ALWAYS random and new
	testPort, _ := utils.GetFreePort()
	if p, ok := overridePorts["test-socks"]; ok {
		testPort = p
	}
	
	// Rule: API and Presets follow "Sticky but Dynamic" policy
	ensurePort := func(label string, current int) int {
		// If provided in overrides (like during isolated test), use it directly
		if val, ok := overridePorts[label]; ok { return val }
		
		// If current is free, stick with it
		if current > 0 && utils.IsPortFree(current) { return current }
		
		// Otherwise, find a new one and WARN
		newPort, _ := utils.GetFreePort()
		fmt.Printf("⚠️  Warning: Port %d (%s) is occupied. Switched to %d.\n", current, label, newPort)
		return newPort
	}

	// Audit API Port
	userCfg.APIInbound = ensurePort("api", userCfg.APIInbound)

	// 3. Inbounds
	inbounds := []interface{}{}
	
	// 3.1 API Inbound
	if userCfg.APIInbound > 0 {
		xc["api"] = map[string]interface{}{"tag": "api", "services": []string{"HandlerService", "LoggerService", "StatsService"}}
		inbounds = append(inbounds, map[string]interface{}{
			"tag": "api", "port": userCfg.APIInbound, "listen": "127.0.0.1", "protocol": "dokodemo-door", "settings": map[string]interface{}{"address": "127.0.0.1"},
		})
	}

	// 3.2 Test Proxy (Always random)
	inbounds = append(inbounds, map[string]interface{}{
		"tag": "test-socks", "port": testPort, "listen": "::", "protocol": "socks",
		"settings": map[string]interface{}{"auth": "noauth", "udp": true},
		"sniffing": map[string]interface{}{"enabled": true, "destOverride": []string{"http", "tls", "quic", "fakedns"}},
	})

	// 3.3 Preset Service Inbounds
	for i, m := range userCfg.ActiveModes {
		if !m.Enabled { continue }
		
		// Audit Preset Port
		newPort := ensurePort(string(m.Mode), m.Port)
		if newPort != m.Port { userCfg.ActiveModes[i].Port = newPort }
		
		in := map[string]interface{}{
			"tag": string(m.Mode), "port": newPort, "listen": "::",
			"sniffing": map[string]interface{}{"enabled": true, "destOverride": []string{"http", "tls", "quic", "fakedns"}},
		}
		
		clientEmail := "service-" + string(m.Mode)
		client := map[string]interface{}{"id": userCfg.UUID, "email": clientEmail}

		switch m.Mode {
		case config.ModeVLESSVision:
			in["protocol"] = "vless"
			client["flow"] = "xtls-rprx-vision"
			in["settings"] = map[string]interface{}{"clients": []interface{}{client}, "decryption": "none"}
			in["streamSettings"] = map[string]interface{}{
				"network": "tcp", "security": "reality",
				"realitySettings": map[string]interface{}{"dest": m.Dest, "serverNames": []string{m.SNI}, "privateKey": m.Settings.PrivateKey, "shortIds": []string{m.Settings.ShortID}},
			}
		case config.ModeVLESSReality:
			in["protocol"] = "vless"
			in["settings"] = map[string]interface{}{"clients": []interface{}{client}, "decryption": "none"}
			in["streamSettings"] = map[string]interface{}{
				"network": "xhttp", "security": "reality", "xhttpSettings": map[string]interface{}{"path": m.Path},
				"realitySettings": map[string]interface{}{"dest": m.Dest, "serverNames": []string{m.SNI}, "privateKey": m.Settings.PrivateKey, "shortIds": []string{m.Settings.ShortID}},
			}
		case config.ModeVLESSXHTTP:
			in["protocol"] = "vless"
			in["settings"] = map[string]interface{}{"clients": []interface{}{client}, "decryption": "none"}
			in["streamSettings"] = map[string]interface{}{"network": "xhttp", "xhttpSettings": map[string]interface{}{"path": m.Path}}
		case config.ModeVMessWS:
			in["protocol"] = "vmess"
			in["settings"] = map[string]interface{}{"clients": []interface{}{client}}
			in["streamSettings"] = map[string]interface{}{"network": "ws", "wsSettings": map[string]interface{}{"path": m.Path}}
		case config.ModeShadowsocksTCP:
			in["protocol"] = "shadowsocks"
			in["settings"] = map[string]interface{}{"method": m.Settings.Cipher, "password": m.Settings.Password, "email": clientEmail}
		}
		inbounds = append(inbounds, in)
	}

	if isGateway {
		inbounds = append(inbounds, map[string]interface{}{
			"tag": "tun-in", "protocol": "tun",
			"settings": map[string]interface{}{
				"name": "proxya-tun", "mtu": 1500, "address": []string{"172.16.255.1/30", "fd00:eea:ff::1/126"},
				"autoRoute": false, "strictRoute": true, "stack": "gvisor",
			},
			"sniffing": map[string]interface{}{"enabled": true, "destOverride": []string{"http", "tls", "quic", "fakedns"}},
		})
		inbounds = append(inbounds, map[string]interface{}{
			"tag": "dns-in", "port": 53, "listen": "::", "protocol": "dokodemo-door",
			"settings": map[string]interface{}{"network": "tcp,udp", "followRedirect": true},
		})
	}
	xc["inbounds"] = inbounds

	// 4. Outbounds
	xc["outbounds"] = []interface{}{
		map[string]interface{}{
			"protocol": "freedom", "tag": "direct", 
			"settings": map[string]interface{}{"domainStrategy": "UseIP"},
			"streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"mark": 255}}, 
		},
		map[string]interface{}{"protocol": "dns", "tag": "dns-out", "streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"mark": 255}}},
		map[string]interface{}{"protocol": "blackhole", "tag": "blocked"},
	}

	for _, co := range userCfg.CustomOutbounds {
		if !co.Enabled { continue }
		out := deepCopyMap(co.Config)
		out["tag"] = "outbound-" + co.Alias
		ss, _ := out["streamSettings"].(map[string]interface{})
		if ss == nil { ss = make(map[string]interface{}); out["streamSettings"] = ss }
		so, _ := ss["sockopt"].(map[string]interface{})
		if so == nil { so = make(map[string]interface{}); ss["sockopt"] = so }
		so["mark"] = 255
		xc["outbounds"] = append(xc["outbounds"].([]interface{}), out)
	}

	// 5. Routing
	rules := []interface{}{
		map[string]interface{}{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
		map[string]interface{}{"type": "field", "inboundTag": []string{"dns-in"}, "outboundTag": "dns-out"},
		map[string]interface{}{"type": "field", "port": "53", "outboundTag": "dns-out"},
		map[string]interface{}{"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "direct"},
	}

	if testTarget != "" {
		rules = append(rules, map[string]interface{}{"type": "field", "inboundTag": []string{"test-socks"}, "outboundTag": "outbound-" + testTarget})
	}

	if isGateway && relayAlias != "" {
		rules = append(rules, map[string]interface{}{
			"type": "field", 
			"inboundTag": []string{"tun-in"}, 
			"outboundTag": "outbound-" + relayAlias,
		})
	}

	rules = append(rules, map[string]interface{}{"type": "field", "user": []string{"regexp:service-.*"}, "outboundTag": "direct"})
	rules = append(rules, map[string]interface{}{"type": "field", "network": "tcp,udp", "outboundTag": "direct"})
	rules = append(rules, map[string]interface{}{"type": "field", "inboundTag": []string{"test-socks"}, "outboundTag": "blocked"})

	xc["routing"] = map[string]interface{}{"domainStrategy": "IPIfNonMatch", "rules": rules}
	xc["stats"] = map[string]interface{}{}

	return json.MarshalIndent(xc, "", "  ")
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

type XrayConfig struct{}
type LogConfig struct{}
type APIConfig struct{}
type DNSConfig struct{}
type InboundConfig struct{}
type StreamSettings struct{}
type SniffingConfig struct{}
type RoutingConfig struct{}
type RoutingRule struct{}
