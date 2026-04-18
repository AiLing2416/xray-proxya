package xray

import (
	"encoding/json"
	"xray-proxya/internal/config"
)

func GenerateXrayJSON(userCfg *config.UserConfig, overridePorts map[string]int) ([]byte, error) {
	isGateway := userCfg.Role == config.RoleGateway
	relayAlias := ""
	if isGateway { relayAlias = userCfg.Gateway.RelayAlias }

	xc := make(map[string]interface{})
	xc["log"] = map[string]interface{}{"loglevel": "debug"}

	// 1. DNS
	dns := make(map[string]interface{})
	dns["servers"] = []interface{}{
		"https://dns.google/dns-query",
		"https://cloudflare-dns.com/dns-query",
	}
	dns["hosts"] = map[string]string{
		"dns.google":         "8.8.8.8",
		"cloudflare-dns.com": "1.1.1.1",
	}
	dns["tag"] = "dns-internal"
	dns["queryStrategy"] = "UseIP"
	xc["dns"] = dns

	// 2. Inbounds
	inbounds := []interface{}{}
	
	apiPort := userCfg.APIInbound; if p, ok := overridePorts["api"]; ok { apiPort = p }
	if apiPort > 0 {
		xc["api"] = map[string]interface{}{"tag": "api", "services": []string{"HandlerService", "LoggerService", "StatsService"}}
		inbounds = append(inbounds, map[string]interface{}{
			"tag": "api", "port": apiPort, "listen": "127.0.0.1", "protocol": "dokodemo-door", "settings": map[string]interface{}{"address": "127.0.0.1"},
		})
	}

	if isGateway {
		if userCfg.Gateway.Mode == "tun" {
			inbounds = append(inbounds, map[string]interface{}{
				"tag": "tun-in", "protocol": "tun",
				"settings": map[string]interface{}{
					"name": "proxya-tun", "mtu": 1500, "address": []string{"172.16.255.1/30", "fd00:eea:ff::1/126"},
					"autoRoute": false, "strictRoute": true, "stack": "gvisor",
				},
				"sniffing": map[string]interface{}{"enabled": true, "destOverride": []string{"http", "tls", "quic", "fakedns"}, "routeOnly": true},
			})
		}
		// PRIMARY DNS: Listen on 53 for everyone
		inbounds = append(inbounds, map[string]interface{}{
			"tag": "dns-in", "port": 53, "listen": "0.0.0.0", "protocol": "dokodemo-door",
			"settings": map[string]interface{}{"network": "tcp,udp", "address": "1.1.1.1", "port": 53},
		})
	}

	xc["inbounds"] = inbounds

	// 3. Outbounds
	outbounds := []interface{}{
		map[string]interface{}{"protocol": "freedom", "tag": "direct", "settings": map[string]interface{}{"domainStrategy": "UseIP"}, "streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"mark": 255}}},
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
		outbounds = append(outbounds, out)
	}
	xc["outbounds"] = outbounds

	// 4. Routing
	rules := []interface{}{
		map[string]interface{}{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
		map[string]interface{}{"type": "field", "inboundTag": []string{"dns-in"}, "outboundTag": "dns-out"},
		map[string]interface{}{"type": "field", "port": "53", "outboundTag": "dns-out"},
		map[string]interface{}{"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "direct"},
	}

	if isGateway && relayAlias != "" {
		target := "outbound-" + relayAlias
		rules = append(rules, map[string]interface{}{"type": "field", "network": "tcp,udp", "outboundTag": target})
	} else {
		rules = append(rules, map[string]interface{}{"type": "field", "network": "tcp,udp", "outboundTag": "direct"})
	}
	
	xc["routing"] = map[string]interface{}{"domainStrategy": "IPIfNonMatch", "rules": rules}
	xc["stats"] = map[string]interface{}{}
	xc["policy"] = map[string]interface{}{"levels": map[string]interface{}{"0": map[string]interface{}{"statsUserUplink": true, "statsUserDownlink": true}}}

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
