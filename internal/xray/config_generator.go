package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"xray-proxya/internal/config"
)

const DefaultDNSQueryStrategy = "UseIP"

var validDNSQueryStrategies = map[string]string{
	"useip":   "UseIP",
	"useipv4": "UseIPv4",
	"useipv6": "UseIPv6",
}

func NormalizeDNSQueryStrategy(value string) (string, bool) {
	normalized, ok := validDNSQueryStrategies[strings.ToLower(strings.TrimSpace(value))]
	return normalized, ok
}

func normalizeDNSServers(servers []string) []string {
	if len(servers) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(servers))
	normalized := make([]string, 0, len(servers))
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		if _, ok := seen[server]; ok {
			continue
		}
		seen[server] = struct{}{}
		normalized = append(normalized, server)
	}
	return normalized
}

func defaultDNSServers(_ bool) []interface{} {
	return []interface{}{"https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"}
}

func findOutboundByAlias(userCfg *config.UserConfig, alias string) *config.CustomOutbound {
	for i := range userCfg.CustomOutbounds {
		if userCfg.CustomOutbounds[i].Alias == alias {
			return &userCfg.CustomOutbounds[i]
		}
	}
	return nil
}

func selectDNSOutboundAlias(relayAlias string, testTarget string) string {
	switch {
	case testTarget != "":
		return testTarget
	case relayAlias != "":
		return relayAlias
	default:
		return ""
	}
}

func resolveDNSConfig(userCfg *config.UserConfig, relayAlias string, testTarget string, isGateway bool) (string, string, []string) {
	selectedAlias := selectDNSOutboundAlias(relayAlias, testTarget)
	strategy := DefaultDNSQueryStrategy
	servers := make([]string, 0, len(defaultDNSServers(isGateway)))
	for _, server := range defaultDNSServers(isGateway) {
		if text, ok := server.(string); ok {
			servers = append(servers, text)
		}
	}

	if selectedAlias != "" {
		if co := findOutboundByAlias(userCfg, selectedAlias); co != nil {
			if normalized, ok := NormalizeDNSQueryStrategy(co.DNSStrategy); ok {
				strategy = normalized
			}
			if customServers := normalizeDNSServers(co.DNSServers); len(customServers) > 0 {
				servers = customServers
			}
		}
	}

	return selectedAlias, strategy, servers
}

func buildDNSConfig(userCfg *config.UserConfig, relayAlias string, testTarget string, isGateway bool) map[string]interface{} {
	_, strategy, serverStrings := resolveDNSConfig(userCfg, relayAlias, testTarget, isGateway)
	servers := make([]interface{}, 0, len(serverStrings)+1)
	servers = append(servers, "fakedns")
	for _, server := range serverStrings {
		servers = append(servers, server)
	}

	return map[string]interface{}{
		"hosts": map[string]interface{}{
			"dns.google":         "8.8.8.8",
			"cloudflare-dns.com": "1.1.1.1",
		},
		"servers":       servers,
		"tag":           "dns-internal",
		"queryStrategy": strategy,
	}
}

func dnsRoutingTargets(servers []string) ([]string, []string) {
	domains := make([]string, 0, len(servers))
	ips := make([]string, 0, len(servers))
	seenDomains := make(map[string]struct{}, len(servers))
	seenIPs := make(map[string]struct{}, len(servers))

	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		host := server
		if strings.Contains(server, "://") {
			u, err := url.Parse(server)
			if err != nil {
				continue
			}
			host = u.Hostname()
		} else if parsedHost, parsedPort, err := net.SplitHostPort(server); err == nil && parsedHost != "" && parsedPort != "" {
			host = parsedHost
		}

		host = strings.Trim(host, "[]")
		if host == "" || strings.EqualFold(host, "localhost") {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			normalizedIP := ip.String()
			if _, ok := seenIPs[normalizedIP]; ok {
				continue
			}
			seenIPs[normalizedIP] = struct{}{}
			ips = append(ips, normalizedIP)
			continue
		}
		if _, ok := seenDomains[host]; ok {
			continue
		}
		seenDomains[host] = struct{}{}
		domains = append(domains, host)
	}

	return domains, ips
}

func buildDNSOutboundRoutingRules(selectedAlias string, servers []string) []interface{} {
	if selectedAlias == "" {
		return nil
	}
	domains, ips := dnsRoutingTargets(servers)
	rules := make([]interface{}, 0, 2)
	outboundTag := "outbound-" + selectedAlias
	if len(domains) > 0 {
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"domain":      domains,
			"outboundTag": outboundTag,
		})
	}
	if len(ips) > 0 {
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"ip":          ips,
			"outboundTag": outboundTag,
		})
	}
	return rules
}

func buildDNSInbound(port int) map[string]interface{} {
	return map[string]interface{}{
		"tag":      "dns-in",
		"port":     port,
		"listen":   "127.0.0.1",
		"protocol": "dokodemo-door",
		"settings": map[string]interface{}{
			"address": "8.8.8.8",
			"port":    53,
			"network": "tcp,udp",
		},
	}
}

func GenerateXrayJSON(userCfg *config.UserConfig, overridePorts map[string]int, testTarget string) ([]byte, error) {
	isGateway := userCfg.Role == config.RoleGateway
	relayAlias := ""
	if isGateway {
		relayAlias = userCfg.Gateway.RelayAlias
	}
	if !isGateway && userCfg.Gateway.RelayAlias != "" {
		relayAlias = userCfg.Gateway.RelayAlias
	}

	xc := make(map[string]interface{})
	xc["log"] = map[string]interface{}{"loglevel": "warning"}

	// 1. DNS
	xc["dns"] = buildDNSConfig(userCfg, relayAlias, testTarget, isGateway)
	xc["policy"] = map[string]interface{}{
		"levels": map[string]interface{}{"0": map[string]interface{}{"statsUserUplink": true, "statsUserDownlink": true}},
		"system": map[string]interface{}{
			"statsInboundUplink":    true,
			"statsInboundDownlink":  true,
			"statsOutboundUplink":   true,
			"statsOutboundDownlink": true,
		},
	}

	// 2. Port Selection
	getPort := func(label string, defaultVal int) int {
		if val, ok := overridePorts[label]; ok {
			return val
		}
		return defaultVal
	}
	apiPort := getPort("api", userCfg.APIInbound)
	testPort := getPort("test-socks", 10086)
	dnsInPort := getPort("dns-in", 0)
	camoPort := getPort("camouflage", 0) // Default 0 means no camo unless requested via override or dynamically in run
	_, disableGatewayTun := overridePorts["gateway-tun-disabled"]
	relayInboundTags := map[string][]string{}
	for _, co := range userCfg.CustomOutbounds {
		if co.InternalProxyPort <= 0 {
			continue
		}
		tagBase := sanitizeTagComponent(co.Alias)
		relayInboundTags[co.Alias] = []string{"relay-socks-" + tagBase, "relay-http-" + tagBase}
	}

	// 3. Inbounds
	inbounds := []interface{}{}
	if apiPort > 0 {
		xc["api"] = map[string]interface{}{"tag": "api", "services": []string{"HandlerService", "LoggerService", "StatsService"}}
		inbounds = append(inbounds, map[string]interface{}{"tag": "api", "port": apiPort, "listen": "127.0.0.1", "protocol": "dokodemo-door", "settings": map[string]interface{}{"address": "127.0.0.1"}})
	}
	if dnsInPort > 0 {
		inbounds = append(inbounds, buildDNSInbound(dnsInPort))
	}
	inbounds = append(inbounds, map[string]interface{}{"tag": "test-socks", "port": testPort, "listen": "0.0.0.0", "protocol": "socks", "settings": map[string]interface{}{"auth": "noauth", "udp": true}, "sniffing": map[string]interface{}{"enabled": true, "destOverride": []string{"http", "tls", "quic", "fakedns"}}})
	for _, co := range userCfg.CustomOutbounds {
		if co.InternalProxyPort <= 0 {
			continue
		}
		tags := relayInboundTags[co.Alias]
		inbounds = append(inbounds,
			map[string]interface{}{"tag": tags[0], "port": co.InternalProxyPort, "listen": "127.0.0.1", "protocol": "socks", "settings": map[string]interface{}{"auth": "noauth", "udp": true}, "sniffing": map[string]interface{}{"enabled": true, "destOverride": []string{"http", "tls", "quic", "fakedns"}}},
			map[string]interface{}{"tag": tags[1], "port": co.InternalProxyPort + 1, "listen": "127.0.0.1", "protocol": "http", "sniffing": map[string]interface{}{"enabled": true, "destOverride": []string{"http", "tls", "quic", "fakedns"}}},
		)
	}

	for _, m := range userCfg.ActiveModes {
		if !m.Enabled {
			continue
		}
		mPort := getPort(string(m.Mode), m.Port)
		in := map[string]interface{}{"tag": string(m.Mode), "port": mPort, "listen": "::", "sniffing": map[string]interface{}{"enabled": true, "destOverride": []string{"http", "tls", "quic", "fakedns"}}}

		dest := m.Dest
		if m.Skin && camoPort > 0 {
			dest = fmt.Sprintf("127.0.0.1:%d", camoPort)
		}

		clients := []interface{}{map[string]interface{}{"id": userCfg.UUID, "email": "service-user"}}
		for _, co := range userCfg.CustomOutbounds {
			if !co.Enabled || co.UserUUID == "" {
				continue
			}
			clients = append(clients, map[string]interface{}{"id": co.UserUUID, "email": relayUserEmail(co.Alias)})
		}
		for _, guest := range userCfg.Guests {
			if guest.UUID == "" {
				continue
			}
			clients = append(clients, map[string]interface{}{"id": guest.UUID, "email": guestUserEmail(guest.Alias)})
		}
		switch m.Mode {
		case config.ModeVLESSVision:
			in["protocol"] = "vless"
			visionClients := make([]interface{}, 0, len(clients))
			for _, rawClient := range clients {
				client := deepCopyMap(rawClient.(map[string]interface{}))
				client["flow"] = "xtls-rprx-vision"
				visionClients = append(visionClients, client)
			}
			in["settings"] = map[string]interface{}{"clients": visionClients, "decryption": "none"}
			in["streamSettings"] = map[string]interface{}{"network": "tcp", "security": "reality", "realitySettings": map[string]interface{}{"dest": dest, "serverNames": []string{m.SNI}, "privateKey": m.Settings.PrivateKey, "shortIds": []string{m.Settings.ShortID}}}
		case config.ModeVLESSReality:
			in["protocol"] = "vless"
			in["settings"] = map[string]interface{}{"clients": clients, "decryption": "none"}
			in["streamSettings"] = map[string]interface{}{"network": "xhttp", "security": "reality", "xhttpSettings": map[string]interface{}{"path": m.Path}, "realitySettings": map[string]interface{}{"dest": dest, "serverNames": []string{m.SNI}, "privateKey": m.Settings.PrivateKey, "shortIds": []string{m.Settings.ShortID}}}
		case config.ModeVLESSXHTTP:
			in["protocol"] = "vless"
			settings := map[string]interface{}{"clients": clients, "decryption": "none"}
			if dest != "" {
				settings["fallbacks"] = []interface{}{map[string]interface{}{"dest": dest}}
			}
			in["settings"] = settings
			in["streamSettings"] = map[string]interface{}{"network": "xhttp", "xhttpSettings": map[string]interface{}{"path": m.Path}}
		case config.ModeVMessWS:
			in["protocol"] = "vmess"
			in["settings"] = map[string]interface{}{"clients": clients}
			in["streamSettings"] = map[string]interface{}{"network": "ws", "wsSettings": map[string]interface{}{"path": m.Path}}
		case config.ModeShadowsocksTCP:
			in["protocol"] = "shadowsocks"
			in["settings"] = map[string]interface{}{"method": m.Settings.Cipher, "password": m.Settings.Password, "email": "service-user"}
		}
		inbounds = append(inbounds, in)
	}

	if isGateway && !disableGatewayTun {
		inbounds = append(inbounds, map[string]interface{}{
			"tag": "tun-in", "protocol": "tun",
			"settings": map[string]interface{}{
				"name": "proxya-tun", "mtu": 1500,
				"address":   []string{"172.16.255.1/30", "fd00:eea:ff::1/126"},
				"autoRoute": false, "strictRoute": true, "stack": "gvisor",
			},
			"sniffing": map[string]interface{}{
				"enabled":      true,
				"destOverride": []string{"http", "tls", "quic", "fakedns"},
			},
		})
	}
	xc["inbounds"] = inbounds

	// 4. Outbounds
	xc["outbounds"] = []interface{}{
		map[string]interface{}{"protocol": "freedom", "tag": "direct", "settings": map[string]interface{}{"domainStrategy": "UseIP"}, "streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"mark": 255}}},
		map[string]interface{}{"protocol": "dns", "tag": "dns-out", "streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"mark": 255}}},
		map[string]interface{}{"protocol": "blackhole", "tag": "blocked"},
	}
	for _, co := range userCfg.CustomOutbounds {
		if !co.Enabled {
			continue
		}
		out := deepCopyMap(co.Config)
		out["tag"] = "outbound-" + co.Alias
		ss, _ := out["streamSettings"].(map[string]interface{})
		if ss == nil {
			ss = make(map[string]interface{})
			out["streamSettings"] = ss
		}
		so, _ := ss["sockopt"].(map[string]interface{})
		if so == nil {
			so = make(map[string]interface{})
			ss["sockopt"] = so
		}
		so["mark"] = 255
		xc["outbounds"] = append(xc["outbounds"].([]interface{}), out)
	}
	for _, guest := range userCfg.Guests {
		if guest.OutboundConf == nil {
			continue
		}
		out := deepCopyMap(guest.OutboundConf)
		out["tag"] = guestOutboundTag(guest.Alias)
		ss, _ := out["streamSettings"].(map[string]interface{})
		if ss == nil {
			ss = make(map[string]interface{})
			out["streamSettings"] = ss
		}
		so, _ := ss["sockopt"].(map[string]interface{})
		if so == nil {
			so = make(map[string]interface{})
			ss["sockopt"] = so
		}
		so["mark"] = 255
		xc["outbounds"] = append(xc["outbounds"].([]interface{}), out)
	}

	// 5. Routing
	selectedDNSAlias, _, selectedDNSServers := resolveDNSConfig(userCfg, relayAlias, testTarget, isGateway)
	rules := []interface{}{
		map[string]interface{}{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
	}
	if testTarget != "" {
		rules = append(rules, map[string]interface{}{"type": "field", "inboundTag": []string{"test-socks"}, "outboundTag": "outbound-" + testTarget})
	}
	if dnsInPort > 0 {
		rules = append(rules, map[string]interface{}{"type": "field", "inboundTag": []string{"dns-in"}, "outboundTag": "dns-out"})
	}
	rules = append(rules, buildDNSOutboundRoutingRules(selectedDNSAlias, selectedDNSServers)...)
	rules = append(rules,
		map[string]interface{}{"type": "field", "port": "53", "outboundTag": "dns-out"},
		map[string]interface{}{"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "direct"},
	)

	if relayAlias != "" {
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"inboundTag":  []string{"tun-in"},
			"outboundTag": "outbound-" + relayAlias,
		})
	}
	for _, co := range userCfg.CustomOutbounds {
		if !co.Enabled {
			continue
		}
		if tags, ok := relayInboundTags[co.Alias]; ok {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"inboundTag":  tags,
				"outboundTag": "outbound-" + co.Alias,
			})
		}
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"user":        []string{relayUserEmail(co.Alias)},
			"outboundTag": "outbound-" + co.Alias,
		})
	}
	for _, guest := range userCfg.Guests {
		targetOutbound := "direct"
		if guest.OutboundConf != nil {
			targetOutbound = guestOutboundTag(guest.Alias)
		}
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"user":        []string{guestUserEmail(guest.Alias)},
			"outboundTag": targetOutbound,
		})
	}

	rules = append(rules, map[string]interface{}{"type": "field", "user": []string{"service-user"}, "outboundTag": "direct"})
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
		case map[string]interface{}:
			cp[k] = deepCopyMap(vm)
		case []interface{}:
			cp[k] = deepCopySlice(vm)
		default:
			cp[k] = v
		}
	}
	return cp
}
func deepCopySlice(s []interface{}) []interface{} {
	cp := make([]interface{}, len(s))
	for i, v := range s {
		switch vm := v.(type) {
		case map[string]interface{}:
			cp[i] = deepCopyMap(vm)
		case []interface{}:
			cp[i] = deepCopySlice(vm)
		default:
			cp[i] = v
		}
	}
	return cp
}

func sanitizeTagComponent(value string) string {
	if value == "" {
		return "default"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune('-')
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "default"
	}
	return out
}

func relayUserEmail(alias string) string {
	return "relay-" + sanitizeTagComponent(alias)
}

func guestUserEmail(alias string) string {
	return "guest-" + sanitizeTagComponent(alias)
}

func guestOutboundTag(alias string) string {
	return "guest-outbound-" + sanitizeTagComponent(alias)
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
