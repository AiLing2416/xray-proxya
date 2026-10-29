package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/pkg/utils"
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
	strategy := ""
	var servers []string

	// 1. If selectedAlias has per-relay co.DNSStrategy / co.DNSServers set, use those.
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

	// 2. Else if isGateway: if userCfg.Gateway.DNSStrategy != "" (valid strategy), use it;
	//    if len(userCfg.Gateway.DNSServers) > 0, use normalizeDNSServers(userCfg.Gateway.DNSServers).
	if isGateway && userCfg != nil {
		if strategy == "" && userCfg.Gateway.DNSStrategy != "" {
			if normalized, ok := NormalizeDNSQueryStrategy(userCfg.Gateway.DNSStrategy); ok {
				strategy = normalized
			}
		}
		if len(servers) == 0 && len(userCfg.Gateway.DNSServers) > 0 {
			if customServers := normalizeDNSServers(userCfg.Gateway.DNSServers); len(customServers) > 0 {
				servers = customServers
			}
		}
	}

	// 3. Else use DefaultDNSQueryStrategy ("UseIP") and defaultDNSServers.
	if strategy == "" {
		strategy = DefaultDNSQueryStrategy
	}
	if len(servers) == 0 {
		for _, server := range defaultDNSServers(isGateway) {
			if text, ok := server.(string); ok {
				servers = append(servers, text)
			}
		}
	}

	return selectedAlias, strategy, servers
}

func buildDNSConfig(userCfg *config.UserConfig, relayAlias string, testTarget string, isGateway bool) map[string]interface{} {
	_, strategy, serverStrings := resolveDNSConfig(userCfg, relayAlias, testTarget, isGateway)
	servers := make([]interface{}, 0, len(serverStrings))
	for _, server := range serverStrings {
		servers = append(servers, server)
	}

	hosts := map[string]interface{}{
		"dns.google":         "8.8.8.8",
		"cloudflare-dns.com": "1.1.1.1",
	}

	if isGateway && userCfg != nil && len(userCfg.Gateway.DNSRecords) > 0 {
		for domain, ips := range userCfg.Gateway.DNSRecords {
			d := strings.ToLower(strings.TrimSpace(domain))
			if d == "" {
				continue
			}
			if len(ips) == 1 {
				hosts[d] = ips[0]
			} else if len(ips) > 1 {
				hosts[d] = ips
			}
		}
	}

	return map[string]interface{}{
		"hosts":         hosts,
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
			scheme := strings.ToLower(u.Scheme)
			if strings.HasSuffix(scheme, "+local") {
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

	hasGoogle := false
	hasCloudflare := false
	for _, d := range domains {
		if d == "dns.google" {
			hasGoogle = true
		} else if d == "cloudflare-dns.com" {
			hasCloudflare = true
		}
	}
	if hasGoogle {
		ips = append(ips, "8.8.8.8")
	}
	if hasCloudflare {
		ips = append(ips, "1.1.1.1")
	}

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

func buildDNSInbound(listen string, port int) map[string]interface{} {
	if listen == "" {
		listen = "127.0.0.1"
	}
	return map[string]interface{}{
		"tag":      "dns-in",
		"port":     port,
		"listen":   listen,
		"protocol": "dokodemo-door",
		"settings": map[string]interface{}{
			"address": "8.8.8.8",
			"port":    53,
			"network": "tcp,udp",
		},
	}
}

func buildSniffingConfig(userCfg *config.UserConfig) map[string]interface{} {
	return map[string]interface{}{
		"enabled":      true,
		"destOverride": []string{"http", "tls", "quic"},
		"metadataOnly": true,
		"routeOnly":    true,
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
	testPort := getPort("test-socks", userCfg.TestInbound)
	pathdPort := getPort("pathd-socks", 0)
	dnsInPort := getPort("dns-in", 0)
	_, disableGatewayTun := overridePorts["gateway-tun-disabled"]
	gatewayState := userCfg.Gateway.State
	if gatewayState == "" {
		gatewayState = "proxy"
	}
	gatewayTunEnabled := isGateway && !disableGatewayTun && gatewayState == "proxy" && (userCfg.Gateway.LocalEnabled || userCfg.Gateway.LANEnabled)
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
	var hasDNSIn bool
	if dnsInPort > 0 {
		inbounds = append(inbounds, buildDNSInbound("127.0.0.1", dnsInPort))
		hasDNSIn = true
	} else if isGateway && !disableGatewayTun && userCfg.Gateway.DNSListen != "" {
		host, port, _, err := config.ParseDNSListen(userCfg.Gateway.DNSListen)
		if err == nil && port > 0 {
			inbounds = append(inbounds, buildDNSInbound(host, port))
			hasDNSIn = true
		}
	}
	inbounds = append(inbounds, map[string]interface{}{"tag": "test-socks", "port": testPort, "listen": "127.0.0.1", "protocol": "socks", "settings": map[string]interface{}{"auth": "noauth", "udp": true}, "sniffing": buildSniffingConfig(userCfg)})
	if pathdPort > 0 {
		inbounds = append(inbounds, map[string]interface{}{"tag": "pathd-socks", "port": pathdPort, "listen": "127.0.0.1", "protocol": "socks", "settings": map[string]interface{}{"auth": "noauth"}})
	}
	for _, co := range userCfg.CustomOutbounds {
		if co.InternalProxyPort <= 0 {
			continue
		}
		port := getPort("outbound-"+co.Alias, co.InternalProxyPort)
		httpPort := co.InternalHttpPort
		if httpPort <= 0 {
			httpPort = port + 1
		} else {
			httpPort = getPort("outbound-http-"+co.Alias, httpPort)
		}
		listenAddr := co.InternalListenAddr
		if listenAddr == "" {
			listenAddr = "127.0.0.1"
		}
		tags := relayInboundTags[co.Alias]
		inbounds = append(inbounds,
			map[string]interface{}{"tag": tags[0], "port": port, "listen": listenAddr, "protocol": "socks", "settings": map[string]interface{}{"auth": "noauth", "udp": true}, "sniffing": buildSniffingConfig(userCfg)},
			map[string]interface{}{"tag": tags[1], "port": httpPort, "listen": listenAddr, "protocol": "http", "sniffing": buildSniffingConfig(userCfg)},
		)
	}

	for _, m := range userCfg.Presets {
		if !m.Enabled {
			continue
		}
		mPort := getPort(string(m.Mode), m.Port)
		in := map[string]interface{}{"tag": string(m.Mode), "port": mPort, "listen": "::", "sniffing": buildSniffingConfig(userCfg)}

		dest := m.Dest

		clients := []interface{}{map[string]interface{}{"id": userCfg.UUID, "email": "service-user"}}
		for _, co := range userCfg.CustomOutbounds {
			if !co.Enabled || co.UserUUID == "" {
				continue
			}
			clients = append(clients, map[string]interface{}{"id": co.UserUUID, "email": relayUserEmail(co.Alias)})
		}
		for _, guest := range userCfg.Guests {
			if !guest.Enabled || guest.UUID == "" {
				continue
			}
			clients = append(clients, map[string]interface{}{"id": guest.UUID, "email": guestUserEmail(guest.Alias)})
		}
		switch m.Mode {
		case config.ModeVLESSVision:
			normSNI, normDest, err := config.ValidateRealitySNIAndDest(m.SNI, m.Dest)
			if err != nil {
				return nil, fmt.Errorf("invalid REALITY configuration for preset %s: %w", m.Mode, err)
			}
			dest = normDest
			in["protocol"] = "vless"
			visionClients := make([]interface{}, 0, len(clients))
			for _, rawClient := range clients {
				client := deepCopyMap(rawClient.(map[string]interface{}))
				client["flow"] = "xtls-rprx-vision"
				visionClients = append(visionClients, client)
			}
			in["settings"] = map[string]interface{}{"clients": visionClients, "decryption": "none"}
			serverNames := []string{normSNI}
			in["streamSettings"] = map[string]interface{}{"network": "tcp", "security": "reality", "realitySettings": map[string]interface{}{"dest": dest, "serverNames": serverNames, "privateKey": m.Settings.PrivateKey, "shortIds": []string{m.Settings.ShortID}, "minClientVer": config.ResolveMinClientVersion(&m)}}
		case config.ModeVLESSReality:
			normSNI, normDest, err := config.ValidateRealitySNIAndDest(m.SNI, m.Dest)
			if err != nil {
				return nil, fmt.Errorf("invalid REALITY configuration for preset %s: %w", m.Mode, err)
			}
			dest = normDest
			in["protocol"] = "vless"
			in["settings"] = map[string]interface{}{"clients": clients, "decryption": "none"}
			serverNames := []string{normSNI}
			in["streamSettings"] = map[string]interface{}{"network": "xhttp", "security": "reality", "xhttpSettings": map[string]interface{}{"path": m.Path}, "realitySettings": map[string]interface{}{"dest": dest, "serverNames": serverNames, "privateKey": m.Settings.PrivateKey, "shortIds": []string{m.Settings.ShortID}, "minClientVer": config.ResolveMinClientVersion(&m)}}
		case config.ModeVLESSXHTTP:
			in["protocol"] = "vless"
			decryption := "none"
			if m.Settings.PrivateKey != "" {
				decryption = m.Settings.PrivateKey
			}
			settings := map[string]interface{}{"clients": clients, "decryption": decryption}
			if decryption == "none" {
				if m.Skin != "" {
					settings["fallbacks"] = []interface{}{map[string]interface{}{"dest": "127.0.0.1:8088"}}
				} else if dest != "" {
					settings["fallbacks"] = []interface{}{map[string]interface{}{"dest": dest}}
				}
			}
			in["settings"] = settings
			in["streamSettings"] = map[string]interface{}{"network": "xhttp", "xhttpSettings": map[string]interface{}{"path": m.Path}}
		case config.ModeVMessWS:
			in["protocol"] = "vmess"
			settings := map[string]interface{}{"clients": clients}
			in["settings"] = settings
			in["streamSettings"] = map[string]interface{}{"network": "ws", "wsSettings": map[string]interface{}{"path": m.Path}}
		case config.ModeShadowsocksTCP:
			in["protocol"] = "shadowsocks"
			in["settings"] = map[string]interface{}{"method": m.Settings.Cipher, "password": m.Settings.Password, "email": "service-user"}
		case config.ModeHysteria2:
			in["protocol"] = "hysteria"
			hyClients := make([]interface{}, 0, len(clients))
			for _, rawClient := range clients {
				cm := rawClient.(map[string]interface{})
				hyClients = append(hyClients, map[string]interface{}{
					"auth":  cm["id"],
					"email": cm["email"],
				})
			}
			in["settings"] = map[string]interface{}{
				"version": 2,
				"clients": hyClients,
			}

			sni := strings.TrimSpace(m.SNI)
			if sni == "" {
				sni = "www.bing.com"
			}

			certPEM := strings.TrimSpace(m.Settings.CertPEM)
			keyPEM := strings.TrimSpace(m.Settings.PrivateKey)
			if certPEM == "" || keyPEM == "" {
				var genErr error
				certPEM, keyPEM, _, genErr = config.GenerateSelfSignedCert(sni)
				if genErr != nil {
					return nil, fmt.Errorf("failed to generate self-signed cert for hysteria2: %w", genErr)
				}
			}

			certLines := strings.Split(strings.ReplaceAll(certPEM, "\r\n", "\n"), "\n")
			keyLines := strings.Split(strings.ReplaceAll(keyPEM, "\r\n", "\n"), "\n")

			var masq map[string]interface{}
			if m.Skin != "" {
				skinPort := userCfg.GetSkinPort()
				if skinPort <= 0 {
					skinPort = 9443
				}
				masq = map[string]interface{}{
					"type":        "proxy",
					"url":         fmt.Sprintf("https://127.0.0.1:%d", skinPort),
					"rewriteHost": true,
					"insecure":    true,
				}
			} else {
				masqHost := sni
				if m.Dest != "" && !strings.HasPrefix(m.Dest, "127.0.0.1:") && !strings.HasPrefix(m.Dest, "localhost:") {
					if h, p, err := net.SplitHostPort(m.Dest); err == nil && h != "" {
						if p != "" && p != "443" {
							masqHost = net.JoinHostPort(h, p)
						} else {
							masqHost = h
						}
					}
				}
				masq = map[string]interface{}{
					"type":        "proxy",
					"url":         "https://" + masqHost,
					"rewriteHost": true,
				}
			}

			streamSettings := map[string]interface{}{
				"network":  "hysteria",
				"security": "tls",
				"tlsSettings": map[string]interface{}{
					"alpn": []string{"h3"},
					"certificates": []interface{}{
						map[string]interface{}{
							"certificate": certLines,
							"key":         keyLines,
						},
					},
				},
				"hysteriaSettings": map[string]interface{}{
					"version":    2,
					"masquerade": masq,
				},
			}
			if m.Settings.Password != "" {
				streamSettings["finalmask"] = map[string]interface{}{
					"udp": []interface{}{
						map[string]interface{}{
							"type": "salamander",
							"settings": map[string]interface{}{
								"password": m.Settings.Password,
							},
						},
					},
				}
			}
			in["streamSettings"] = streamSettings
		}
		inbounds = append(inbounds, in)
	}

	if gatewayTunEnabled {
		if userCfg.Gateway.EffectiveMode() == "tun" {
			inbounds = append(inbounds, map[string]interface{}{
				"tag":      "tun-in",
				"protocol": "tun",
				"settings": map[string]interface{}{
					"name":    "proxya-tun",
					"mtu":     1500,
					"gateway": []string{"172.16.255.1/30", "fd00:eea:ff::1/126"},
				},
				"sniffing": buildSniffingConfig(userCfg),
			})
		} else {
			basePort := userCfg.Gateway.EffectiveTProxyPort()
			tproxyPort := getPort("tproxy-in", basePort)
			inbounds = append(inbounds, map[string]interface{}{
				"tag":      "tproxy-in",
				"port":     tproxyPort,
				"listen":   "::",
				"protocol": "dokodemo-door",
				"settings": map[string]interface{}{
					"network":        "tcp,udp",
					"followRedirect": true,
				},
				"streamSettings": map[string]interface{}{
					"sockopt": map[string]interface{}{
						"tproxy": "tproxy",
						"mark":   255,
					},
				},
				"sniffing": buildSniffingConfig(userCfg),
			})

			tproxyPorts := config.GatewayTProxyPorts(userCfg)
			var extraAliases []string
			for alias, port := range tproxyPorts {
				if port != basePort {
					extraAliases = append(extraAliases, alias)
				}
			}
			sort.Strings(extraAliases)
			for _, alias := range extraAliases {
				port := tproxyPorts[alias]
				inboundTag := "tproxy-in-" + sanitizeTagComponent(alias)
				inbounds = append(inbounds, map[string]interface{}{
					"tag":      inboundTag,
					"port":     getPort(inboundTag, port),
					"listen":   "::",
					"protocol": "dokodemo-door",
					"settings": map[string]interface{}{
						"network":        "tcp,udp",
						"followRedirect": true,
					},
					"streamSettings": map[string]interface{}{
						"sockopt": map[string]interface{}{
							"tproxy": "tproxy",
							"mark":   255,
						},
					},
					"sniffing": buildSniffingConfig(userCfg),
				})
			}
		}
	}
	if err := validateInboundsPortConflicts(inbounds); err != nil {
		return nil, err
	}
	xc["inbounds"] = inbounds

	// 4. Outbounds
	xc["outbounds"] = []interface{}{
		map[string]interface{}{
			"protocol": "freedom",
			"tag":      "direct",
			"settings": map[string]interface{}{
				"finalRules": []interface{}{
					map[string]interface{}{
						"action": "allow",
						"ip":     []string{"0.0.0.0/0", "::/0"},
					},
				},
			},
			"streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"mark": 255, "domainStrategy": "UseIP"}},
		},
		map[string]interface{}{"protocol": "dns", "tag": "dns-out", "streamSettings": map[string]interface{}{"sockopt": map[string]interface{}{"mark": 255}}},
		map[string]interface{}{"protocol": "blackhole", "tag": "blocked"},
	}
	for _, co := range userCfg.CustomOutbounds {
		if !co.Enabled {
			continue
		}
		out := deepCopyMap(co.Config)
		out["tag"] = "outbound-" + co.Alias
		ensureUDP443Support(out)
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
		if !guest.Enabled || guest.OutboundConf == nil {
			continue
		}
		out := deepCopyMap(guest.OutboundConf)
		out["tag"] = guestOutboundTag(guest.Alias)
		ensureUDP443Support(out)
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
	if pathdPort > 0 && relayAlias != "" {
		rules = append(rules, map[string]interface{}{"type": "field", "inboundTag": []string{"pathd-socks"}, "outboundTag": "outbound-" + relayAlias})
	}
	if hasDNSIn {
		rules = append(rules, map[string]interface{}{"type": "field", "inboundTag": []string{"dns-in"}, "outboundTag": "dns-out"})
	}
	// test-socks is only used as a local validation endpoint. Keep its
	// explicit test target route above this guard, but never let the later
	// catch-all rules turn it into an open proxy.
	rules = append(rules, map[string]interface{}{"type": "field", "inboundTag": []string{"test-socks"}, "outboundTag": "blocked"})

	type tproxyRoute struct {
		alias      string
		inboundTag string
	}
	var tproxyRoutes []tproxyRoute
	var mainAlias string
	if gatewayTunEnabled {
		if userCfg.Gateway.EffectiveMode() == "tun" {
			mainAlias = userCfg.Gateway.RelayAlias
			if mainAlias != "" && mainAlias != "direct" && mainAlias != "block" {
				tproxyRoutes = append(tproxyRoutes, tproxyRoute{alias: mainAlias, inboundTag: "tun-in"})
			}
		} else {
			basePort := userCfg.Gateway.EffectiveTProxyPort()
			tproxyPorts := config.GatewayTProxyPorts(userCfg)
			mainAlias = userCfg.Gateway.RelayAlias
			if mainAlias == "" || mainAlias == "direct" || mainAlias == "block" {
				for alias, p := range tproxyPorts {
					if p == basePort {
						mainAlias = alias
						break
					}
				}
			}
			if mainAlias != "" && mainAlias != "direct" && mainAlias != "block" {
				tproxyRoutes = append(tproxyRoutes, tproxyRoute{alias: mainAlias, inboundTag: "tproxy-in"})
			}
			var extraAliases []string
			for alias, p := range tproxyPorts {
				if p != basePort {
					extraAliases = append(extraAliases, alias)
				}
			}
			sort.Strings(extraAliases)
			for _, alias := range extraAliases {
				tproxyRoutes = append(tproxyRoutes, tproxyRoute{
					alias:      alias,
					inboundTag: "tproxy-in-" + sanitizeTagComponent(alias),
				})
			}
		}
	}

	// Route port 53 traffic:
	// For each traversed relay inbound (e.g. tproxy-in-<alias>), route port 53 queries
	// to its corresponding relay outbound so DNS requests traverse the exact proxy node as the client.
	for _, tr := range tproxyRoutes {
		if tr.alias != "" && tr.alias != mainAlias && tr.alias != "direct" && tr.alias != "block" {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"inboundTag":  []string{tr.inboundTag},
				"port":        "53",
				"outboundTag": "outbound-" + tr.alias,
			})
		}
	}

	// Route port 53 traffic to dns-out first, so IP rules for DoH servers don't override port 53 interception
	rules = append(rules, map[string]interface{}{"type": "field", "port": "53", "outboundTag": "dns-out"})
	rules = append(rules, buildDNSOutboundRoutingRules(selectedDNSAlias, selectedDNSServers)...)

	// Explicit loopback protection before AllowPrivateTargets rules
	rules = append(rules, map[string]interface{}{"type": "field", "ip": []string{"127.0.0.0/8", "::1/128"}, "outboundTag": "direct"})

	// Only an outbound explicitly opted into private targets may route its
	// relay user before the private-IP guard. This supports chained relays to
	// a next-hop loopback service (such as remote pathd) without exposing a
	// next-hop private network to every relay link by default.
	for _, co := range userCfg.CustomOutbounds {
		if !co.Enabled || !co.AllowPrivateTargets {
			continue
		}
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"user":        []string{relayUserEmail(co.Alias)},
			"outboundTag": "outbound-" + co.Alias,
		})
	}

	allowPrivateByAlias := make(map[string]bool)
	for _, co := range userCfg.CustomOutbounds {
		if co.Enabled && co.AllowPrivateTargets {
			allowPrivateByAlias[co.Alias] = true
		}
	}

	var bypassGeoIPs []string
	var bypassGeoSites []string
	if gatewayTunEnabled && len(userCfg.Gateway.BypassCountries) > 0 {
		for _, country := range userCfg.Gateway.BypassCountries {
			code := strings.ToLower(strings.TrimSpace(country))
			if code != "" {
				if code == "cn" {
					bypassGeoSites = append(bypassGeoSites, "geosite:"+code)
				}
				bypassGeoIPs = append(bypassGeoIPs, "geoip:"+code)
			}
		}
	}

	appendBypassCountries := func(tag string) {
		if len(bypassGeoSites) > 0 {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"inboundTag":  []string{tag},
				"domain":      bypassGeoSites,
				"outboundTag": "direct",
			})
		}
		if len(bypassGeoIPs) > 0 {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"inboundTag":  []string{tag},
				"ip":          bypassGeoIPs,
				"outboundTag": "direct",
			})
		}
	}

	// 1. Relays with AllowPrivateTargets == true placed ABOVE geoip:private
	for _, tr := range tproxyRoutes {
		if allowPrivateByAlias[tr.alias] {
			appendBypassCountries(tr.inboundTag)
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"inboundTag":  []string{tr.inboundTag},
				"outboundTag": "outbound-" + tr.alias,
			})
		}
	}

	// geoip:private guard
	rules = append(rules,
		map[string]interface{}{"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "direct"},
	)

	// 2. Relays without AllowPrivateTargets placed AFTER geoip:private
	for _, tr := range tproxyRoutes {
		if !allowPrivateByAlias[tr.alias] {
			appendBypassCountries(tr.inboundTag)
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"inboundTag":  []string{tr.inboundTag},
				"outboundTag": "outbound-" + tr.alias,
			})
		}
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
		if !guest.Enabled {
			continue
		}
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

func ensureUDP443Support(outbound map[string]interface{}) {
	settings, ok := outbound["settings"].(map[string]interface{})
	if !ok {
		return
	}
	vnext, ok := settings["vnext"].([]interface{})
	if !ok {
		return
	}
	for _, rawV := range vnext {
		v, ok := rawV.(map[string]interface{})
		if !ok {
			continue
		}
		users, ok := v["users"].([]interface{})
		if !ok {
			continue
		}
		for _, rawU := range users {
			u, ok := rawU.(map[string]interface{})
			if !ok {
				continue
			}
			if flow, ok := u["flow"].(string); ok {
				if flow == "xtls-rprx-vision" {
					u["flow"] = "xtls-rprx-vision-udp443"
				}
			}
		}
	}
}

func guestUserEmail(alias string) string {
	return "guest-" + sanitizeTagComponent(alias)
}

func guestOutboundTag(alias string) string {
	return "guest-outbound-" + sanitizeTagComponent(alias)
}

type inboundListener struct {
	tag      string
	protocol string
	listen   string
	port     int
	hasTCP   bool
	hasUDP   bool
}

func validateInboundsPortConflicts(inbounds []interface{}) error {
	listeners := make([]inboundListener, 0, len(inbounds))
	for _, item := range inbounds {
		inb, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		proto, _ := inb["protocol"].(string)
		if proto == "tun" {
			continue
		}
		portRaw := 0
		if p, ok := inb["port"].(int); ok {
			portRaw = p
		} else if p, ok := inb["port"].(float64); ok {
			portRaw = int(p)
		}
		if portRaw <= 0 {
			continue
		}
		tag, _ := inb["tag"].(string)
		listen, _ := inb["listen"].(string)
		if listen == "" {
			listen = "0.0.0.0"
		}

		hasTCP := true
		hasUDP := false
		if proto == "hysteria" {
			hasTCP = false
			hasUDP = true
		} else if proto == "socks" {
			if settings, ok := inb["settings"].(map[string]interface{}); ok {
				if udp, ok := settings["udp"].(bool); ok && udp {
					hasUDP = true
				}
			}
		} else if proto == "dokodemo-door" {
			hasUDP = true
		}

		current := inboundListener{
			tag:      tag,
			protocol: proto,
			listen:   listen,
			port:     portRaw,
			hasTCP:   hasTCP,
			hasUDP:   hasUDP,
		}

		for _, prev := range listeners {
			if prev.port == current.port && utils.ListenAddressesOverlap(prev.listen, current.listen) {
				conflictTCP := prev.hasTCP && current.hasTCP
				conflictUDP := prev.hasUDP && current.hasUDP
				if conflictTCP || conflictUDP {
					return fmt.Errorf("inbound port conflict: %q (%s:%d/%s) and %q (%s:%d/%s) cannot bind the same port on overlapping addresses",
						prev.tag, prev.listen, prev.port, prev.protocol,
						current.tag, current.listen, current.port, current.protocol)
				}
			}
		}
		listeners = append(listeners, current)
	}
	return nil
}
