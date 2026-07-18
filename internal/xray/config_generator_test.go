package xray

import (
	"encoding/json"
	"testing"

	"xray-proxya/internal/config"
)

func TestGenerateXrayJSONUsesDefaultDNSConfig(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "relay-a", Enabled: true, Config: map[string]interface{}{"protocol": "freedom"}},
		},
	}

	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	dns := getMap(t, parsed, "dns")

	if got := getString(t, dns, "queryStrategy"); got != DefaultDNSQueryStrategy {
		t.Fatalf("queryStrategy = %q, want %q", got, DefaultDNSQueryStrategy)
	}

	servers := getStringSlice(t, dns, "servers")
	want := []string{"https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"}
	assertStringSliceEqual(t, servers, want)
}

func TestGenerateXrayJSONUsesTestTargetDNSConfig(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:       "relay-a",
				Enabled:     true,
				DNSStrategy: "UseIPv4",
				DNSServers:  []string{"1.1.1.1", " https://dns.google/dns-query ", "1.1.1.1"},
				Config:      map[string]interface{}{"protocol": "freedom"},
			},
		},
	}

	parsed := generateAndDecodeXrayConfig(t, cfg, "relay-a")
	dns := getMap(t, parsed, "dns")

	if got := getString(t, dns, "queryStrategy"); got != "UseIPv4" {
		t.Fatalf("queryStrategy = %q, want %q", got, "UseIPv4")
	}

	servers := getStringSlice(t, dns, "servers")
	want := []string{"1.1.1.1", "https://dns.google/dns-query"}
	assertStringSliceEqual(t, servers, want)
}

func TestGenerateXrayJSONUsesGatewayRelayDNSConfig(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			RelayAlias: "relay-b",
		},
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:       "relay-b",
				Enabled:     true,
				DNSStrategy: "UseIPv6",
				DNSServers:  []string{"https://cloudflare-dns.com/dns-query"},
				Config:      map[string]interface{}{"protocol": "freedom"},
			},
		},
	}

	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	dns := getMap(t, parsed, "dns")

	if got := getString(t, dns, "queryStrategy"); got != "UseIPv6" {
		t.Fatalf("queryStrategy = %q, want %q", got, "UseIPv6")
	}

	servers := getStringSlice(t, dns, "servers")
	want := []string{"https://cloudflare-dns.com/dns-query"}
	assertStringSliceEqual(t, servers, want)
}

func TestGenerateXrayJSONSkipsLegacyDNSInboundRule(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "relay-a", Enabled: true, Config: map[string]interface{}{"protocol": "freedom"}},
		},
	}

	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	routing := getMap(t, parsed, "routing")
	rules, ok := routing["rules"].([]interface{})
	if !ok {
		t.Fatalf("routing.rules has type %T, want []interface{}", routing["rules"])
	}

	for _, rawRule := range rules {
		rule, ok := rawRule.(map[string]interface{})
		if !ok {
			t.Fatalf("rule has type %T, want map[string]interface{}", rawRule)
		}
		if inboundTags, ok := rule["inboundTag"].([]interface{}); ok {
			for _, rawTag := range inboundTags {
				tag, _ := rawTag.(string)
				if tag == "dns-in" {
					t.Fatalf("unexpected legacy dns-in rule present: %#v", rule)
				}
			}
		}
	}
}

func TestGenerateXrayJSONAddsDNSInboundWhenOverridden(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "relay-a", Enabled: true, Config: map[string]interface{}{"protocol": "freedom"}},
		},
	}

	parsed := generateAndDecodeXrayConfigWithOverrides(t, cfg, map[string]int{"dns-in": 5300}, "")
	inbounds, ok := parsed["inbounds"].([]interface{})
	if !ok {
		t.Fatalf("inbounds has type %T, want []interface{}", parsed["inbounds"])
	}

	found := false
	for _, rawInbound := range inbounds {
		inbound, ok := rawInbound.(map[string]interface{})
		if !ok {
			t.Fatalf("inbound has type %T, want map[string]interface{}", rawInbound)
		}
		if inbound["tag"] == "dns-in" {
			found = true
			if got := int(inbound["port"].(float64)); got != 5300 {
				t.Fatalf("dns-in port = %d, want 5300", got)
			}
		}
	}
	if !found {
		t.Fatalf("dns-in inbound not found")
	}

	routing := getMap(t, parsed, "routing")
	rules, ok := routing["rules"].([]interface{})
	if !ok {
		t.Fatalf("routing.rules has type %T, want []interface{}", routing["rules"])
	}
	if !containsInboundRule(rules, "dns-in", "dns-out") {
		t.Fatalf("dns-in routing rule not found")
	}
}

func TestGenerateXrayJSONRoutesDNSUpstreamsThroughSelectedOutbound(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:       "relay-a",
				Enabled:     true,
				DNSServers:  []string{"1.1.1.1", "https://dns.google/dns-query"},
				DNSStrategy: "UseIPv4",
				Config:      map[string]interface{}{"protocol": "freedom"},
			},
		},
	}

	parsed := generateAndDecodeXrayConfig(t, cfg, "relay-a")
	routing := getMap(t, parsed, "routing")
	rules, ok := routing["rules"].([]interface{})
	if !ok {
		t.Fatalf("routing.rules has type %T, want []interface{}", routing["rules"])
	}
	if !containsDomainRule(rules, "dns.google", "outbound-relay-a") {
		t.Fatalf("dns.google routing rule not found")
	}
	if !containsIPRule(rules, "1.1.1.1", "outbound-relay-a") {
		t.Fatalf("1.1.1.1 routing rule not found")
	}
}

func TestGenerateXrayJSONRoutesDNSPacketsThroughDNSOutInServerMode(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:   "relay-a",
				Enabled: true,
				Config:  map[string]interface{}{"protocol": "freedom"},
			},
		},
	}

	parsed := generateAndDecodeXrayConfig(t, cfg, "relay-a")
	routing := getMap(t, parsed, "routing")
	rules, ok := routing["rules"].([]interface{})
	if !ok {
		t.Fatalf("routing.rules has type %T, want []interface{}", routing["rules"])
	}
	if !containsPortRule(rules, "53", "dns-out") {
		t.Fatalf("port 53 routing rule to dns-out not found")
	}
}

func TestGenerateXrayJSONRoutesDNSPacketsThroughDNSOut(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			RelayAlias: "relay-a",
		},
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:   "relay-a",
				Enabled: true,
				Config:  map[string]interface{}{"protocol": "freedom"},
			},
		},
	}

	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	routing := getMap(t, parsed, "routing")
	rules, ok := routing["rules"].([]interface{})
	if !ok {
		t.Fatalf("routing.rules has type %T, want []interface{}", routing["rules"])
	}
	// Currently it fails because it routes to outbound-relay-a instead of dns-out
	if !containsPortRule(rules, "53", "dns-out") {
		t.Fatalf("port 53 routing rule to dns-out not found")
	}
}

func TestGenerateXrayJSONCanDisableGatewayTunForRuntimeTest(t *testing.T) {
	cfg := &config.UserConfig{
		Role:        config.RoleGateway,
		APIInbound:  10085,
		TestInbound: 10086,
		Gateway: config.GatewayConfig{
			LocalEnabled: true,
			LANEnabled:   true,
			Mode:         "tun",
			RelayAlias:   "relay-a",
		},
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:   "relay-a",
				Enabled: true,
				Config: map[string]interface{}{
					"protocol": "freedom",
					"settings": map[string]interface{}{},
				},
			},
		},
	}

	parsed := generateAndDecodeXrayConfigWithOverrides(t, cfg, map[string]int{"gateway-tun-disabled": 1}, "")
	inbounds := parsed["inbounds"].([]interface{})
	for _, rawInbound := range inbounds {
		inbound := rawInbound.(map[string]interface{})
		if inbound["tag"] == "tun-in" {
			t.Fatal("tun-in inbound should be disabled during runtime isolation tests")
		}
	}
}

func TestGenerateXrayJSONUsesConfiguredTestInboundPort(t *testing.T) {
	cfg := &config.UserConfig{
		Role:        config.RoleServer,
		APIInbound:  10085,
		TestInbound: 23456,
	}

	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	inbounds := parsed["inbounds"].([]interface{})
	found := false
	for _, rawInbound := range inbounds {
		inbound := rawInbound.(map[string]interface{})
		if inbound["tag"] != "test-socks" {
			continue
		}
		found = true
		if got := int(inbound["port"].(float64)); got != 23456 {
			t.Fatalf("test-socks port = %d, want 23456", got)
		}
	}
	if !found {
		t.Fatalf("test-socks inbound not found")
	}
}

func TestGenerateXrayJSONSkipsDisabledGuests(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Presets: []config.ModeInfo{
			{
				Mode:    config.ModeVLESSVision,
				Enabled: true,
				Port:    443,
				SNI:     "www.amazon.com",
				Dest:    "www.amazon.com:443",
				Settings: config.Settings{
					PrivateKey: "priv",
					ShortID:    "abcd",
				},
			},
		},
		Guests: []config.GuestConfig{
			{Alias: "enabled-guest", Enabled: true, UUID: "enabled-uuid"},
			{Alias: "disabled-guest", Enabled: false, UUID: "disabled-uuid"},
		},
	}

	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	inbounds := parsed["inbounds"].([]interface{})
	foundEnabled := false
	foundDisabled := false
	for _, rawInbound := range inbounds {
		inbound := rawInbound.(map[string]interface{})
		settings, ok := inbound["settings"].(map[string]interface{})
		if !ok {
			continue
		}
		clients, ok := settings["clients"].([]interface{})
		if !ok {
			continue
		}
		for _, rawClient := range clients {
			client := rawClient.(map[string]interface{})
			email, _ := client["email"].(string)
			if email == "guest-enabled-guest" {
				foundEnabled = true
			}
			if email == "guest-disabled-guest" {
				foundDisabled = true
			}
		}
	}
	if !foundEnabled {
		t.Fatalf("enabled guest client missing from generated config")
	}
	if foundDisabled {
		t.Fatalf("disabled guest client should not appear in generated config")
	}

	routing := getMap(t, parsed, "routing")
	rules, _ := routing["rules"].([]interface{})
	for _, rawRule := range rules {
		rule := rawRule.(map[string]interface{})
		users, ok := rule["user"].([]interface{})
		if !ok {
			continue
		}
		for _, rawUser := range users {
			user, _ := rawUser.(string)
			if user == "guest-disabled-guest" {
				t.Fatalf("disabled guest routing rule should not appear in generated config")
			}
		}
	}
}

func TestGenerateXrayJSONOutboundSetDNSOverrides(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			RelayAlias: "relay-a",
		},
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:       "relay-a",
				Enabled:     true,
				DNSStrategy: "UseIPv6",
				DNSServers:  []string{"8.8.4.4"},
				Config:      map[string]interface{}{"protocol": "freedom"},
			},
		},
	}

	// 1. Verify DNS servers and strategy are overridden
	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	dns := getMap(t, parsed, "dns")
	if got := getString(t, dns, "queryStrategy"); got != "UseIPv6" {
		t.Fatalf("queryStrategy = %q, want %q", got, "UseIPv6")
	}
	servers := getStringSlice(t, dns, "servers")
	// Should be custom server
	want := []string{"8.8.4.4"}
	assertStringSliceEqual(t, servers, want)

	// 2. Verify routing rules for custom DNS servers are added
	routing := getMap(t, parsed, "routing")
	rules, _ := routing["rules"].([]interface{})
	if !containsIPRule(rules, "8.8.4.4", "outbound-relay-a") {
		t.Fatalf("routing rule for custom DNS server 8.8.4.4 to outbound-relay-a not found")
	}
}

func TestGenerateXrayJSONCamouflageSkinning(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Presets: []config.ModeInfo{
			{
				Mode:    config.ModeVLESSVision,
				Enabled: true,
				Port:    443,
				SNI:     "www.intel.com",
				Dest:    "www.intel.com:443",
				Skin:    true,
			},
		},
	}

	// 1. Verify dest is redirected to camouflage port
	parsed := generateAndDecodeXrayConfigWithOverrides(t, cfg, map[string]int{"camouflage": 49152}, "")
	inbounds := parsed["inbounds"].([]interface{})

	found := false
	for _, rawIn := range inbounds {
		in := rawIn.(map[string]interface{})
		if in["tag"] == string(config.ModeVLESSVision) {
			found = true
			ss := in["streamSettings"].(map[string]interface{})
			rs := ss["realitySettings"].(map[string]interface{})
			if got := rs["dest"].(string); got != "127.0.0.1:49152" {
				t.Fatalf("Vision dest = %q, want %q (camouflage)", got, "127.0.0.1:49152")
			}
		}
	}
	if !found {
		t.Fatalf("Vision inbound not found")
	}
}

func generateAndDecodeXrayConfig(t *testing.T, cfg *config.UserConfig, testTarget string) map[string]interface{} {
	t.Helper()

	return generateAndDecodeXrayConfigWithOverrides(t, cfg, nil, testTarget)
}

func generateAndDecodeXrayConfigWithOverrides(t *testing.T, cfg *config.UserConfig, overrides map[string]int, testTarget string) map[string]interface{} {
	t.Helper()

	data, err := GenerateXrayJSON(cfg, overrides, testTarget)
	if err != nil {
		t.Fatalf("GenerateXrayJSON() error = %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	return parsed
}

func containsInboundRule(rules []interface{}, inboundTag string, outboundTag string) bool {
	for _, rawRule := range rules {
		rule, ok := rawRule.(map[string]interface{})
		if !ok {
			continue
		}
		if rule["outboundTag"] != outboundTag {
			continue
		}
		inboundTags, ok := rule["inboundTag"].([]interface{})
		if !ok {
			continue
		}
		for _, rawTag := range inboundTags {
			if tag, _ := rawTag.(string); tag == inboundTag {
				return true
			}
		}
	}
	return false
}

func containsDomainRule(rules []interface{}, domain string, outboundTag string) bool {
	return containsSliceRuleValue(rules, "domain", domain, outboundTag)
}

func containsIPRule(rules []interface{}, ip string, outboundTag string) bool {
	return containsSliceRuleValue(rules, "ip", ip, outboundTag)
}

func containsSliceRuleValue(rules []interface{}, key string, expected string, outboundTag string) bool {
	for _, rawRule := range rules {
		rule, ok := rawRule.(map[string]interface{})
		if !ok {
			continue
		}
		if rule["outboundTag"] != outboundTag {
			continue
		}
		values, ok := rule[key].([]interface{})
		if !ok {
			continue
		}
		for _, rawValue := range values {
			if value, _ := rawValue.(string); value == expected {
				return true
			}
		}
	}
	return false
}

func containsPortRule(rules []interface{}, port string, outboundTag string) bool {
	for _, rawRule := range rules {
		rule, ok := rawRule.(map[string]interface{})
		if !ok {
			continue
		}
		if rule["outboundTag"] != outboundTag {
			continue
		}
		if rule["port"] == port {
			return true
		}
	}
	return false
}

func getMap(t *testing.T, source map[string]interface{}, key string) map[string]interface{} {
	t.Helper()
	value, ok := source[key].(map[string]interface{})
	if !ok {
		t.Fatalf("%s has type %T, want map[string]interface{}", key, source[key])
	}
	return value
}

func getString(t *testing.T, source map[string]interface{}, key string) string {
	t.Helper()
	value, ok := source[key].(string)
	if !ok {
		t.Fatalf("%s has type %T, want string", key, source[key])
	}
	return value
}

func getStringSlice(t *testing.T, source map[string]interface{}, key string) []string {
	t.Helper()
	rawItems, ok := source[key].([]interface{})
	if !ok {
		t.Fatalf("%s has type %T, want []interface{}", key, source[key])
	}
	items := make([]string, 0, len(rawItems))
	for _, rawItem := range rawItems {
		item, ok := rawItem.(string)
		if !ok {
			t.Fatalf("%s item has type %T, want string", key, rawItem)
		}
		items = append(items, item)
	}
	return items
}

func assertStringSliceEqual(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d; got=%v want=%v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d = %q, want %q; got=%v want=%v", i, got[i], want[i], got, want)
		}
	}
}

func TestGenerateXrayJSONBypassCountries(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:            "tun",
			RelayAlias:      "us-relay",
			BypassCountries: []string{"CN", "US"},
		},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "us-relay", Enabled: true, UserUUID: "some-uuid"},
		},
	}

	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	routing := getMap(t, parsed, "routing")
	rules, ok := routing["rules"].([]interface{})
	if !ok {
		t.Fatalf("routing.rules has type %T, want []interface{}", routing["rules"])
	}

	foundDomainRule := false
	foundIPRule := false
	for _, ruleRaw := range rules {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}
		outbound, _ := rule["outboundTag"].(string)
		if outbound != "direct" {
			continue
		}
		inboundsRaw, _ := rule["inboundTag"].([]interface{})
		if len(inboundsRaw) != 1 || inboundsRaw[0] != "tun-in" {
			continue
		}

		if domainsRaw, ok := rule["domain"].([]interface{}); ok {
			domains := make([]string, 0, len(domainsRaw))
			for _, d := range domainsRaw {
				domains = append(domains, d.(string))
			}
			if len(domains) == 1 && domains[0] == "geosite:cn" {
				foundDomainRule = true
			}
		}

		if ipsRaw, ok := rule["ip"].([]interface{}); ok {
			ips := make([]string, 0, len(ipsRaw))
			for _, ip := range ipsRaw {
				ips = append(ips, ip.(string))
			}
			if len(ips) == 2 && ips[0] == "geoip:cn" && ips[1] == "geoip:us" {
				foundIPRule = true
			}
		}
	}

	if !foundDomainRule {
		t.Errorf("expected bypass domain routing rule not found or incorrect")
	}
	if !foundIPRule {
		t.Errorf("expected bypass ip routing rule not found or incorrect")
	}
}

func TestGenerateXrayJSONInternalProxy(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:              "relay-p",
				Enabled:            true,
				InternalProxyPort:  1080,
				InternalHttpPort:   8080,
				InternalListenAddr: "192.168.1.100",
				Config:             map[string]interface{}{"protocol": "freedom"},
			},
		},
	}

	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	inbounds, ok := parsed["inbounds"].([]interface{})
	if !ok {
		t.Fatalf("expected inbounds list")
	}

	foundSocks := false
	foundHttp := false
	for _, inbRaw := range inbounds {
		inb, ok := inbRaw.(map[string]interface{})
		if !ok {
			continue
		}
		tag, _ := inb["tag"].(string)
		portRaw, _ := inb["port"].(float64)
		port := int(portRaw)
		listen, _ := inb["listen"].(string)
		protocol, _ := inb["protocol"].(string)

		if tag == "relay-socks-relay-p" {
			foundSocks = true
			if port != 1080 {
				t.Errorf("socks port = %d, want 1080", port)
			}
			if listen != "192.168.1.100" {
				t.Errorf("socks listen = %q, want 192.168.1.100", listen)
			}
			if protocol != "socks" {
				t.Errorf("socks protocol = %q, want socks", protocol)
			}
		}
		if tag == "relay-http-relay-p" {
			foundHttp = true
			if port != 8080 {
				t.Errorf("http port = %d, want 8080", port)
			}
			if listen != "192.168.1.100" {
				t.Errorf("http listen = %q, want 192.168.1.100", listen)
			}
			if protocol != "http" {
				t.Errorf("http protocol = %q, want http", protocol)
			}
		}
	}

	if !foundSocks {
		t.Errorf("socks inbound not found")
	}
	if !foundHttp {
		t.Errorf("http inbound not found")
	}
}
