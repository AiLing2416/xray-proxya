package xray

import (
	"encoding/json"
	"strings"
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

func TestGenerateXrayJSONOmitsGatewayTunWhenDisabled(t *testing.T) {
	cfg := &config.UserConfig{
		Role:    config.RoleGateway,
		Gateway: config.GatewayConfig{Mode: "tproxy", State: "disabled", LocalEnabled: true},
	}
	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	inbounds, ok := parsed["inbounds"].([]interface{})
	if !ok {
		t.Fatal("generated config has no inbounds")
	}
	for _, raw := range inbounds {
		inbound, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if inbound["tag"] == "tun-in" || inbound["tag"] == "tproxy-in" {
			t.Fatal("disabled gateway config must not include tun-in or tproxy-in")
		}
	}
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
		if inbound["tag"] == "tun-in" || inbound["tag"] == "tproxy-in" {
			t.Fatal("tproxy-in/tun-in inbound should be disabled during runtime isolation tests")
		}
	}
}

func TestGenerateXrayJSONGatewayTProxySettings(t *testing.T) {
	cfg := &config.UserConfig{
		Role:        config.RoleGateway,
		APIInbound:  10085,
		TestInbound: 10086,
		Gateway: config.GatewayConfig{
			LocalEnabled: true,
			LANEnabled:   true,
			Mode:         "tproxy",
			TProxyPort:   12345,
			State:        "proxy",
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

	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	inbounds := parsed["inbounds"].([]interface{})
	var tproxyInbound map[string]interface{}
	for _, rawInbound := range inbounds {
		inbound := rawInbound.(map[string]interface{})
		if inbound["tag"] == "tproxy-in" {
			tproxyInbound = inbound
			break
		}
	}
	if tproxyInbound == nil {
		t.Fatal("expected tproxy-in inbound to be generated for active gateway")
	}

	if tproxyInbound["protocol"] != "dokodemo-door" {
		t.Errorf("tproxy-in protocol = %v, want dokodemo-door", tproxyInbound["protocol"])
	}
	if tproxyInbound["listen"] != "::" {
		t.Errorf("tproxy-in listen = %v, want ::", tproxyInbound["listen"])
	}
	portVal := int(tproxyInbound["port"].(float64))
	if portVal != 12345 {
		t.Errorf("tproxy-in port = %d, want 12345", portVal)
	}

	settings, ok := tproxyInbound["settings"].(map[string]interface{})
	if !ok {
		t.Fatalf("tproxy-in settings missing or invalid type: %T", tproxyInbound["settings"])
	}
	if settings["network"] != "tcp,udp" {
		t.Errorf("tproxy-in network = %v, want tcp,udp", settings["network"])
	}
	if settings["followRedirect"] != true {
		t.Errorf("tproxy-in followRedirect = %v, want true", settings["followRedirect"])
	}

	streamSettings, ok := tproxyInbound["streamSettings"].(map[string]interface{})
	if !ok {
		t.Fatalf("tproxy-in streamSettings missing or invalid type: %T", tproxyInbound["streamSettings"])
	}
	sockopt, ok := streamSettings["sockopt"].(map[string]interface{})
	if !ok {
		t.Fatalf("tproxy-in sockopt missing or invalid type: %T", streamSettings["sockopt"])
	}
	if sockopt["tproxy"] != "tproxy" {
		t.Errorf("tproxy-in sockopt.tproxy = %v, want tproxy", sockopt["tproxy"])
	}
	markVal := int(sockopt["mark"].(float64))
	if markVal != 255 {
		t.Errorf("tproxy-in sockopt.mark = %d, want 255", markVal)
	}

	// Verify routing rules route tproxy-in to relay-a
	rules := parsed["routing"].(map[string]interface{})["rules"].([]interface{})
	if !containsInboundRule(rules, "tproxy-in", "outbound-relay-a") {
		t.Fatal("tproxy-in inbound is not routed to outbound-relay-a")
	}
}

func TestGenerateXrayJSONGatewayTunSettings(t *testing.T) {
	cfg := &config.UserConfig{
		Role:        config.RoleGateway,
		APIInbound:  10085,
		TestInbound: 10086,
		Gateway: config.GatewayConfig{
			LocalEnabled: true,
			LANEnabled:   true,
			Mode:         "tun",
			State:        "proxy",
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

	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	inbounds := parsed["inbounds"].([]interface{})
	var tunInbound map[string]interface{}
	for _, rawInbound := range inbounds {
		inbound := rawInbound.(map[string]interface{})
		if inbound["tag"] == "tun-in" {
			tunInbound = inbound
			break
		}
	}
	if tunInbound == nil {
		t.Fatal("expected tun-in inbound to be generated for active tun gateway")
	}

	if tunInbound["protocol"] != "tun" {
		t.Errorf("tun-in protocol = %v, want tun", tunInbound["protocol"])
	}

	settings, ok := tunInbound["settings"].(map[string]interface{})
	if !ok {
		t.Fatalf("tun-in settings missing or invalid type: %T", tunInbound["settings"])
	}

	if settings["name"] != "proxya-tun" {
		t.Errorf("tun-in name = %v, want proxya-tun", settings["name"])
	}
	if settings["mtu"] != float64(1500) && settings["mtu"] != 1500 {
		t.Errorf("tun-in mtu = %v, want 1500", settings["mtu"])
	}

	gatewaysRaw, ok := settings["gateway"].([]interface{})
	if !ok {
		t.Fatalf("tun-in gateway missing or invalid type: %T", settings["gateway"])
	}
	expectedGateways := []string{"172.16.255.1/30", "fd00:eea:ff::1/126"}
	if len(gatewaysRaw) != len(expectedGateways) {
		t.Fatalf("tun-in gateway count = %d, want %d", len(gatewaysRaw), len(expectedGateways))
	}
	for i, g := range gatewaysRaw {
		if g.(string) != expectedGateways[i] {
			t.Errorf("tun-in gateway[%d] = %v, want %v", i, g, expectedGateways[i])
		}
	}

	// Verify routing rules route tun-in to relay-a
	rules := parsed["routing"].(map[string]interface{})["rules"].([]interface{})
	if !containsInboundRule(rules, "tun-in", "outbound-relay-a") {
		t.Fatal("tun-in inbound is not routed to outbound-relay-a")
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
		if got := inbound["listen"]; got != "127.0.0.1" {
			t.Fatalf("test-socks listen = %q, want 127.0.0.1", got)
		}
	}
	if !found {
		t.Fatalf("test-socks inbound not found")
	}
}

func TestGenerateXrayJSONBlocksTestSocksBeforeCatchAllRules(t *testing.T) {
	cfg := &config.UserConfig{Role: config.RoleServer, TestInbound: 23456}
	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	rules := parsed["routing"].(map[string]interface{})["rules"].([]interface{})

	blockedIndex, directIndex := -1, -1
	for index, rawRule := range rules {
		rule := rawRule.(map[string]interface{})
		if rule["outboundTag"] == "blocked" && containsInboundRule([]interface{}{rule}, "test-socks", "blocked") {
			blockedIndex = index
		}
		if rule["outboundTag"] == "direct" && rule["network"] == "tcp,udp" {
			directIndex = index
		}
	}
	if blockedIndex < 0 {
		t.Fatal("missing test-socks blocked rule")
	}
	if directIndex < 0 || blockedIndex > directIndex {
		t.Fatalf("test-socks blocked rule index = %d, network catch-all index = %d", blockedIndex, directIndex)
	}
}

func TestGenerateXrayJSONRoutesPathdThroughGatewayRelay(t *testing.T) {
	cfg := &config.UserConfig{Role: config.RoleGateway, Gateway: config.GatewayConfig{RelayAlias: "relay-a"}}
	cfg.CustomOutbounds = []config.CustomOutbound{{Alias: "relay-a", Enabled: true, UserUUID: "test", Config: map[string]interface{}{"protocol": "freedom"}}}
	parsed := generateAndDecodeXrayConfigWithOverrides(t, cfg, map[string]int{"pathd-socks": 19192}, "")
	inbounds, _ := parsed["inbounds"].([]interface{})
	found := false
	for _, raw := range inbounds {
		inbound := raw.(map[string]interface{})
		if inbound["tag"] == "pathd-socks" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing pathd SOCKS inbound")
	}
	rules := parsed["routing"].(map[string]interface{})["rules"].([]interface{})
	if !containsInboundRule(rules, "pathd-socks", "outbound-relay-a") {
		t.Fatal("pathd SOCKS inbound is not pinned to gateway relay")
	}
}

func TestGenerateXrayJSONRoutesRelayPrivateTargetsOnlyWhenAllowed(t *testing.T) {
	for _, test := range []struct {
		name           string
		allowPrivate   bool
		wantRelayFirst bool
	}{
		{name: "blocked by default", wantRelayFirst: false},
		{name: "explicitly allowed", allowPrivate: true, wantRelayFirst: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := &config.UserConfig{
				Role: config.RoleServer,
				CustomOutbounds: []config.CustomOutbound{{
					Alias:               "remote",
					Enabled:             true,
					AllowPrivateTargets: test.allowPrivate,
					Config:              map[string]interface{}{"protocol": "freedom"},
				}},
			}
			rules := generateAndDecodeXrayConfig(t, cfg, "")["routing"].(map[string]interface{})["rules"].([]interface{})
			relayIndex, privateIndex := -1, -1
			for index, rawRule := range rules {
				rule := rawRule.(map[string]interface{})
				if relayIndex < 0 && rule["outboundTag"] == "outbound-remote" && containsString(rule["user"], "relay-remote") {
					relayIndex = index
				}
				if rule["outboundTag"] == "direct" && containsString(rule["ip"], "geoip:private") {
					privateIndex = index
				}
			}
			if relayIndex < 0 || privateIndex < 0 {
				t.Fatalf("missing relay or private-IP rule: relay=%d private=%d", relayIndex, privateIndex)
			}
			if got := relayIndex < privateIndex; got != test.wantRelayFirst {
				t.Fatalf("relay user rule before private-IP guard = %t, want %t (relay=%d private=%d)", got, test.wantRelayFirst, relayIndex, privateIndex)
			}
		})
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

func TestGenerateXrayJSONSkinPreservesRealityDestination(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Presets: []config.ModeInfo{
			{
				Mode:    config.ModeVLESSVision,
				Enabled: true,
				Port:    443,
				SNI:     "www.intel.com",
				Dest:    "www.intel.com:443",
				Skin:    "",
			},
		},
	}

	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	inbounds := parsed["inbounds"].([]interface{})

	found := false
	for _, rawIn := range inbounds {
		in := rawIn.(map[string]interface{})
		if in["tag"] == string(config.ModeVLESSVision) {
			found = true
			ss := in["streamSettings"].(map[string]interface{})
			rs := ss["realitySettings"].(map[string]interface{})
			if got := rs["dest"].(string); got != "www.intel.com:443" {
				t.Fatalf("Vision dest = %q, want original Reality destination", got)
			}
		}
	}
	if !found {
		t.Fatalf("Vision inbound not found")
	}
}

func TestGenerateXrayJSONRejectsMismatchedRealityTarget(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Presets: []config.ModeInfo{
			{
				Mode:    config.ModeVLESSVision,
				Enabled: true,
				Port:    443,
				SNI:     "www.intel.com",
				Dest:    "other.target.com:443",
			},
		},
	}

	_, err := GenerateXrayJSON(cfg, nil, "")
	if err == nil {
		t.Fatalf("GenerateXrayJSON with mismatched SNI/dest expected error, got nil")
	}
}

func TestGenerateXrayJSONIncludesMinClientVerForReality(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		Presets: []config.ModeInfo{
			{
				Mode:    config.ModeVLESSVision,
				Enabled: true,
				Port:    443,
				SNI:     "www.intel.com",
				Dest:    "www.intel.com:443",
			},
			{
				Mode:         config.ModeVLESSReality,
				Enabled:      true,
				Port:         8443,
				SNI:          "www.intel.com",
				Dest:         "www.intel.com:443",
				Path:         "/xhttp",
				MinClientVer: "0.0.0",
			},
			{
				Mode:    config.ModeVLESSXHTTP,
				Enabled: true,
				Port:    8080,
				Path:    "/xhttp-direct",
			},
		},
	}

	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	inbounds := parsed["inbounds"].([]interface{})

	for _, rawIn := range inbounds {
		in := rawIn.(map[string]interface{})
		tag := in["tag"].(string)
		if tag == string(config.ModeVLESSVision) {
			ss, ok := in["streamSettings"].(map[string]interface{})
			if !ok {
				t.Fatalf("inbound %s missing streamSettings", tag)
			}
			rs, ok := ss["realitySettings"].(map[string]interface{})
			if !ok {
				t.Fatalf("inbound %s missing realitySettings", tag)
			}
			ver, ok := rs["minClientVer"].(string)
			if !ok || ver != config.MinRealityClientVersion {
				t.Errorf("inbound %s minClientVer = %q, want %s", tag, ver, config.MinRealityClientVersion)
			}
		} else if tag == string(config.ModeVLESSReality) {
			ss, ok := in["streamSettings"].(map[string]interface{})
			if !ok {
				t.Fatalf("inbound %s missing streamSettings", tag)
			}
			rs, ok := ss["realitySettings"].(map[string]interface{})
			if !ok {
				t.Fatalf("inbound %s missing realitySettings", tag)
			}
			ver, ok := rs["minClientVer"].(string)
			if !ok || ver != "0.0.0" {
				t.Errorf("inbound %s minClientVer = %q, want 0.0.0", tag, ver)
			}
		} else if tag == string(config.ModeVLESSXHTTP) {
			ss, ok := in["streamSettings"].(map[string]interface{})
			if ok {
				if rs, ok := ss["realitySettings"].(map[string]interface{}); ok {
					t.Errorf("non-reality inbound %s has realitySettings: %v", tag, rs)
				}
			}
		}
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

func containsString(value interface{}, expected string) bool {
	items, ok := value.([]interface{})
	if !ok {
		return false
	}
	for _, rawItem := range items {
		if item, _ := rawItem.(string); item == expected {
			return true
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
			Mode:            "tproxy",
			State:           "proxy",
			LocalEnabled:    true,
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
		if len(inboundsRaw) != 1 || inboundsRaw[0] != "tproxy-in" {
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

	for _, ruleRaw := range rules {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}
		if domainsRaw, ok := rule["domain"].([]interface{}); ok {
			for _, d := range domainsRaw {
				if d.(string) == "geosite:us" {
					t.Errorf("unexpected geosite:us domain rule found (only CN should have geosite bypass)")
				}
			}
		}
	}
}

func TestGenerateXrayJSONBypassCountries_Tun(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:            "tun",
			State:           "proxy",
			LocalEnabled:    true,
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

func TestGenerateXrayJSONInboundPortConflict(t *testing.T) {
	// Outbound proxy port conflicting with another outbound proxy port
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:              "relay-1",
				Enabled:            true,
				InternalProxyPort:  10808,
				InternalHttpPort:   10809,
				InternalListenAddr: "127.0.0.1",
				Config:             map[string]interface{}{"protocol": "freedom"},
			},
			{
				Alias:              "relay-2",
				Enabled:            true,
				InternalProxyPort:  10808, // Conflict!
				InternalHttpPort:   10810,
				InternalListenAddr: "127.0.0.1",
				Config:             map[string]interface{}{"protocol": "freedom"},
			},
		},
	}

	_, err := GenerateXrayJSON(cfg, nil, "")
	if err == nil {
		t.Fatalf("expected error due to port collision between relay-1 and relay-2")
	}
	if !strings.Contains(err.Error(), "inbound port conflict") {
		t.Fatalf("expected 'inbound port conflict' error, got %v", err)
	}
}

func TestGenerateXrayJSONGatewayDNSConfig(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:        "tproxy",
			State:       "proxy",
			DNSStrategy: "UseIPv4",
			DNSServers:  []string{"8.8.8.8", "tcp://1.1.1.1:53"},
			DNSRecords: map[string][]string{
				"router.lan": {"10.0.82.1"},
				"multi.lan":  {"10.0.82.1", "fd00:82::1"},
			},
		},
	}

	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	dns := getMap(t, parsed, "dns")

	if got := getString(t, dns, "queryStrategy"); got != "UseIPv4" {
		t.Fatalf("queryStrategy = %q, want UseIPv4", got)
	}

	servers := getStringSlice(t, dns, "servers")
	wantServers := []string{"8.8.8.8", "tcp://1.1.1.1:53"}
	assertStringSliceEqual(t, servers, wantServers)

	hosts := getMap(t, dns, "hosts")
	if hosts["router.lan"] != "10.0.82.1" {
		t.Errorf("hosts[router.lan] = %v, want 10.0.82.1", hosts["router.lan"])
	}
	multi, ok := hosts["multi.lan"].([]interface{})
	if !ok || len(multi) != 2 || multi[0] != "10.0.82.1" || multi[1] != "fd00:82::1" {
		t.Errorf("hosts[multi.lan] = %v, want [10.0.82.1, fd00:82::1]", hosts["multi.lan"])
	}
}

func TestGenerateXrayJSONGatewayDNSInbound(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:         "tproxy",
			State:        "proxy",
			LocalEnabled: true,
			LANEnabled:   true,
			DNSListen:    ":53",
		},
	}

	parsed := generateAndDecodeXrayConfig(t, cfg, "")
	inbounds, ok := parsed["inbounds"].([]interface{})
	if !ok {
		t.Fatal("inbounds not found")
	}

	var dnsIn map[string]interface{}
	for _, inb := range inbounds {
		m, _ := inb.(map[string]interface{})
		if m["tag"] == "dns-in" {
			dnsIn = m
			break
		}
	}

	if dnsIn == nil {
		t.Fatal("expected dns-in inbound")
	}
	if dnsIn["port"] != float64(53) {
		t.Errorf("dns-in port = %v, want 53", dnsIn["port"])
	}
	if dnsIn["listen"] != "::" {
		t.Errorf("dns-in listen = %v, want ::", dnsIn["listen"])
	}

	// Verify routing rule
	routing := getMap(t, parsed, "routing")
	rules, ok := routing["rules"].([]interface{})
	if !ok {
		t.Fatal("routing rules not found")
	}
	foundDNSInRule := false
	for _, r := range rules {
		ruleMap, _ := r.(map[string]interface{})
		inTags, _ := ruleMap["inboundTag"].([]interface{})
		for _, tag := range inTags {
			if tag == "dns-in" && ruleMap["outboundTag"] == "dns-out" {
				foundDNSInRule = true
				break
			}
		}
	}
	if !foundDNSInRule {
		t.Fatal("expected routing rule for dns-in -> dns-out")
	}
}

func TestGenerateXrayJSONGatewayDNSInboundDisabledWhenTunDisabled(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:         "tproxy",
			State:        "proxy",
			LocalEnabled: true,
			DNSListen:    ":53",
		},
	}

	raw, err := GenerateXrayJSON(cfg, map[string]int{"gateway-tun-disabled": 1}, "")
	if err != nil {
		t.Fatalf("GenerateXrayJSON failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}

	inbounds, _ := parsed["inbounds"].([]interface{})
	for _, inb := range inbounds {
		m, _ := inb.(map[string]interface{})
		if m["tag"] == "dns-in" {
			t.Fatal("dns-in should NOT be present when gateway-tun-disabled is set")
		}
	}
}

func TestDNSRoutingTargetsSkipsLocalSchemes(t *testing.T) {
	servers := []string{
		"https+local://1.1.1.1/dns-query",
		"tcp+local://8.8.8.8:53",
		"quic+local://dns.adguard.com:853",
		"tls://1.1.1.1:853",
		"quic://dns.adguard.com:853",
		"tcp://8.8.8.8:53",
	}

	domains, ips := dnsRoutingTargets(servers)
	for _, d := range domains {
		if strings.Contains(d, "local") {
			t.Errorf("unexpected local domain in routing targets: %s", d)
		}
	}
	for _, ip := range ips {
		if ip == "1.1.1.1" && len(domains) == 0 {
			// 1.1.1.1 comes from tls://1.1.1.1:853
		}
	}
	foundAdguard := false
	for _, d := range domains {
		if d == "dns.adguard.com" {
			foundAdguard = true
			break
		}
	}
	if !foundAdguard {
		t.Errorf("expected dns.adguard.com in domains, got: %v", domains)
	}
	found8888 := false
	for _, ip := range ips {
		if ip == "8.8.8.8" {
			found8888 = true
			break
		}
	}
	if !found8888 {
		t.Errorf("expected 8.8.8.8 in ips, got: %v", ips)
	}
}

func TestMultiRelayTProxyInboundsAndAllowPrivateTargets(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:         "tproxy",
			State:        "proxy",
			LANEnabled:   true,
			LocalEnabled: true,
			TProxyPort:   12345,
			RelayAlias:   "relay-public",
			Rules: []config.GatewayRule{
				{Interface: "eth1", Target: "direct"},
				{MAC: "52:54:00:83:00:11", Target: "relay-private"},
			},
		},
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:               "relay-public",
				Enabled:             true,
				AllowPrivateTargets: false,
			},
			{
				Alias:               "relay-private",
				Enabled:             true,
				AllowPrivateTargets: true,
			},
		},
	}

	rawJSON, err := GenerateXrayJSON(cfg, nil, "")
	if err != nil {
		t.Fatalf("GenerateXrayJSON failed: %v", err)
	}

	var root map[string]interface{}
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		t.Fatalf("unmarshal xray json failed: %v", err)
	}

	// 1. Inbounds check
	inbounds, ok := root["inbounds"].([]interface{})
	if !ok {
		t.Fatalf("missing inbounds")
	}
	inboundMap := make(map[string]map[string]interface{})
	for _, in := range inbounds {
		m := in.(map[string]interface{})
		tag := m["tag"].(string)
		inboundMap[tag] = m
	}

	tproxyIn, ok := inboundMap["tproxy-in"]
	if !ok {
		t.Fatalf("expected tproxy-in inbound")
	}
	if int(tproxyIn["port"].(float64)) != 12345 {
		t.Errorf("tproxy-in port = %v, want 12345", tproxyIn["port"])
	}

	tproxyExtra, ok := inboundMap["tproxy-in-relay-private"]
	if !ok {
		t.Fatalf("expected tproxy-in-relay-private inbound, got inbounds: %v", inboundMap)
	}
	if int(tproxyExtra["port"].(float64)) != 12346 {
		t.Errorf("tproxy-in-relay-private port = %v, want 12346", tproxyExtra["port"])
	}

	// 2. Routing rules order check
	routing := root["routing"].(map[string]interface{})
	rules := routing["rules"].([]interface{})

	var idxLoopback = -1
	var idxPrivateRelay = -1
	var idxGeoIPPrivate = -1
	var idxPublicRelay = -1

	for i, r := range rules {
		rm := r.(map[string]interface{})
		outTag, _ := rm["outboundTag"].(string)
		inTags, _ := rm["inboundTag"].([]interface{})
		ips, _ := rm["ip"].([]interface{})

		if outTag == "direct" && len(ips) == 2 {
			if ips[0] == "127.0.0.0/8" && ips[1] == "::1/128" {
				idxLoopback = i
			}
		}
		if outTag == "direct" && len(ips) == 1 && ips[0] == "geoip:private" {
			idxGeoIPPrivate = i
		}
		if outTag == "outbound-relay-private" && len(inTags) == 1 && inTags[0] == "tproxy-in-relay-private" {
			idxPrivateRelay = i
		}
		if outTag == "outbound-relay-public" && len(inTags) == 1 && inTags[0] == "tproxy-in" {
			idxPublicRelay = i
		}
	}

	if idxLoopback == -1 {
		t.Fatal("missing loopback protection rule (127.0.0.0/8, ::1/128 -> direct)")
	}
	if idxPrivateRelay == -1 {
		t.Fatal("missing relay-private routing rule")
	}
	if idxGeoIPPrivate == -1 {
		t.Fatal("missing geoip:private rule")
	}
	if idxPublicRelay == -1 {
		t.Fatal("missing relay-public routing rule")
	}

	// Order asserts:
	// idxLoopback < idxPrivateRelay < idxGeoIPPrivate < idxPublicRelay
	if idxLoopback >= idxPrivateRelay {
		t.Errorf("idxLoopback (%d) should be before idxPrivateRelay (%d)", idxLoopback, idxPrivateRelay)
	}
	if idxPrivateRelay >= idxGeoIPPrivate {
		t.Errorf("idxPrivateRelay (%d) should be BEFORE idxGeoIPPrivate (%d)", idxPrivateRelay, idxGeoIPPrivate)
	}
	if idxGeoIPPrivate >= idxPublicRelay {
		t.Errorf("idxGeoIPPrivate (%d) should be BEFORE idxPublicRelay (%d)", idxGeoIPPrivate, idxPublicRelay)
	}
}
