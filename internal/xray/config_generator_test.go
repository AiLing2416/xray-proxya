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
	want := []string{"https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query", "localhost"}
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
