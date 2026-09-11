package endpoint

import (
	"strings"
	"testing"

	"xray-proxya/internal/config"
)

func TestResolveStaticSingleAndMultiple(t *testing.T) {
	cfg := &config.UserConfig{
		Endpoints: map[string]config.EndpointConfig{
			"single": {
				Type: config.EndpointTypeStatic,
				Host: "hk.example.com",
			},
			"multi": {
				Type: config.EndpointTypeStatic,
				Host: " 1.1.1.1, 2.2.2.2 , 3.3.3.3 ",
			},
			"empty": {
				Type: config.EndpointTypeStatic,
				Host: "  ",
			},
		},
	}

	// Test single
	addrs, err := Resolve(cfg, "single")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != "hk.example.com" {
		t.Fatalf("expected ['hk.example.com'], got %v", addrs)
	}

	// Test multi
	addrs, err = Resolve(cfg, "multi")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 3 || addrs[0] != "1.1.1.1" || addrs[1] != "2.2.2.2" || addrs[2] != "3.3.3.3" {
		t.Fatalf("expected ['1.1.1.1', '2.2.2.2', '3.3.3.3'], got %v", addrs)
	}

	// Test empty static
	_, err = Resolve(cfg, "empty")
	if err == nil {
		t.Fatalf("expected error for empty static host, got nil")
	}
}

func TestResolveAutoFallback(t *testing.T) {
	cfg := &config.UserConfig{
		Endpoints: map[string]config.EndpointConfig{
			"default": {
				Type:   config.EndpointTypeAuto,
				Family: "v4",
			},
			"auto-v6": {
				Type:   config.EndpointTypeAuto,
				Family: "v6",
			},
		},
	}

	// Resolve default (empty string should use "default")
	addrs, err := Resolve(cfg, "")
	if err != nil {
		t.Fatalf("failed to resolve default endpoint: %v", err)
	}
	if len(addrs) == 0 || addrs[0] == "" {
		t.Fatalf("expected non-empty IP for default auto, got %v", addrs)
	}

	// Resolve auto-v6 (in test environment with or without public v6, GetSmartIP falls back to local IP)
	addrsV6, err := Resolve(cfg, "auto-v6")
	if err != nil {
		t.Fatalf("failed to resolve auto-v6: %v", err)
	}
	if len(addrsV6) == 0 || addrsV6[0] == "" {
		t.Fatalf("expected non-empty IP for auto-v6, got %v", addrsV6)
	}
}

func TestResolveNonExistent(t *testing.T) {
	cfg := &config.UserConfig{
		Endpoints: map[string]config.EndpointConfig{
			"default": {
				Type:   config.EndpointTypeAuto,
				Family: "v4",
			},
		},
	}

	_, err := Resolve(cfg, "non-existent")
	if err == nil {
		t.Fatalf("expected error for non-existent endpoint, got nil")
	}
	expectedMsg := "endpoint 'non-existent' not found"
	if err.Error() != expectedMsg {
		t.Fatalf("expected error message %q, got %q", expectedMsg, err.Error())
	}
}

func TestGetTargetDescription(t *testing.T) {
	tests := []struct {
		ep   config.EndpointConfig
		want string
	}{
		{ep: config.EndpointConfig{Type: config.EndpointTypeStatic, Host: "node.test.com"}, want: "node.test.com"},
		{ep: config.EndpointConfig{Type: config.EndpointTypeStatic, Host: ""}, want: "(none)"},
		{ep: config.EndpointConfig{Type: config.EndpointTypeAuto, Family: "v4"}, want: "auto (v4)"},
		{ep: config.EndpointConfig{Type: config.EndpointTypeAuto, Family: "v6"}, want: "auto (v6)"},
		{ep: config.EndpointConfig{Type: config.EndpointTypeDynamicV6, Subnet: "2001:db8::/64"}, want: "dynamic-v6 (2001:db8::/64)"},
		{ep: config.EndpointConfig{Type: config.EndpointTypeDynamicV6}, want: "dynamic-v6"},
	}

	for _, tc := range tests {
		got := GetTargetDescription(tc.ep)
		if got != tc.want {
			t.Errorf("GetTargetDescription(%+v) = %q, want %q", tc.ep, got, tc.want)
		}
	}
}

func TestFindReferences(t *testing.T) {
	cfg := &config.UserConfig{
		AdminSub: config.AdminSubConfig{
			Token:    "admin-token",
			Endpoint: "custom-ep",
		},
		Guests: []config.GuestConfig{
			{Alias: "alice", Endpoint: "custom-ep"},
			{Alias: "bob", Endpoint: "default"},
			{Alias: "carol", Endpoint: ""},
		},
	}

	refsCustom := FindReferences(cfg, "custom-ep")
	if len(refsCustom) != 2 {
		t.Fatalf("expected 2 references for custom-ep, got %d: %v", len(refsCustom), refsCustom)
	}

	refsDefault := FindReferences(cfg, "default")
	if len(refsDefault) != 2 { // bob and carol
		t.Fatalf("expected 2 references for default, got %d: %v", len(refsDefault), refsDefault)
	}
}

func TestFindReferences_SubscriptionInstances(t *testing.T) {
	cfg := &config.UserConfig{
		AdminSub: config.AdminSubConfig{
			Token:    "admin-tok",
			Endpoint: "ep-admin",
		},
		SubscriptionInstances: map[string]config.AdminSubConfig{
			"default": {
				Token:    "admin-tok",
				Endpoint: "ep-admin",
			},
			"node-hk": {
				Token:    "hk-tok",
				Endpoint: "ep-hk",
			},
			"node-jp": {
				Token:    "jp-tok",
				Endpoint: "default",
			},
			"node-us": {
				Token: "us-tok",
				// Endpoint is empty -> defaults to default
			},
			"node-disabled": {
				Token:    "", // no token, inactive
				Endpoint: "ep-hk",
			},
		},
		Guests: []config.GuestConfig{
			{Alias: "alice", Endpoint: "ep-hk"},
		},
	}

	refsHK := FindReferences(cfg, "ep-hk")
	refsHKStr := strings.Join(refsHK, ",")
	if !strings.Contains(refsHKStr, "sub:node-hk") || !strings.Contains(refsHKStr, "guest:alice") || len(refsHK) != 2 {
		t.Errorf("FindReferences(ep-hk) = %v, want [sub:node-hk guest:alice]", refsHK)
	}

	refsDefault := FindReferences(cfg, "default")
	refsDefStr := strings.Join(refsDefault, ",")
	if !strings.Contains(refsDefStr, "sub:node-jp") || !strings.Contains(refsDefStr, "sub:node-us") || len(refsDefault) != 2 {
		t.Errorf("FindReferences(default) = %v, want [sub:node-jp sub:node-us]", refsDefault)
	}
}

