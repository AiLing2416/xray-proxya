package tui

import (
	"reflect"
	"testing"

	"xray-proxya/internal/config"
)

func TestGatewayTestEndpointsExcludeBypassDNS(t *testing.T) {
	cfg := &config.UserConfig{Gateway: config.GatewayConfig{BypassDNS: []string{"1.1.1.1", "invalid"}}}
	want := []string{"https://1.0.0.1/cdn-cgi/trace"}
	if got := gatewayTestEndpoints(cfg); !reflect.DeepEqual(got, want) {
		t.Fatalf("gatewayTestEndpoints() = %v, want %v", got, want)
	}
}

func TestGatewayTestEndpointsCanBeExhausted(t *testing.T) {
	cfg := &config.UserConfig{Gateway: config.GatewayConfig{BypassDNS: []string{"1.1.1.1", "1.0.0.1"}}}
	if got := gatewayTestEndpoints(cfg); len(got) != 0 {
		t.Fatalf("gatewayTestEndpoints() = %v, want no endpoints", got)
	}
}

func newTestGatewayConfig() *config.UserConfig {
	return &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			State:           "proxy",
			LocalEnabled:    true,
			LANEnabled:      true,
			LANInterface:    "eth0",
			BypassCountries: []string{"CN"},
		},
	}
}

func TestHasGatewayStagedChanges(t *testing.T) {
	active := newTestGatewayConfig()
	staging := newTestGatewayConfig()

	if HasGatewayStagedChanges(active, staging) {
		t.Fatal("expected no staged changes for identical configs")
	}

	staging.Gateway.State = "forward-only"
	if !HasGatewayStagedChanges(active, staging) {
		t.Fatal("expected staged changes after modifying Gateway.State")
	}

	staging = newTestGatewayConfig()
	staging.Gateway.LocalEnabled = !active.Gateway.LocalEnabled
	if !HasGatewayStagedChanges(active, staging) {
		t.Fatal("expected staged changes after modifying Gateway.LocalEnabled")
	}

	staging = newTestGatewayConfig()
	staging.Gateway.BypassCountries = []string{"CN", "US"}
	if !HasGatewayStagedChanges(active, staging) {
		t.Fatal("expected staged changes after modifying Gateway.BypassCountries")
	}
}

func TestBuildGatewayReport(t *testing.T) {
	active := newTestGatewayConfig()
	staging := newTestGatewayConfig()
	staging.Gateway.State = "proxy"
	staging.Gateway.LocalEnabled = true
	staging.Gateway.LANEnabled = true
	staging.Gateway.LANInterface = "eth0"
	staging.Gateway.BypassCountries = []string{"CN"}

	for row := 0; row <= 6; row++ {
		report := BuildGatewayReport(active, staging, row, true, true, true, "10.49.0.201", "10.49.0.202")
		if report == "" {
			t.Fatalf("row %d: report should not be empty", row)
		}
	}
}

func TestValidateCountryCodes(t *testing.T) {
	tests := []struct {
		input   string
		want    []string
		wantErr bool
	}{
		{"CN", []string{"CN"}, false},
		{"cn, us , hk", []string{"CN", "US", "HK"}, false},
		{"", nil, false},
		{"   ", nil, false},
		{"C", nil, true},
		{"CHN", nil, true},
		{"12", nil, true},
		{"C1", nil, true},
	}

	for _, tt := range tests {
		got, err := validateCountryCodes(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateCountryCodes(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
			t.Errorf("validateCountryCodes(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
