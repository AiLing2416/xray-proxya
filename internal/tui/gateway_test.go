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
