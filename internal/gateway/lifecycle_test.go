package gateway

import (
	"testing"

	"xray-proxya/internal/config"
)

func TestWantsTunnel(t *testing.T) {
	base := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{Mode: "tun", State: "proxy", LocalEnabled: true},
	}
	if !WantsTunnel(base) {
		t.Fatal("proxy state with local gateway enabled should require TUN")
	}

	base.Gateway.State = "disabled"
	if WantsTunnel(base) {
		t.Fatal("disabled state should not require TUN")
	}
	base.Gateway.State = "forward-only"
	if WantsTunnel(base) {
		t.Fatal("forward-only state should not require TUN")
	}
	base.Gateway.State = "proxy"
	base.Gateway.LocalEnabled = false
	base.Gateway.LANEnabled = false
	if WantsTunnel(base) {
		t.Fatal("gateway with both local and LAN disabled should not require TUN")
	}
}
