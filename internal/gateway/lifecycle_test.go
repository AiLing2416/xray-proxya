package gateway

import (
	"testing"

	"xray-proxya/internal/config"
)

func TestWantsTunnel(t *testing.T) {
	base := &config.UserConfig{
		Role:    config.RoleGateway,
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

func TestPathTunnelDisabledMarkerDegradesOnlyPathLink(t *testing.T) {
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", t.TempDir())
	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode: "tun", State: "proxy", LocalEnabled: true, RelayAlias: "relay-a",
		},
		Path: config.PathConfig{Enabled: true, Token: "token"},
	}
	if !WantsTunnel(cfg) || !pathTunnelEnabled(cfg) {
		t.Fatal("expected a configured gateway with PathLink to request both tunnels")
	}
	if err := config.SetPathTunDisabled(true); err != nil {
		t.Fatal(err)
	}
	if !WantsTunnel(cfg) {
		t.Fatal("PathLink failure must not disable the main gateway TUN")
	}
	if pathTunnelEnabled(cfg) {
		t.Fatal("PathLink runtime marker must disable only path-tun")
	}
}
