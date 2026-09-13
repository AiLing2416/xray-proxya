package tui

import (
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func TestRenderRelaysWithPrivateColumn(t *testing.T) {
	active := &config.UserConfig{
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:               "node-1",
				Enabled:             true,
				UserUUID:            "uuid-1",
				AllowPrivateTargets: false,
				Config: map[string]interface{}{
					"protocol": "vless",
					"settings": map[string]interface{}{
						"vnext": []interface{}{
							map[string]interface{}{
								"address": "1.2.3.4",
								"port":    443,
							},
						},
					},
				},
			},
		},
	}
	staging := &config.UserConfig{
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:               "node-1",
				Enabled:             true,
				UserUUID:            "uuid-1",
				AllowPrivateTargets: false,
				Config: map[string]interface{}{
					"protocol": "vless",
					"settings": map[string]interface{}{
						"vnext": []interface{}{
							map[string]interface{}{
								"address": "1.2.3.4",
								"port":    443,
							},
						},
					},
				},
			},
			{
				Alias:               "node-2",
				Enabled:             true,
				UserUUID:            "uuid-2",
				AllowPrivateTargets: true,
				Config: map[string]interface{}{
					"protocol": "vmess",
					"settings": map[string]interface{}{
						"vnext": []interface{}{
							map[string]interface{}{
								"address": "5.6.7.8",
								"port":    8443,
							},
						},
					},
				},
			},
		},
	}

	rendered := RenderRelays(active, staging, 0, 120, nil)
	if !strings.Contains(rendered, "PRIVATE") {
		t.Fatalf("expected RenderRelays to have 'PRIVATE' column, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "BLOCKED") {
		t.Fatalf("expected RenderRelays to show BLOCKED for node-1, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "ALLOWED") {
		t.Fatalf("expected RenderRelays to show ALLOWED for node-2, got:\n%s", rendered)
	}
}

func TestRelayDetailAndLinkGatewayAndServer(t *testing.T) {
	co := config.CustomOutbound{
		Alias:               "relay-gw",
		Enabled:             true,
		UserUUID:            "test-uuid-1",
		AllowPrivateTargets: false,
		Config: map[string]interface{}{
			"protocol": "vless",
		},
	}

	// 1. Gateway Role: Relay link should be suppressed
	gwCfg := &config.UserConfig{
		Role:            "gateway",
		CustomOutbounds: []config.CustomOutbound{co},
	}
	gwModel := Model{
		staging:      gwCfg,
		currentTab:   tabRelays,
		cursor:       0,
		cachedIP:     "198.51.100.99",
		relayViewMode: make(map[string]string),
	}

	if link := gwModel.getSelectedLink(); link != "" {
		t.Fatalf("expected empty relay link for gateway role, got: %s", link)
	}
	if copyContent := gwModel.getSelectedCopyContent(); copyContent != "" {
		t.Fatalf("expected empty relay copy content for gateway role, got: %s", copyContent)
	}
	detailGW := gwModel.getSelectedDetailContent()
	if strings.Contains(detailGW, "Link:") {
		t.Fatalf("expected gateway relay detail not to contain 'Link:', got:\n%s", detailGW)
	}
	if !strings.Contains(detailGW, "Relay:    relay-gw") {
		t.Fatalf("expected gateway relay detail to contain 'Relay:    relay-gw', got:\n%s", detailGW)
	}

	// 2. Server Role: Relay link uses cachedIP non-blockingly
	serverCfg := &config.UserConfig{
		Role:            "server",
		UUID:            "server-uuid",
		CustomOutbounds: []config.CustomOutbound{co},
		Presets: []config.ModeInfo{
			{
				Mode:    config.ModeVLESSReality,
				Port:    443,
				Enabled: true,
				Settings: config.Settings{
					PublicKey: "test-pubkey",
					ShortID:   "01234567",
				},
			},
		},
	}
	serverModel := Model{
		staging:       serverCfg,
		currentTab:    tabRelays,
		cursor:        0,
		cachedIP:      "198.51.100.88",
		relayViewMode: make(map[string]string),
	}

	srvLink := serverModel.getSelectedLink()
	if srvLink == "" {
		t.Fatalf("expected non-empty link for server role with presets, got empty")
	}
	if !strings.Contains(srvLink, "198.51.100.88") {
		t.Fatalf("expected server relay link to use cachedIP 198.51.100.88, got: %s", srvLink)
	}
	srvDetail := serverModel.getSelectedDetailContent()
	if !strings.Contains(srvDetail, "Link:     "+srvLink) {
		t.Fatalf("expected server relay detail to contain link, got:\n%s", srvDetail)
	}
}

