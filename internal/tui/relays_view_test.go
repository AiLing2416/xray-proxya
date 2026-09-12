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
