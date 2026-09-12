package tui

import (
	"strings"
	"testing"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
)

func TestStatusViewStagingIndicator(t *testing.T) {
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		UUID: "test-uuid",
	}
	state := xray.ServiceState{
		Active:      true,
		PID:         1234,
		ControlMode: "systemd",
	}

	report := BuildStatusReport(cfg, state, nil)
	if !strings.Contains(report, "Staging Config:") {
		t.Fatalf("expected BuildStatusReport to contain 'Staging Config:', got:\n%s", report)
	}

	rendered := RenderStatus(cfg, state, nil)
	if !strings.Contains(rendered, "Staging Config:") {
		t.Fatalf("expected RenderStatus to contain 'Staging Config:', got:\n%s", rendered)
	}
}
