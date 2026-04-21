package main

import (
	"strings"
	"testing"
)

func TestBuildSystemdServiceContentIncludesUnifiedLogPath(t *testing.T) {
	content := buildSystemdServiceContent("/usr/local/bin/xray-proxya", "/root/.local/share/xray-proxya", "/root/.local/share/xray-proxya/bin", "/root/.config/xray-proxya/xray.log")
	if !strings.Contains(content, "StandardOutput=append:/root/.config/xray-proxya/xray.log") {
		t.Fatalf("systemd content missing StandardOutput append path:\n%s", content)
	}
	if !strings.Contains(content, "StandardError=append:/root/.config/xray-proxya/xray.log") {
		t.Fatalf("systemd content missing StandardError append path:\n%s", content)
	}
}

func TestBuildOpenRCServiceContentIncludesUnifiedLogPath(t *testing.T) {
	content := buildOpenRCServiceContent("/usr/local/bin/xray-proxya", "/root/.local/share/xray-proxya/bin", "/root/.config/xray-proxya/xray.log")
	if !strings.Contains(content, "output_log=\"/root/.config/xray-proxya/xray.log\"") {
		t.Fatalf("openrc content missing output_log path:\n%s", content)
	}
	if !strings.Contains(content, "error_log=\"/root/.config/xray-proxya/xray.log\"") {
		t.Fatalf("openrc content missing error_log path:\n%s", content)
	}
}
