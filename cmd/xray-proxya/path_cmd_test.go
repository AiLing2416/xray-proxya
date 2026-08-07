package main

import (
	"strings"
	"testing"
)

func TestPathdSystemdUnitIsCapabilityBounded(t *testing.T) {
	unit := buildPathdSystemdServiceContent("/root/.local/bin/xray-proxya-pathd", "/root/.config/xray-proxya/pathd.json")
	for _, required := range []string{
		"User=root", "CapabilityBoundingSet=CAP_NET_RAW", "AmbientCapabilities=CAP_NET_RAW",
		"NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=read-only",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
	} {
		if !strings.Contains(unit, required) {
			t.Fatalf("unit missing %q", required)
		}
	}
	if strings.Contains(unit, "CAP_NET_ADMIN") {
		t.Fatal("pathd must not receive CAP_NET_ADMIN")
	}
}
