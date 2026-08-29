package main

import (
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func TestPathRequiresDirectRootShell(t *testing.T) {
	for _, test := range []struct {
		name                           string
		euid                           int
		sudoUser, sudoUID, sudoCommand string
		wantError                      bool
	}{
		{name: "direct root", euid: 0},
		{name: "ordinary user", euid: 1000, wantError: true},
		{name: "sudo -i bash", euid: 0, sudoUser: "ailing", sudoUID: "1000", sudoCommand: "/bin/bash", wantError: false},
		{name: "sudo -i zsh", euid: 0, sudoUser: "ailing", sudoUID: "1000", sudoCommand: "/bin/zsh", wantError: false},
		{name: "sudo su", euid: 0, sudoUser: "ailing", sudoUID: "1000", sudoCommand: "/bin/su", wantError: false},
		{name: "sudo user marker without shell", euid: 0, sudoUser: "ailing", sudoUID: "1000", sudoCommand: "/root/.local/bin/xray-proxya path token", wantError: true},
		{name: "sudo uid marker without shell", euid: 0, sudoUID: "1000", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := pathRootOnlyError(test.euid, test.sudoUser, test.sudoUID, test.sudoCommand)
			if (err != nil) != test.wantError {
				t.Fatalf("pathRootOnlyError() error = %v, want error %t", err, test.wantError)
			}
		})
	}
}

func TestPathRoleRelayValidation(t *testing.T) {
	if err := validatePathRole(config.RoleServer, "relay-a"); err == nil {
		t.Fatal("Server must reject --relay")
	}
	if err := validatePathRole(config.RoleServer, ""); err != nil {
		t.Fatalf("Server local Pathd config rejected: %v", err)
	}
	if err := validatePathRole(config.RoleGateway, ""); err == nil {
		t.Fatal("Gateway must require --relay")
	}
	if err := validatePathRole(config.RoleGateway, "relay-a"); err != nil {
		t.Fatalf("Gateway relay config rejected: %v", err)
	}
}

func TestPathdSystemdUnitIsCapabilityBounded(t *testing.T) {
	unit := buildPathdSystemdServiceContent("/root/.local/share/xray-proxya/bin/pathd", "/root/.config/xray-proxya/pathd.json")
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
