package main

import (
	"encoding/json"
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

func TestPathPingServerRoleGuard(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("save config: %v", err)
	}

	const expectedErrMsg = "ICMP probing commands (ping, trace, mtu) are only supported on Gateway nodes"

	// 1. path ping
	err := pathPingCmd.RunE(pathPingCmd, []string{"1.1.1.1"})
	if err == nil || !strings.Contains(err.Error(), expectedErrMsg) {
		t.Fatalf("expected server role guard error on path ping, got: %v", err)
	}

	// 2. path trace
	err = pathTraceCmd.RunE(pathTraceCmd, []string{"1.1.1.1"})
	if err == nil || !strings.Contains(err.Error(), expectedErrMsg) {
		t.Fatalf("expected server role guard error on path trace, got: %v", err)
	}

	// 3. path mtu
	err = pathMTUCmd.RunE(pathMTUCmd, []string{"1.1.1.1"})
	if err == nil || !strings.Contains(err.Error(), expectedErrMsg) {
		t.Fatalf("expected server role guard error on path mtu, got: %v", err)
	}
}

func TestPathStatusJSON(t *testing.T) {
	setupTestConfigDir(t)

	// 1. Test Server Role
	cfgServer := &config.UserConfig{
		Role: config.RoleServer,
		Path: config.PathConfig{
			Listen: "127.0.0.1:39091",
			Token:  "test-tok",
		},
	}
	if err := cfgServer.Save(); err != nil {
		t.Fatalf("save config: %v", err)
	}

	pathStatusCmd.Flags().Set("json", "true")
	defer pathStatusCmd.Flags().Set("json", "false")

	out := captureStdout(t, func() {
		if err := pathStatusCmd.RunE(pathStatusCmd, nil); err != nil {
			t.Fatalf("path status failed: %v", err)
		}
	})

	var parsedServer PathStatusJSON
	if err := json.Unmarshal([]byte(out), &parsedServer); err != nil {
		t.Fatalf("unmarshal json: %v\nOutput: %s", err, out)
	}
	if parsedServer.Role != "server" {
		t.Errorf("role = %q, want server", parsedServer.Role)
	}
	if parsedServer.Listen != "127.0.0.1:39091" {
		t.Errorf("listen = %q, want 127.0.0.1:39091", parsedServer.Listen)
	}

	// 2. Test Gateway Role
	cfgGateway := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			RelayAlias: "hk-relay",
		},
	}
	if err := cfgGateway.Save(); err != nil {
		t.Fatalf("save gateway config: %v", err)
	}

	outGateway := captureStdout(t, func() {
		if err := pathStatusCmd.RunE(pathStatusCmd, nil); err != nil {
			t.Fatalf("path status gateway failed: %v", err)
		}
	})

	var parsedGateway PathStatusJSON
	if err := json.Unmarshal([]byte(outGateway), &parsedGateway); err != nil {
		t.Fatalf("unmarshal gateway json: %v\nOutput: %s", err, outGateway)
	}
	if parsedGateway.Role != "gateway" {
		t.Errorf("role = %q, want gateway", parsedGateway.Role)
	}
	if parsedGateway.Relay != "hk-relay" {
		t.Errorf("relay = %q, want hk-relay", parsedGateway.Relay)
	}
}

