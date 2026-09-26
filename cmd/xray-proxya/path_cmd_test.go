package main

import (
	"encoding/json"
	"strings"
	"testing"
	"xray-proxya/internal/config"
	"xray-proxya/internal/pathd"
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
			Listen: pathd.DefaultListenAddress,
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
	if parsedServer.Listen != pathd.DefaultListenAddress {
		t.Errorf("listen = %q, want %s", parsedServer.Listen, pathd.DefaultListenAddress)
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

func resetPathSetFlags() {
	pathRelay = ""
	pathListen = ""
	pathToken = ""
	pathIdle = 20
	pathGenerate = false
	_ = pathSetCmd.Flags().Set("relay", "")
	_ = pathSetCmd.Flags().Set("listen", "")
	_ = pathSetCmd.Flags().Set("token", "")
	_ = pathSetCmd.Flags().Set("idle", "20")
	_ = pathSetCmd.Flags().Set("generate-token", "false")
	pathSetCmd.Flags().Lookup("relay").Changed = false
	pathSetCmd.Flags().Lookup("listen").Changed = false
	pathSetCmd.Flags().Lookup("token").Changed = false
	pathSetCmd.Flags().Lookup("idle").Changed = false
	pathSetCmd.Flags().Lookup("generate-token").Changed = false
}

func resetPathUnsetFlags() {
	pathRelay = ""
	_ = pathUnsetCmd.Flags().Set("relay", "")
	pathUnsetCmd.Flags().Lookup("relay").Changed = false
}

func TestPathSetUnsetPositionalAndFlags(t *testing.T) {
	setupTestConfigDir(t)

	// 1. Gateway Role Tests
	cfgGateway := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			RelayAlias: "hk-relay",
		},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "hk-relay", Enabled: true},
			{Alias: "jp-relay", Enabled: true},
		},
	}
	if err := cfgGateway.SaveEx(true); err != nil {
		t.Fatalf("save gateway staging config: %v", err)
	}

	// 1.1 Test positional relay in path set
	resetPathSetFlags()
	_ = pathSetCmd.Flags().Set("token", "token-hk-123")
	if err := pathSetCmd.RunE(pathSetCmd, []string{"hk-relay"}); err != nil {
		t.Fatalf("path set positional relay failed: %v", err)
	}
	stagingCfg, _ := config.LoadConfigEx(true)
	if stagingCfg.CustomOutbounds[0].Path == nil || stagingCfg.CustomOutbounds[0].Path.Token != "token-hk-123" {
		t.Fatalf("expected token-hk-123 for hk-relay, got: %+v", stagingCfg.CustomOutbounds[0].Path)
	}

	// 1.2 Test flag --relay in path set
	resetPathSetFlags()
	_ = pathSetCmd.Flags().Set("relay", "jp-relay")
	_ = pathSetCmd.Flags().Set("token", "token-jp-456")
	if err := pathSetCmd.RunE(pathSetCmd, nil); err != nil {
		t.Fatalf("path set --relay flag failed: %v", err)
	}
	stagingCfg, _ = config.LoadConfigEx(true)
	if stagingCfg.CustomOutbounds[1].Path == nil || stagingCfg.CustomOutbounds[1].Path.Token != "token-jp-456" {
		t.Fatalf("expected token-jp-456 for jp-relay, got: %+v", stagingCfg.CustomOutbounds[1].Path)
	}

	// 1.3 Test conflicting positional and flag
	resetPathSetFlags()
	_ = pathSetCmd.Flags().Set("relay", "jp-relay")
	_ = pathSetCmd.Flags().Set("token", "token-conflict")
	if err := pathSetCmd.RunE(pathSetCmd, []string{"hk-relay"}); err == nil {
		t.Fatal("expected error on conflicting relay positional and flag")
	}

	// 1.4 Test non-existent relay on gateway
	resetPathSetFlags()
	_ = pathSetCmd.Flags().Set("token", "token-nonexistent")
	if err := pathSetCmd.RunE(pathSetCmd, []string{"us-relay"}); err == nil {
		t.Fatal("expected error for non-existent relay")
	}

	// 1.5 Test missing relay on gateway
	resetPathSetFlags()
	_ = pathSetCmd.Flags().Set("token", "token-no-relay")
	if err := pathSetCmd.RunE(pathSetCmd, nil); err == nil {
		t.Fatal("expected error when relay is omitted on gateway")
	}

	// 1.6 Test positional unset on gateway
	resetPathUnsetFlags()
	if err := pathUnsetCmd.RunE(pathUnsetCmd, []string{"hk-relay"}); err != nil {
		t.Fatalf("path unset positional failed: %v", err)
	}
	stagingCfg, _ = config.LoadConfigEx(true)
	if stagingCfg.CustomOutbounds[0].Path != nil {
		t.Fatalf("expected hk-relay Path to be nil after unset, got: %+v", stagingCfg.CustomOutbounds[0].Path)
	}

	// 1.7 Test flag unset on gateway
	resetPathUnsetFlags()
	_ = pathUnsetCmd.Flags().Set("relay", "jp-relay")
	if err := pathUnsetCmd.RunE(pathUnsetCmd, nil); err != nil {
		t.Fatalf("path unset --relay flag failed: %v", err)
	}
	stagingCfg, _ = config.LoadConfigEx(true)
	if stagingCfg.CustomOutbounds[1].Path != nil {
		t.Fatalf("expected jp-relay Path to be nil after unset, got: %+v", stagingCfg.CustomOutbounds[1].Path)
	}

	// 1.8 Test unset non-existent relay on gateway
	resetPathUnsetFlags()
	if err := pathUnsetCmd.RunE(pathUnsetCmd, []string{"us-relay"}); err == nil {
		t.Fatal("expected error when unsetting non-existent relay")
	}

	// 2. Server Role Tests
	cfgServer := &config.UserConfig{
		Role: config.RoleServer,
	}
	if err := cfgServer.SaveEx(true); err != nil {
		t.Fatalf("save server staging config: %v", err)
	}

	// 2.1 Test server rejects relay arg
	resetPathSetFlags()
	_ = pathSetCmd.Flags().Set("token", "server-tok")
	if err := pathSetCmd.RunE(pathSetCmd, []string{"hk-relay"}); err == nil {
		t.Fatal("expected error when relay is specified on server")
	}

	// 2.2 Test server path set with --generate-token
	resetPathSetFlags()
	_ = pathSetCmd.Flags().Set("generate-token", "true")
	if err := pathSetCmd.RunE(pathSetCmd, nil); err != nil {
		t.Fatalf("server path set --generate-token failed: %v", err)
	}
	stagingCfg, _ = config.LoadConfigEx(true)
	if stagingCfg.Path.Token == "" {
		t.Fatal("expected generated token on server")
	}

	// 2.3 Test server path unset
	resetPathUnsetFlags()
	if err := pathUnsetCmd.RunE(pathUnsetCmd, nil); err != nil {
		t.Fatalf("server path unset failed: %v", err)
	}
	stagingCfg, _ = config.LoadConfigEx(true)
	if stagingCfg.Path.Token != "" {
		t.Fatalf("expected empty token on server after unset, got: %s", stagingCfg.Path.Token)
	}
}

