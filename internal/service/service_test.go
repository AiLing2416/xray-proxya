package service

import (
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func TestBuildSystemdServiceContentUsesJournaldAndSandbox(t *testing.T) {
	content := BuildSystemdServiceContent(RootManagerBinary, "/root/.local/share/xray-proxya", "/root/.local/share/xray-proxya/bin", "/root/.config/xray-proxya", "CAP_NET_BIND_SERVICE", true, true)
	for _, required := range []string{
		"User=root", "ExecStart=/root/.local/bin/xray-proxya run",
		"Type=exec",
		"NoNewPrivileges=yes", "ProtectSystem=strict",
		"ReadWritePaths=/root/.config/xray-proxya /root/.local/share/xray-proxya",
		"CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("unit missing %q:\n%s", required, content)
		}
	}
	if strings.Contains(content, "StandardOutput=") || strings.Contains(content, "StandardError=") {
		t.Fatalf("unit must send logs to journald:\n%s", content)
	}
}

func TestBuildSubServiceContent(t *testing.T) {
	content := BuildSubServiceContent(RootManagerBinary, "/root/.local/share/xray-proxya", "/root/.config/xray-proxya", "/root/.local/share/xray-proxya/bin", true)
	for _, required := range []string{
		"ExecStartPre=/root/.local/bin/xray-proxya sub validate",
		"ExecStart=/root/.local/bin/xray-proxya sub run",
		"NoNewPrivileges=yes", "ProtectSystem=strict",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("template missing %q:\n%s", required, content)
		}
	}
}

func TestBuildIPv6RotateServiceIsPrivilegedAndIsolated(t *testing.T) {
	content := BuildIPv6RotateServiceContent(RootManagerBinary, "/root/.local/share/xray-proxya", "/root/.config/xray-proxya", "/root/.local/share/xray-proxya/bin")
	for _, required := range []string{
		"ExecStartPre=/root/.local/bin/xray-proxya ipv6-rotate validate",
		"ExecStart=/root/.local/bin/xray-proxya ipv6-rotate run",
		"CapabilityBoundingSet=CAP_NET_ADMIN",
		"NoNewPrivileges=yes", "ProtectSystem=strict",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("rotate service missing %q:\n%s", required, content)
		}
	}
}

func TestUserUnitDoesNotRequestCapabilities(t *testing.T) {
	content := BuildSystemdServiceContent("/home/ailing/.local/bin/xray-proxya", "/home/ailing/.local/share/xray-proxya", "/home/ailing/.local/share/xray-proxya/bin", "/home/ailing/.config/xray-proxya", "", false, true)
	if strings.Contains(content, "CapabilityBoundingSet=") || strings.Contains(content, "AmbientCapabilities=") || strings.Contains(content, "User=root") {
		t.Fatalf("user service must not request root capabilities:\n%s", content)
	}
}

func TestGatewayUnitExposesTUNDeviceOnlyForGateway(t *testing.T) {
	content := BuildSystemdServiceContent(RootManagerBinary, "/root/.local/share/xray-proxya", "/root/.local/share/xray-proxya/bin", "/root/.config/xray-proxya", "CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW", true, false)
	if !strings.Contains(content, "PrivateDevices=no") {
		t.Fatalf("gateway unit must expose /dev/net/tun:\n%s", content)
	}
}

func TestBuildPathdServiceContent(t *testing.T) {
	content := BuildPathdServiceContent("/root/.local/share/xray-proxya/bin/pathd", "/root/.config/xray-proxya/pathd.json")
	for _, required := range []string{
		"Description=Xray-Proxya PathLink Agent",
		"User=root",
		"ExecStart=/root/.local/share/xray-proxya/bin/pathd serve --config /root/.config/xray-proxya/pathd.json",
		"CapabilityBoundingSet=CAP_NET_RAW",
		"AmbientCapabilities=CAP_NET_RAW",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("pathd service missing %q:\n%s", required, content)
		}
	}
}

func TestNormalizeUnitName(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"", MainUnit, false},
		{"xray-proxya", MainUnit, false},
		{"core", MainUnit, false},
		{MainUnit, MainUnit, false},
		{"xray-proxya-pathd", PathdUnit, false},
		{"pathd", PathdUnit, false},
		{PathdUnit, PathdUnit, false},
		{"xray-proxya-ipv6-rotate", RotateUnit, false},
		{"ipv6-rotate", RotateUnit, false},
		{"rotate", RotateUnit, false},
		{RotateUnit, RotateUnit, false},
		{"xray-proxya-sub", SubUnit, false},
		{"sub", SubUnit, false},
		{SubUnit, SubUnit, false},
		{"xray-proxya-sub@default.service", SubUnit, false},
		{"ssh.service", "", true},
		{"unknown", "", true},
	}

	for _, tt := range tests {
		got, err := NormalizeUnitName(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("NormalizeUnitName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("NormalizeUnitName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDirectRootServiceAllowsSudoLoginShellButRejectsDirectSudo(t *testing.T) {
	for _, test := range []struct {
		euid                           int
		sudoUser, sudoUID, sudoCommand string
		wantError                      bool
	}{
		{euid: 0},
		{euid: 1000, wantError: true},
		{euid: 0, sudoUser: "ailing", sudoUID: "1000", sudoCommand: "/bin/bash"},
		{euid: 0, sudoUser: "ailing", sudoUID: "1000", sudoCommand: "/bin/zsh"},
		{euid: 0, sudoUser: "ailing", sudoUID: "1000", sudoCommand: "/bin/su"},
		{euid: 0, sudoUser: "ailing", sudoUID: "1000", sudoCommand: "/usr/bin/su -"},
		{euid: 0, sudoUser: "ailing", sudoUID: "1000", sudoCommand: "/root/.local/bin/xray-proxya service install", wantError: true},
		{euid: 0, sudoUser: "ailing", sudoUID: "1000", wantError: true},
	} {
		if err := DirectRootServiceErrorFor(test.euid, test.sudoUser, test.sudoUID, test.sudoCommand); (err != nil) != test.wantError {
			t.Fatalf("DirectRootServiceErrorFor(%d, %q, %q, %q) = %v, want error %t", test.euid, test.sudoUser, test.sudoUID, test.sudoCommand, err, test.wantError)
		}
	}
}

func TestMainUnitCapabilities(t *testing.T) {
	gwCfg := &config.UserConfig{Role: config.RoleGateway}
	if caps := MainUnitCapabilities(gwCfg); !strings.Contains(caps, "CAP_NET_ADMIN") {
		t.Fatalf("gateway capabilities missing CAP_NET_ADMIN: %s", caps)
	}

	serverCfg := &config.UserConfig{Role: config.RoleServer}
	if caps := MainUnitCapabilities(serverCfg); strings.Contains(caps, "CAP_NET_ADMIN") {
		t.Fatalf("server capabilities should not include CAP_NET_ADMIN: %s", caps)
	}
}
