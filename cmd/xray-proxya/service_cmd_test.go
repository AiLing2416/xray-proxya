package main

import (
	"strings"
	"testing"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

func TestBuildSystemdServiceContentUsesJournaldAndSandbox(t *testing.T) {
	content := buildSystemdServiceContent(rootManagerBinary, "/root/.local/share/xray-proxya", "/root/.local/share/xray-proxya/bin", "/root/.config/xray-proxya", "CAP_NET_BIND_SERVICE", true, true)
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

func TestRunCommandReturnsErrorsToSystemd(t *testing.T) {
	if runCmd.RunE == nil {
		t.Fatal("run command must use RunE so startup and TUN recovery failures reach systemd")
	}
}

func TestGatewayServiceStartUsesLifecycleRecovery(t *testing.T) {
	for _, test := range []struct {
		action string
		now    bool
		want   bool
	}{
		{action: "start", want: true},
		{action: "enable", now: true, want: true},
		{action: "enable", want: false},
		{action: "restart", want: false},
		{action: "stop", want: false},
	} {
		if got := mainServiceActionNeedsGatewayRecovery(test.action, test.now); got != test.want {
			t.Fatalf("mainServiceActionNeedsGatewayRecovery(%q, %t) = %t, want %t", test.action, test.now, got, test.want)
		}
	}
}

func TestBuildSubServiceContent(t *testing.T) {
	content := buildSubServiceContent(rootManagerBinary, "/root/.local/share/xray-proxya", "/root/.config/xray-proxya", "/root/.local/share/xray-proxya/bin", true)
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

func TestUserUnitDoesNotRequestCapabilities(t *testing.T) {
	content := buildSystemdServiceContent("/home/ailing/.local/bin/xray-proxya", "/home/ailing/.local/share/xray-proxya", "/home/ailing/.local/share/xray-proxya/bin", "/home/ailing/.config/xray-proxya", "", false, true)
	if strings.Contains(content, "CapabilityBoundingSet=") || strings.Contains(content, "AmbientCapabilities=") || strings.Contains(content, "User=root") {
		t.Fatalf("user service must not request root capabilities:\n%s", content)
	}
}

func TestGatewayUnitExposesTUNDeviceOnlyForGateway(t *testing.T) {
	content := buildSystemdServiceContent(rootManagerBinary, "/root/.local/share/xray-proxya", "/root/.local/share/xray-proxya/bin", "/root/.config/xray-proxya", "CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW", true, false)
	if !strings.Contains(content, "PrivateDevices=no") {
		t.Fatalf("gateway unit must expose /dev/net/tun:\n%s", content)
	}
}

func TestNormalizedManagedUnitRejectsForeignUnits(t *testing.T) {
	if _, err := normalizedManagedUnit("ssh.service"); err == nil {
		t.Fatal("foreign unit was accepted")
	}

	tests := []struct {
		inputs   []string
		expected string
	}{
		{
			inputs:   []string{"", "core", "CORE", "xray-proxya", "xray-proxya.service"},
			expected: "xray-proxya.service",
		},
		{
			inputs:   []string{"sub", "SUB", "xray-proxya-sub", "xray-proxya-sub.service"},
			expected: "xray-proxya-sub.service",
		},
		{
			inputs:   []string{"pathd", "PATHD", "xray-proxya-pathd", "xray-proxya-pathd.service"},
			expected: "xray-proxya-pathd.service",
		},
	}

	for _, tc := range tests {
		for _, in := range tc.inputs {
			unit, err := normalizedManagedUnit(in)
			if err != nil || unit != tc.expected {
				t.Fatalf("normalizedManagedUnit(%q) = %q, %v; want %q", in, unit, err, tc.expected)
			}
		}
	}
}

func TestManagedServiceUnitCompletionIncludesDefaultSubscription(t *testing.T) {
	units, directive := completeManagedServiceUnits(nil, nil, "")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("completion directive = %v, want no file completion", directive)
	}
	for _, want := range []string{
		"core\tCore proxy service (xray-proxya)",
		"sub\tSubscription distribution service (xray-proxya-sub)",
		"pathd\tPathLink ICMP latency & health daemon (xray-proxya-pathd)",
		"xray-proxya\tCore proxy service (xray-proxya)",
		"xray-proxya-sub\tSubscription distribution service (xray-proxya-sub)",
		"xray-proxya-pathd\tPathLink ICMP latency & health daemon (xray-proxya-pathd)",
	} {
		if !containsCompletion(units, want) {
			t.Fatalf("completion missing %q: %v", want, units)
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
		if err := directRootServiceErrorFor(test.euid, test.sudoUser, test.sudoUID, test.sudoCommand); (err != nil) != test.wantError {
			t.Fatalf("directRootServiceErrorFor(%d, %q, %q, %q) = %v, want error %t", test.euid, test.sudoUser, test.sudoUID, test.sudoCommand, err, test.wantError)
		}
	}
}

func TestSubscriptionInstanceReadsActiveConfiguration(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", tempDir)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		AdminSub: config.AdminSubConfig{
			Token:      "instance-token",
			Port:       18443,
			TargetType: "direct",
		},
		GuestSubBind: "127.0.0.1",
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("save config: %v", err)
	}
	defaultConfig, err := subscriptionInstance(defaultSubInstance)
	if err != nil {
		t.Fatalf("load subscription instance: %v", err)
	}
	if defaultConfig.Port != 18443 {
		t.Fatalf("port = %d, want 18443", defaultConfig.Port)
	}
	if _, err := subscriptionInstance("mysub"); err == nil {
		t.Fatal("unknown instance was accepted")
	}
}
