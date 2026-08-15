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

func TestBuildSubTemplateUsesInstanceConfiguration(t *testing.T) {
	content := buildSubTemplateServiceContent(rootManagerBinary, "/root/.local/share/xray-proxya", "/root/.config/xray-proxya", "/root/.local/share/xray-proxya/bin", true)
	for _, required := range []string{
		"ExecStartPre=/root/.local/bin/xray-proxya sub validate %i",
		"ExecStart=/root/.local/bin/xray-proxya sub run %i",
		"NoNewPrivileges=yes", "ProtectSystem=strict",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("template missing %q:\n%s", required, content)
		}
	}
}

func TestBuildIPv6RotateServiceIsPrivilegedAndIsolated(t *testing.T) {
	content := buildIPv6RotateServiceContent(rootManagerBinary, "/root/.local/share/xray-proxya", "/root/.config/xray-proxya", "/root/.local/share/xray-proxya/bin")
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
	unit, err := normalizedManagedUnit("xray-proxya-sub@mysub")
	if err != nil || unit != "xray-proxya-sub@mysub.service" {
		t.Fatalf("sub unit = %q, %v", unit, err)
	}
	unit, err = normalizedManagedUnit("xray-proxya-ipv6-rotate")
	if err != nil || unit != "xray-proxya-ipv6-rotate.service" {
		t.Fatalf("rotate unit = %q, %v", unit, err)
	}
}

func TestManagedServiceUnitCompletionIncludesDefaultSubscription(t *testing.T) {
	units, directive := completeManagedServiceUnits(nil, nil, "")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("completion directive = %v, want no file completion", directive)
	}
	for _, want := range []string{
		"xray-proxya\tmain Xray-Proxya service",
		"xray-proxya-pathd\tPathLink ICMP agent",
		"xray-proxya-sub@default\tsubscription instance",
		"xray-proxya-ipv6-rotate\tIPv6 rotation service",
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
