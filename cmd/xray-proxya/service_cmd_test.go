package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func TestBuildSystemdServiceContentUsesJournaldAndSandbox(t *testing.T) {
	content := buildSystemdServiceContent(rootManagerBinary, "/root/.local/share/xray-proxya", "/root/.local/share/xray-proxya/bin", "/root/.config/xray-proxya", "CAP_NET_BIND_SERVICE", true)
	for _, required := range []string{
		"User=root", "ExecStart=/root/.local/bin/xray-proxya run",
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

func TestBuildSubTemplateUsesInstanceConfiguration(t *testing.T) {
	content := buildSubTemplateServiceContent(rootManagerBinary, "/root/.local/share/xray-proxya", "/root/.config/xray-proxya", "/root/.local/share/xray-proxya/bin", true)
	for _, required := range []string{
		"ExecStartPre=/root/.local/bin/xray-proxya sub ensure-instance %i",
		"ExecStart=/root/.local/bin/xray-proxya sub run --instance %i",
		"NoNewPrivileges=yes", "ProtectSystem=strict",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("template missing %q:\n%s", required, content)
		}
	}
}

func TestUserUnitDoesNotRequestCapabilities(t *testing.T) {
	content := buildSystemdServiceContent("/home/ailing/.local/bin/xray-proxya", "/home/ailing/.local/share/xray-proxya", "/home/ailing/.local/share/xray-proxya/bin", "/home/ailing/.config/xray-proxya", "", false)
	if strings.Contains(content, "CapabilityBoundingSet=") || strings.Contains(content, "AmbientCapabilities=") || strings.Contains(content, "User=root") {
		t.Fatalf("user service must not request root capabilities:\n%s", content)
	}
}

func TestNormalizedManagedUnitRejectsForeignUnits(t *testing.T) {
	if _, err := normalizedManagedUnit("ssh.service"); err == nil {
		t.Fatal("foreign unit was accepted")
	}
	unit, err := normalizedManagedUnit("xray-proxya-sub@mysub")
	if err != nil || unit != "xray-proxya-sub@mysub.service" {
		t.Fatalf("template unit = %q, %v", unit, err)
	}
}

func TestDirectRootServiceRejectsSudoMarkers(t *testing.T) {
	for _, test := range []struct {
		euid              int
		sudoUser, sudoUID string
		wantError         bool
	}{
		{euid: 0},
		{euid: 1000, wantError: true},
		{euid: 0, sudoUser: "ailing", wantError: true},
		{euid: 0, sudoUID: "1000", wantError: true},
	} {
		if err := directRootServiceErrorFor(test.euid, test.sudoUser, test.sudoUID); (err != nil) != test.wantError {
			t.Fatalf("directRootServiceErrorFor(%d, %q, %q) = %v, want error %t", test.euid, test.sudoUser, test.sudoUID, err, test.wantError)
		}
	}
}

func TestEnsureSubInstanceCreatesIndependentConfiguration(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", tempDir)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		AdminSub: config.AdminSubConfig{
			Enabled:    true,
			Token:      "instance-token",
			Port:       18443,
			TargetType: "direct",
		},
		GuestSubBind: "127.0.0.1",
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("save config: %v", err)
	}
	if err := ensureSubInstance(defaultSubInstance); err != nil {
		t.Fatalf("ensure default instance: %v", err)
	}
	if err := ensureSubInstance("mysub"); err != nil {
		t.Fatalf("ensure named instance: %v", err)
	}
	defaultConfig, err := loadSubInstance(defaultSubInstance)
	if err != nil {
		t.Fatalf("load default instance: %v", err)
	}
	namedConfig, err := loadSubInstance("mysub")
	if err != nil {
		t.Fatalf("load named instance: %v", err)
	}
	if defaultConfig.Port != 18443 || namedConfig.Port == defaultConfig.Port {
		t.Fatalf("ports = default:%d named:%d, want independent listeners", defaultConfig.Port, namedConfig.Port)
	}
	path, err := subInstancePath("mysub")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 || filepath.Dir(path) != filepath.Join(tempDir, "subscriptions") {
		t.Fatalf("instance file permissions/path = %o %s", info.Mode().Perm(), path)
	}
}
