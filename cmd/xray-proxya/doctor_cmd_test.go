package main

import (
	"strings"
	"testing"

	proxyaSELinux "xray-proxya/internal/selinux"
)

func TestDoctorCommandIsAContainerWithSELinuxSubcommand(t *testing.T) {
	if doctorCmd.Run != nil || doctorCmd.RunE != nil {
		t.Fatal("doctor must not perform an action without an explicit subcommand")
	}
	command, _, err := doctorCmd.Find([]string{"selinux"})
	if err != nil {
		t.Fatalf("find doctor selinux: %v", err)
	}
	if command != doctorSELinuxCmd {
		t.Fatalf("doctor selinux command = %q, want %q", command.Name(), doctorSELinuxCmd.Name())
	}
}

func TestSELinuxEnabledStatus(t *testing.T) {
	if !containsSELinuxEnabled("SELinux status:                 enabled\nCurrent mode:                   enforcing\n") {
		t.Fatal("enabled SELinux status was not recognized")
	}
	if containsSELinuxEnabled("SELinux status:                 disabled\n") {
		t.Fatal("disabled SELinux status was recognized")
	}
}

func TestLegacySELinuxTopLevelCommandIsRemoved(t *testing.T) {
	for _, command := range rootCmd.Commands() {
		if command.Name() == "selinux" {
			t.Fatal("legacy top-level selinux command is still registered")
		}
	}
}

func TestSELinuxPolicyDoesNotGrantPrivateLogFileAccess(t *testing.T) {
	if strings.Contains(proxyaSELinux.PolicySource, "xray_proxya_log_t") {
		t.Fatal("journald-based service policy must not reference xray_proxya_log_t")
	}
}

func TestSELinuxPolicyAllowsHardenedServiceTransitions(t *testing.T) {
	if !strings.Contains(proxyaSELinux.PolicySource, "allow init_t xray_proxya_t:process2 nnp_transition;") {
		t.Fatal("root service needs an nnp_transition permission under NoNewPrivileges")
	}
}

func TestSELinuxPolicyReadsEnforcementModeWithoutGetenforce(t *testing.T) {
	for _, domain := range []string{"xray_proxya_t", "xray_proxya_gateway_t"} {
		if !strings.Contains(proxyaSELinux.PolicySource, "selinux_get_enforce_mode("+domain+")") {
			t.Fatalf("%s cannot read SELinux enforcement mode", domain)
		}
	}
}

func TestSELinuxPolicyAllowsOnlyGatewayLifecycleSystemActions(t *testing.T) {
	want := "allow xray_proxya_gateway_t init_t:system { start stop status };"
	if !strings.Contains(proxyaSELinux.PolicySource, want) {
		t.Fatalf("gateway lifecycle system permission is missing: %q", want)
	}
}
