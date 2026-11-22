package main

import (
	"bytes"
	"os"
	"path/filepath"
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

func TestDoctorSELinuxUninstallFlag(t *testing.T) {
	flag := doctorSELinuxCmd.Flags().Lookup("uninstall")
	if flag == nil {
		t.Fatal("expected doctor selinux to have --uninstall flag")
	}
	if flag.Shorthand != "u" {
		t.Fatalf("expected shorthand 'u', got %q", flag.Shorthand)
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

func TestSELinuxPolicyAllowsSubscriptionRotationSocket(t *testing.T) {
	if !strings.Contains(proxyaSELinux.PolicySource, "manage_sock_files_pattern(xray_proxya_t, xray_proxya_config_t, xray_proxya_config_t)") {
		t.Fatal("policy must permit the private IPv6 rotation Unix socket")
	}
}

func TestSELinuxPolicyAllowsIPv6RotationCommands(t *testing.T) {
	for _, rule := range []string{"sysnet_exec_ifconfig(xray_proxya_t)", "corecmd_exec_bin(xray_proxya_t)"} {
		if !strings.Contains(proxyaSELinux.PolicySource, rule) {
			t.Fatalf("policy missing %q", rule)
		}
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

func TestSELinuxPolicyAllowsUDPPortBinding(t *testing.T) {
	if !strings.Contains(proxyaSELinux.PolicySource, "corenet_udp_bind_all_ports(xray_proxya_t)") {
		t.Fatal("policy must permit UDP port binding for local proxies and inbounds")
	}
}

func TestSELinuxPolicyAllowsGatewayNetworkStateAndTerminal(t *testing.T) {
	for _, rule := range []string{
		"kernel_read_network_state(xray_proxya_gateway_t)",
		"userdom_use_inherited_user_ptys(xray_proxya_gateway_t)",
	} {
		if !strings.Contains(proxyaSELinux.PolicySource, rule) {
			t.Fatalf("policy missing %q for gateway domain", rule)
		}
	}
}

func TestSELinuxPolicyAllowsSystemdGatewayRestoreTransition(t *testing.T) {
	for _, rule := range []string{
		"spec_domtrans_pattern(init_t, xray_proxya_exec_t, xray_proxya_gateway_t)",
		"allow init_t xray_proxya_gateway_t:process2 { nnp_transition nosuid_transition };",
		"allow init_t xray_proxya_gateway_t:unix_stream_socket create_stream_socket_perms;",
		"allow xray_proxya_gateway_t init_t:unix_dgram_socket sendto;",
	} {
		if !strings.Contains(proxyaSELinux.PolicySource, rule) {
			t.Fatalf("policy missing %q for companion restore service", rule)
		}
	}
}

func TestSELinuxPolicyAllowsParentDirAttributes(t *testing.T) {
	for _, domain := range []string{"xray_proxya_t", "xray_proxya_gateway_t", "xray_proxya_pathd_t"} {
		want := "allow " + domain + " config_home_t:dir { getattr open search };"
		if !strings.Contains(proxyaSELinux.PolicySource, want) {
			t.Fatalf("%s missing permission %q for evaluating parent config directory", domain, want)
		}
	}
}

func TestSELinuxPolicyAllowsPathdMultiCallSymlinkTransition(t *testing.T) {
	for _, rule := range []string{
		"policy_module(xray_proxya, 2.1.5)",
		"init_daemon_domain(xray_proxya_pathd_t, xray_proxya_pathd_exec_t)",
		"spec_domtrans_pattern(init_t, xray_proxya_exec_t, xray_proxya_pathd_t)",
		"domain_entry_file(xray_proxya_pathd_t, xray_proxya_exec_t)",
		"can_exec(xray_proxya_pathd_t, xray_proxya_exec_t)",
		"allow init_t xray_proxya_pathd_t:process2 { nnp_transition nosuid_transition };",
		"allow init_t { xray_proxya_pathd_exec_t xray_proxya_data_t }:lnk_file read;",
	} {
		if !strings.Contains(proxyaSELinux.PolicySource, rule) {
			t.Fatalf("policy missing %q for pathd multi-call symlink transition", rule)
		}
	}
}

func TestPathdUnitLacksSELinuxContextAndWarn(t *testing.T) {
	dir := t.TempDir()

	missingPath := filepath.Join(dir, "missing.service")
	if pathdUnitLacksSELinuxContext(missingPath) {
		t.Fatal("missing unit file should not report lacking SELinuxContext")
	}

	legacyPath := filepath.Join(dir, "legacy.service")
	if err := os.WriteFile(legacyPath, []byte("[Service]\nExecStart=/root/.local/share/xray-proxya/bin/pathd serve\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !pathdUnitLacksSELinuxContext(legacyPath) {
		t.Fatal("legacy unit without SELinuxContext= should be detected")
	}

	var buf bytes.Buffer
	warnIfLegacyPathdUnit(&buf, legacyPath)
	if !strings.Contains(buf.String(), "xray-proxya service install") || !strings.Contains(buf.String(), "SELinuxContext=") {
		t.Fatalf("unexpected hint output: %q", buf.String())
	}

	commentedPath := filepath.Join(dir, "commented.service")
	if err := os.WriteFile(commentedPath, []byte("[Service]\n# SELinuxContext=-system_u:system_r:xray_proxya_pathd_t:s0\nSELinuxContext=\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !pathdUnitLacksSELinuxContext(commentedPath) {
		t.Fatal("unit with commented/empty SELinuxContext= should be detected")
	}

	updatedPath := filepath.Join(dir, "updated.service")
	if err := os.WriteFile(updatedPath, []byte("[Service]\nSELinuxContext=-system_u:system_r:xray_proxya_pathd_t:s0\nExecStart=/root/.local/share/xray-proxya/bin/pathd serve\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if pathdUnitLacksSELinuxContext(updatedPath) {
		t.Fatal("updated unit with SELinuxContext= should not trigger legacy warning")
	}
	buf.Reset()
	warnIfLegacyPathdUnit(&buf, updatedPath)
	if buf.Len() != 0 {
		t.Fatalf("expected no warning for updated unit, got %q", buf.String())
	}
}
