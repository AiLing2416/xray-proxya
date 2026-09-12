package endpoint

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"xray-proxya/internal/config"
)

func TestResolveStaticSingleAndMultiple(t *testing.T) {
	cfg := &config.UserConfig{
		Endpoints: map[string]config.EndpointConfig{
			"single": {
				Type: config.EndpointTypeStatic,
				Host: "hk.example.com",
			},
			"multi": {
				Type: config.EndpointTypeStatic,
				Host: " 1.1.1.1, 2.2.2.2 , 3.3.3.3 ",
			},
			"empty": {
				Type: config.EndpointTypeStatic,
				Host: "  ",
			},
		},
	}

	// Test single
	addrs, err := Resolve(cfg, "single")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != "hk.example.com" {
		t.Fatalf("expected ['hk.example.com'], got %v", addrs)
	}

	// Test multi
	addrs, err = Resolve(cfg, "multi")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 3 || addrs[0] != "1.1.1.1" || addrs[1] != "2.2.2.2" || addrs[2] != "3.3.3.3" {
		t.Fatalf("expected ['1.1.1.1', '2.2.2.2', '3.3.3.3'], got %v", addrs)
	}

	// Test empty static
	_, err = Resolve(cfg, "empty")
	if err == nil {
		t.Fatalf("expected error for empty static host, got nil")
	}
}

func TestResolveAutoFallback(t *testing.T) {
	cfg := &config.UserConfig{
		Endpoints: map[string]config.EndpointConfig{
			"default": {
				Type:   config.EndpointTypeAuto,
				Family: "v4",
			},
			"auto-v6": {
				Type:   config.EndpointTypeAuto,
				Family: "v6",
			},
		},
	}

	// Resolve default (empty string should use "default")
	addrs, err := Resolve(cfg, "")
	if err != nil {
		t.Fatalf("failed to resolve default endpoint: %v", err)
	}
	if len(addrs) == 0 || addrs[0] == "" {
		t.Fatalf("expected non-empty IP for default auto, got %v", addrs)
	}

	// Resolve auto-v6 (in test environment with or without public v6, GetSmartIP falls back to local IP)
	addrsV6, err := Resolve(cfg, "auto-v6")
	if err != nil {
		t.Fatalf("failed to resolve auto-v6: %v", err)
	}
	if len(addrsV6) == 0 || addrsV6[0] == "" {
		t.Fatalf("expected non-empty IP for auto-v6, got %v", addrsV6)
	}
}

func TestResolveNonExistent(t *testing.T) {
	cfg := &config.UserConfig{
		Endpoints: map[string]config.EndpointConfig{
			"default": {
				Type:   config.EndpointTypeAuto,
				Family: "v4",
			},
		},
	}

	_, err := Resolve(cfg, "non-existent")
	if err == nil {
		t.Fatalf("expected error for non-existent endpoint, got nil")
	}
	expectedMsg := "endpoint 'non-existent' not found"
	if err.Error() != expectedMsg {
		t.Fatalf("expected error message %q, got %q", expectedMsg, err.Error())
	}
}

func TestGetTargetDescription(t *testing.T) {
	tests := []struct {
		ep   config.EndpointConfig
		want string
	}{
		{ep: config.EndpointConfig{Type: config.EndpointTypeStatic, Host: "node.test.com"}, want: "node.test.com"},
		{ep: config.EndpointConfig{Type: config.EndpointTypeStatic, Host: ""}, want: "(none)"},
		{ep: config.EndpointConfig{Type: config.EndpointTypeAuto, Family: "v4"}, want: "auto (v4)"},
		{ep: config.EndpointConfig{Type: config.EndpointTypeAuto, Family: "v6"}, want: "auto (v6)"},
		{ep: config.EndpointConfig{Type: config.EndpointTypeDynamicV6, Subnet: "2001:db8::/64"}, want: "2001:db8::/64"},
		{ep: config.EndpointConfig{Type: config.EndpointTypeDynamicV6}, want: "dynamic-v6"},
	}

	for _, tc := range tests {
		got := GetTargetDescription(tc.ep)
		if got != tc.want {
			t.Errorf("GetTargetDescription(%+v) = %q, want %q", tc.ep, got, tc.want)
		}
	}
}

func TestFormatDisplayResolvedIP(t *testing.T) {
	ep64 := config.EndpointConfig{
		Type:   config.EndpointTypeDynamicV6,
		Subnet: "2001:db8:1f0a:692::/64",
	}
	got := FormatDisplayResolvedIP(ep64, "2001:db8:1f0a:692:a7d7:2136:b3b0:11ea")
	want := "::a7d7:2136:b3b0:11ea"
	if got != want {
		t.Errorf("FormatDisplayResolvedIP(/64) = %q, want %q", got, want)
	}

	ep48 := config.EndpointConfig{
		Type:   config.EndpointTypeDynamicV6,
		Subnet: "2001:db8:abcd::/48",
	}
	got48 := FormatDisplayResolvedIP(ep48, "2001:db8:abcd:1234:5678:9abc:def0:1111")
	want48 := "::1234:5678:9abc:def0:1111"
	if got48 != want48 {
		t.Errorf("FormatDisplayResolvedIP(/48) = %q, want %q", got48, want48)
	}

	// Static or Auto endpoint should remain intact
	epAuto := config.EndpointConfig{
		Type:   config.EndpointTypeAuto,
		Family: "v4",
	}
	gotAuto := FormatDisplayResolvedIP(epAuto, "198.51.100.87")
	if gotAuto != "198.51.100.87" {
		t.Errorf("FormatDisplayResolvedIP(auto) = %q, want '198.51.100.87'", gotAuto)
	}

	// Slices mapping
	ips := []string{"2001:db8:1f0a:692:a7d7:2136:b3b0:11ea", "2001:db8:1f0a:692:1111:2222:3333:4444"}
	mapped := FormatDisplayResolvedIPs(ep64, ips)
	if len(mapped) != 2 || mapped[0] != "::a7d7:2136:b3b0:11ea" || mapped[1] != "::1111:2222:3333:4444" {
		t.Errorf("FormatDisplayResolvedIPs unexpected: %+v", mapped)
	}
}

func TestFindReferences(t *testing.T) {
	cfg := &config.UserConfig{
		AdminSub: config.AdminSubConfig{
			Token:    "admin-token",
			Endpoint: "custom-ep",
		},
		Guests: []config.GuestConfig{
			{Alias: "alice", Endpoint: "custom-ep"},
			{Alias: "bob", Endpoint: "default"},
			{Alias: "carol", Endpoint: ""},
		},
	}

	refsCustom := FindReferences(cfg, "custom-ep")
	if len(refsCustom) != 2 {
		t.Fatalf("expected 2 references for custom-ep, got %d: %v", len(refsCustom), refsCustom)
	}

	refsDefault := FindReferences(cfg, "default")
	if len(refsDefault) != 2 { // bob and carol
		t.Fatalf("expected 2 references for default, got %d: %v", len(refsDefault), refsDefault)
	}
}

func TestFindReferences_SubscriptionInstances(t *testing.T) {
	cfg := &config.UserConfig{
		AdminSub: config.AdminSubConfig{
			Token:    "admin-tok",
			Endpoint: "ep-admin",
		},
		SubscriptionInstances: map[string]config.AdminSubConfig{
			"default": {
				Token:    "admin-tok",
				Endpoint: "ep-admin",
			},
			"node-hk": {
				Token:    "hk-tok",
				Endpoint: "ep-hk",
			},
			"node-jp": {
				Token:    "jp-tok",
				Endpoint: "default",
			},
			"node-us": {
				Token: "us-tok",
				// Endpoint is empty -> defaults to default
			},
			"node-disabled": {
				Token:    "", // no token, inactive
				Endpoint: "ep-hk",
			},
		},
		Guests: []config.GuestConfig{
			{Alias: "alice", Endpoint: "ep-hk"},
		},
	}

	refsHK := FindReferences(cfg, "ep-hk")
	refsHKStr := strings.Join(refsHK, ",")
	if !strings.Contains(refsHKStr, "sub:node-hk") || !strings.Contains(refsHKStr, "guest:alice") || len(refsHK) != 2 {
		t.Errorf("FindReferences(ep-hk) = %v, want [sub:node-hk guest:alice]", refsHK)
	}

	refsDefault := FindReferences(cfg, "default")
	refsDefStr := strings.Join(refsDefault, ",")
	if !strings.Contains(refsDefStr, "sub:node-jp") || !strings.Contains(refsDefStr, "sub:node-us") || len(refsDefault) != 2 {
		t.Errorf("FindReferences(default) = %v, want [sub:node-jp sub:node-us]", refsDefault)
	}
}

func TestRotationStateSerialization(t *testing.T) {
	st := &RotationState{
		ActivePool: []AddressEntry{
			{Address: "2001:db8::1", State: "active", CreatedAt: time.Now()},
		},
		DeprecatedPool: []AddressEntry{
			{Address: "2001:db8::2", State: "deprecated", CreatedAt: time.Now().Add(-2 * time.Hour), DeprecatedAt: time.Now().Add(-1 * time.Hour)},
		},
	}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("failed to marshal RotationState: %v", err)
	}
	var loaded RotationState
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to unmarshal RotationState: %v", err)
	}
	if len(loaded.ActivePool) != 1 || loaded.ActivePool[0].Address != "2001:db8::1" {
		t.Errorf("unexpected active pool: %+v", loaded.ActivePool)
	}
	if len(loaded.DeprecatedPool) != 1 || loaded.DeprecatedPool[0].Address != "2001:db8::2" {
		t.Errorf("unexpected deprecated pool: %+v", loaded.DeprecatedPool)
	}
}

func TestDynamicV6RotationSlidingWindow(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "endpoint-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := os.Getenv("XRAY_PROXYA_CONFIG_DIR")
	os.Setenv("XRAY_PROXYA_CONFIG_DIR", tmpDir)
	defer os.Setenv("XRAY_PROXYA_CONFIG_DIR", oldConfigDir)

	var recordedCommands [][]string
	origCmdRunner := cmdRunner
	origProbeFunc := probeFunc
	defer func() {
		cmdRunner = origCmdRunner
		probeFunc = origProbeFunc
	}()

	cmdRunner = func(name string, arg ...string) ([]byte, error) {
		recordedCommands = append(recordedCommands, append([]string{name}, arg...))
		return []byte("ok"), nil
	}
	probeFunc = func(sourceIPv6 string, timeout time.Duration) (bool, time.Duration, error) {
		return true, 10 * time.Millisecond, nil
	}
	restoreChecker := SetTestInterfaceChecker(func(string) bool { return true }, 100*time.Millisecond, 10*time.Millisecond)
	defer restoreChecker()

	ep := config.EndpointConfig{
		Type:         config.EndpointTypeDynamicV6,
		Subnet:       "2001:db8:cafe::/64",
		Interface:    "he-ipv6",
		MaxAddresses: 2,
	}

	// 1st allocation
	ip1, err := NextAddress("test-ep", ep)
	if err != nil {
		t.Fatalf("NextAddress 1 failed: %v", err)
	}
	st, err := LoadRotationState("test-ep")
	if err != nil || len(st.ActivePool) != 1 {
		t.Fatalf("expected 1 active IP, got %+v (err: %v)", st, err)
	}
	if st.ActivePool[0].Address != ip1 {
		t.Errorf("expected active IP %s, got %s", ip1, st.ActivePool[0].Address)
	}

	// 2nd allocation
	ip2, err := NextAddress("test-ep", ep)
	if err != nil {
		t.Fatalf("NextAddress 2 failed: %v", err)
	}
	st, _ = LoadRotationState("test-ep")
	if len(st.ActivePool) != 2 || len(st.DeprecatedPool) != 0 {
		t.Fatalf("expected 2 active IPs and 0 deprecated, got %+v", st)
	}

	// 3rd allocation: max is 2, so ip1 should be demoted to DeprecatedPool
	ip3, err := NextAddress("test-ep", ep)
	if err != nil {
		t.Fatalf("NextAddress 3 failed: %v", err)
	}
	st, _ = LoadRotationState("test-ep")
	if len(st.ActivePool) != 2 {
		t.Fatalf("expected 2 active IPs, got %d", len(st.ActivePool))
	}
	if len(st.DeprecatedPool) != 1 {
		t.Fatalf("expected 1 deprecated IP, got %d", len(st.DeprecatedPool))
	}
	if st.DeprecatedPool[0].Address != ip1 {
		t.Errorf("expected deprecated IP %s, got %s", ip1, st.DeprecatedPool[0].Address)
	}
	if st.ActivePool[0].Address != ip2 || st.ActivePool[1].Address != ip3 {
		t.Errorf("unexpected active pool after slide: %+v", st.ActivePool)
	}

	// ReconcileOnStartup test
	if err := ReconcileOnStartup("test-ep", ep); err != nil {
		t.Fatalf("ReconcileOnStartup failed: %v", err)
	}
}

func TestResolveDynamicV6_OrdinaryAndSub(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "endpoint-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := os.Getenv("XRAY_PROXYA_CONFIG_DIR")
	os.Setenv("XRAY_PROXYA_CONFIG_DIR", tmpDir)
	defer os.Setenv("XRAY_PROXYA_CONFIG_DIR", oldConfigDir)

	origCmdRunner := cmdRunner
	origProbeFunc := probeFunc
	defer func() {
		cmdRunner = origCmdRunner
		probeFunc = origProbeFunc
	}()

	cmdRunner = func(name string, arg ...string) ([]byte, error) {
		return []byte("ok"), nil
	}
	probeFunc = func(sourceIPv6 string, timeout time.Duration) (bool, time.Duration, error) {
		return true, 5 * time.Millisecond, nil
	}

	cfg := &config.UserConfig{
		Endpoints: map[string]config.EndpointConfig{
			"dyn": {
				Type:         config.EndpointTypeDynamicV6,
				Subnet:       "2001:db8:1234::/64",
				Interface:    "he-ipv6",
				TTL:          "10ms",
				MaxAddresses: 3,
			},
		},
	}

	// Ordinary query on empty state triggers initial allocation
	res1, err := Resolve(cfg, "dyn")
	if err != nil {
		t.Fatalf("Resolve ordinary failed: %v", err)
	}
	if len(res1) != 1 {
		t.Fatalf("expected 1 IP, got %v", res1)
	}

	// Second ordinary query returns the SAME IP (no rotation)
	res2, err := Resolve(cfg, "dyn")
	if err != nil {
		t.Fatalf("Resolve ordinary 2 failed: %v", err)
	}
	if res2[0] != res1[0] {
		t.Fatalf("expected ordinary query to return same IP %s, got %s", res1[0], res2[0])
	}

	// Subscription pull before TTL expires returns the SAME IP (turtle protects against churn)
	resSubEarly, err := Resolve(cfg, "dyn", true)
	if err != nil {
		t.Fatalf("Resolve sub early failed: %v", err)
	}
	if resSubEarly[0] != res1[0] {
		t.Fatalf("expected early sub pull to return same IP %s, got %s", res1[0], resSubEarly[0])
	}

	// Wait for TTL to expire
	time.Sleep(15 * time.Millisecond)

	// Subscription pull after TTL expired triggers rotation and gives a NEW IP
	resSubLater, err := Resolve(cfg, "dyn", true)
	if err != nil {
		t.Fatalf("Resolve sub later failed: %v", err)
	}
	if resSubLater[0] == res1[0] {
		t.Fatalf("expected subscription pull after TTL to rotate to new IP, but got same %s", resSubLater[0])
	}
}

func TestProbeIPv6Reachability_Invalid(t *testing.T) {
	ok, _, err := TestIPv6Reachability("not-an-ip", time.Second)
	if ok || err == nil {
		t.Errorf("expected error for invalid IP, got ok=%v, err=%v", ok, err)
	}

	ok4, _, err4 := TestIPv6Reachability("192.168.1.1", time.Second)
	if ok4 || err4 == nil {
		t.Errorf("expected error for IPv4 IP, got ok=%v, err=%v", ok4, err4)
	}
}

func TestReconcileOnStartup_TimeAwarePruning(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "endpoint-prune-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := os.Getenv("XRAY_PROXYA_CONFIG_DIR")
	os.Setenv("XRAY_PROXYA_CONFIG_DIR", tmpDir)
	defer os.Setenv("XRAY_PROXYA_CONFIG_DIR", oldConfigDir)

	var recordedCmds [][]string
	restoreRunners := SetTestRunners(func(name string, arg ...string) ([]byte, error) {
		cmd := append([]string{name}, arg...)
		recordedCmds = append(recordedCmds, cmd)
		return []byte("ok"), nil
	}, func(ip string, d time.Duration) (bool, time.Duration, error) {
		return true, time.Millisecond, nil
	})
	defer restoreRunners()

	restoreChecker := SetTestInterfaceChecker(func(iface string) bool {
		return true
	}, 100*time.Millisecond, 10*time.Millisecond)
	defer restoreChecker()

	now := time.Now()
	initialState := &RotationState{
		ActivePool: []AddressEntry{
			{Address: "2001:db8::active1", State: "active", CreatedAt: now.Add(-3 * time.Hour)},
		},
		DeprecatedPool: []AddressEntry{
			{Address: "2001:db8::expired", State: "deprecated", CreatedAt: now.Add(-3 * time.Hour), DeprecatedAt: now.Add(-2 * time.Hour)},
			{Address: "2001:db8::recent", State: "deprecated", CreatedAt: now.Add(-1 * time.Hour), DeprecatedAt: now.Add(-20 * time.Minute)},
		},
	}
	if err := SaveRotationState("prune-ep", initialState); err != nil {
		t.Fatalf("SaveRotationState failed: %v", err)
	}

	ep := config.EndpointConfig{
		Type:      config.EndpointTypeDynamicV6,
		Subnet:    "2001:db8::/64",
		Interface: "he-ipv6",
	}

	if err := ReconcileOnStartup("prune-ep", ep); err != nil {
		t.Fatalf("ReconcileOnStartup failed: %v", err)
	}

	st, err := LoadRotationState("prune-ep")
	if err != nil {
		t.Fatalf("LoadRotationState failed: %v", err)
	}

	if len(st.ActivePool) != 1 || st.ActivePool[0].Address != "2001:db8::active1" {
		t.Errorf("unexpected ActivePool: %+v", st.ActivePool)
	}

	if len(st.DeprecatedPool) != 1 {
		t.Fatalf("expected 1 remaining deprecated IP, got %d: %+v", len(st.DeprecatedPool), st.DeprecatedPool)
	}
	if st.DeprecatedPool[0].Address != "2001:db8::recent" {
		t.Errorf("expected 2001:db8::recent to remain, got %s", st.DeprecatedPool[0].Address)
	}

	foundActive := false
	foundRecent := false
	foundExpired := false

	for _, cmd := range recordedCmds {
		cmdStr := strings.Join(cmd, " ")
		if strings.Contains(cmdStr, "2001:db8::active1") {
			foundActive = true
		}
		if strings.Contains(cmdStr, "2001:db8::recent") && strings.Contains(cmdStr, "preferred_lft 0") {
			foundRecent = true
		}
		if strings.Contains(cmdStr, "2001:db8::expired") {
			foundExpired = true
		}
	}

	if !foundActive {
		t.Errorf("expected command replacing active address into kernel")
	}
	if !foundRecent {
		t.Errorf("expected command re-injecting recent deprecated address with preferred_lft 0 into kernel")
	}
	if foundExpired {
		t.Errorf("did not expect expired address 2001:db8::expired to be injected into kernel")
	}
}

func TestReconcileOnStartup_InterfaceWaitRetryAndTimeout(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "endpoint-wait-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := os.Getenv("XRAY_PROXYA_CONFIG_DIR")
	os.Setenv("XRAY_PROXYA_CONFIG_DIR", tmpDir)
	defer os.Setenv("XRAY_PROXYA_CONFIG_DIR", oldConfigDir)

	var recordedCmds [][]string
	restoreRunners := SetTestRunners(func(name string, arg ...string) ([]byte, error) {
		cmd := append([]string{name}, arg...)
		recordedCmds = append(recordedCmds, cmd)
		return []byte("ok"), nil
	}, func(ip string, d time.Duration) (bool, time.Duration, error) {
		return true, time.Millisecond, nil
	})
	defer restoreRunners()

	ep := config.EndpointConfig{
		Type:      config.EndpointTypeDynamicV6,
		Subnet:    "2001:db8::/64",
		Interface: "he-ipv6",
	}

	// 1. Retry test: interface becomes UP on 3rd attempt
	attempts := 0
	restoreChecker := SetTestInterfaceChecker(func(iface string) bool {
		attempts++
		return attempts >= 3
	}, 500*time.Millisecond, 10*time.Millisecond)

	initialState := &RotationState{
		ActivePool: []AddressEntry{
			{Address: "2001:db8::act", State: "active", CreatedAt: time.Now()},
		},
	}
	_ = SaveRotationState("wait-ep", initialState)

	err = ReconcileOnStartup("wait-ep", ep)
	restoreChecker()

	if err != nil {
		t.Fatalf("ReconcileOnStartup failed on retry: %v", err)
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts to poll interface, got %d", attempts)
	}

	// 2. Timeout test: interface is permanently down
	recordedCmds = nil
	restoreChecker2 := SetTestInterfaceChecker(func(iface string) bool {
		return false
	}, 50*time.Millisecond, 10*time.Millisecond)

	err = ReconcileOnStartup("wait-ep", ep)
	restoreChecker2()

	if err != nil {
		t.Fatalf("expected nil error on interface timeout, got: %v", err)
	}
	if len(recordedCmds) > 0 {
		t.Errorf("expected no kernel commands to be executed when interface wait times out, got %v", recordedCmds)
	}
}

func TestReconcileOnStartup_ColdStartPrewarm(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "endpoint-prewarm-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := os.Getenv("XRAY_PROXYA_CONFIG_DIR")
	os.Setenv("XRAY_PROXYA_CONFIG_DIR", tmpDir)
	defer os.Setenv("XRAY_PROXYA_CONFIG_DIR", oldConfigDir)

	restoreRunners := SetTestRunners(func(name string, arg ...string) ([]byte, error) {
		return []byte("ok"), nil
	}, func(ip string, d time.Duration) (bool, time.Duration, error) {
		return true, time.Millisecond, nil
	})
	defer restoreRunners()

	restoreChecker := SetTestInterfaceChecker(func(iface string) bool {
		return true
	}, 100*time.Millisecond, 10*time.Millisecond)
	defer restoreChecker()

	ep := config.EndpointConfig{
		Type:      config.EndpointTypeDynamicV6,
		Subnet:    "2001:db8:8888::/64",
		Interface: "he-ipv6",
	}

	// ActivePool is empty
	err = ReconcileOnStartup("empty-ep", ep)
	if err != nil {
		t.Fatalf("ReconcileOnStartup with empty pool failed: %v", err)
	}

	st, err := LoadRotationState("empty-ep")
	if err != nil {
		t.Fatalf("LoadRotationState failed: %v", err)
	}
	if len(st.ActivePool) != 1 {
		t.Fatalf("expected 1 active IP prewarmed, got %d", len(st.ActivePool))
	}
	if !strings.HasPrefix(st.ActivePool[0].Address, "2001:db8:8888:") {
		t.Errorf("expected prewarmed IP in subnet 2001:db8:8888::/64, got %s", st.ActivePool[0].Address)
	}
}

func TestResolveTargets_CompositeAndOrder(t *testing.T) {
	cfg := &config.UserConfig{
		Endpoints: map[string]config.EndpointConfig{
			"ep1": {Type: config.EndpointTypeStatic, Host: "1.1.1.1"},
			"ep2": {Type: config.EndpointTypeStatic, Host: "2.2.2.2"},
		},
	}

	// 1. Order-preserving multi-endpoint resolution
	targets, err := ResolveTargets(cfg, "ep1,ep2,3.3.3.3,proxy.node.com", "", false)
	if err != nil {
		t.Fatalf("ResolveTargets failed: %v", err)
	}
	if len(targets) != 4 {
		t.Fatalf("expected 4 targets, got %d", len(targets))
	}
	if targets[0].Alias != "ep1" || targets[0].Address != "1.1.1.1" {
		t.Errorf("unexpected target 0: %+v", targets[0])
	}
	if targets[1].Alias != "ep2" || targets[1].Address != "2.2.2.2" {
		t.Errorf("unexpected target 1: %+v", targets[1])
	}
	if targets[2].Alias != "3.3.3.3" || targets[2].Address != "3.3.3.3" {
		t.Errorf("unexpected target 2: %+v", targets[2])
	}
	if targets[3].Alias != "proxy.node.com" || targets[3].Address != "proxy.node.com" {
		t.Errorf("unexpected target 3: %+v", targets[3])
	}

	// 2. Reject empty item in list
	_, err = ResolveTargets(cfg, "ep1,,ep2", "", false)
	if err == nil || !strings.Contains(err.Error(), "contains empty item") {
		t.Fatalf("expected error for empty item in list, got: %v", err)
	}

	// 3. Fallback to default
	defTargets, err := ResolveTargets(cfg, "", "", false)
	if err != nil {
		t.Fatalf("ResolveTargets empty failed: %v", err)
	}
	if len(defTargets) == 0 || defTargets[0].Alias != "default" {
		t.Fatalf("expected default target, got: %+v", defTargets)
	}
}

func TestDynamicV6Profiles_Turtle(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "turtle-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := os.Getenv("XRAY_PROXYA_CONFIG_DIR")
	os.Setenv("XRAY_PROXYA_CONFIG_DIR", tmpDir)
	defer os.Setenv("XRAY_PROXYA_CONFIG_DIR", oldConfigDir)

	restoreRunners := SetTestRunners(func(name string, arg ...string) ([]byte, error) {
		return []byte("ok"), nil
	}, func(ip string, d time.Duration) (bool, time.Duration, error) {
		return true, time.Millisecond, nil
	})
	defer restoreRunners()

	ep := config.EndpointConfig{
		Type:      config.EndpointTypeDynamicV6,
		Subnet:    "2001:db8:aaaa::/64",
		Interface: "eth0",
		Profile:   config.RotationProfileTurtle,
		TTL:       "2h",
	}

	// Initial resolution creates active IP
	ip1, err := ResolveDynamicV6Address("turtle-ep", ep, "guest:SPYS", false)
	if err != nil {
		t.Fatalf("initial resolve failed: %v", err)
	}

	// Subscription pull before TTL expires returns SAME IP (lazy on-demand)
	ip2, err := ResolveDynamicV6Address("turtle-ep", ep, "guest:SPYS", true)
	if err != nil {
		t.Fatalf("subscription resolve within TTL failed: %v", err)
	}
	if ip2 != ip1 {
		t.Fatalf("turtle profile rotated within TTL: %s != %s", ip1, ip2)
	}

	// Fast-forward state to simulate TTL expiration (older than 2h)
	st, err := LoadRotationState("turtle-ep")
	if err != nil || len(st.ActivePool) == 0 {
		t.Fatalf("load rotation state failed: %v", err)
	}
	st.ActivePool[0].CreatedAt = time.Now().Add(-3 * time.Hour)
	_ = SaveRotationState("turtle-ep", st)

	// Ordinary query after TTL expires still returns current IP (lazy - no rotate without sub)
	ip3, err := ResolveDynamicV6Address("turtle-ep", ep, "guest:SPYS", false)
	if err != nil {
		t.Fatalf("query after TTL failed: %v", err)
	}
	if ip3 != ip1 {
		t.Fatalf("ordinary query rotated without subscription pull: %s != %s", ip1, ip3)
	}

	// Subscription pull after TTL triggers rotation!
	ip4, err := ResolveDynamicV6Address("turtle-ep", ep, "guest:SPYS", true)
	if err != nil {
		t.Fatalf("sub pull after TTL failed: %v", err)
	}
	if ip4 == ip1 {
		t.Fatalf("expected rotation on subscription pull after TTL, got same IP: %s", ip4)
	}

	// Check that old IP was demoted to DeprecatedPool with 3600s transition window
	stAfter, _ := LoadRotationState("turtle-ep")
	if len(stAfter.ActivePool) != 1 {
		t.Fatalf("expected 1 active IP, got %d", len(stAfter.ActivePool))
	}
	if len(stAfter.DeprecatedPool) != 1 || stAfter.DeprecatedPool[0].Address != ip1 {
		t.Fatalf("expected ip1 in DeprecatedPool, got: %+v", stAfter.DeprecatedPool)
	}
}

func TestDynamicV6Profiles_Isolated(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "isolated-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := os.Getenv("XRAY_PROXYA_CONFIG_DIR")
	os.Setenv("XRAY_PROXYA_CONFIG_DIR", tmpDir)
	defer os.Setenv("XRAY_PROXYA_CONFIG_DIR", oldConfigDir)

	restoreRunners := SetTestRunners(func(name string, arg ...string) ([]byte, error) {
		return []byte("ok"), nil
	}, func(ip string, d time.Duration) (bool, time.Duration, error) {
		return true, time.Millisecond, nil
	})
	defer restoreRunners()

	ep := config.EndpointConfig{
		Type:      config.EndpointTypeDynamicV6,
		Subnet:    "2001:db8:bbbb::/64",
		Interface: "eth0",
		Profile:   config.RotationProfileIsolated,
		TTL:       "1h",
	}

	// Guest A allocates their single dedicated IP
	ipA, err := ResolveDynamicV6Address("iso-ep", ep, "guest:alice", true)
	if err != nil {
		t.Fatalf("alice resolve failed: %v", err)
	}

	// Guest B allocates their independent dedicated IP
	ipB, err := ResolveDynamicV6Address("iso-ep", ep, "guest:bob", true)
	if err != nil {
		t.Fatalf("bob resolve failed: %v", err)
	}

	if ipA == ipB {
		t.Fatalf("expected isolated IPs for alice and bob, got identical %s", ipA)
	}

	// Fast-forward alice's IP past TTL
	st, _ := LoadRotationState("iso-ep")
	st.Consumers["guest:alice"].ActivePool[0].CreatedAt = time.Now().Add(-2 * time.Hour)
	_ = SaveRotationState("iso-ep", st)

	// Alice rotates to new IP
	ipA2, err := ResolveDynamicV6Address("iso-ep", ep, "guest:alice", true)
	if err != nil {
		t.Fatalf("alice rotate failed: %v", err)
	}
	if ipA2 == ipA {
		t.Fatalf("expected alice to rotate to new IP, got %s", ipA2)
	}

	// Bob's IP is completely unaffected
	ipB2, err := ResolveDynamicV6Address("iso-ep", ep, "guest:bob", false)
	if err != nil {
		t.Fatalf("bob check failed: %v", err)
	}
	if ipB2 != ipB {
		t.Fatalf("bob's IP was mutated by alice's rotation: %s != %s", ipB2, ipB)
	}
}

func TestDynamicV6_MissingInterfaceFails(t *testing.T) {
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", t.TempDir())
	ep := config.EndpointConfig{
		Type:   config.EndpointTypeDynamicV6,
		Subnet: "2001:db8::/64",
	}

	_, err := ResolveDynamicV6Address("test-missing-iface", ep, "guest1", false)
	if err == nil || !strings.Contains(err.Error(), "has no network interface configured") {
		t.Fatalf("expected missing interface error in ResolveDynamicV6Address, got %v", err)
	}

	_, err = NextAddress("test-missing-iface", ep)
	if err == nil || !strings.Contains(err.Error(), "has no network interface configured") {
		t.Fatalf("expected missing interface error in NextAddress, got %v", err)
	}

	err = ReconcileOnStartup("test-missing-iface", ep)
	if err == nil || !strings.Contains(err.Error(), "has no network interface configured") {
		t.Fatalf("expected missing interface error in ReconcileOnStartup, got %v", err)
	}
}


