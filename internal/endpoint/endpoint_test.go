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
		{ep: config.EndpointConfig{Type: config.EndpointTypeDynamicV6, Subnet: "2001:db8::/64"}, want: "dynamic-v6 (2001:db8::/64)"},
		{ep: config.EndpointConfig{Type: config.EndpointTypeDynamicV6}, want: "dynamic-v6"},
	}

	for _, tc := range tests {
		got := GetTargetDescription(tc.ep)
		if got != tc.want {
			t.Errorf("GetTargetDescription(%+v) = %q, want %q", tc.ep, got, tc.want)
		}
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

	// Subscription pull (forSubscription=true) triggers rotation and gives a NEW IP
	resSub, err := Resolve(cfg, "dyn", true)
	if err != nil {
		t.Fatalf("Resolve sub failed: %v", err)
	}
	if resSub[0] == res1[0] {
		t.Fatalf("expected subscription pull to rotate to new IP, but got same %s", resSub[0])
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

