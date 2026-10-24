package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestBackfillMigratesEnabledLegacyGatewayPathToSelectedRelay(t *testing.T) {
	var cfg UserConfig
	data := []byte(`{
  "role": "gateway",
  "gateway": {"relay_alias": "remote", "state": "proxy"},
  "custom_outbounds": [{"alias": "remote", "enabled": true, "config": {}}],
  "path": {"enabled": true, "listen": "127.0.0.1:2828", "token": "legacy-token", "idle_seconds": 20}
}`)
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	changes := cfg.BackfillDefaults()
	if cfg.CustomOutbounds[0].Path == nil || cfg.CustomOutbounds[0].Path.Token != "legacy-token" || cfg.CustomOutbounds[0].Path.Listen != "127.0.0.1:2828" {
		t.Fatalf("legacy PathLink was not assigned to selected relay: %#v", cfg.CustomOutbounds[0].Path)
	}
	if cfg.Path.Token != "" {
		t.Fatalf("legacy global gateway PathLink remained populated: %#v", cfg.Path)
	}
	if len(changes) == 0 {
		t.Fatal("expected migration change")
	}
}

func TestBackfillDoesNotMigrateDisabledLegacyGatewayPath(t *testing.T) {
	var cfg UserConfig
	data := []byte(`{
  "role": "gateway",
  "gateway": {"relay_alias": "remote", "state": "proxy"},
  "custom_outbounds": [{"alias": "remote", "enabled": true, "config": {}}],
  "path": {"enabled": false, "token": "legacy-token"}
}`)
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.BackfillDefaults()
	if cfg.CustomOutbounds[0].Path != nil {
		t.Fatalf("disabled legacy PathLink must not create relay credentials: %#v", cfg.CustomOutbounds[0].Path)
	}
}

func TestBackfillDefaultsPopulatesMissingFields(t *testing.T) {
	cfg := &UserConfig{
		CustomOutbounds: []CustomOutbound{
			{
				Alias:       "relay-a",
				DNSStrategy: "useipv4",
				DNSServers:  []string{" 1.1.1.1 ", "1.1.1.1", ""},
			},
		},
		Guests: []GuestConfig{
			{Alias: "guest-a", ResetDay: 0},
		},
	}

	changes := cfg.BackfillDefaults()
	if len(changes) == 0 {
		t.Fatalf("BackfillDefaults() returned no changes")
	}
	if cfg.Role != RoleServer {
		t.Fatalf("Role = %q, want %q", cfg.Role, RoleServer)
	}
	if cfg.UUID == "" {
		t.Fatalf("UUID was not generated")
	}
	if cfg.CustomOutbounds[0].UserUUID == "" {
		t.Fatalf("Custom outbound user UUID was not generated")
	}
	if cfg.CustomOutbounds[0].AllowPrivateTargets {
		t.Fatal("AllowPrivateTargets = true, want safe default false")
	}
	if cfg.CustomOutbounds[0].DNSStrategy != "UseIPv4" {
		t.Fatalf("DNSStrategy = %q, want UseIPv4", cfg.CustomOutbounds[0].DNSStrategy)
	}
	if len(cfg.CustomOutbounds[0].DNSServers) != 1 || cfg.CustomOutbounds[0].DNSServers[0] != "1.1.1.1" {
		t.Fatalf("DNSServers = %v, want [1.1.1.1]", cfg.CustomOutbounds[0].DNSServers)
	}
	if cfg.Guests[0].UUID == "" {
		t.Fatalf("Guest UUID was not generated")
	}
	if cfg.Guests[0].DisabledReason != GuestDisabledQuotaZero {
		t.Fatalf("DisabledReason = %q, want %q", cfg.Guests[0].DisabledReason, GuestDisabledQuotaZero)
	}
	if cfg.Guests[0].ResetDay != 1 {
		t.Fatalf("ResetDay = %d, want 1", cfg.Guests[0].ResetDay)
	}
	if cfg.CustomOutbounds[0].Config == nil {
		t.Fatalf("Custom outbound config was not initialized")
	}
	if len(cfg.Presets) != len(PresetOrder) {
		t.Fatalf("len(Presets) = %d, want %d", len(cfg.Presets), len(PresetOrder))
	}
}

func TestBackfillDefaultsGatewayMode(t *testing.T) {
	cfg := &UserConfig{
		Role:    RoleGateway,
		Gateway: GatewayConfig{},
	}

	cfg.BackfillDefaults()

	if cfg.Gateway.Mode != "tproxy" {
		t.Fatalf("Gateway.Mode = %q, want tproxy", cfg.Gateway.Mode)
	}
	if cfg.Gateway.TProxyPort != DefaultTProxyPort {
		t.Fatalf("Gateway.TProxyPort = %d, want %d", cfg.Gateway.TProxyPort, DefaultTProxyPort)
	}
	if cfg.Gateway.EffectiveTProxyPort() != DefaultTProxyPort {
		t.Fatalf("EffectiveTProxyPort() = %d, want %d", cfg.Gateway.EffectiveTProxyPort(), DefaultTProxyPort)
	}
	if len(cfg.Presets) != 0 {
		t.Fatalf("gateway config should not auto-expand active modes; got %d", len(cfg.Presets))
	}
}

func TestBackfillDefaultsGatewayMigratesTunMode(t *testing.T) {
	cfg := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			Mode: "tun",
		},
	}

	cfg.BackfillDefaults()

	if cfg.Gateway.Mode != "tproxy" {
		t.Fatalf("Gateway.Mode = %q, want tproxy", cfg.Gateway.Mode)
	}
	if cfg.Gateway.TProxyPort != DefaultTProxyPort {
		t.Fatalf("Gateway.TProxyPort = %d, want %d", cfg.Gateway.TProxyPort, DefaultTProxyPort)
	}
}

func TestNewDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()
	if cfg.Role != RoleGateway {
		t.Fatalf("cfg.Role = %q, want %q", cfg.Role, RoleGateway)
	}
	if cfg.Gateway.Mode != "tproxy" {
		t.Fatalf("Gateway.Mode = %q, want tproxy", cfg.Gateway.Mode)
	}
	if cfg.Gateway.EffectiveTProxyPort() != DefaultTProxyPort {
		t.Fatalf("EffectiveTProxyPort() = %d, want %d", cfg.Gateway.EffectiveTProxyPort(), DefaultTProxyPort)
	}
}

func TestBackfillDefaultsSetsDisabledReasonForDisabledGuest(t *testing.T) {
	cfg := &UserConfig{
		Guests: []GuestConfig{
			{Alias: "guest-a", Enabled: false, QuotaGB: 0},
			{Alias: "guest-b", Enabled: false, QuotaGB: 5},
		},
	}

	cfg.BackfillDefaults()

	if cfg.Guests[0].DisabledReason != GuestDisabledQuotaZero {
		t.Fatalf("guest-a DisabledReason = %q, want %q", cfg.Guests[0].DisabledReason, GuestDisabledQuotaZero)
	}
	if cfg.Guests[1].DisabledReason != GuestDisabledManual {
		t.Fatalf("guest-b DisabledReason = %q, want %q", cfg.Guests[1].DisabledReason, GuestDisabledManual)
	}
}

func TestBackfillDefaultsMigratesLegacyAdminSubscription(t *testing.T) {
	var cfg UserConfig
	if err := json.Unmarshal([]byte(`{"subscriptions":[{"alias":"admin","target_type":"direct","address":"sub.example.com","token":"legacy-token"}],"sub_port":9443,"ipv6_pool":{"enabled":true,"subnet":"2001:db8::/64","interface":"eth0","max_addresses":6,"enable_ndp":true}}`), &cfg); err != nil {
		t.Fatal(err)
	}

	cfg.BackfillDefaults()

	if cfg.AdminSub.Token != "legacy-token" {
		t.Fatalf("token = %q, want legacy-token", cfg.AdminSub.Token)
	}
	if cfg.AdminSub.Address != "sub.example.com" {
		t.Fatalf("address = %q", cfg.AdminSub.Address)
	}
	if cfg.AdminSub.Port != 9443 {
		t.Fatalf("port = %d, want 9443", cfg.AdminSub.Port)
	}
	if cfg.AdminSub.IPv6Rotation != "default" {
		t.Fatalf("rotation = %q, want default", cfg.AdminSub.IPv6Rotation)
	}
	if cfg.IPv6Rotations["default"].Subnet != "2001:db8::/64" {
		t.Fatalf("subnet = %q", cfg.IPv6Rotations["default"].Subnet)
	}
	if len(cfg.Subscriptions) != 0 {
		t.Fatalf("expected legacy managed subscription to be removed from subscriptions, got %d", len(cfg.Subscriptions))
	}
}

func TestUserConfigUnmarshalLegacyActiveModes(t *testing.T) {
	jsonData := []byte(`{
		"role": "server",
		"active_modes": [
			{"mode": "vless-vision-reality-tcp", "enabled": true, "port": 443}
		]
	}`)
	var cfg UserConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if len(cfg.Presets) != 1 {
		t.Fatalf("expected 1 preset, got %d", len(cfg.Presets))
	}
	if cfg.Presets[0].Mode != ModeVLESSVision {
		t.Fatalf("expected mode %q, got %q", ModeVLESSVision, cfg.Presets[0].Mode)
	}
}

func TestGetConfigDir(t *testing.T) {
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", "/tmp/xray-proxya-test-dir")
	dir := GetConfigDir()
	if dir != "/tmp/xray-proxya-test-dir" {
		t.Fatalf("GetConfigDir() = %q, want /tmp/xray-proxya-test-dir", dir)
	}
}

func TestBackfillDefaultsPreservesQuotaResetSentinel(t *testing.T) {
	cfg := &UserConfig{
		Guests: []GuestConfig{
			{Alias: "guest-reset", UsedBytes: -1, QuotaGB: 10, ResetDay: 1},
		},
	}
	cfg.BackfillDefaults()
	if cfg.Guests[0].UsedBytes != -1 {
		t.Fatalf("UsedBytes = %d, want -1 (quota reset sentinel should be preserved)", cfg.Guests[0].UsedBytes)
	}
}

func TestGetHomeDir(t *testing.T) {
	home := GetHomeDir()
	if home == "" {
		t.Fatalf("GetHomeDir() returned empty string")
	}
}

func TestBackfillDefaultsRealitySNIAndDestMigration(t *testing.T) {
	cfg := &UserConfig{
		Role: RoleServer,
		Presets: []ModeInfo{
			{
				Mode:    ModeVLESSVision,
				Enabled: true,
				SNI:     "SUB.Example.COM.",
				Dest:    "",
				Skin:    "invalid-skin",
			},
			{
				Mode:    ModeVLESSReality,
				Enabled: true,
				SNI:     "target.org",
				Dest:    "mismatched.net:443",
				Skin:    "",
			},
		},
	}

	changes := cfg.BackfillDefaults()
	if len(changes) == 0 {
		t.Fatalf("expected changes during BackfillDefaults")
	}

	// 1. SNI normalized, dest backfilled, invalid Skin cleared
	if cfg.Presets[0].SNI != "sub.example.com" {
		t.Errorf("Preset 0 SNI = %q, want sub.example.com", cfg.Presets[0].SNI)
	}
	if cfg.Presets[0].Dest != "sub.example.com:443" {
		t.Errorf("Preset 0 Dest = %q, want sub.example.com:443", cfg.Presets[0].Dest)
	}
	if cfg.Presets[0].Skin != "" {
		t.Errorf("Preset 0 Skin = %q, want empty", cfg.Presets[0].Skin)
	}

	// 2. Mismatched dest aligned with SNI even when skin was false
	if cfg.Presets[1].SNI != "target.org" {
		t.Errorf("Preset 1 SNI = %q, want target.org", cfg.Presets[1].SNI)
	}
	if cfg.Presets[1].Dest != "target.org:443" {
		t.Errorf("Preset 1 Dest = %q, want target.org:443", cfg.Presets[1].Dest)
	}

	// 3. Test matching custom port preservation
	cfgCustom := &UserConfig{
		Role: RoleServer,
		Presets: []ModeInfo{
			{
				Mode:    ModeVLESSVision,
				Enabled: true,
				SNI:     "custom.port.com",
				Dest:    "custom.port.com:8443",
			},
		},
	}
	cfgCustom.BackfillDefaults()
	if cfgCustom.Presets[0].Dest != "custom.port.com:8443" {
		t.Errorf("Preset Dest = %q, want custom.port.com:8443", cfgCustom.Presets[0].Dest)
	}
}

func TestRealityFingerprintAllowlist(t *testing.T) {
	for i := 0; i < 50; i++ {
		fp, err := GetRandomRealityFingerprint()
		if err != nil {
			t.Fatalf("GetRandomRealityFingerprint failed: %v", err)
		}
		if !IsAllowedRealityFingerprint(fp) {
			t.Errorf("generated fingerprint %q not in allowlist", fp)
		}
	}

	if IsAllowedRealityFingerprint("random") || IsAllowedRealityFingerprint("randomized") || IsAllowedRealityFingerprint("") {
		t.Errorf("IsAllowedRealityFingerprint accepted forbidden fingerprint")
	}
}

func TestBackfillDefaultsFingerprintIdempotent(t *testing.T) {
	cfg := &UserConfig{
		Role: RoleServer,
		Presets: []ModeInfo{
			{
				Mode:    ModeVLESSVision,
				Enabled: true,
				SNI:     "test.domain.com",
				Dest:    "test.domain.com:443",
			},
		},
	}

	cfg.BackfillDefaults()
	fp1 := cfg.Presets[0].Fingerprint
	if fp1 == "" || !IsAllowedRealityFingerprint(fp1) {
		t.Fatalf("expected valid initial fingerprint, got %q", fp1)
	}

	// Repeat backfill - must preserve fp1
	changes2 := cfg.BackfillDefaults()
	fp2 := cfg.Presets[0].Fingerprint
	if fp2 != fp1 {
		t.Errorf("fingerprint mutated on second backfill: %q != %q", fp2, fp1)
	}
	for _, c := range changes2 {
		if c == "backfilled reality fingerprint for preset "+string(ModeVLESSVision) {
			t.Errorf("redundant fingerprint backfill change reported")
		}
	}
}

func TestNormalizeMinClientVersion(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"26.10.21", "26.10.21", false},
		{"v26.10.21", "26.10.21", false},
		{"26.3.27", "26.3.27", false},
		{"v26.3.27", "26.3.27", false},
		{"V26.3.27", "26.3.27", false},
		{"26.3", "26.3.0", false},
		{"26", "26.0.0", false},
		{"0", "0.0.0", false},
		{"0.0.0", "0.0.0", false},
		{"1.8.0", "1.8.0", false},
		{"", "", true},
		{"   ", "", true},
		{"invalid", "", true},
		{"1.2.3.4", "", true},
		{"1.-2.3", "", true},
	}

	for _, tt := range tests {
		got, err := NormalizeMinClientVersion(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("NormalizeMinClientVersion(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("NormalizeMinClientVersion(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestResolveMinClientVersion(t *testing.T) {
	if got := ResolveMinClientVersion(nil); got != MinRealityClientVersion {
		t.Errorf("ResolveMinClientVersion(nil) = %q, want %q", got, MinRealityClientVersion)
	}

	mDefault := &ModeInfo{Mode: ModeVLESSVision}
	if got := ResolveMinClientVersion(mDefault); got != MinRealityClientVersion {
		t.Errorf("ResolveMinClientVersion(mDefault) = %q, want %q", got, MinRealityClientVersion)
	}

	mCustom := &ModeInfo{Mode: ModeVLESSVision, MinClientVer: "0.0.0"}
	if got := ResolveMinClientVersion(mCustom); got != "0.0.0" {
		t.Errorf("ResolveMinClientVersion(mCustom) = %q, want 0.0.0", got)
	}
}

func TestBackfillDefaultsSkinPort(t *testing.T) {
	// Case 1: Skin configured, SkinPort == 0 -> should allocate random free port
	cfg := &UserConfig{
		Role: RoleServer,
		Presets: []ModeInfo{
			{
				Mode:       ModeVLESSVision,
				Enabled:    true,
				Skin:       "seafile",
				SkinDomain: "sea.example.com",
				SNI:        "sea.example.com",
			},
		},
	}
	cfg.BackfillDefaults()
	if cfg.SkinPort <= 0 || cfg.SkinPort >= 65536 {
		t.Fatalf("expected allocated SkinPort, got %d", cfg.SkinPort)
	}
	expectedDest := fmt.Sprintf("127.0.0.1:%d", cfg.SkinPort)
	if cfg.Presets[0].Dest != expectedDest {
		t.Errorf("Dest = %q, want %q", cfg.Presets[0].Dest, expectedDest)
	}

	// Case 2: SkinPort already persisted -> should preserve it
	savedPort := cfg.SkinPort
	cfg.BackfillDefaults()
	if cfg.SkinPort != savedPort {
		t.Errorf("SkinPort changed from %d to %d", savedPort, cfg.SkinPort)
	}

	// Case 3: Explicit custom port in Dest adopted when SkinPort is 0
	cfgCustom := &UserConfig{
		Role: RoleServer,
		Presets: []ModeInfo{
			{
				Mode:       ModeVLESSVision,
				Enabled:    true,
				Skin:       "nextcloud",
				SkinDomain: "cloud.example.com",
				SNI:        "cloud.example.com",
				Dest:       "127.0.0.1:18443",
			},
		},
	}
	cfgCustom.BackfillDefaults()
	if cfgCustom.SkinPort != 18443 {
		t.Errorf("SkinPort = %d, want 18443", cfgCustom.SkinPort)
	}
	if cfgCustom.Presets[0].Dest != "127.0.0.1:18443" {
		t.Errorf("Dest = %q, want 127.0.0.1:18443", cfgCustom.Presets[0].Dest)
	}

	// Case 4: No skins enabled -> SkinPort remains 0
	cfgNoSkin := &UserConfig{
		Role: RoleServer,
		Presets: []ModeInfo{
			{
				Mode:    ModeVLESSVision,
				Enabled: true,
				SNI:     "direct.example.com",
			},
		},
	}
	cfgNoSkin.BackfillDefaults()
	if cfgNoSkin.SkinPort != 0 {
		t.Errorf("expected SkinPort = 0 when no skin is configured, got %d", cfgNoSkin.SkinPort)
	}
}

func TestBackfillDefaultsEndpointsAndGateURL(t *testing.T) {
	// Case 1: Legacy config with AddressNode and AddressSub
	cfg1 := &UserConfig{
		Role:        RoleServer,
		AddressNode: "node.legacy.com",
		AddressSub:  "https://sub.legacy.com",
	}
	cfg1.BackfillDefaults()

	if cfg1.GateURL != "https://sub.legacy.com" {
		t.Errorf("GateURL = %q, want https://sub.legacy.com", cfg1.GateURL)
	}
	ep1, ok := cfg1.Endpoints["default"]
	if !ok {
		t.Fatal("missing default endpoint in Endpoints")
	}
	if ep1.Type != EndpointTypeStatic || ep1.Host != "node.legacy.com" {
		t.Errorf("ep1 = %+v, want static node.legacy.com", ep1)
	}

	// Case 2: Clean config without AddressNode or AddressSub
	cfg2 := &UserConfig{
		Role: RoleServer,
	}
	cfg2.BackfillDefaults()

	if cfg2.GateURL != "" {
		t.Errorf("expected empty GateURL, got %q", cfg2.GateURL)
	}
	ep2, ok := cfg2.Endpoints["default"]
	if !ok {
		t.Fatal("missing default endpoint in Endpoints")
	}
	if ep2.Type != EndpointTypeAuto || ep2.Family != "v4" {
		t.Errorf("ep2 = %+v, want auto(v4)", ep2)
	}
}

func TestGuestAliasCleaningAndSanitization(t *testing.T) {
	cases := []struct {
		input       string
		wantClean   string
		wantSan     string
		expectError bool
	}{
		{"  Alice  ", "alice", "alice", false},
		{"Bob-01", "bob-01", "bob-01", false},
		{"Guest_User", "guest_user", "guest-user", false},
		{"x", "", "x", true},
		{"toolongguestnameovertwenty", "", "toolongguestnameovertwenty", true},
		{"invalid@guest", "", "invalid-guest", true},
	}

	for _, tc := range cases {
		clean, err := CleanGuestAlias(tc.input)
		if tc.expectError {
			if err == nil {
				t.Errorf("CleanGuestAlias(%q) expected error, got nil", tc.input)
			}
		} else {
			if err != nil {
				t.Errorf("CleanGuestAlias(%q) unexpected error: %v", tc.input, err)
			}
			if clean != tc.wantClean {
				t.Errorf("CleanGuestAlias(%q) = %q, want %q", tc.input, clean, tc.wantClean)
			}
		}

		san := SanitizeGuestAlias(tc.input)
		if san != tc.wantSan {
			t.Errorf("SanitizeGuestAlias(%q) = %q, want %q", tc.input, san, tc.wantSan)
		}
	}
}

func TestBackfillDefaultsNormalizesGuestAlias(t *testing.T) {
	cfg := &UserConfig{
		Guests: []GuestConfig{
			{Alias: "Alice_Upper", Enabled: true},
			{Alias: "bob-already-clean", Enabled: true},
		},
	}
	changes := cfg.BackfillDefaults()
	if cfg.Guests[0].Alias != "alice_upper" {
		t.Errorf("Guest 0 alias = %q, want %q", cfg.Guests[0].Alias, "alice_upper")
	}
	if cfg.Guests[1].Alias != "bob-already-clean" {
		t.Errorf("Guest 1 alias = %q, want %q", cfg.Guests[1].Alias, "bob-already-clean")
	}

	foundNormalizedChange := false
	for _, c := range changes {
		if strings.Contains(c, "normalized guest alias") {
			foundNormalizedChange = true
			break
		}
	}
	if !foundNormalizedChange {
		t.Errorf("expected changes to record normalized guest alias")
	}
}

func TestParseDNSListen(t *testing.T) {
	tests := []struct {
		input       string
		wantHost    string
		wantPort    int
		wantNorm    string
		wantErr     bool
	}{
		{"127.0.0.1:5353", "127.0.0.1", 5353, "127.0.0.1:5353", false},
		{"5353", "127.0.0.1", 5353, "127.0.0.1:5353", false},
		{":53", "::", 53, ":53", false},
		{"0.0.0.0:53", "::", 53, ":53", false},
		{"[::]:53", "::", 53, ":53", false},
		{"[::1]:5353", "::1", 5353, "[::1]:5353", false},
		{"192.168.1.1:53", "192.168.1.1", 53, "192.168.1.1:53", false},
		{"[2001:db8::1]:5353", "2001:db8::1", 5353, "[2001:db8::1]:5353", false},
		{"", "", 0, "", true},
		{"0", "", 0, "", true},
		{"70000", "", 0, "", true},
		{":-1", "", 0, "", true},
		{":70000", "", 0, "", true},
		{"localhost:53", "", 0, "", true},
		{"example.com:53", "", 0, "", true},
		{"127.0.0.1", "", 0, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			host, port, norm, err := ParseDNSListen(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseDNSListen(%q) error = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
			if !tc.wantErr {
				if host != tc.wantHost || port != tc.wantPort || norm != tc.wantNorm {
					t.Errorf("ParseDNSListen(%q) = (%q, %d, %q), want (%q, %d, %q)",
						tc.input, host, port, norm, tc.wantHost, tc.wantPort, tc.wantNorm)
				}
			}
		})
	}
}

func TestValidateDNSServerEntry(t *testing.T) {
	tests := []struct {
		input    string
		wantNorm string
		wantErr  bool
	}{
		{"1.1.1.1", "1.1.1.1", false},
		{"2606:4700:4700::1111", "2606:4700:4700::1111", false},
		{"8.8.8.8:53", "8.8.8.8:53", false},
		{"[2606:4700:4700::1111]:53", "[2606:4700:4700::1111]:53", false},
		{"localhost", "localhost", false},
		{"https://1.1.1.1/dns-query", "https://1.1.1.1/dns-query", false},
		{"https+local://1.1.1.1/dns-query", "https+local://1.1.1.1/dns-query", false},
		{"h2c://127.0.0.1:8053", "h2c://127.0.0.1:8053", false},
		{"tcp://8.8.8.8:53", "tcp://8.8.8.8:53", false},
		{"tcp+local://8.8.8.8:53", "tcp+local://8.8.8.8:53", false},
		{"tls://1.1.1.1:853", "tls://1.1.1.1:853", false},
		{"quic://dns.adguard.com:853", "quic://dns.adguard.com:853", false},
		{"quic+local://dns.adguard.com:853", "quic+local://dns.adguard.com:853", false},
		{"", "", true},
		{"ftp://1.1.1.1", "", true},
		{"invalid-server", "", true},
		{"8.8.8.8:99999", "", true},
		{"https://", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			norm, err := ValidateDNSServerEntry(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateDNSServerEntry(%q) error = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
			if !tc.wantErr && norm != tc.wantNorm {
				t.Errorf("ValidateDNSServerEntry(%q) = %q, want %q", tc.input, norm, tc.wantNorm)
			}
		})
	}
}

func TestNormalizeDNSRecordDomain(t *testing.T) {
	tests := []struct {
		input    string
		wantNorm string
		wantErr  bool
	}{
		{"router.lan", "router.lan", false},
		{"  ROUTER.LAN  ", "router.lan", false},
		{"domain:google.com", "domain:google.com", false},
		{"full:router.lan", "full:router.lan", false},
		{"regexp:.*\\.lan", "regexp:.*\\.lan", false},
		{"", "", true},
		{"   ", "", true},
		{"router lan", "", true},
		{"router/lan", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			norm, err := NormalizeDNSRecordDomain(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("NormalizeDNSRecordDomain(%q) error = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
			if !tc.wantErr && norm != tc.wantNorm {
				t.Errorf("NormalizeDNSRecordDomain(%q) = %q, want %q", tc.input, norm, tc.wantNorm)
			}
		})
	}
}

func TestValidateDNSRecordIPs(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		wantNorm []string
		wantErr  bool
	}{
		{"single IPv4", []string{"10.0.82.1"}, []string{"10.0.82.1"}, false},
		{"dual stack with dedup", []string{"10.0.82.1", "10.0.82.1", "fd00:82::1"}, []string{"10.0.82.1", "fd00:82::1"}, false},
		{"empty list", []string{}, nil, true},
		{"invalid IP", []string{"not-an-ip"}, nil, true},
		{"mix valid and invalid", []string{"10.0.82.1", "bad-ip"}, nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			norm, err := ValidateDNSRecordIPs(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateDNSRecordIPs(%v) error = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
			if !tc.wantErr {
				if len(norm) != len(tc.wantNorm) {
					t.Fatalf("len = %d, want %d", len(norm), len(tc.wantNorm))
				}
				for i := range norm {
					if norm[i] != tc.wantNorm[i] {
						t.Errorf("norm[%d] = %q, want %q", i, norm[i], tc.wantNorm[i])
					}
				}
			}
		})
	}
}

func TestBackfillDefaultsGatewayDNS(t *testing.T) {
	cfg := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			DNSStrategy: "useipv4",
			DNSServers:  []string{" 1.1.1.1 ", "1.1.1.1", ""},
			DNSListen:   "5353",
			DNSRecords: map[string][]string{
				" ROUTER.LAN ": {" 10.0.82.1 ", "10.0.82.1"},
			},
		},
	}

	cfg.BackfillDefaults()
	if cfg.Gateway.DNSStrategy != "UseIPv4" {
		t.Errorf("DNSStrategy = %q, want UseIPv4", cfg.Gateway.DNSStrategy)
	}
	if len(cfg.Gateway.DNSServers) != 1 || cfg.Gateway.DNSServers[0] != "1.1.1.1" {
		t.Errorf("DNSServers = %v, want [1.1.1.1]", cfg.Gateway.DNSServers)
	}
	if cfg.Gateway.DNSListen != "127.0.0.1:5353" {
		t.Errorf("DNSListen = %q, want 127.0.0.1:5353", cfg.Gateway.DNSListen)
	}
	ips, ok := cfg.Gateway.DNSRecords["router.lan"]
	if !ok || len(ips) != 1 || ips[0] != "10.0.82.1" {
		t.Errorf("DNSRecords[router.lan] = %v, want [10.0.82.1]", ips)
	}
}

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"52:54:00:83:00:11", "52:54:00:83:00:11", false},
		{"52-54-00-83-00-11", "52:54:00:83:00:11", false},
		{"5254.0083.0011", "52:54:00:83:00:11", false},
		{"  52:54:00:AB:CD:EF  ", "52:54:00:ab:cd:ef", false},
		{"", "", true},
		{"invalid", "", true},
		{"52:54:00:83:00", "", true},                                   // 5 bytes
		{"52:54:00:83:00:11:22:33", "", true},                         // 8 bytes (EUI-64)
	}

	for _, tc := range tests {
		got, err := NormalizeMAC(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("NormalizeMAC(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestValidateGatewayRule(t *testing.T) {
	// Empty MAC and interface
	_, err := ValidateGatewayRule(GatewayRule{Target: "direct"})
	if err == nil {
		t.Error("expected error for empty MAC and interface")
	}

	// Empty target
	_, err = ValidateGatewayRule(GatewayRule{Interface: "eth1"})
	if err == nil {
		t.Error("expected error for empty target")
	}

	// Valid rule with MAC and interface, target case normalization
	rule, err := ValidateGatewayRule(GatewayRule{
		MAC:       "52-54-00-83-00-11",
		Interface: "  eth1  ",
		Target:    "DIRECT",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule.MAC != "52:54:00:83:00:11" {
		t.Errorf("MAC = %q, want 52:54:00:83:00:11", rule.MAC)
	}
	if rule.Interface != "eth1" {
		t.Errorf("Interface = %q, want eth1", rule.Interface)
	}
	if rule.Target != "direct" {
		t.Errorf("Target = %q, want direct", rule.Target)
	}

	// Target BLOCK normalization
	ruleBlock, err := ValidateGatewayRule(GatewayRule{
		Interface: "eth2",
		Target:    "BLOCK",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ruleBlock.Target != "block" {
		t.Errorf("Target = %q, want block", ruleBlock.Target)
	}

	// Target custom relay
	ruleRelay, err := ValidateGatewayRule(GatewayRule{
		MAC:    "52:54:00:83:00:12",
		Target: "relay-jp",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ruleRelay.Target != "relay-jp" {
		t.Errorf("Target = %q, want relay-jp", ruleRelay.Target)
	}
}

func TestEffectiveLANInterfaces(t *testing.T) {
	// From LANInterface
	g1 := GatewayConfig{LANInterface: "eth1, eth2 ,eth1"}
	got1 := g1.EffectiveLANInterfaces()
	if len(got1) != 2 || got1[0] != "eth1" || got1[1] != "eth2" {
		t.Errorf("EffectiveLANInterfaces() = %v, want [eth1 eth2]", got1)
	}

	// From LANInterfaces
	g2 := GatewayConfig{LANInterfaces: []string{"eth1", "eth2", "eth1"}}
	got2 := g2.EffectiveLANInterfaces()
	if len(got2) != 2 || got2[0] != "eth1" || got2[1] != "eth2" {
		t.Errorf("EffectiveLANInterfaces() = %v, want [eth1 eth2]", got2)
	}

	// Mixed
	g3 := GatewayConfig{
		LANInterface:  "eth2,eth3",
		LANInterfaces: []string{"eth1", "eth2"},
	}
	got3 := g3.EffectiveLANInterfaces()
	if len(got3) != 3 || got3[0] != "eth1" || got3[1] != "eth2" || got3[2] != "eth3" {
		t.Errorf("EffectiveLANInterfaces() = %v, want [eth1 eth2 eth3]", got3)
	}
}

func TestGatewayTProxyPorts(t *testing.T) {
	cfg := &UserConfig{
		Gateway: GatewayConfig{
			TProxyPort: 12345,
			RelayAlias: "relay-default",
			Rules: []GatewayRule{
				{Interface: "eth1", Target: "direct"},
				{Interface: "eth2", Target: "block"},
				{Interface: "eth3", Target: "relay-extra1"},
				{MAC: "52:54:00:83:00:11", Target: "relay-extra1"}, // duplicate target
				{MAC: "52:54:00:83:00:12", Target: "relay-extra2"},
			},
		},
	}

	ports := GatewayTProxyPorts(cfg)
	if ports["relay-default"] != 12345 {
		t.Errorf("relay-default port = %d, want 12345", ports["relay-default"])
	}
	if ports["relay-extra1"] != 12346 {
		t.Errorf("relay-extra1 port = %d, want 12346", ports["relay-extra1"])
	}
	if ports["relay-extra2"] != 12347 {
		t.Errorf("relay-extra2 port = %d, want 12347", ports["relay-extra2"])
	}
	if _, ok := ports["direct"]; ok {
		t.Error("ports should not contain direct")
	}
	if _, ok := ports["block"]; ok {
		t.Error("ports should not contain block")
	}

	// No default relay
	cfgNoDef := &UserConfig{
		Gateway: GatewayConfig{
			TProxyPort: 12345,
			Rules: []GatewayRule{
				{Interface: "eth1", Target: "relay-first"},
				{Interface: "eth2", Target: "relay-second"},
			},
		},
	}
	portsNoDef := GatewayTProxyPorts(cfgNoDef)
	if portsNoDef["relay-first"] != 12345 {
		t.Errorf("relay-first port = %d, want 12345", portsNoDef["relay-first"])
	}
	if portsNoDef["relay-second"] != 12346 {
		t.Errorf("relay-second port = %d, want 12346", portsNoDef["relay-second"])
	}
}

func TestBackfillDefaultsGatewayRouter(t *testing.T) {
	cfg := &UserConfig{
		Role: RoleGateway,
		Gateway: GatewayConfig{
			LANInterface: "eth1,eth2, eth1",
			WANInterface: "  eth0  ",
			Rules: []GatewayRule{
				{MAC: "52-54-00-83-00-11", Target: "DIRECT"},
				{MAC: "invalid", Target: "direct"}, // invalid, should be discarded
			},
		},
	}

	cfg.BackfillDefaults()
	if len(cfg.Gateway.LANInterfaces) != 2 || cfg.Gateway.LANInterfaces[0] != "eth1" || cfg.Gateway.LANInterfaces[1] != "eth2" {
		t.Errorf("LANInterfaces = %v, want [eth1 eth2]", cfg.Gateway.LANInterfaces)
	}
	if cfg.Gateway.LANInterface != "eth1,eth2" {
		t.Errorf("LANInterface = %q, want eth1,eth2", cfg.Gateway.LANInterface)
	}
	if cfg.Gateway.WANInterface != "eth0" {
		t.Errorf("WANInterface = %q, want eth0", cfg.Gateway.WANInterface)
	}
	if len(cfg.Gateway.Rules) != 1 || cfg.Gateway.Rules[0].MAC != "52:54:00:83:00:11" || cfg.Gateway.Rules[0].Target != "direct" {
		t.Errorf("Rules = %v, want 1 normalized rule", cfg.Gateway.Rules)
	}
}

