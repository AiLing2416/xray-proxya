package main

import (
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func TestEnsureManagedSubscriptionCreatesAdminEntry(t *testing.T) {
	cfg := &config.UserConfig{}
	subEntry := ensureManagedSubscription(cfg)
	if subEntry == nil {
		t.Fatalf("expected managed subscription to be created")
	}
	if subEntry.TargetType != "direct" {
		t.Fatalf("target_type = %q, want direct", subEntry.TargetType)
	}
	if subEntry.Token == "" {
		t.Fatalf("expected generated token")
	}
}

func TestManagedSubURLUsesOverrideAddress(t *testing.T) {
	// Defaults to http without explicit https scheme
	cfg := &config.UserConfig{AdminSub: config.AdminSubConfig{Port: 8443}}
	subEntry := &config.AdminSubConfig{Token: "abc123", Address: "sub.example.com"}
	got := managedSubURL(cfg, subEntry)
	want := "http://sub.example.com:8443/abc123"
	if got != want {
		t.Fatalf("managedSubURL = %q, want %q", got, want)
	}

	// Explicit https scheme is preserved
	subEntryHTTPS := &config.AdminSubConfig{Token: "abc123", Address: "https://sub.example.com"}
	gotHTTPS := managedSubURL(cfg, subEntryHTTPS)
	wantHTTPS := "https://sub.example.com/abc123"
	if gotHTTPS != wantHTTPS {
		t.Fatalf("managedSubURL = %q, want %q", gotHTTPS, wantHTTPS)
	}
}

func TestManagedSubURLPrioritizesGateURL(t *testing.T) {
	cfg := &config.UserConfig{
		GateURL:    "https://gate.example.com",
		AddressSub: "https://old.example.com",
		AdminSub:   config.AdminSubConfig{Port: 8443, Token: "abc123"},
	}
	got := managedSubURL(cfg, &cfg.AdminSub)
	want := "https://gate.example.com/abc123"
	if got != want {
		t.Fatalf("managedSubURL = %q, want %q", got, want)
	}
}

func TestManagedSubURLHandlesHostWithPort(t *testing.T) {
	cfg := &config.UserConfig{AdminSub: config.AdminSubConfig{Port: 8443}}
	subEntry := &config.AdminSubConfig{Token: "abc123", Address: "sub.example.com:9443"}
	got := managedSubURL(cfg, subEntry)
	want := "http://sub.example.com:9443/abc123"
	if got != want {
		t.Fatalf("managedSubURL = %q, want %q", got, want)
	}
}

func TestManagedSubURLSupportsAddressSubWithScheme(t *testing.T) {
	cfg := &config.UserConfig{
		AddressSub: "https://sub.example.com",
		AdminSub:   config.AdminSubConfig{Port: 8443, Token: "abc123"},
	}
	got := managedSubURL(cfg, &cfg.AdminSub)
	want := "https://sub.example.com/abc123"
	if got != want {
		t.Fatalf("managedSubURL = %q, want %q", got, want)
	}
}

func TestEnsureSubPortConfiguredKeepsExistingPort(t *testing.T) {
	cfg := &config.UserConfig{AdminSub: config.AdminSubConfig{Port: 9443}}
	ensureSubPortConfigured(cfg)
	if cfg.AdminSub.Port != 9443 {
		t.Fatalf("admin_sub.port = %d, want 9443", cfg.AdminSub.Port)
	}
}

func TestManagedSubscriptionReusesExistingEntry(t *testing.T) {
	cfg := &config.UserConfig{
		AdminSub: config.AdminSubConfig{Token: "existing", TargetType: "direct"},
	}
	subEntry := ensureManagedSubscription(cfg)
	if subEntry.Token != "existing" {
		t.Fatalf("token = %q, want existing", subEntry.Token)
	}
	url := managedSubURL(&config.UserConfig{AdminSub: config.AdminSubConfig{Port: 8443}}, subEntry)
	if !strings.HasSuffix(url, "/existing") {
		t.Fatalf("expected managed URL path to end with /existing, got %q", url)
	}
}

func TestSubscriptionServiceManagement(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", tempDir)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		AdminSub: config.AdminSubConfig{
			Token: "default-tok",
			Port:  8443,
		},
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("save config: %v", err)
	}

	subServ, err := subscriptionInstance()
	if err != nil || subServ.Port != 8443 {
		t.Fatalf("load sub: %v, port: %d", err, subServ.Port)
	}
	if subServ.AdminSub.Token != "default-tok" {
		t.Fatalf("token = %q, want default-tok", subServ.AdminSub.Token)
	}
}

func TestSubShowInstancePenetration(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		AdminSub: config.AdminSubConfig{
			Token:      "admin-tok-12345",
			Port:       8443,
			Listen:     "127.0.0.1",
			TargetType: "direct",
		},
		SubscriptionInstances: map[string]config.AdminSubConfig{
			"default": {
				Token:      "admin-tok-12345",
				Port:       8443,
				Listen:     "127.0.0.1",
				TargetType: "direct",
			},
			"node-hk": {
				Token:      "hk-token-9999",
				Port:       9443,
				Listen:     "127.0.0.1",
				TargetType: "direct",
			},
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("save active config: %v", err)
	}

	// 1. Show existing custom instance
	out := captureStdout(t, func() {
		err := subShowCmd.RunE(subShowCmd, []string{"node-hk"})
		if err != nil {
			t.Fatalf("sub show node-hk failed: %v", err)
		}
	})
	if !strings.Contains(out, "Subscription Instance: node-hk") || !strings.Contains(out, "hk-token-9999") {
		t.Errorf("expected node-hk details in output, got: %s", out)
	}
	if strings.Contains(out, "admin-tok-12345") {
		t.Errorf("sub show node-hk should not display default instance details")
	}

	// 2. Show nonexistent instance
	err := subShowCmd.RunE(subShowCmd, []string{"nonexistent"})
	if err == nil || !strings.Contains(err.Error(), "Subscription instance 'nonexistent' not found.") {
		t.Fatalf("expected not found error, got %v", err)
	}

	// 3. Show without args (Admin only, aligns with show)
	adminOnlyOut := captureStdout(t, func() {
		err := subShowCmd.RunE(subShowCmd, []string{})
		if err != nil {
			t.Fatalf("sub show failed: %v", err)
		}
	})
	if !strings.Contains(adminOnlyOut, "Admin Subscription") || !strings.Contains(adminOnlyOut, "admin-tok-12345") {
		t.Errorf("expected Admin Subscription in output, got: %s", adminOnlyOut)
	}
	if strings.Contains(adminOnlyOut, "node-hk") {
		t.Errorf("sub show without args should only display Admin Subscription, got: %s", adminOnlyOut)
	}

	// 4. Show with --all
	subShowAll = true
	allOut := captureStdout(t, func() {
		err := subShowCmd.RunE(subShowCmd, []string{})
		if err != nil {
			t.Fatalf("sub show --all failed: %v", err)
		}
	})
	subShowAll = false
	if !strings.Contains(allOut, "Admin Subscription") || !strings.Contains(allOut, "node-hk") {
		t.Errorf("expected both admin and node-hk in sub show --all, got: %s", allOut)
	}

	// 5. sub list lists all instances
	listOut := captureStdout(t, func() {
		err := subListCmd.RunE(subListCmd, []string{})
		if err != nil {
			t.Fatalf("sub list failed: %v", err)
		}
	})
	if !strings.Contains(listOut, "Admin Subscription") || !strings.Contains(listOut, "node-hk") {
		t.Errorf("expected both admin and node-hk in sub list, got: %s", listOut)
	}

	// 6. Validate instance penetration
	if err := subValidateCmd.RunE(subValidateCmd, []string{"node-hk"}); err != nil {
		t.Errorf("sub validate node-hk failed: %v", err)
	}
	if err := subValidateCmd.RunE(subValidateCmd, []string{"nonexistent"}); err == nil {
		t.Errorf("expected error validating nonexistent instance, got nil")
	}
}

func TestSubSetAndShow_EndpointFlag(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		AdminSub: config.AdminSubConfig{
			Token:      "admin-tok-ep",
			Port:       8443,
			Listen:     "127.0.0.1",
			TargetType: "direct",
		},
		Endpoints: map[string]config.EndpointConfig{
			"hk-node": {
				Type: config.EndpointTypeStatic,
				Host: "hk.example.com",
			},
		},
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("save staging config: %v", err)
	}

	defer func() {
		subEndpoint = ""
		subSetCmd.Flags().Lookup("endpoint").Changed = false
		_ = subSetCmd.Flags().Lookup("endpoint").Value.Set("")
	}()

	// 1. sub set -e hk-node
	subEndpoint = "hk-node"
	subSetCmd.Flags().Lookup("endpoint").Changed = true
	if err := subSetCmd.RunE(subSetCmd, []string{}); err != nil {
		t.Fatalf("sub set -e hk-node failed: %v", err)
	}

	staged, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load staging: %v", err)
	}
	if staged.AdminSub.Endpoint != "hk-node" {
		t.Fatalf("expected AdminSub.Endpoint == 'hk-node', got %q", staged.AdminSub.Endpoint)
	}

	// 2. sub show should display Endpoint: hk-node
	showOut := captureStdout(t, func() {
		if err := subShowCmd.RunE(subShowCmd, []string{}); err != nil {
			t.Fatalf("sub show failed: %v", err)
		}
	})
	if !strings.Contains(showOut, "Endpoint: hk-node") {
		t.Errorf("expected 'Endpoint: hk-node' in output, got: %s", showOut)
	}

	// 3. sub set -e default should clear endpoint
	subEndpoint = "default"
	subSetCmd.Flags().Lookup("endpoint").Changed = true
	if err := subSetCmd.RunE(subSetCmd, []string{}); err != nil {
		t.Fatalf("sub set -e default failed: %v", err)
	}

	staged2, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("load staging: %v", err)
	}
	if staged2.AdminSub.Endpoint != "default" {
		t.Fatalf("expected AdminSub.Endpoint set to 'default', got %q", staged2.AdminSub.Endpoint)
	}

	// 4. sub set -e "" must be rejected
	subEndpoint = ""
	subSetCmd.Flags().Lookup("endpoint").Changed = true
	if err := subSetCmd.RunE(subSetCmd, []string{}); err == nil {
		t.Fatalf("expected error when setting empty endpoint, got nil")
	}
}

func TestManagedSubURLMultiInstanceGateURLPriority(t *testing.T) {
	cfg := &config.UserConfig{
		GateURL:  "https://gate.global.com",
		AdminSub: config.AdminSubConfig{Port: 8443, Token: "admin-token"},
		SubscriptionInstances: map[string]config.AdminSubConfig{
			"custom": {
				Token:      "custom-token",
				Port:       8443,
				AddressSub: "https://inst.custom.com",
			},
			"fallback": {
				Token: "fallback-token",
				Port:  8443,
				// AddressSub is intentionally empty
			},
		},
	}

	customEntry := cfg.SubscriptionInstances["custom"]
	gotCustom := managedSubURL(cfg, &customEntry)
	if !strings.HasPrefix(gotCustom, "https://inst.custom.com") {
		t.Errorf("managedSubURL for custom instance = %q, want prefix https://inst.custom.com", gotCustom)
	}

	fallbackEntry := cfg.SubscriptionInstances["fallback"]
	gotFallback := managedSubURL(cfg, &fallbackEntry)
	if !strings.HasPrefix(gotFallback, "https://gate.global.com") {
		t.Errorf("managedSubURL for fallback instance = %q, want prefix https://gate.global.com", gotFallback)
	}
}

func TestSubShowCmd_QRCodeFlag(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		GateURL: "https://sub.example.com",
		AdminSub: config.AdminSubConfig{
			Token:      "admin-tok-qr",
			Port:       8443,
			Listen:     "127.0.0.1",
			TargetType: "direct",
		},
		Guests: []config.GuestConfig{
			{
				Alias:   "alice",
				UUID:    "alice-uuid-1111",
				Enabled: true,
			},
		},
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("SaveEx error: %v", err)
	}

	defer func() {
		subShowQRCode = false
		subShowQRInvert = false
		subShowGuest = ""
		subShowAll = false
		subShowCmd.Flags().Lookup("qrcode").Changed = false
		_ = subShowCmd.Flags().Lookup("qrcode").Value.Set("false")
		subShowCmd.Flags().Lookup("guest").Changed = false
		_ = subShowCmd.Flags().Lookup("guest").Value.Set("")
		subShowCmd.Flags().Lookup("all").Changed = false
		_ = subShowCmd.Flags().Lookup("all").Value.Set("false")
	}()

	// 1. Run sub show --qrcode (Admin only)
	subShowQRCode = true
	out := captureStdout(t, func() {
		err := subShowCmd.RunE(subShowCmd, []string{})
		if err != nil {
			t.Fatalf("subShowCmd.RunE failed: %v", err)
		}
	})

	if !strings.Contains(out, "admin-tok-qr") {
		t.Errorf("expected admin in sub show output, got: %s", out)
	}
	if strings.Contains(out, "alice") {
		t.Errorf("sub show without args should only display admin, got: %s", out)
	}
	if !strings.Contains(out, "█") || !strings.Contains(out, "▀") {
		t.Errorf("expected QR code blocks in output when --qrcode is set, got: %s", out)
	}

	// 2. Run sub show --all --qrcode
	subShowAll = true
	outAll := captureStdout(t, func() {
		err := subShowCmd.RunE(subShowCmd, []string{})
		if err != nil {
			t.Fatalf("subShowCmd.RunE --all failed: %v", err)
		}
	})
	subShowAll = false
	if !strings.Contains(outAll, "admin-tok-qr") || !strings.Contains(outAll, "alice") {
		t.Errorf("expected admin and alice in sub show --all, got: %s", outAll)
	}

	// 3. Filter by specific guest: sub show -g alice --qrcode
	subShowGuest = "alice"
	outAlice := captureStdout(t, func() {
		err := subShowCmd.RunE(subShowCmd, []string{})
		if err != nil {
			t.Fatalf("subShowCmd.RunE with guest failed: %v", err)
		}
	})
	if !strings.Contains(outAlice, "Guest Subscription") || !strings.Contains(outAlice, "alice") {
		t.Errorf("expected alice guest subscription in output, got: %s", outAlice)
	}
	if strings.Contains(outAlice, "Admin Subscription") {
		t.Errorf("sub show -g alice should not contain Admin Subscription")
	}
	if !strings.Contains(outAlice, "█") || !strings.Contains(outAlice, "▀") {
		t.Errorf("expected QR code blocks in output for guest alice, got: %s", outAlice)
	}

	// 4. Non-existent guest returns error
	subShowGuest = "nonexistent"
	err := subShowCmd.RunE(subShowCmd, []string{})
	if err == nil || !strings.Contains(err.Error(), "Guest 'nonexistent' not found.") {
		t.Fatalf("expected error for nonexistent guest, got: %v", err)
	}
}



