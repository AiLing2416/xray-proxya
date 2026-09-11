package sub

import (
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"xray-proxya/internal/config"
)

func TestFormatGuestSubRemark(t *testing.T) {
	now := time.Date(2026, 5, 9, 8, 0, 0, 0, time.UTC)

	// 1. Normal GB usage
	guest1 := config.GuestConfig{
		Alias:     "alice",
		UsedBytes: 2 * config.GigaByte,
		QuotaGB:   5,
		ResetDay:  15,
		Enabled:   true,
	}
	if got, want := formatGuestSubRemark(guest1, now), "TRAFFIC: 2.00GB / 5.00GB | RESET: 6d"; got != want {
		t.Fatalf("formatGuestSubRemark = %q, want %q", got, want)
	}

	// 2. Dynamic MB usage
	guest2 := config.GuestConfig{
		Alias:     "bob",
		UsedBytes: 50 * config.MegaByte,
		QuotaGB:   5,
		ResetDay:  15,
		Enabled:   true,
	}
	if got, want := formatGuestSubRemark(guest2, now), "TRAFFIC: 50.00MB / 5.00GB | RESET: 6d"; got != want {
		t.Fatalf("formatGuestSubRemark = %q, want %q", got, want)
	}

	// 3. Quota exceeded
	guest3 := config.GuestConfig{
		Alias:     "charlie",
		UsedBytes: 6 * config.GigaByte,
		QuotaGB:   5,
		ResetDay:  15,
		Enabled:   true,
	}
	if got, want := formatGuestSubRemark(guest3, now), "EXPIRED: Quota Exceeded (6.00GB / 5.00GB) | Reset in 6d"; got != want {
		t.Fatalf("formatGuestSubRemark = %q, want %q", got, want)
	}

	// 4. Admin disabled guest
	guest4 := config.GuestConfig{
		Alias:     "dave",
		UsedBytes: 1 * config.GigaByte,
		QuotaGB:   5,
		ResetDay:  15,
		Enabled:   false,
	}
	if got, want := formatGuestSubRemark(guest4, now), "dave is disabled"; got != want {
		t.Fatalf("formatGuestSubRemark = %q, want %q", got, want)
	}
}

func TestGenerateMemorialShadowsocksNode(t *testing.T) {
	now := time.Date(2026, 5, 9, 8, 0, 0, 0, time.UTC)
	guest := config.GuestConfig{
		UsedBytes: 2 * config.GigaByte,
		QuotaGB:   5,
		ResetDay:  15,
		Enabled:   true,
	}
	link := GenerateMemorialShadowsocksNode(guest, now)
	if !strings.HasPrefix(link, "ss://") {
		t.Fatalf("expected ss:// prefix, got %q", link)
	}
	if !strings.Contains(link, "@127.0.0.1:1#") {
		t.Fatalf("expected @127.0.0.1:1# in link, got %q", link)
	}
	if !strings.Contains(link, "TRAFFIC") {
		t.Fatalf("expected TRAFFIC in link remark, got %q", link)
	}
}

func TestDaysUntilResetClampsMonthEnd(t *testing.T) {
	now := time.Date(2026, 2, 27, 12, 0, 0, 0, time.UTC)
	if got, want := daysUntilReset(31, now), 1; got != want {
		t.Fatalf("daysUntilReset = %d, want %d", got, want)
	}
}

func TestResolveSubAndNodeAddresses(t *testing.T) {
	cfg1 := &config.UserConfig{
		AddressSub:  "sub.example.com",
		AddressNode: "node.example.com",
	}
	if got, want := ResolveSubAddress(cfg1), "sub.example.com"; got != want {
		t.Fatalf("ResolveSubAddress = %q, want %q", got, want)
	}
	if got, want := ResolveNodeAddress(cfg1), "node.example.com"; got != want {
		t.Fatalf("ResolveNodeAddress = %q, want %q", got, want)
	}

	cfg2 := &config.UserConfig{
		AdminSub: config.AdminSubConfig{
			AddressSub:  "admin-sub.example.com",
			AddressNode: "admin-node.example.com",
		},
	}
	if got, want := ResolveSubAddress(cfg2), "admin-sub.example.com"; got != want {
		t.Fatalf("ResolveSubAddress = %q, want %q", got, want)
	}
	if got, want := ResolveNodeAddress(cfg2), "admin-node.example.com"; got != want {
		t.Fatalf("ResolveNodeAddress = %q, want %q", got, want)
	}
}

func TestFormatSubURL(t *testing.T) {
	// Level 1: Scheme preserved
	if got, want := FormatSubURL("https://sub.example.com", 8443, "mytoken"), "https://sub.example.com/mytoken"; got != want {
		t.Fatalf("FormatSubURL = %q, want %q", got, want)
	}
	if got, want := FormatSubURL("http://sub.example.com:8080", 8443, "mytoken"), "http://sub.example.com:8080/mytoken"; got != want {
		t.Fatalf("FormatSubURL = %q, want %q", got, want)
	}
	// Level 2: Port 8443 or 443 auto-promoted to https
	if got, want := FormatSubURL("sub.example.com", 8443, "mytoken"), "https://sub.example.com:8443/mytoken"; got != want {
		t.Fatalf("FormatSubURL = %q, want %q", got, want)
	}
	if got, want := FormatSubURL("sub.example.com", 443, "mytoken"), "https://sub.example.com/mytoken"; got != want {
		t.Fatalf("FormatSubURL = %q, want %q", got, want)
	}
	// Level 2: Cert awareness auto-promoted to https even on arbitrary port
	cfgWithCert := &config.UserConfig{
		Certs: []config.ManagedCert{
			{Domain: "secure.example.com"},
		},
	}
	if got, want := FormatSubURL("secure.example.com", 9443, "mytoken", cfgWithCert), "https://secure.example.com:9443/mytoken"; got != want {
		t.Fatalf("FormatSubURL = %q, want %q", got, want)
	}
	// Level 3: Non-secure port and no cert falls back to http
	if got, want := FormatSubURL("sub.example.com:9443", 8443, "mytoken"), "http://sub.example.com:9443/mytoken"; got != want {
		t.Fatalf("FormatSubURL = %q, want %q", got, want)
	}
	// Level 3: Bare IP with non-secure port falls back to http
	if got, want := FormatSubURL("192.168.1.1", 8080, "mytoken"), "http://192.168.1.1:8080/mytoken"; got != want {
		t.Fatalf("FormatSubURL = %q, want %q", got, want)
	}
}

func TestUnifiedSubHandler(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	cfg := &config.UserConfig{
		Role:        config.RoleServer,
		UUID:        "server-uuid",
		AddressNode: "node.example.com",
		AddressSub:  "https://sub.example.com",
		AdminSub: config.AdminSubConfig{
			Token:      "admintoken",
			Port:       8443,
			TargetType: "direct",
		},
		Presets: []config.ModeInfo{{
			Mode:    config.ModeVLESSVision,
			Enabled: true,
			Port:    443,
			SNI:     "example.com",
			Settings: config.Settings{
				PublicKey: "pub",
				ShortID:   "abcd",
			},
		}},
		Guests: []config.GuestConfig{
			{
				Alias:    "alice-active",
				UUID:     "uuid-alice",
				Enabled:  true,
				QuotaGB:  5,
				ResetDay: 20,
				Notify:   config.GuestNotifyAll,
			},
			{
				Alias:    "bob-disabled",
				UUID:     "uuid-bob",
				Enabled:  false,
				QuotaGB:  5,
				ResetDay: 20,
				Notify:   config.GuestNotifyAll,
			},
		},
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("save config: %v", err)
	}

	handler := httpUnifiedSubHandler(cfg.AdminSub)

	// 1. Admin Token request
	{
		req := httptest.NewRequest("GET", "http://127.0.0.1/admintoken", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != 200 {
			t.Fatalf("admin sub code = %d, want 200", rec.Code)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rec.Body.String()))
		if err != nil {
			t.Fatalf("decode admin body: %v", err)
		}
		if !strings.Contains(string(decoded), "@node.example.com:443?") {
			t.Fatalf("expected node address in admin sub, got %q", string(decoded))
		}
	}

	// 2. Active Guest UUID request: contains real node and memorial node
	{
		req := httptest.NewRequest("GET", "http://127.0.0.1/uuid-alice", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != 200 {
			t.Fatalf("guest sub code = %d, want 200", rec.Code)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rec.Body.String()))
		if err != nil {
			t.Fatalf("decode guest body: %v", err)
		}
		body := string(decoded)
		lines := strings.Split(strings.TrimSpace(body), "\n")
		if len(lines) < 2 {
			t.Fatalf("expected memorial + real node lines, got %d", len(lines))
		}
		if !strings.HasPrefix(lines[0], "ss://") {
			t.Fatalf("expected memorial node on first line, got %q", lines[0])
		}
		if !strings.Contains(lines[1], "@node.example.com:443?") {
			t.Fatalf("expected real proxy node on second line, got %q", lines[1])
		}
	}

	// 3. Disabled Guest UUID request: ONLY memorial node with "bob-disabled is disabled", NO real proxy nodes
	{
		req := httptest.NewRequest("GET", "http://127.0.0.1/uuid-bob", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != 200 {
			t.Fatalf("disabled guest sub code = %d, want 200", rec.Code)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rec.Body.String()))
		if err != nil {
			t.Fatalf("decode disabled guest body: %v", err)
		}
		body := string(decoded)
		lines := strings.Split(strings.TrimSpace(body), "\n")
		if len(lines) != 1 {
			t.Fatalf("expected exactly 1 memorial node for disabled guest, got %d lines: %q", len(lines), body)
		}
		if !strings.HasPrefix(lines[0], "ss://") {
			t.Fatalf("expected memorial node, got %q", lines[0])
		}
		if !strings.Contains(lines[0], "bob-disabled%20is%20disabled") && !strings.Contains(lines[0], "bob-disabled+is+disabled") {
			t.Fatalf("expected 'bob-disabled is disabled' remark in link, got %q", lines[0])
		}
	}

	// 4. Unknown token -> 404
	{
		req := httptest.NewRequest("GET", "http://127.0.0.1/nonexistent", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != 404 {
			t.Fatalf("expected 404 for unknown token, got %d", rec.Code)
		}
	}

	// 5. Dynamic config reload without restarting handler
	{
		cfg.AdminSub.AddressNode = "updated-node.example.com"
		if err := cfg.Save(); err != nil {
			t.Fatalf("save updated config: %v", err)
		}
		req := httptest.NewRequest("GET", "http://127.0.0.1/admintoken", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != 200 {
			t.Fatalf("admin sub code after update = %d, want 200", rec.Code)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rec.Body.String()))
		if err != nil {
			t.Fatalf("decode admin body after update: %v", err)
		}
		if !strings.Contains(string(decoded), "@updated-node.example.com:443?") {
			t.Fatalf("expected dynamically updated node address in admin sub, got %q", string(decoded))
		}
	}
}

func TestServer_Handler_EndpointResolution(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		UUID: "server-uuid-1111",
		Endpoints: map[string]config.EndpointConfig{
			"admin-ep": {
				Type: config.EndpointTypeStatic,
				Host: "admin-edge.example.com",
			},
			"guest-ep": {
				Type: config.EndpointTypeStatic,
				Host: "guest-edge.example.com",
			},
		},
		AdminSub: config.AdminSubConfig{
			Token:      "admin-ep-token",
			Endpoint:   "admin-ep",
			Port:       8443,
			TargetType: "direct",
		},
		Presets: []config.ModeInfo{{
			Mode:    config.ModeVLESSVision,
			Enabled: true,
			Port:    443,
			SNI:     "example.com",
			Settings: config.Settings{
				PublicKey: "pub",
				ShortID:   "abcd",
			},
		}},
		Guests: []config.GuestConfig{
			{
				Alias:      "alice",
				UUID:       "alice-ep-uuid",
				Enabled:    true,
				LimitBytes: 10 * config.GigaByte,
				Endpoint:   "guest-ep",
			},
		},
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("save config: %v", err)
	}

	handler := httpUnifiedSubHandler(cfg.AdminSub)

	// Admin sub request should contain admin-edge.example.com
	{
		req := httptest.NewRequest("GET", "http://127.0.0.1/admin-ep-token", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != 200 {
			t.Fatalf("admin sub code = %d, want 200", rec.Code)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rec.Body.String()))
		if err != nil {
			t.Fatalf("decode admin body: %v", err)
		}
		if !strings.Contains(string(decoded), "@admin-edge.example.com:443?") {
			t.Fatalf("expected admin-edge.example.com in admin sub, got %q", string(decoded))
		}
	}

	// Guest sub request should contain guest-edge.example.com
	{
		req := httptest.NewRequest("GET", "http://127.0.0.1/alice-ep-uuid", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != 200 {
			t.Fatalf("guest sub code = %d, want 200", rec.Code)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rec.Body.String()))
		if err != nil {
			t.Fatalf("decode guest body: %v", err)
		}
		if !strings.Contains(string(decoded), "@guest-edge.example.com:443?") {
			t.Fatalf("expected guest-edge.example.com in guest sub, got %q", string(decoded))
		}
	}
}

