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
	guest := config.GuestConfig{
		UsedBytes: 2 * config.GigaByte,
		QuotaGB:   5,
		ResetDay:  15,
		Enabled:   true,
	}
	if got, want := formatGuestSubRemark(guest, now), "TRAFFIC: 2.00GB / 5.00GB | RESET: 6d"; got != want {
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
	if !strings.Contains(link, "@127.0.0.1:0#") {
		t.Fatalf("expected @127.0.0.1:0# in link, got %q", link)
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

func TestResolveGuestSubAddressUsesForwardedHost(t *testing.T) {
	req := httptest.NewRequest("GET", "https://127.0.0.1/guest-sub/token", nil)
	req.Header.Set("X-Forwarded-Host", "guest.example.com")
	if got, want := resolveGuestSubAddress(req), "guest.example.com"; got != want {
		t.Fatalf("resolveGuestSubAddress = %q, want %q", got, want)
	}
}

func TestValidatePrivateBindAddress(t *testing.T) {
	valid := []string{"127.0.0.1", "10.0.0.5", "192.168.1.9", "localhost"}
	for _, bind := range valid {
		if err := validatePrivateBindAddress(bind); err != nil {
			t.Fatalf("validatePrivateBindAddress(%q) unexpected error: %v", bind, err)
		}
	}
	if err := validatePrivateBindAddress("8.8.8.8"); err == nil {
		t.Fatalf("expected public bind address to fail validation")
	}
}

func TestGuestSubHandlerNotifyModes(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	cfg := &config.UserConfig{
		Role:         config.RoleServer,
		UUID:         "server-uuid",
		GuestSubBind: "127.0.0.1",
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
				Alias:    "alice-off",
				UUID:     "uuid-off",
				Enabled:  true,
				QuotaGB:  5,
				ResetDay: 20,
				SubToken: "token-off",
				Notify:   config.GuestNotifyOff,
			},
			{
				Alias:    "alice-all",
				UUID:     "uuid-all",
				Enabled:  true,
				QuotaGB:  5,
				ResetDay: 20,
				SubToken: "token-all",
				Notify:   config.GuestNotifyAll,
			},
		},
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("save config: %v", err)
	}

	handler := httpGuestSubHandler()

	// Test default / off mode: no header, no memorial node, real nodes clean
	{
		req := httptest.NewRequest("GET", "http://127.0.0.1/guest-sub/token-off", nil)
		req.Host = "sub.example.com"
		rec := httptest.NewRecorder()
		handler(rec, req)

		if rec.Code != 200 {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if rec.Header().Get("Subscription-Userinfo") != "" {
			t.Fatalf("expected no Subscription-Userinfo header in off mode")
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rec.Body.String()))
		if err != nil {
			t.Fatalf("decode body: %v", err)
		}
		body := string(decoded)
		for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
			if strings.HasPrefix(line, "ss://") {
				t.Fatalf("expected no memorial ss node in off mode, got %q", line)
			}
		}
		if !strings.Contains(body, "@sub.example.com:443?") {
			t.Fatalf("expected real node in generated links, got %q", body)
		}
	}

	// Test all mode: has Subscription-Userinfo header AND memorial ss node prepended
	{
		req := httptest.NewRequest("GET", "http://127.0.0.1/guest-sub/token-all", nil)
		req.Host = "sub.example.com"
		rec := httptest.NewRecorder()
		handler(rec, req)

		if rec.Code != 200 {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		userInfo := rec.Header().Get("Subscription-Userinfo")
		if !strings.Contains(userInfo, "download=0") || !strings.Contains(userInfo, "total=5000000000") {
			t.Fatalf("expected Subscription-Userinfo header, got %q", userInfo)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rec.Body.String()))
		if err != nil {
			t.Fatalf("decode body: %v", err)
		}
		body := string(decoded)
		lines := strings.Split(strings.TrimSpace(body), "\n")
		if len(lines) < 2 {
			t.Fatalf("expected at least 2 lines (memorial node + real node), got %d", len(lines))
		}
		if !strings.HasPrefix(lines[0], "ss://") || !strings.Contains(lines[0], "@127.0.0.1:0#") {
			t.Fatalf("expected memorial node on first line, got %q", lines[0])
		}
		if !strings.Contains(lines[1], "@sub.example.com:443?") {
			t.Fatalf("expected real node on second line, got %q", lines[1])
		}
	}
}

func TestAdminSubHandlerPrefersAdminSubConfig(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		AdminSub: config.AdminSubConfig{
			Token:      "admintoken",
			Port:       8443,
			Address:    "sub.example.com",
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
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("save config: %v", err)
	}

	req := httptest.NewRequest("GET", "http://127.0.0.1/sub/admintoken", nil)
	rec := httptest.NewRecorder()
	httpAdminSubHandler(cfg.AdminSub)(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rec.Body.String()))
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	body := string(decoded)
	if !strings.Contains(body, "@sub.example.com:443?") {
		t.Fatalf("expected admin_sub address in body, got %q", body)
	}
}
