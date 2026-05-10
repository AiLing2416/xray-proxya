package sub

import (
	"encoding/base64"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"xray-proxya/internal/config"
)

func TestFormatGuestSubRemark(t *testing.T) {
	now := time.Date(2026, 5, 9, 8, 0, 0, 0, time.UTC)
	guest := config.GuestConfig{
		UsedBytes: 2 * 1024 * 1024 * 1024,
		QuotaGB:   5,
		ResetDay:  15,
	}
	if got, want := formatGuestSubRemark(guest, now), "2.00GB/5.00GB/6d"; got != want {
		t.Fatalf("formatGuestSubRemark = %q, want %q", got, want)
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

func TestGuestSubHandlerReturnsAnnotatedSubscription(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	cfg := &config.UserConfig{
		Role:         config.RoleServer,
		UUID:         "server-uuid",
		GuestSubBind: "127.0.0.1",
		ActiveModes: []config.ModeInfo{{
			Mode:    config.ModeVLESSVision,
			Enabled: true,
			Port:    443,
			SNI:     "example.com",
			Settings: config.Settings{
				PublicKey: "pub",
				ShortID:   "abcd",
			},
		}},
		Guests: []config.GuestConfig{{
			Alias:    "alice",
			UUID:     "guest-uuid",
			Enabled:  true,
			QuotaGB:  5,
			ResetDay: 20,
			SubToken: "token123",
		}},
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("save config: %v", err)
	}

	certPath, keyPath, err := EnsureCertificates()
	if err != nil {
		t.Fatalf("EnsureCertificates: %v", err)
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("cert file missing: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key file missing: %v", err)
	}

	req := httptest.NewRequest("GET", "https://127.0.0.1/guest-sub/token123", nil)
	req.Host = "sub.example.com"
	rec := httptest.NewRecorder()

	handler := httpGuestSubHandler()
	handler(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rec.Body.String()))
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	body := string(decoded)
	if !strings.Contains(body, "#0GB%2F5.00GB%2F") {
		t.Fatalf("expected annotated remark in body, got %q", body)
	}
	if !strings.Contains(body, "@sub.example.com:443?") {
		t.Fatalf("expected request host in generated link, got %q", body)
	}

	if _, err := os.Stat(filepath.Join(config.GetConfigDir(), "certs", "server.crt")); err != nil {
		t.Fatalf("expected cert in config dir: %v", err)
	}
}

func TestAdminSubHandlerPrefersAdminSubConfig(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	cfg := &config.UserConfig{
		Role: config.RoleServer,
		AdminSub: config.AdminSubConfig{
			Enabled:    true,
			Token:      "admintoken",
			Port:       8443,
			Mode:       config.AdminSubModeFixed,
			Address:    "sub.example.com",
			TargetType: "direct",
		},
		ActiveModes: []config.ModeInfo{{
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

	req := httptest.NewRequest("GET", "https://127.0.0.1/sub/admintoken", nil)
	rec := httptest.NewRecorder()
	httpAdminSubHandler()(rec, req)
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
