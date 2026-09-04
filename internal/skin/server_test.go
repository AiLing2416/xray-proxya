package skin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func init() {
	// Disable sleep during tests for speed
	DelaySimulateAuth = false
}

func TestFilebrowserHandler(t *testing.T) {
	h, err := NewHandler(config.SkinFilebrowser)
	if err != nil {
		t.Fatalf("NewHandler(filebrowser) error: %v", err)
	}

	// 1. GET /
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET / code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "File Browser") {
		t.Errorf("GET / missing File Browser title")
	}

	// 2. GET /manifest.json
	req = httptest.NewRequest("GET", "/manifest.json", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /manifest.json code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "File Browser") {
		t.Errorf("GET /manifest.json content mismatch")
	}

	// 3. GET /api/public/settings
	req = httptest.NewRequest("GET", "/api/public/settings", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /api/public/settings code = %d, want 200", rec.Code)
	}

	// 4. POST /api/login (wrong credentials)
	req = httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"password"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST /api/login code = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "403 Forbidden") {
		t.Errorf("POST /api/login body = %q, want '403 Forbidden'", rec.Body.String())
	}

	// 5. GET /api/resources/
	req = httptest.NewRequest("GET", "/api/resources/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/resources/ code = %d, want 401", rec.Code)
	}

	// 6. Static asset /static/assets/index-BOEsmRAc.css
	req = httptest.NewRequest("GET", "/static/assets/index-BOEsmRAc.css", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /static/assets/index-BOEsmRAc.css code = %d, want 200", rec.Code)
	}

	// 7. GET /health
	req = httptest.NewRequest("GET", "/health", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "OK") {
		t.Errorf("GET /health failed: %s", rec.Body.String())
	}
}

func TestNextcloudHandler(t *testing.T) {
	h, err := NewHandler(config.SkinNextcloud)
	if err != nil {
		t.Fatalf("NewHandler(nextcloud) error: %v", err)
	}

	// 1. GET / redirects to /login
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("GET / code = %d, want 302", rec.Code)
	}
	if rec.Header().Get("Location") != "/login" {
		t.Errorf("GET / location = %q, want /login", rec.Header().Get("Location"))
	}

	// 2. GET /status.php probe
	req = httptest.NewRequest("GET", "/status.php", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /status.php code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"productname":"Nextcloud"`) {
		t.Errorf("GET /status.php body missing Nextcloud")
	}

	// 3. GET /login
	req = httptest.NewRequest("GET", "/login", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /login code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "initial-state-core-loginUsername") {
		t.Errorf("GET /login missing initial state")
	}

	// 4. POST /login (wrong credentials redirects 303 to login?direct=1&user=admin)
	formData := url.Values{
		"user":     {"admin"},
		"password": {"wrongpass"},
	}
	req = httptest.NewRequest("POST", "/login", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("POST /login code = %d, want 303", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "direct=1") {
		t.Errorf("POST /login Location = %q, want direct=1", rec.Header().Get("Location"))
	}

	// 5. GET /login with direct=1 and user populated
	req = httptest.NewRequest("GET", "/login?direct=1&user=admin", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /login?direct=1 code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ImFkbWluIg==") {
		t.Errorf("GET /login?direct=1 missing base64 encoded username")
	}

	// 6. WebDAV probe
	req = httptest.NewRequest("GET", "/remote.php/webdav/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /remote.php/webdav/ code = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Www-Authenticate"), "Nextcloud") {
		t.Errorf("GET /remote.php/webdav/ Www-Authenticate header mismatch")
	}

	// 7. CalDAV probe redirect
	req = httptest.NewRequest("GET", "/.well-known/caldav", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently {
		t.Errorf("GET /.well-known/caldav code = %d, want 301", rec.Code)
	}

	// 8. OCS getapppassword probe
	req = httptest.NewRequest("GET", "/ocs/v2.php/core/getapppassword", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /ocs/v2.php/core/getapppassword code = %d, want 401", rec.Code)
	}
}

func TestSeafileHandler(t *testing.T) {
	h, err := NewHandler(config.SkinSeafile)
	if err != nil {
		t.Fatalf("NewHandler(seafile) error: %v", err)
	}

	// 1. GET / redirects to /accounts/login/?next=/
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("GET / code = %d, want 302", rec.Code)
	}

	// 2. GET /api2/ping/
	req = httptest.NewRequest("GET", "/api2/ping/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "pong") {
		t.Errorf("GET /api2/ping/ = %q, want 'pong'", rec.Body.String())
	}

	// 3. GET /accounts/login/
	req = httptest.NewRequest("GET", "/accounts/login/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /accounts/login/ code = %d, want 200", rec.Code)
	}
	cookies := rec.Result().Cookies()
	hasCSRF := false
	for _, c := range cookies {
		if c.Name == "sfcsrftoken" {
			hasCSRF = true
			break
		}
	}
	if !hasCSRF {
		t.Errorf("GET /accounts/login/ missing sfcsrftoken cookie")
	}

	// 4. POST /accounts/login/ (wrong credentials)
	formData := url.Values{
		"login":    {"user@example.com"},
		"password": {"badpass"},
	}
	req = httptest.NewRequest("POST", "/accounts/login/", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("POST /accounts/login/ code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Incorrect email or password") {
		t.Errorf("POST /accounts/login/ should display error notice")
	}

	// 5. POST /api2/auth-token/
	req = httptest.NewRequest("POST", "/api2/auth-token/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /api2/auth-token/ code = %d, want 400", rec.Code)
	}
}

func TestStartMultiSkinServer(t *testing.T) {
	mappings := []DomainSkinMapping{
		{Domain: "nc.example.com", SkinType: config.SkinNextcloud},
		{Domain: "fb.example.com", SkinType: config.SkinFilebrowser},
		{Domain: "sf.example.com", SkinType: config.SkinSeafile},
	}

	srv, err := StartMultiSkinServer("127.0.0.1:0", mappings, config.SkinNextcloud)
	if err != nil {
		t.Fatalf("StartMultiSkinServer error: %v", err)
	}

	// 1. Host: nc.example.com -> Nextcloud
	req := httptest.NewRequest("GET", "/status.php", nil)
	req.Host = "nc.example.com"
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Nextcloud") {
		t.Errorf("nc.example.com /status.php failed: %s", rec.Body.String())
	}

	// 2. Host: fb.example.com -> File Browser
	req = httptest.NewRequest("GET", "/api/public/settings", nil)
	req.Host = "fb.example.com"
	rec = httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "signup") {
		t.Errorf("fb.example.com /api/public/settings failed: %s", rec.Body.String())
	}

	// 3. Host: sf.example.com -> Seafile
	req = httptest.NewRequest("GET", "/api2/ping/", nil)
	req.Host = "sf.example.com"
	rec = httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "pong") {
		t.Errorf("sf.example.com /api2/ping/ failed: %s", rec.Body.String())
	}

	// 4. Unknown host -> returns 404 Not Found
	req = httptest.NewRequest("GET", "/status.php", nil)
	req.Host = "unknown.example.com"
	rec = httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown host code = %d, want 404", rec.Code)
	}
}

