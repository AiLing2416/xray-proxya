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
	if rec.Body.String() != "401 Unauthorized\n" {
		t.Errorf("GET /api/resources/ body = %q, want '401 Unauthorized\\n'", rec.Body.String())
	}

	// 6. Static asset /static/assets/index-BOEsmRAc.css
	req = httptest.NewRequest("GET", "/static/assets/index-BOEsmRAc.css", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /static/assets/index-BOEsmRAc.css code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Cache-Control"), "max-age=86400") {
		t.Errorf("GET /static/assets/index-BOEsmRAc.css missing Cache-Control: max-age=86400")
	}
	if rec.Header().Get("Server") != "Caddy" {
		t.Errorf("GET /static/assets/index-BOEsmRAc.css Server = %q, want 'Caddy'", rec.Header().Get("Server"))
	}

	// 7. Non-existent static asset returns 404 Not Found (no Go runtime leak)
	req = httptest.NewRequest("GET", "/static/nonexistent.js", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /static/nonexistent.js code = %d, want 404", rec.Code)
	}
	if rec.Body.String() != "404 Not Found\n" {
		t.Errorf("GET /static/nonexistent.js body = %q, want '404 Not Found\\n'", rec.Body.String())
	}

	// 8. GET /health
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

	// 6. WebDAV probe (SabreDAV XML, no Go plaintext)
	req = httptest.NewRequest("GET", "/remote.php/webdav/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /remote.php/webdav/ code = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Www-Authenticate"), "Nextcloud") {
		t.Errorf("GET /remote.php/webdav/ Www-Authenticate header mismatch")
	}
	if !strings.Contains(rec.Body.String(), "<s:exception>Sabre\\DAV\\Exception\\NotAuthenticated</s:exception>") {
		t.Errorf("GET /remote.php/webdav/ missing SabreDAV XML body, got %q", rec.Body.String())
	}
	if rec.Body.String() == "Unauthorized\n" {
		t.Errorf("GET /remote.php/webdav/ returned Go plaintext Unauthorized")
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

	// 9. Static asset: no X-Powered-By, valid Cache-Control, text/javascript MIME
	req = httptest.NewRequest("GET", "/dist/core-common.js", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /dist/core-common.js code = %d, want 200", rec.Code)
	}
	if rec.Header().Get("X-Powered-By") != "" {
		t.Errorf("GET /dist/core-common.js should not have X-Powered-By header, got %q", rec.Header().Get("X-Powered-By"))
	}
	if rec.Header().Get("Content-Type") != "text/javascript" {
		t.Errorf("GET /dist/core-common.js Content-Type = %q, want 'text/javascript'", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Header().Get("Cache-Control"), "max-age=15778463") {
		t.Errorf("GET /dist/core-common.js missing Cache-Control max-age header")
	}

	// 10. 204 Ping probe
	req = httptest.NewRequest("GET", "/index.php/204", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("GET /index.php/204 code = %d, want 204", rec.Code)
	}
	if rec.Header().Get("X-Powered-By") != "PHP/8.5.10" {
		t.Errorf("GET /index.php/204 missing X-Powered-By: PHP/8.5.10")
	}

	// 11. Webcron probe
	req = httptest.NewRequest("GET", "/cron.php", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"success"`) {
		t.Errorf("GET /cron.php failed: %s", rec.Body.String())
	}

	// 12. Robots.txt: no X-Powered-By
	req = httptest.NewRequest("GET", "/robots.txt", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "User-agent: *") {
		t.Errorf("GET /robots.txt failed: %s", rec.Body.String())
	}
	if rec.Header().Get("X-Powered-By") != "" {
		t.Errorf("GET /robots.txt should not have X-Powered-By header")
	}

	// 13. Nodeinfo probe
	req = httptest.NewRequest("GET", "/.well-known/nodeinfo", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /.well-known/nodeinfo code = %d, want 404", rec.Code)
	}
	if rec.Header().Get("X-Nextcloud-Well-Known") != "1" {
		t.Errorf("GET /.well-known/nodeinfo missing X-Nextcloud-Well-Known header")
	}

	// 14. Capabilities probe
	req = httptest.NewRequest("GET", "/ocs/v2.php/cloud/capabilities", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusPreconditionFailed {
		t.Errorf("GET /ocs/v2.php/cloud/capabilities code = %d, want 412", rec.Code)
	}

	// 15. Catch-all 404: Apache HTML, no Go plaintext 404
	req = httptest.NewRequest("GET", "/some/random/nonexistent/path", nil)
	req.Host = "nextcloud.example.com"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /some/random/nonexistent/path code = %d, want 404", rec.Code)
	}
	if rec.Body.String() == "404 page not found\n" {
		t.Errorf("GET /some/random/nonexistent/path returned Go plaintext 404")
	}
	if !strings.Contains(rec.Body.String(), "<title>404 Not Found</title>") {
		t.Errorf("GET /some/random/nonexistent/path missing Apache 404 title")
	}
	if !strings.Contains(rec.Body.String(), "Apache/2.4.68 (Debian) Server at nextcloud.example.com Port 443") {
		t.Errorf("GET /some/random/nonexistent/path missing Apache server address banner")
	}

	// 16. GET /login CSP and cookie verification
	req = httptest.NewRequest("GET", "/login", nil)
	req.Host = "nextcloud.example.com"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self' 'nonce-") {
		t.Errorf("GET /login CSP missing nonce: %s", csp)
	}
	if strings.Contains(rec.Body.String(), "skin1.ailing.dev") {
		t.Errorf("GET /login body contains leaked reference to skin1.ailing.dev")
	}
	cookies := rec.Result().Cookies()
	var hasPassphrase, hasSID, hasLax, hasStrict bool
	for _, c := range cookies {
		switch c.Name {
		case "oc_sessionPassphrase":
			hasPassphrase = true
		case "ocouaube3hh1":
			hasSID = true
		case "nc_sameSiteCookielax":
			hasLax = true
		case "nc_sameSiteCookiestrict":
			hasStrict = true
		}
	}
	if !hasPassphrase || !hasSID || !hasLax || !hasStrict {
		t.Errorf("GET /login missing expected Nextcloud cookies")
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

