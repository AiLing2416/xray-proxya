package skin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
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

	// 4. /api/login: POST, GET, OPTIONS all return 403 Forbidden
	for _, method := range []string{"POST", "GET", "OPTIONS"} {
		req = httptest.NewRequest(method, "/api/login", strings.NewReader(`{"username":"admin","password":"password"}`))
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s /api/login code = %d, want 403", method, rec.Code)
		}
		if rec.Body.String() != "403 Forbidden\n" {
			t.Errorf("%s /api/login body = %q, want '403 Forbidden\\n'", method, rec.Body.String())
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s /api/login missing nosniff header", method)
		}
	}

	// 5. /api/signup: GET and POST both return 405 Method Not Allowed
	for _, method := range []string{"GET", "POST"} {
		req = httptest.NewRequest(method, "/api/signup", nil)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/signup code = %d, want 405", method, rec.Code)
		}
		if rec.Body.String() != "405 Method Not Allowed\n" {
			t.Errorf("%s /api/signup body = %q, want '405 Method Not Allowed\\n'", method, rec.Body.String())
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s /api/signup missing nosniff header", method)
		}
	}

	// 6. Redirects: /api/resources and /api/raw return 301
	for _, p := range []string{"/api/resources", "/api/raw"} {
		req = httptest.NewRequest("GET", p, nil)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMovedPermanently {
			t.Errorf("GET %s code = %d, want 301", p, rec.Code)
		}
		if rec.Header().Get("Location") != p+"/" {
			t.Errorf("GET %s Location = %q, want %s/", p, rec.Header().Get("Location"), p)
		}
	}

	// 7. Public share / dl: return 404 Not Found on invalid token
	for _, p := range []string{"/api/public/share/invalidtoken", "/api/public/dl/invalidtoken"} {
		req = httptest.NewRequest("GET", p, nil)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s code = %d, want 404", p, rec.Code)
		}
		if rec.Body.String() != "404 Not Found\n" {
			t.Errorf("GET %s body = %q, want '404 Not Found\\n'", p, rec.Body.String())
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("GET %s missing nosniff header", p)
		}
	}

	// 8. Unknown /api/ routes fall back to SPA index.html (200 OK)
	req = httptest.NewRequest("GET", "/api/unknown_custom_route", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /api/unknown_custom_route code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Errorf("GET /api/unknown_custom_route Content-Type = %q, want text/html", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "File Browser") {
		t.Errorf("GET /api/unknown_custom_route should return SPA HTML")
	}

	// 9. Authenticated API: /api/resources/ returns 401
	req = httptest.NewRequest("GET", "/api/resources/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/resources/ code = %d, want 401", rec.Code)
	}
	if rec.Body.String() != "401 Unauthorized\n" {
		t.Errorf("GET /api/resources/ body = %q, want '401 Unauthorized\\n'", rec.Body.String())
	}

	// 10. Static asset CSS: /static/assets/index-BOEsmRAc.css
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
	if rec.Header().Get("ETag") != "" {
		t.Errorf("GET /static/assets/index-BOEsmRAc.css should NOT have ETag, got %q", rec.Header().Get("ETag"))
	}
	if rec.Header().Get("Accept-Ranges") != "" {
		t.Errorf("GET /static/assets/index-BOEsmRAc.css should NOT have Accept-Ranges, got %q", rec.Header().Get("Accept-Ranges"))
	}

	// 11. Static asset JS: /static/assets/index-BqkXVoMb.js
	req = httptest.NewRequest("GET", "/static/assets/index-BqkXVoMb.js", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /static/assets/index-BqkXVoMb.js code = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/javascript; charset=utf-8" {
		t.Errorf("GET /static/assets/index-BqkXVoMb.js Content-Type = %q, want 'application/javascript; charset=utf-8'", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("ETag") != "" {
		t.Errorf("GET /static/assets/index-BqkXVoMb.js should NOT have ETag, got %q", rec.Header().Get("ETag"))
	}
	if rec.Header().Get("Accept-Ranges") != "" {
		t.Errorf("GET /static/assets/index-BqkXVoMb.js should NOT have Accept-Ranges, got %q", rec.Header().Get("Accept-Ranges"))
	}

	// 12. Non-existent static asset returns 404 Not Found (no Go runtime leak)
	req = httptest.NewRequest("GET", "/static/nonexistent.js", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /static/nonexistent.js code = %d, want 404", rec.Code)
	}
	if rec.Body.String() != "404 Not Found\n" {
		t.Errorf("GET /static/nonexistent.js body = %q, want '404 Not Found\\n'", rec.Body.String())
	}

	// 13. GET /health
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
	if rec.Header().Get("Allow") != "GET, HEAD, OPTIONS" {
		t.Errorf("GET /api2/ping/ Allow = %q, want 'GET, HEAD, OPTIONS'", rec.Header().Get("Allow"))
	}

	// 3. GET /seafhttp/protocol-version
	req = httptest.NewRequest("GET", "/seafhttp/protocol-version", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /seafhttp/protocol-version code = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "text/plain" {
		t.Errorf("GET /seafhttp/protocol-version Content-Type = %q, want 'text/plain'", rec.Header().Get("Content-Type"))
	}
	if rec.Body.String() != `{"version": 2}` {
		t.Errorf("GET /seafhttp/protocol-version body = %q, want '{\"version\": 2}'", rec.Body.String())
	}

	// 4. GET /accounts/login/ (dynamic CSRF & Cookies)
	req = httptest.NewRequest("GET", "/accounts/login/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /accounts/login/ code = %d, want 200", rec.Code)
	}
	cookies := rec.Result().Cookies()
	var csrfCookie, sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "sfcsrftoken" {
			csrfCookie = c
		} else if c.Name == "sessionid" {
			sessionCookie = c
		}
	}
	if csrfCookie == nil || len(csrfCookie.Value) != 32 || csrfCookie.MaxAge != 31449600 {
		t.Errorf("invalid sfcsrftoken cookie: %+v", csrfCookie)
	}
	if sessionCookie == nil || len(sessionCookie.Value) != 32 || sessionCookie.MaxAge != 86400 || !sessionCookie.HttpOnly {
		t.Errorf("invalid sessionid cookie: %+v", sessionCookie)
	}
	body1 := rec.Body.String()
	m1 := regexp.MustCompile(`name="csrfmiddlewaretoken" value="([^"]*)"`).FindStringSubmatch(body1)
	if len(m1) < 2 || len(m1[1]) != 64 {
		t.Errorf("GET /accounts/login/ missing 64-char csrf token: %v", m1)
	}

	// Second request should generate different random tokens
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest("GET", "/accounts/login/", nil))
	body2 := rec2.Body.String()
	m2 := regexp.MustCompile(`name="csrfmiddlewaretoken" value="([^"]*)"`).FindStringSubmatch(body2)
	if len(m2) >= 2 && m1[1] == m2[1] {
		t.Errorf("CSRF token was not dynamically randomized across requests")
	}

	// 5. POST /accounts/login/ (wrong credentials)
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

	// 6. API2 auth-token: GET returns 405 with JSON, POST returns 400 with JSON
	req = httptest.NewRequest("GET", "/api2/auth-token/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api2/auth-token/ code = %d, want 405", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `Method \"GET\" not allowed`) {
		t.Errorf("GET /api2/auth-token/ body = %q", rec.Body.String())
	}
	if rec.Header().Get("Allow") != "POST, OPTIONS" {
		t.Errorf("GET /api2/auth-token/ Allow = %q, want 'POST, OPTIONS'", rec.Header().Get("Allow"))
	}

	req = httptest.NewRequest("POST", "/api2/auth-token/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /api2/auth-token/ code = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Unable to login with provided credentials") {
		t.Errorf("POST /api2/auth-token/ body = %q", rec.Body.String())
	}

	// 7. API2 protected endpoints (403 Forbidden with proper Allow)
	req = httptest.NewRequest("GET", "/api2/account/info/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("GET /api2/account/info/ code = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Authentication credentials were not provided") {
		t.Errorf("GET /api2/account/info/ body = %q", rec.Body.String())
	}
	if rec.Header().Get("Allow") != "GET, PUT, HEAD, OPTIONS" {
		t.Errorf("GET /api2/account/info/ Allow = %q, want 'GET, PUT, HEAD, OPTIONS'", rec.Header().Get("Allow"))
	}

	req = httptest.NewRequest("GET", "/api2/repos/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Allow") != "GET, POST, HEAD, OPTIONS" {
		t.Errorf("GET /api2/repos/ code = %d, Allow = %q", rec.Code, rec.Header().Get("Allow"))
	}

	req = httptest.NewRequest("POST", "/api2/client-login/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Allow") != "POST, OPTIONS" {
		t.Errorf("POST /api2/client-login/ code = %d, Allow = %q", rec.Code, rec.Header().Get("Allow"))
	}

	// 8. Password Reset: /accounts/password/reset/
	req = httptest.NewRequest("GET", "/accounts/password/reset/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /accounts/password/reset/ code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Password Reset") {
		t.Errorf("GET /accounts/password/reset/ body missing 'Password Reset'")
	}
	mPr := regexp.MustCompile(`name="csrfmiddlewaretoken" value="([^"]*)"`).FindStringSubmatch(rec.Body.String())
	if len(mPr) < 2 || len(mPr[1]) != 64 {
		t.Errorf("password reset missing 64-char csrf token: %v", mPr)
	}

	// 9. Language Switch: /i18n/?lang=zh-cn
	req = httptest.NewRequest("GET", "/i18n/?lang=zh-cn", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("GET /i18n/?lang=zh-cn code = %d, want 302", rec.Code)
	}
	if rec.Header().Get("Location") != "/" {
		t.Errorf("GET /i18n/?lang=zh-cn Location = %q, want '/'", rec.Header().Get("Location"))
	}
	var langCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "django_language" {
			langCookie = c
			break
		}
	}
	if langCookie == nil || langCookie.Value != "zh-cn" || langCookie.MaxAge != 2592000 {
		t.Errorf("invalid django_language cookie: %+v", langCookie)
	}

	// 10. Global 404 fallback
	req = httptest.NewRequest("GET", "/some-random-unknown-path", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /some-random-unknown-path code = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Private Seafile") || !strings.Contains(rec.Body.String(), "could not be found") {
		t.Errorf("GET /some-random-unknown-path did not return Seafile branded 404 HTML")
	}

	// 11. Media 404: non-existent static asset returns nginx default 404
	req = httptest.NewRequest("GET", "/media/nonexistent.js", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /media/nonexistent.js code = %d, want 404", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "text/html" {
		t.Errorf("GET /media/nonexistent.js Content-Type = %q, want 'text/html'", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "<center><h1>404 Not Found</h1></center>") {
		t.Errorf("GET /media/nonexistent.js did not return Nginx 404 HTML")
	}

	// 12. Static CSS headers: text/css without charset, ETag, Last-Modified, no X-Frame-Options
	req = httptest.NewRequest("GET", "/media/css/seafile-ui.css", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /media/css/seafile-ui.css code = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "text/css" {
		t.Errorf("GET /media/css/seafile-ui.css Content-Type = %q, want 'text/css'", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("ETag") == "" {
		t.Errorf("GET /media/css/seafile-ui.css missing ETag")
	}
	if rec.Header().Get("Last-Modified") == "" {
		t.Errorf("GET /media/css/seafile-ui.css missing Last-Modified")
	}
	if rec.Header().Get("X-Frame-Options") != "" {
		t.Errorf("GET /media/css/seafile-ui.css should NOT have X-Frame-Options, got %q", rec.Header().Get("X-Frame-Options"))
	}

	// 13. Static JS headers: application/javascript without charset, no X-Frame-Options
	req = httptest.NewRequest("GET", "/media/assets/scripts/lib/jquery.min.js", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /media/assets/scripts/lib/jquery.min.js code = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/javascript" {
		t.Errorf("GET /media/assets/scripts/lib/jquery.min.js Content-Type = %q, want 'application/javascript'", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("X-Frame-Options") != "" {
		t.Errorf("GET /media/assets/scripts/lib/jquery.min.js should NOT have X-Frame-Options, got %q", rec.Header().Get("X-Frame-Options"))
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

