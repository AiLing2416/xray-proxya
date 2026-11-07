package skin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"xray-proxya/internal/config"

	"github.com/quic-go/quic-go/http3"
)

func init() {
	// Disable sleep during tests for speed
	DelaySimulateAuth = false
}

func TestFilebrowserHandler(t *testing.T) {
	if !Enabled {
		t.Skip("Skin feature is disabled in slim build")
	}
	h, err := NewHandler(config.SkinFilebrowser)
	if err != nil {
		t.Fatalf("NewHandler(filebrowser) error: %v", err)
	}

	// 1. GET / returns 200 OK with SPA HTML
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET / code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "File Browser") {
		t.Errorf("GET / missing File Browser title")
	}

	// Non-GET methods on SPA routes return 404 Not Found
	for _, m := range []string{"POST", "HEAD", "OPTIONS", "PUT", "DELETE"} {
		req = httptest.NewRequest(m, "/", nil)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s / code = %d, want 404", m, rec.Code)
		}
		if rec.Body.String() != "404 Not Found\n" {
			t.Errorf("%s / body = %q, want '404 Not Found\\n'", m, rec.Body.String())
		}
	}

	// 2. GET /manifest.json falls through to SPA index.html
	req = httptest.NewRequest("GET", "/manifest.json", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /manifest.json code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "File Browser") {
		t.Errorf("GET /manifest.json content mismatch")
	}

	// 3. GET /health probe returns exact 15 bytes {"status":"OK"} without newline
	req = httptest.NewRequest("GET", "/health", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /health code = %d, want 200", rec.Code)
	}
	if rec.Body.String() != `{"status":"OK"}` {
		t.Errorf("GET /health body = %q, want '{\"status\":\"OK\"}'", rec.Body.String())
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

	// 6. Redirects: /api/resources, /api/raw, /api/usage, /api/tus, /api/search return 301
	for _, p := range []string{"/api/resources", "/api/raw", "/api/usage", "/api/tus", "/api/search", "/api/subtitle", "/api/command", "/api/share"} {
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

	// 7. Public share / dl: return 404 Not Found
	for _, p := range []string{"/api/public/share/invalidtoken", "/api/public/dl/invalidtoken", "/api/public/share", "/api/public/dl"} {
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

	// 8. Unknown /api/ routes fall back to SPA index.html on GET (200 OK), but 404 on POST
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

	req = httptest.NewRequest("POST", "/api/unknown_custom_route", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST /api/unknown_custom_route code = %d, want 404", rec.Code)
	}

	// 9. Authenticated API: /api/resources/, /api/renew, /api/settings return 401
	for _, p := range []string{"/api/resources/", "/api/renew", "/api/settings", "/api/users", "/api/shares", "/api/usage/", "/api/tus/"} {
		req = httptest.NewRequest("GET", p, nil)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s code = %d, want 401", p, rec.Code)
		}
		if rec.Body.String() != "401 Unauthorized\n" {
			t.Errorf("GET %s body = %q, want '401 Unauthorized\\n'", p, rec.Body.String())
		}
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
	if rec.Header().Get("Accept-Ranges") != "bytes" {
		t.Errorf("GET /static/assets/index-BOEsmRAc.css Accept-Ranges = %q, want 'bytes'", rec.Header().Get("Accept-Ranges"))
	}

	// 11. Static webfont: /static/assets/material-icons-kAwBdRge.woff2
	req = httptest.NewRequest("GET", "/static/assets/material-icons-kAwBdRge.woff2", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /static/assets/material-icons-kAwBdRge.woff2 code = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "font/woff2" {
		t.Errorf("GET /static/assets/material-icons-kAwBdRge.woff2 Content-Type = %q, want 'font/woff2'", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Accept-Ranges") != "bytes" {
		t.Errorf("GET /static/assets/material-icons-kAwBdRge.woff2 Accept-Ranges = %q, want 'bytes'", rec.Header().Get("Accept-Ranges"))
	}

	// 12. Static asset JS: /static/assets/index-BqkXVoMb.js
	req = httptest.NewRequest("GET", "/static/assets/index-BqkXVoMb.js", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /static/assets/index-BqkXVoMb.js code = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/javascript; charset=utf-8" {
		t.Errorf("GET /static/assets/index-BqkXVoMb.js Content-Type = %q, want 'application/javascript; charset=utf-8'", rec.Header().Get("Content-Type"))
	}

	// Non-GET on static assets returns 404
	req = httptest.NewRequest("POST", "/static/assets/index-BqkXVoMb.js", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST /static/assets/index-BqkXVoMb.js code = %d, want 404", rec.Code)
	}

	// 13. Non-existent static asset returns 404 Not Found
	req = httptest.NewRequest("GET", "/static/nonexistent.js", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /static/nonexistent.js code = %d, want 404", rec.Code)
	}
	if rec.Body.String() != "404 Not Found\n" {
		t.Errorf("GET /static/nonexistent.js body = %q, want '404 Not Found\\n'", rec.Body.String())
	}
}

func TestNextcloudHandler(t *testing.T) {
	if !Enabled {
		t.Skip("Skin feature is disabled in slim build")
	}
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
	if !strings.Contains(rec.Body.String(), `"version":"34.0.3.2"`) {
		t.Errorf("GET /status.php body missing version 34.0.3.2: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"productname":"Nextcloud"`) {
		t.Errorf("GET /status.php body missing Nextcloud")
	}
	if rec.Header().Get("Server") != "Apache/2.4.68 (Debian)" {
		t.Errorf("GET /status.php Server = %q, want Apache/2.4.68 (Debian)", rec.Header().Get("Server"))
	}
	if rec.Header().Get("X-Powered-By") != "PHP/8.5.10" {
		t.Errorf("GET /status.php X-Powered-By = %q, want PHP/8.5.10", rec.Header().Get("X-Powered-By"))
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("GET /status.php missing nosniff header")
	}
	var hasStatusLax, hasStatusStrict bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "nc_sameSiteCookielax" {
			hasStatusLax = true
		}
		if c.Name == "nc_sameSiteCookiestrict" {
			hasStatusStrict = true
		}
	}
	if !hasStatusLax || !hasStatusStrict {
		t.Errorf("GET /status.php missing SameSite cookies")
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
	if !strings.Contains(rec.Header().Get("Feature-Policy"), "camera 'none'") {
		t.Errorf("GET /login missing Feature-Policy header")
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
	if rec.Header().Get("X-Nextcloud-Bruteforce-Throttled") != "6400ms" {
		t.Errorf("POST /login missing bruteforce throttling header: %q", rec.Header().Get("X-Nextcloud-Bruteforce-Throttled"))
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

	// 6. WebDAV probes (direct processing, Basic & Bearer messages)
	req = httptest.NewRequest("GET", "/remote.php/webdav", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /remote.php/webdav code = %d, want 401 (no 301 redirect)", rec.Code)
	}

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
	if !strings.Contains(rec.Body.String(), "No 'Authorization: Basic' header found") {
		t.Errorf("GET /remote.php/webdav/ missing expected no-header message")
	}

	// WebDAV with invalid Basic Auth
	req = httptest.NewRequest("GET", "/remote.php/webdav/", nil)
	req.Header.Set("Authorization", "Basic YWRtaW46d3JvbmdwYXNz")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /remote.php/webdav/ with Basic auth code = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Username or password was incorrect") {
		t.Errorf("GET /remote.php/webdav/ with Basic auth body missing 'Username or password was incorrect', got %q", rec.Body.String())
	}

	// WebDAV with invalid Bearer Auth
	req = httptest.NewRequest("GET", "/remote.php/webdav/", nil)
	req.Header.Set("Authorization", "Bearer badtoken123")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /remote.php/webdav/ with Bearer auth code = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Bearer token was incorrect") {
		t.Errorf("GET /remote.php/webdav/ with Bearer auth body missing 'Bearer token was incorrect', got %q", rec.Body.String())
	}

	// 7. Well-known routes
	req = httptest.NewRequest("GET", "/.well-known/webdav", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /.well-known/webdav code = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"message":"webdav not supported"`) {
		t.Errorf("GET /.well-known/webdav body = %q", rec.Body.String())
	}
	if rec.Header().Get("X-Nextcloud-Well-Known") != "1" {
		t.Errorf("GET /.well-known/webdav missing X-Nextcloud-Well-Known header")
	}

	req = httptest.NewRequest("GET", "/.well-known/caldav", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/remote.php/dav/" {
		t.Errorf("GET /.well-known/caldav code = %d, loc = %q, want 301 to /remote.php/dav/", rec.Code, rec.Header().Get("Location"))
	}

	req = httptest.NewRequest("GET", "/.well-known/carddav", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/remote.php/dav/" {
		t.Errorf("GET /.well-known/carddav code = %d, loc = %q, want 301 to /remote.php/dav/", rec.Code, rec.Header().Get("Location"))
	}

	req = httptest.NewRequest("GET", "/.well-known/change-password", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/settings/user/security" {
		t.Errorf("GET /.well-known/change-password code = %d, loc = %q, want 303 to /settings/user/security", rec.Code, rec.Header().Get("Location"))
	}

	req = httptest.NewRequest("GET", "/.well-known/security.txt", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "hackerone.com/nextcloud") {
		t.Errorf("GET /.well-known/security.txt code = %d, body = %s", rec.Code, rec.Body.String())
	}

	// 8. Login Flow v2
	req = httptest.NewRequest("POST", "/index.php/login/v2", nil)
	req.Host = "cloud.example.com"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("POST /index.php/login/v2 code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"endpoint":"https://cloud.example.com/login/v2/poll"`) {
		t.Errorf("POST /index.php/login/v2 body missing poll endpoint: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"login":"https://cloud.example.com/login/v2/flow/`) {
		t.Errorf("POST /index.php/login/v2 body missing flow URL: %s", rec.Body.String())
	}

	req = httptest.NewRequest("POST", "/index.php/login/v2/poll", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("POST /index.php/login/v2/poll code = %d, body = %s, want 404 []", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest("GET", "/index.php/login/flow", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "initial-state-core-loginUsername") {
		t.Errorf("GET /index.php/login/flow code = %d, want 200", rec.Code)
	}

	// 9. OCS endpoints & capabilities
	req = httptest.NewRequest("GET", "/ocs/v2.php/cloud/capabilities", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusPreconditionFailed {
		t.Errorf("GET /ocs/v2.php/cloud/capabilities without OCS header code = %d, want 412", rec.Code)
	}

	// Capabilities with OCS header (XML)
	req = httptest.NewRequest("GET", "/ocs/v2.php/cloud/capabilities", nil)
	req.Header.Set("OCS-APIRequest", "true")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<theming>") {
		t.Errorf("GET /ocs/v2.php/cloud/capabilities XML failed: %d, body = %s", rec.Code, rec.Body.String())
	}

	// Capabilities with OCS header (JSON)
	req = httptest.NewRequest("GET", "/ocs/v2.php/cloud/capabilities?format=json", nil)
	req.Header.Set("OCS-APIRequest", "true")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"statuscode":200`) {
		t.Errorf("GET /ocs/v2.php/cloud/capabilities?format=json failed: %d, body = %s", rec.Code, rec.Body.String())
	}

	// Capabilities v1 with OCS header (JSON)
	req = httptest.NewRequest("GET", "/ocs/v1.php/cloud/capabilities?format=json", nil)
	req.Header.Set("OCS-APIRequest", "true")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"statuscode":100`) {
		t.Errorf("GET /ocs/v1.php/cloud/capabilities?format=json failed: %d, body = %s", rec.Code, rec.Body.String())
	}

	// OCS getapppassword probe (JSON)
	req = httptest.NewRequest("GET", "/ocs/v2.php/core/getapppassword?format=json", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"statuscode":997`) {
		t.Errorf("GET /ocs/v2.php/core/getapppassword?format=json code = %d, body = %s", rec.Code, rec.Body.String())
	}

	// 10. Dynamic instance ID & cookies
	req1 := httptest.NewRequest("GET", "/login", nil)
	req1.Host = "host1.example.com"
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)
	var instanceID1 string
	for _, c := range rec1.Result().Cookies() {
		if strings.HasPrefix(c.Name, "oc") && len(c.Name) == 12 && c.Name != "oc_sessionPassphrase" {
			instanceID1 = c.Name
		}
	}
	if instanceID1 == "" || instanceID1 == "ocouaube3hh1" {
		t.Errorf("expected dynamic instance ID cookie for host1, got %q", instanceID1)
	}

	// Repeated request to host1 gets same cookie name
	req1Repeat := httptest.NewRequest("GET", "/login", nil)
	req1Repeat.Host = "host1.example.com"
	rec1Repeat := httptest.NewRecorder()
	h.ServeHTTP(rec1Repeat, req1Repeat)
	var instanceID1Repeat string
	for _, c := range rec1Repeat.Result().Cookies() {
		if strings.HasPrefix(c.Name, "oc") && len(c.Name) == 12 && c.Name != "oc_sessionPassphrase" {
			instanceID1Repeat = c.Name
		}
	}
	if instanceID1Repeat != instanceID1 {
		t.Errorf("instance ID cookie not consistent on same host: %q vs %q", instanceID1Repeat, instanceID1)
	}

	// Request to host2 gets different cookie name
	req2 := httptest.NewRequest("GET", "/login", nil)
	req2.Host = "host2.example.com"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	var instanceID2 string
	for _, c := range rec2.Result().Cookies() {
		if strings.HasPrefix(c.Name, "oc") && len(c.Name) == 12 && c.Name != "oc_sessionPassphrase" {
			instanceID2 = c.Name
		}
	}
	if instanceID2 == "" || instanceID2 == instanceID1 {
		t.Errorf("expected different instance ID cookie for host2, got %q (host1 had %q)", instanceID2, instanceID1)
	}

	// 11. Static assets & caching (with and without ?v=, and newly bundled files)
	req = httptest.NewRequest("GET", "/dist/core-common.js?v=bc8081c2-0", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /dist/core-common.js?v=... code = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "max-age=15778463, immutable" {
		t.Errorf("GET /dist/core-common.js?v=... Cache-Control = %q, want 'max-age=15778463, immutable'", rec.Header().Get("Cache-Control"))
	}

	req = httptest.NewRequest("GET", "/dist/core-common.js", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /dist/core-common.js code = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "max-age=15778463" {
		t.Errorf("GET /dist/core-common.js Cache-Control = %q, want 'max-age=15778463'", rec.Header().Get("Cache-Control"))
	}

	// Newly bundled static assets
	newAssets := []struct {
		path  string
		ctype string
	}{
		{"/apps/theming/img/background/jo-myoung-hee-fluid-dark.webp", "image/webp"},
		{"/apps/theming/fonts/OpenDyslexic-Regular.otf", "font/otf"},
		{"/apps/theming/fonts/OpenDyslexic-Bold.otf", "font/otf"},
		{"/core/img/actions/confirm.svg", "image/svg+xml"},
		{"/core/img/loading-dark.gif", "image/gif"},
	}
	for _, na := range newAssets {
		req = httptest.NewRequest("GET", na.path, nil)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s code = %d, want 200", na.path, rec.Code)
		}
		if rec.Header().Get("Content-Type") != na.ctype {
			t.Errorf("GET %s Content-Type = %q, want %q", na.path, rec.Header().Get("Content-Type"), na.ctype)
		}
	}

	// 12. 204 Ping probe
	req = httptest.NewRequest("GET", "/index.php/204", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("GET /index.php/204 code = %d, want 204", rec.Code)
	}
	if rec.Header().Get("X-Powered-By") != "PHP/8.5.10" {
		t.Errorf("GET /index.php/204 missing X-Powered-By: PHP/8.5.10")
	}

	// 13. Webcron probe
	req = httptest.NewRequest("GET", "/cron.php", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"success"`) {
		t.Errorf("GET /cron.php failed: %s", rec.Body.String())
	}

	// 14. Robots.txt
	req = httptest.NewRequest("GET", "/robots.txt", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "User-agent: *") {
		t.Errorf("GET /robots.txt failed: %s", rec.Body.String())
	}

	// 15. Catch-all Nextcloud 404 (styled HTML page, not Apache raw error)
	req = httptest.NewRequest("GET", "/some/random/nonexistent/path", nil)
	req.Host = "nextcloud.example.com"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /some/random/nonexistent/path code = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Page not found") {
		t.Errorf("GET /some/random/nonexistent/path body missing Nextcloud 'Page not found'")
	}
	if !strings.Contains(rec.Body.String(), "Back to Nextcloud") {
		t.Errorf("GET /some/random/nonexistent/path body missing 'Back to Nextcloud'")
	}
	if rec.Header().Get("Server") != "Apache/2.4.68 (Debian)" {
		t.Errorf("GET /some/random/nonexistent/path Server = %q, want Apache/2.4.68 (Debian)", rec.Header().Get("Server"))
	}
	if rec.Header().Get("X-Powered-By") != "PHP/8.5.10" {
		t.Errorf("GET /some/random/nonexistent/path X-Powered-By = %q, want PHP/8.5.10", rec.Header().Get("X-Powered-By"))
	}
}

func TestSeafileHandler(t *testing.T) {
	if !Enabled {
		t.Skip("Skin feature is disabled in slim build")
	}
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
	if rec.Header().Get("Location") != "/accounts/login/?next=/" {
		t.Errorf("GET / Location = %q, want '/accounts/login/?next=/'", rec.Header().Get("Location"))
	}

	// 1b. GET /?next=/repo/123 encodes query string into next
	req = httptest.NewRequest("GET", "/?next=/repo/123", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("GET /?next=/repo/123 code = %d, want 302", rec.Code)
	}
	if rec.Header().Get("Location") != "/accounts/login/?next=/%3Fnext%3D/repo/123" {
		t.Errorf("GET /?next=/repo/123 Location = %q, want '/accounts/login/?next=/%%3Fnext%%3D/repo/123'", rec.Header().Get("Location"))
	}

	// 1c. POST / without CSRF returns 403 Forbidden with Django CSRF error page
	req = httptest.NewRequest("POST", "/", strings.NewReader("foo=bar"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST / without CSRF code = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "CSRF verification failed") {
		t.Errorf("POST / without CSRF missing CSRF verification failed message")
	}

	// 2. GET /api2/ping/ & OPTIONS /api2/ping/
	req = httptest.NewRequest("GET", "/api2/ping/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "pong") {
		t.Errorf("GET /api2/ping/ = %q, want 'pong'", rec.Body.String())
	}
	if rec.Header().Get("Allow") != "GET, HEAD, OPTIONS" {
		t.Errorf("GET /api2/ping/ Allow = %q, want 'GET, HEAD, OPTIONS'", rec.Header().Get("Allow"))
	}

	req = httptest.NewRequest("OPTIONS", "/api2/ping/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"name":"Ping"`) {
		t.Errorf("OPTIONS /api2/ping/ code = %d, body = %s", rec.Code, rec.Body.String())
	}

	// 2b. Django APPEND_SLASH: GET /api2/ping -> 301 to /api2/ping/
	req = httptest.NewRequest("GET", "/api2/ping", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently {
		t.Errorf("GET /api2/ping code = %d, want 301", rec.Code)
	}
	if rec.Header().Get("Location") != "/api2/ping/" {
		t.Errorf("GET /api2/ping Location = %q, want '/api2/ping/'", rec.Header().Get("Location"))
	}
	if rec.Header().Get("Server") != "nginx" {
		t.Errorf("GET /api2/ping Server = %q, want 'nginx'", rec.Header().Get("Server"))
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

	// 3b. /seafhttp/ unknown endpoints (including fake ping probe) return 404 with empty body
	req = httptest.NewRequest("GET", "/seafhttp/ping", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /seafhttp/ping code = %d, want 404", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("GET /seafhttp/ping should have 0 bytes body, got %d bytes: %q", rec.Body.Len(), rec.Body.String())
	}
	if rec.Header().Get("Server") != "nginx" {
		t.Errorf("GET /seafhttp/ping Server = %q, want 'nginx'", rec.Header().Get("Server"))
	}

	// 4. Modern /api/v2.1/ endpoints
	req = httptest.NewRequest("GET", "/api/v2.1/repos/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("GET /api/v2.1/repos/ code = %d, want 403", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("GET /api/v2.1/repos/ Content-Type = %q, want 'application/json'", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "Authentication credentials were not provided") {
		t.Errorf("GET /api/v2.1/repos/ body = %q", rec.Body.String())
	}

	req = httptest.NewRequest("GET", "/api/v2.1/repos", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/api/v2.1/repos/" {
		t.Errorf("GET /api/v2.1/repos unslashed code = %d, Location = %q", rec.Code, rec.Header().Get("Location"))
	}

	// 5. GET /accounts/login/ (dynamic CSRF & Cookies)
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

	// 6. POST /accounts/login/
	// 6a. Without CSRF -> 403 Forbidden with Django CSRF error page
	formDataNoCSRF := url.Values{
		"login":    {"user@example.com"},
		"password": {"badpass"},
	}
	req = httptest.NewRequest("POST", "/accounts/login/", strings.NewReader(formDataNoCSRF.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST /accounts/login/ without CSRF code = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<title>403 Forbidden</title>") || !strings.Contains(rec.Body.String(), "CSRF verification failed") {
		t.Errorf("POST /accounts/login/ without CSRF body missing Django CSRF failure message")
	}

	// 6b. With valid CSRF -> 200 OK with Incorrect email or password, value="" kept empty, sfcsrftoken rotated, no sessionid
	formDataWithCSRF := url.Values{
		"csrfmiddlewaretoken": {m1[1]},
		"login":               {"user@example.com"},
		"password":            {"badpass"},
	}
	req = httptest.NewRequest("POST", "/accounts/login/", strings.NewReader(formDataWithCSRF.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sfcsrftoken", Value: csrfCookie.Value})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("POST /accounts/login/ with CSRF code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Incorrect email or password") {
		t.Errorf("POST /accounts/login/ should display error notice")
	}
	if strings.Contains(rec.Body.String(), `value="user@example.com"`) {
		t.Errorf("POST /accounts/login/ should NOT reflect submitted username into value")
	}
	// Check cookies: sfcsrftoken rotated, sessionid NOT present on failure
	var postCSRF, postSession *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sfcsrftoken" {
			postCSRF = c
		} else if c.Name == "sessionid" {
			postSession = c
		}
	}
	if postCSRF == nil || len(postCSRF.Value) != 32 {
		t.Errorf("POST /accounts/login/ missing rotated sfcsrftoken cookie")
	}
	if postSession != nil {
		t.Errorf("POST /accounts/login/ should NOT set sessionid cookie on authentication failure")
	}

	// 7. API2 auth-token: OPTIONS, empty body POST, valid credentials POST, GET 405
	req = httptest.NewRequest("OPTIONS", "/api2/auth-token/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"name":"Obtain Auth Token"`) {
		t.Errorf("OPTIONS /api2/auth-token/ code = %d, body = %s", rec.Code, rec.Body.String())
	}

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

	// Empty body -> returns required field errors
	req = httptest.NewRequest("POST", "/api2/auth-token/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /api2/auth-token/ code = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"username":["This field is required."]`) || !strings.Contains(rec.Body.String(), `"password":["This field is required."]`) {
		t.Errorf("POST /api2/auth-token/ empty body = %q", rec.Body.String())
	}

	// Provided credentials -> returns non_field_errors
	tokenForm := url.Values{"username": {"user@example.com"}, "password": {"badpass"}}
	req = httptest.NewRequest("POST", "/api2/auth-token/", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /api2/auth-token/ with creds code = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Unable to login with provided credentials") {
		t.Errorf("POST /api2/auth-token/ body = %q", rec.Body.String())
	}

	// 8. API2 protected endpoints (403 Forbidden with proper Allow; unauthenticated OPTIONS is also 403)
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

	req = httptest.NewRequest("OPTIONS", "/api2/account/info/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("OPTIONS /api2/account/info/ code = %d, want 403", rec.Code)
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

	// 9. Password Reset: /accounts/password/reset/
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

	// POST /accounts/password/reset/ without CSRF -> 403
	req = httptest.NewRequest("POST", "/accounts/password/reset/", strings.NewReader("email=admin@example.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST /accounts/password/reset/ without CSRF code = %d, want 403", rec.Code)
	}

	// 10. Language Switch: /i18n/?lang=zh-cn
	// Without Referer -> redirects to /
	req = httptest.NewRequest("GET", "/i18n/?lang=zh-cn", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("GET /i18n/?lang=zh-cn code = %d, want 302", rec.Code)
	}
	if rec.Header().Get("Location") != "/" {
		t.Errorf("GET /i18n/?lang=zh-cn Location = %q, want '/'", rec.Header().Get("Location"))
	}

	// With Referer -> redirects to Referer
	req = httptest.NewRequest("GET", "/i18n/?lang=zh-cn", nil)
	req.Header.Set("Referer", "http://example.com/accounts/login/")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "http://example.com/accounts/login/" {
		t.Errorf("GET /i18n/?lang=zh-cn with Referer code = %d, Location = %q", rec.Code, rec.Header().Get("Location"))
	}

	// GET /i18n unslashed -> 301 to /i18n/
	req = httptest.NewRequest("GET", "/i18n", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/i18n/" {
		t.Errorf("GET /i18n code = %d, Location = %q, want 301 /i18n/", rec.Code, rec.Header().Get("Location"))
	}

	// 11. Global 404 fallback
	req = httptest.NewRequest("GET", "/some-random-unknown-path", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /some-random-unknown-path code = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Private Seafile") || !strings.Contains(rec.Body.String(), "could not be found") {
		t.Errorf("GET /some-random-unknown-path did not return Seafile branded 404 HTML")
	}

	// 12. Media requests: directory returns 403, nonexistent returns 404
	req = httptest.NewRequest("GET", "/media/css/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("GET /media/css/ code = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<center><h1>403 Forbidden</h1></center>") {
		t.Errorf("GET /media/css/ did not return Nginx 403 HTML")
	}

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

	// 13. Double-slash request /media//css/seafile-ui.css (line 17 of 404.html) must serve 200 OK directly
	req = httptest.NewRequest("GET", "/media//css/seafile-ui.css", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /media//css/seafile-ui.css code = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "text/css" {
		t.Errorf("GET /media//css/seafile-ui.css Content-Type = %q, want 'text/css'", rec.Header().Get("Content-Type"))
	}

	// 14. Static CSS headers: text/css without charset, ETag, Last-Modified, no X-Frame-Options
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

	// 15. Newly extracted static assets from seafile image: bg.png, grippy_large.png, ui-icons_444444_256x240.png
	extraAssets := []struct {
		urlPath string
		ctype   string
	}{
		{"/media/img/bg.png", "image/png"},
		{"/media/img/grippy_large.png", "image/png"},
		{"/media/img/ui-icons_444444_256x240.png", "image/png"},
	}
	for _, ea := range extraAssets {
		req = httptest.NewRequest("GET", ea.urlPath, nil)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s code = %d, want 200", ea.urlPath, rec.Code)
		}
		if rec.Header().Get("Content-Type") != ea.ctype {
			t.Errorf("GET %s Content-Type = %q, want %q", ea.urlPath, rec.Header().Get("Content-Type"), ea.ctype)
		}
	}
}

func TestStartMultiSkinServer(t *testing.T) {
	if !Enabled {
		t.Skip("Skin feature is disabled in slim build")
	}
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
	req = httptest.NewRequest("GET", "/health", nil)
	req.Host = "fb.example.com"
	rec = httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `{"status":"OK"}`) {
		t.Errorf("fb.example.com /health failed: %s", rec.Body.String())
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

func generateTestCert(domain string) (string, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{domain},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	certBuf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	keyBuf := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	return string(certBuf), string(keyBuf), nil
}

func TestStartMultiSkinServerWithInlineCert(t *testing.T) {
	if !Enabled {
		t.Skip("Skin feature is disabled in slim build")
	}
	certPEM, keyPEM, err := generateTestCert("example.com")
	if err != nil {
		t.Fatalf("generateTestCert failed: %v", err)
	}

	mappings := []DomainSkinMapping{
		{
			Domain:   "example.com",
			SkinType: config.SkinNextcloud,
			CertPEM:  certPEM,
			KeyPEM:   keyPEM,
		},
	}

	srv, err := StartMultiSkinServer("127.0.0.1:0", mappings, config.SkinNextcloud)
	if err != nil {
		t.Fatalf("StartMultiSkinServer failed: %v", err)
	}

	if srv.TLSConfig == nil || srv.TLSConfig.GetCertificate == nil {
		t.Fatalf("expected TLSConfig.GetCertificate to be set")
	}

	// 1. SNI match
	cert, err := srv.TLSConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil || cert == nil {
		t.Errorf("GetCertificate for example.com failed: %v", err)
	}

	// 2. Fallback for 127.0.0.1 / localhost / empty
	for _, sni := range []string{"", "127.0.0.1", "localhost"} {
		cert, err = srv.TLSConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
		if err != nil || cert == nil {
			t.Errorf("GetCertificate for %q failed: %v", sni, err)
		}
	}

	// 3. HTTP Request with Host: 127.0.0.1:9443 routes to firstHandler
	req := httptest.NewRequest("GET", "/status.php", nil)
	req.Host = "127.0.0.1:9443"
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Nextcloud") {
		t.Errorf("127.0.0.1:9443 /status.php failed: %d, body: %s", rec.Code, rec.Body.String())
	}
}

func TestStartMultiSkinH3Server(t *testing.T) {
	if !Enabled {
		t.Skip("Skin feature is disabled in slim build")
	}

	certPEM, keyPEM, _, err := config.GenerateSelfSignedCert("h3.example.com")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert error: %v", err)
	}

	mappings := []DomainSkinMapping{
		{
			Domain:   "h3.example.com",
			SkinType: config.SkinNextcloud,
			CertPEM:  certPEM,
			KeyPEM:   keyPEM,
		},
	}

	h3Srv, err := StartMultiSkinH3Server("127.0.0.1:9443", mappings, config.SkinNextcloud)
	if err != nil {
		t.Fatalf("StartMultiSkinH3Server error: %v", err)
	}
	defer h3Srv.Close()

	if h3Srv.TLSConfig == nil {
		t.Fatal("expected non-nil TLSConfig on H3 server")
	}

	req := httptest.NewRequest("GET", "/status.php", nil)
	req.Host = "h3.example.com"
	rec := httptest.NewRecorder()
	h3Srv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Nextcloud") {
		t.Errorf("H3 handler /status.php failed: %d, body: %s", rec.Code, rec.Body.String())
	}

	// Verify Alt-Svc header is not forced and Server header is authentic
	if srvHdr := rec.Header().Get("Server"); srvHdr != "Apache/2.4.68 (Debian)" {
		t.Errorf("Server header = %q, want Apache/2.4.68 (Debian)", srvHdr)
	}
	if altSvc := rec.Header().Get("Alt-Svc"); altSvc != "" {
		t.Errorf("Alt-Svc header should not be forced, got %q", altSvc)
	}
	// Nextcloud authentic PHP header must not be stripped
	if xpb := rec.Header().Get("X-Powered-By"); xpb != "PHP/8.5.10" {
		t.Errorf("Nextcloud X-Powered-By = %q, want PHP/8.5.10", xpb)
	}

	// For loopback IP requests, verify handler serves correctly without forced Alt-Svc
	reqLoopback := httptest.NewRequest("GET", "/status.php", nil)
	reqLoopback.Host = "127.0.0.1"
	recLoopback := httptest.NewRecorder()
	h3Srv.Handler.ServeHTTP(recLoopback, reqLoopback)
	if altSvc := recLoopback.Header().Get("Alt-Svc"); altSvc != "" {
		t.Errorf("Alt-Svc header for loopback should not be forced, got %q", altSvc)
	}
}

func TestNativeHTTP3ClientRealConn(t *testing.T) {
	if !Enabled {
		t.Skip("Skin feature is disabled in slim build")
	}

	certPEM, keyPEM, _, err := config.GenerateSelfSignedCert("nc-h3.example.com")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert error: %v", err)
	}

	mappings := []DomainSkinMapping{
		{
			Domain:   "nc-h3.example.com",
			SkinType: config.SkinNextcloud,
			CertPEM:  certPEM,
			KeyPEM:   keyPEM,
		},
		{
			Domain:   "sea-h3.example.com",
			SkinType: config.SkinSeafile,
			CertPEM:  certPEM,
			KeyPEM:   keyPEM,
		},
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP error: %v", err)
	}
	defer udpConn.Close()

	addr := udpConn.LocalAddr().String()
	h3Srv, err := StartMultiSkinH3Server(addr, mappings, config.SkinNextcloud)
	if err != nil {
		t.Fatalf("StartMultiSkinH3Server error: %v", err)
	}
	defer h3Srv.Close()

	go func() {
		_ = h3Srv.Serve(udpConn)
	}()

	client := &http.Client{
		Transport: &http3.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "nc-h3.example.com",
			},
		},
		Timeout: 5 * time.Second,
	}

	// 1. Nextcloud over native HTTP/3
	req, err := http.NewRequestWithContext(context.Background(), "GET", fmt.Sprintf("https://%s/status.php", addr), nil)
	if err != nil {
		t.Fatalf("NewRequest error: %v", err)
	}
	req.Host = "nc-h3.example.com"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do over HTTP/3 failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.Proto != "HTTP/3.0" {
		t.Errorf("resp.Proto = %q, want HTTP/3.0", resp.Proto)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("resp.StatusCode = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Nextcloud") {
		t.Errorf("unexpected body over HTTP/3: %s", string(body))
	}
	if srv := resp.Header.Get("Server"); srv != "Apache/2.4.68 (Debian)" {
		t.Errorf("Server header = %q, want Apache/2.4.68 (Debian)", srv)
	}
	if xpb := resp.Header.Get("X-Powered-By"); xpb != "PHP/8.5.10" {
		t.Errorf("X-Powered-By over HTTP/3 = %q, want PHP/8.5.10", xpb)
	}

	// 2. Seafile over native HTTP/3
	clientSea := &http.Client{
		Transport: &http3.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "sea-h3.example.com",
			},
		},
		Timeout: 5 * time.Second,
	}
	reqSea, err := http.NewRequestWithContext(context.Background(), "GET", fmt.Sprintf("https://%s/api2/ping/", addr), nil)
	if err != nil {
		t.Fatalf("NewRequest error: %v", err)
	}
	reqSea.Host = "sea-h3.example.com"

	respSea, err := clientSea.Do(reqSea)
	if err != nil {
		t.Fatalf("clientSea.Do over HTTP/3 failed: %v", err)
	}
	defer respSea.Body.Close()

	if respSea.StatusCode != http.StatusOK {
		t.Errorf("Seafile StatusCode = %d, want 200", respSea.StatusCode)
	}
	bodySea, _ := io.ReadAll(respSea.Body)
	if !strings.Contains(string(bodySea), "pong") {
		t.Errorf("unexpected Seafile body over HTTP/3: %s", string(bodySea))
	}
	if srv := respSea.Header.Get("Server"); srv != "nginx" {
		t.Errorf("Server header for Seafile = %q, want nginx", srv)
	}
}

func TestGoFingerprintMasking(t *testing.T) {
	if !Enabled {
		t.Skip("Skin feature is disabled in slim build")
	}

	// 1. User-Agent with Go-http-client is stripped
	var receivedUA string
	handler := hideGoClientFingerprint(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Go-http-client/1.1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if receivedUA != "" {
		t.Errorf("expected User-Agent to be stripped, got %q", receivedUA)
	}

	// 2. sanitizingResponseWriter removes Go fingerprints but preserves authentic PHP headers
	dummyGo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Go/1.25.0")
		w.Header().Set("Server", "Go-http-client")
		w.Header().Set("X-Custom-Client", "Go-http-client/1.1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	rec = httptest.NewRecorder()
	reqLoop := httptest.NewRequest("GET", "/", nil)
	reqLoop.Host = "127.0.0.1"
	sw := &sanitizingResponseWriter{ResponseWriter: rec, req: reqLoop, skinType: config.SkinSeafile, port: 8443}
	dummyGo.ServeHTTP(sw, reqLoop)

	if xpb := rec.Header().Get("X-Powered-By"); xpb != "" {
		t.Errorf("Go X-Powered-By not stripped: %q", xpb)
	}
	if xcc := rec.Header().Get("X-Custom-Client"); xcc != "" {
		t.Errorf("Header with Go-http-client value not stripped: %q", xcc)
	}
	if srv := rec.Header().Get("Server"); srv != "nginx" {
		t.Errorf("Server header = %q, want nginx", srv)
	}
	if altSvc := rec.Header().Get("Alt-Svc"); altSvc != "" {
		t.Errorf("Alt-Svc header should not be forced, got %q", altSvc)
	}

	// Verify authentic PHP X-Powered-By is preserved for Nextcloud
	dummyPHP := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.WriteHeader(http.StatusOK)
	})
	recPHP := httptest.NewRecorder()
	reqDomain := httptest.NewRequest("GET", "/", nil)
	reqDomain.Host = "cloud.example.com"
	swPHP := &sanitizingResponseWriter{ResponseWriter: recPHP, req: reqDomain, skinType: config.SkinNextcloud, port: 8443}
	dummyPHP.ServeHTTP(swPHP, reqDomain)

	if xpb := recPHP.Header().Get("X-Powered-By"); xpb != "PHP/8.5.10" {
		t.Errorf("Authentic PHP X-Powered-By unexpectedly stripped: %q", xpb)
	}
	if srv := recPHP.Header().Get("Server"); srv != "Apache/2.4.68 (Debian)" {
		t.Errorf("Server header = %q, want Apache/2.4.68 (Debian)", srv)
	}
	if altSvc := recPHP.Header().Get("Alt-Svc"); altSvc != "" {
		t.Errorf("Alt-Svc for domain should not be forced, got %q", altSvc)
	}

	// 3. Panic recovery does not leak Go stack trace and outputs skin-specific 500 error
	panickingNextcloud := disguiseRecovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("critical internal runtime error at pointer 0xdeadbeef")
	}), func(r *http.Request) string { return config.SkinNextcloud })

	rec = httptest.NewRecorder()
	panickingNextcloud.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("code = %d, want 500", rec.Code)
	}
	if srv := rec.Header().Get("Server"); srv != "Apache/2.4.68 (Debian)" {
		t.Errorf("Server header = %q, want Apache/2.4.68 (Debian)", srv)
	}
	if strings.Contains(rec.Body.String(), "panic") || strings.Contains(rec.Body.String(), "0xdeadbeef") || strings.Contains(rec.Body.String(), ".go:") {
		t.Errorf("Go stack trace or panic leaked to client: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "The server encountered an internal error") {
		t.Errorf("Body missing Apache 500 text: %s", rec.Body.String())
	}

	// Panic recovery for Seafile outputs Nginx 500
	panickingSeafile := disguiseRecovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("seafile internal error")
	}), func(r *http.Request) string { return config.SkinSeafile })

	recSea := httptest.NewRecorder()
	panickingSeafile.ServeHTTP(recSea, req)
	if recSea.Code != http.StatusInternalServerError {
		t.Errorf("Seafile panic code = %d, want 500", recSea.Code)
	}
	if srv := recSea.Header().Get("Server"); srv != "nginx" {
		t.Errorf("Seafile panic Server header = %q, want nginx", srv)
	}
}

func TestSkinDisabledInSlim(t *testing.T) {
	if Enabled {
		t.Skip("Only tested in slim build")
	}

	_, err := NewHandler(config.SkinFilebrowser)
	if !errors.Is(err, ErrSkinDisabled) {
		t.Errorf("expected ErrSkinDisabled from NewHandler, got %v", err)
	}

	_, err = StartSkinServer("127.0.0.1:0", config.SkinFilebrowser, "", "")
	if !errors.Is(err, ErrSkinDisabled) {
		t.Errorf("expected ErrSkinDisabled from StartSkinServer, got %v", err)
	}

	_, err = StartMultiSkinServer("127.0.0.1:0", nil, "")
	if !errors.Is(err, ErrSkinDisabled) {
		t.Errorf("expected ErrSkinDisabled from StartMultiSkinServer, got %v", err)
	}

	_, err = StartSkinH3Server("127.0.0.1:0", config.SkinFilebrowser, "", "")
	if !errors.Is(err, ErrSkinDisabled) {
		t.Errorf("expected ErrSkinDisabled from StartSkinH3Server, got %v", err)
	}

	_, err = StartMultiSkinH3Server("127.0.0.1:0", nil, "")
	if !errors.Is(err, ErrSkinDisabled) {
		t.Errorf("expected ErrSkinDisabled from StartMultiSkinH3Server, got %v", err)
	}
}

func TestSkinServerHTTPTimeouts(t *testing.T) {
	if !Enabled {
		t.Skip("Only tested in full build")
	}

	srv, err := StartSkinServer("127.0.0.1:0", config.SkinNextcloud, "", "")
	if err != nil {
		t.Fatalf("StartSkinServer error: %v", err)
	}
	if srv.ReadHeaderTimeout != 20*time.Second {
		t.Errorf("StartSkinServer ReadHeaderTimeout = %v, want 20s", srv.ReadHeaderTimeout)
	}
	if srv.IdleTimeout != 60*time.Second {
		t.Errorf("StartSkinServer IdleTimeout = %v, want 60s", srv.IdleTimeout)
	}
	if srv.WriteTimeout != 0 {
		t.Errorf("StartSkinServer WriteTimeout = %v, want 0", srv.WriteTimeout)
	}

	multiSrv, err := StartMultiSkinServer("127.0.0.1:0", nil, config.SkinNextcloud)
	if err != nil {
		t.Fatalf("StartMultiSkinServer error: %v", err)
	}
	if multiSrv.ReadHeaderTimeout != 20*time.Second {
		t.Errorf("StartMultiSkinServer ReadHeaderTimeout = %v, want 20s", multiSrv.ReadHeaderTimeout)
	}
	if multiSrv.IdleTimeout != 60*time.Second {
		t.Errorf("StartMultiSkinServer IdleTimeout = %v, want 60s", multiSrv.IdleTimeout)
	}
	if multiSrv.WriteTimeout != 0 {
		t.Errorf("StartMultiSkinServer WriteTimeout = %v, want 0", multiSrv.WriteTimeout)
	}
}

func TestStaticStreamingAnd416RangeRewriting(t *testing.T) {
	if !Enabled {
		t.Skip("Only tested in full build")
	}

	positiveHexRegex := regexp.MustCompile(`^"[0-9a-f]+-[0-9a-f]+"$$`)

	// 1. Nextcloud
	ncSrv, err := StartSkinServer("127.0.0.1:0", config.SkinNextcloud, "", "")
	if err != nil {
		t.Fatalf("StartSkinServer(nextcloud) error: %v", err)
	}

	// 1a. Normal GET
	req := httptest.NewRequest("GET", "/dist/core-common.js", nil)
	req.Host = "cloud.example.com"
	rec := httptest.NewRecorder()
	ncSrv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Nextcloud GET /dist/core-common.js code = %d, want 200", rec.Code)
	}
	etag := rec.Header().Get("ETag")
	if !positiveHexRegex.MatchString(etag) {
		t.Errorf("Nextcloud ETag %q does not match positive hex regex %s", etag, positiveHexRegex.String())
	}
	if rec.Header().Get("Last-Modified") != "Fri, 04 Sep 2026 05:12:32 GMT" {
		t.Errorf("Nextcloud Last-Modified = %q, want 'Fri, 04 Sep 2026 05:12:32 GMT'", rec.Header().Get("Last-Modified"))
	}
	if rec.Header().Get("Accept-Ranges") != "bytes" {
		t.Errorf("Nextcloud Accept-Ranges = %q, want 'bytes'", rec.Header().Get("Accept-Ranges"))
	}

	// 1b. Range request (Partial Content)
	reqRange := httptest.NewRequest("GET", "/dist/core-common.js", nil)
	reqRange.Host = "cloud.example.com"
	reqRange.Header.Set("Range", "bytes=0-15")
	recRange := httptest.NewRecorder()
	ncSrv.Handler.ServeHTTP(recRange, reqRange)
	if recRange.Code != http.StatusPartialContent {
		t.Fatalf("Nextcloud Range request code = %d, want 206", recRange.Code)
	}
	if !strings.HasPrefix(recRange.Header().Get("Content-Range"), "bytes 0-15/") {
		t.Errorf("Nextcloud Content-Range = %q, want 'bytes 0-15/...'", recRange.Header().Get("Content-Range"))
	}
	if recRange.Body.Len() != 16 {
		t.Errorf("Nextcloud Range body length = %d, want 16", recRange.Body.Len())
	}

	// 1c. Unsatisfiable range request (HTTP 416)
	reqInvalid := httptest.NewRequest("GET", "/dist/core-common.js", nil)
	reqInvalid.Host = "cloud.example.com"
	reqInvalid.Header.Set("Range", "bytes=99999999-99999999")
	recInvalid := httptest.NewRecorder()
	ncSrv.Handler.ServeHTTP(recInvalid, reqInvalid)
	if recInvalid.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("Nextcloud invalid range code = %d, want 416", recInvalid.Code)
	}
	body416 := recInvalid.Body.String()
	if strings.Contains(body416, "failed to overlap") {
		t.Errorf("Nextcloud leaked Go signature: %q", body416)
	}
	if !strings.Contains(body416, "<title>416 Range Not Satisfiable</title>") {
		t.Errorf("Nextcloud 416 body missing Apache title, got: %s", body416)
	}
	if !strings.Contains(body416, "Apache/2.4.68 (Debian) Server at cloud.example.com Port 443") {
		t.Errorf("Nextcloud 416 body missing Apache server footer, got: %s", body416)
	}
	if recInvalid.Header().Get("Server") != "Apache/2.4.68 (Debian)" {
		t.Errorf("Nextcloud 416 Server header = %q, want Apache/2.4.68 (Debian)", recInvalid.Header().Get("Server"))
	}
	if !strings.HasPrefix(recInvalid.Header().Get("Content-Type"), "text/html") {
		t.Errorf("Nextcloud 416 Content-Type = %q, want text/html...", recInvalid.Header().Get("Content-Type"))
	}

	// 1d. HEAD with unsatisfiable range (HTTP 416)
	reqHead := httptest.NewRequest("HEAD", "/dist/core-common.js", nil)
	reqHead.Host = "cloud.example.com"
	reqHead.Header.Set("Range", "bytes=99999999-99999999")
	recHead := httptest.NewRecorder()
	ncSrv.Handler.ServeHTTP(recHead, reqHead)
	if recHead.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("Nextcloud HEAD invalid range code = %d, want 416", recHead.Code)
	}
	if recHead.Body.Len() != 0 {
		t.Errorf("Nextcloud HEAD 416 body should be empty, got length %d", recHead.Body.Len())
	}
	if recHead.Header().Get("Content-Length") != strconv.Itoa(len(body416)) {
		t.Errorf("Nextcloud HEAD Content-Length = %q, want %d", recHead.Header().Get("Content-Length"), len(body416))
	}

	// 2. Seafile
	seaSrv, err := StartSkinServer("127.0.0.1:0", config.SkinSeafile, "", "")
	if err != nil {
		t.Fatalf("StartSkinServer(seafile) error: %v", err)
	}
	reqSea := httptest.NewRequest("GET", "/media/css/seafile-ui.css", nil)
	recSea := httptest.NewRecorder()
	seaSrv.Handler.ServeHTTP(recSea, reqSea)
	if recSea.Code != http.StatusOK {
		t.Fatalf("Seafile GET /media/css/seafile-ui.css code = %d, want 200", recSea.Code)
	}
	seaEtag := recSea.Header().Get("ETag")
	if !positiveHexRegex.MatchString(seaEtag) {
		t.Errorf("Seafile ETag %q does not match positive hex regex", seaEtag)
	}
	if recSea.Header().Get("Accept-Ranges") != "bytes" {
		t.Errorf("Seafile Accept-Ranges = %q, want 'bytes'", recSea.Header().Get("Accept-Ranges"))
	}

	// 2b. Seafile unsatisfiable range
	reqSeaInvalid := httptest.NewRequest("GET", "/media/css/seafile-ui.css", nil)
	reqSeaInvalid.Header.Set("Range", "bytes=99999999-99999999")
	recSeaInvalid := httptest.NewRecorder()
	seaSrv.Handler.ServeHTTP(recSeaInvalid, reqSeaInvalid)
	if recSeaInvalid.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("Seafile invalid range code = %d, want 416", recSeaInvalid.Code)
	}
	bodySea416 := recSeaInvalid.Body.String()
	if strings.Contains(bodySea416, "failed to overlap") {
		t.Errorf("Seafile leaked Go signature: %q", bodySea416)
	}
	if !strings.Contains(bodySea416, "<title>416 Requested Range Not Satisfiable</title>") {
		t.Errorf("Seafile 416 body missing Nginx title, got: %s", bodySea416)
	}
	if !strings.Contains(bodySea416, "<center>nginx</center>") {
		t.Errorf("Seafile 416 body missing Nginx center tag, got: %s", bodySea416)
	}
	if recSeaInvalid.Header().Get("Server") != "nginx" {
		t.Errorf("Seafile 416 Server header = %q, want nginx", recSeaInvalid.Header().Get("Server"))
	}
	if recSeaInvalid.Header().Get("Content-Type") != "text/html" {
		t.Errorf("Seafile 416 Content-Type = %q, want text/html", recSeaInvalid.Header().Get("Content-Type"))
	}

	// 3. Filebrowser
	fbSrv, err := StartSkinServer("127.0.0.1:0", config.SkinFilebrowser, "", "")
	if err != nil {
		t.Fatalf("StartSkinServer(filebrowser) error: %v", err)
	}
	reqFb := httptest.NewRequest("GET", "/static/assets/index-BOEsmRAc.css", nil)
	recFb := httptest.NewRecorder()
	fbSrv.Handler.ServeHTTP(recFb, reqFb)
	if recFb.Code != http.StatusOK {
		t.Fatalf("Filebrowser GET static asset code = %d, want 200", recFb.Code)
	}
	fbEtag := recFb.Header().Get("ETag")
	if !positiveHexRegex.MatchString(fbEtag) {
		t.Errorf("Filebrowser ETag %q does not match positive hex regex", fbEtag)
	}

	// 3b. Filebrowser unsatisfiable range
	reqFbInvalid := httptest.NewRequest("GET", "/static/assets/index-BOEsmRAc.css", nil)
	reqFbInvalid.Header.Set("Range", "bytes=99999999-99999999")
	recFbInvalid := httptest.NewRecorder()
	fbSrv.Handler.ServeHTTP(recFbInvalid, reqFbInvalid)
	if recFbInvalid.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("Filebrowser invalid range code = %d, want 416", recFbInvalid.Code)
	}
	bodyFb416 := recFbInvalid.Body.String()
	if strings.Contains(bodyFb416, "failed to overlap") {
		t.Errorf("Filebrowser leaked Go signature: %q", bodyFb416)
	}
	if !strings.Contains(bodyFb416, "416 Requested Range Not Satisfiable") {
		t.Errorf("Filebrowser 416 body missing title, got: %s", bodyFb416)
	}
}

func TestSanitizingResponseWriterReadFrom416(t *testing.T) {
	if !Enabled {
		t.Skip("Only tested in full build")
	}

	// 1. GET with 416 written via io.Copy (ReadFrom path)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	sw := &sanitizingResponseWriter{
		ResponseWriter: rec,
		req:            req,
		skinType:       config.SkinNextcloud,
		port:           443,
	}
	sw.WriteHeader(http.StatusRequestedRangeNotSatisfiable)

	dummyData := strings.NewReader("dummy payload")
	n, err := io.Copy(sw, dummyData)
	if err != nil {
		t.Fatalf("io.Copy error: %v", err)
	}
	if n == 0 {
		t.Errorf("expected non-zero bytes written for 416 body via ReadFrom, got 0")
	}
	if !strings.Contains(rec.Body.String(), "<title>416 Range Not Satisfiable</title>") {
		t.Errorf("expected Apache 416 HTML body, got: %s", rec.Body.String())
	}

	// 2. HEAD with 416 via io.Copy (ReadFrom path) should suppress body
	recHead := httptest.NewRecorder()
	reqHead := httptest.NewRequest("HEAD", "/test", nil)
	swHead := &sanitizingResponseWriter{
		ResponseWriter: recHead,
		req:            reqHead,
		skinType:       config.SkinNextcloud,
		port:           443,
	}
	swHead.WriteHeader(http.StatusRequestedRangeNotSatisfiable)

	nHead, err := io.Copy(swHead, strings.NewReader("dummy payload"))
	if err != nil {
		t.Fatalf("io.Copy HEAD error: %v", err)
	}
	if recHead.Body.Len() != 0 {
		t.Errorf("expected 0 bytes written to recorder for HEAD 416 body, got len=%d", recHead.Body.Len())
	}
	if nHead != int64(len("dummy payload")) {
		t.Errorf("expected %d bytes consumed from reader, got %d", len("dummy payload"), nHead)
	}
}


