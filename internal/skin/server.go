package skin

import (
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"xray-proxya/internal/config"
)

//go:embed assets/*
var assetsFS embed.FS

// DelaySimulateAuth controls whether simulated password hashing delay is enabled (can be disabled in tests).
var DelaySimulateAuth = true

func simulatedHashDelay() {
	if !DelaySimulateAuth {
		return
	}
	time.Sleep(180 * time.Millisecond)
}

func simulatedLoginDelay() {
	if !DelaySimulateAuth {
		return
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(1400))
	delay := 800*time.Millisecond + time.Duration(n.Int64())*time.Millisecond
	time.Sleep(delay)
}

func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func generate32ByteBase64() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// NewHandler creates an http.Handler implementing the requested skin camouflage.
func NewHandler(skinType string) (http.Handler, error) {
	st := strings.ToLower(strings.TrimSpace(skinType))
	switch st {
	case config.SkinFilebrowser:
		return newFilebrowserHandler()
	case config.SkinNextcloud:
		return newNextcloudHandler()
	case config.SkinSeafile:
		return newSeafileHandler()
	default:
		return nil, fmt.Errorf("unknown skin type: %q", skinType)
	}
}

// StartSkinServer spins up an HTTP or HTTPS listener serving the chosen skin.
func StartSkinServer(addr string, skinType string, certFile, keyFile string) (*http.Server, error) {
	handler, err := NewHandler(skinType)
	if err != nil {
		return nil, err
	}

	server := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load skin TLS certificate: %w", err)
		}
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	return server, nil
}

// DomainSkinMapping configures a domain, skin type, and TLS certificate for multi-domain skin serving.
type DomainSkinMapping struct {
	Domain   string
	SkinType string
	CertPath string
	KeyPath  string
}

type certHolder struct {
	mu       sync.RWMutex
	certPath string
	keyPath  string
	modTime  time.Time
	cert     *tls.Certificate
}

func (ch *certHolder) getCertificate() (*tls.Certificate, error) {
	ch.mu.RLock()
	if ch.cert != nil {
		if fi, err := os.Stat(ch.certPath); err == nil && !fi.ModTime().After(ch.modTime) {
			cert := ch.cert
			ch.mu.RUnlock()
			return cert, nil
		}
	}
	ch.mu.RUnlock()

	ch.mu.Lock()
	defer ch.mu.Unlock()

	fi, err := os.Stat(ch.certPath)
	if err != nil {
		if ch.cert != nil {
			return ch.cert, nil
		}
		return nil, err
	}
	pair, err := tls.LoadX509KeyPair(ch.certPath, ch.keyPath)
	if err != nil {
		if ch.cert != nil {
			return ch.cert, nil
		}
		return nil, err
	}
	ch.cert = &pair
	ch.modTime = fi.ModTime()
	return ch.cert, nil
}

// StartMultiSkinServer spins up an HTTPS listener serving Web camouflage skins for multiple domains.
// It uses SNI in the TLS ClientHello to dynamically serve each domain's valid certificate,
// and routes incoming HTTP requests to each domain's configured skin handler.
func StartMultiSkinServer(addr string, mappings []DomainSkinMapping, defaultSkin string) (*http.Server, error) {
	handlers := make(map[string]http.Handler)
	certHolders := make(map[string]*certHolder)
	var firstHolder *certHolder
	var firstHandler http.Handler

	for _, m := range mappings {
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(m.Domain), "."))
		st := strings.ToLower(strings.TrimSpace(m.SkinType))

		if st != "" {
			h, err := NewHandler(st)
			if err != nil {
				return nil, err
			}
			if domain != "" {
				handlers[domain] = h
			}
			if firstHandler == nil {
				firstHandler = h
			}
		}

		if domain != "" && m.CertPath != "" && m.KeyPath != "" {
			holder := &certHolder{certPath: m.CertPath, keyPath: m.KeyPath}
			if _, err := holder.getCertificate(); err == nil {
				certHolders[domain] = holder
				if firstHolder == nil {
					firstHolder = holder
				}
			}
		}
	}

	if firstHandler == nil && defaultSkin != "" {
		h, err := NewHandler(defaultSkin)
		if err == nil {
			firstHandler = h
		}
	}

	muxHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))

		if h, ok := handlers[host]; ok {
			h.ServeHTTP(w, r)
			return
		}
		if defaultSkin == config.SkinFilebrowser {
			serveFilebrowser404(w, r)
			return
		}
		serveApache404(w, r)
	})

	server := &http.Server{
		Addr:    addr,
		Handler: muxHandler,
	}

	if len(certHolders) > 0 {
		server.TLSConfig = &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				serverName := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hello.ServerName), "."))
				if holder, ok := certHolders[serverName]; ok {
					return holder.getCertificate()
				}
				return nil, fmt.Errorf("no certificate found for SNI %q", hello.ServerName)
			},
			MinVersion: tls.VersionTLS12,
		}
	}

	return server, nil
}

// -----------------------------------------------------------------------------------------
// Filebrowser Handler & Helpers
// -----------------------------------------------------------------------------------------

func serveFilebrowser404(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Caddy")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("404 Not Found\n"))
}

func serveFilebrowserStatic(sub fs.FS, w http.ResponseWriter, r *http.Request) {
	relPath := strings.TrimPrefix(r.URL.Path, "/")
	f, err := sub.Open(relPath)
	if err != nil {
		serveFilebrowser404(w, r)
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		serveFilebrowser404(w, r)
		return
	}

	etag := fmt.Sprintf(`"%x-%x"`, fi.Size(), fi.ModTime().UnixNano())
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
		w.Header().Set("Server", "Caddy")
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	ext := strings.ToLower(filepath.Ext(relPath))
	var ctype string
	switch ext {
	case ".js", ".mjs":
		ctype = "text/javascript; charset=utf-8"
	case ".css":
		ctype = "text/css; charset=utf-8"
	case ".svg":
		ctype = "image/svg+xml"
	case ".png":
		ctype = "image/png"
	case ".ico":
		ctype = "image/x-icon"
	case ".json":
		ctype = "application/json; charset=utf-8"
	case ".woff2":
		ctype = "font/woff2"
	case ".woff":
		ctype = "font/woff"
	default:
		ctype = "application/octet-stream"
	}

	data, err := io.ReadAll(f)
	if err != nil {
		serveFilebrowser404(w, r)
		return
	}

	w.Header().Set("Server", "Caddy")
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func addFilebrowserHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Caddy")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func newFilebrowserHandler() (http.Handler, error) {
	sub, err := fs.Sub(assetsFS, "assets/filebrowser")
	if err != nil {
		return nil, err
	}

	indexHTML, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()

	// Static assets: /static/...
	mux.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		serveFilebrowserStatic(sub, w, r)
	})

	// API and SPA routes
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/api/login" {
			if r.Method != http.MethodPost {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
				w.WriteHeader(http.StatusMethodNotAllowed)
				_, _ = w.Write([]byte("Method Not Allowed\n"))
				return
			}
			simulatedHashDelay()
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("403 Forbidden\n"))
			return
		}
		if path == "/api/public/settings" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"signup":false,"createUserDir":false}`))
			return
		}
		if strings.HasPrefix(path, "/api/") {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("401 Unauthorized\n"))
			return
		}
		if path == "/health" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{\"status\":\"OK\"}\n"))
			return
		}
		if path == "/manifest.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"File Browser","short_name":"File Browser","start_url":"/","display":"standalone"}`))
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(indexHTML)
	})

	return addFilebrowserHeaders(mux), nil
}

// -----------------------------------------------------------------------------------------
// Nextcloud Handler & Decoy Helpers
// -----------------------------------------------------------------------------------------

func serveApache404(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		host = "localhost"
	}
	w.Header().Set("Content-Type", "text/html; charset=iso-8859-1")
	w.Header().Set("Server", "Apache/2.4.68 (Debian)")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.68 (Debian) Server at %s Port 443</address>
</body></html>
`, host)
}

func serveNextcloudWebDAV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("WWW-Authenticate", `Basic realm="Nextcloud", charset="UTF-8"`)
	w.Header().Set("Server", "Apache/2.4.68 (Debian)")
	w.Header().Set("X-Powered-By", "PHP/8.5.10")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Content-Security-Policy", "default-src 'none';")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<d:error xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns">
  <s:exception>Sabre\DAV\Exception\NotAuthenticated</s:exception>
  <s:message>No 'Authorization: Basic' header found. Either the client didn't send one, or the server is misconfigured, No 'Authorization: Bearer' header found. Either the client didn't send one, or the server is mis-configured</s:message>
</d:error>
`))
}

func serveNextcloudStatic(sub fs.FS, w http.ResponseWriter, r *http.Request) {
	relPath := strings.TrimPrefix(r.URL.Path, "/")
	f, err := sub.Open(relPath)
	if err != nil {
		serveApache404(w, r)
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		serveApache404(w, r)
		return
	}

	etag := fmt.Sprintf(`"%x-%x"`, fi.Size(), fi.ModTime().UnixNano())
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	ext := strings.ToLower(filepath.Ext(relPath))
	var ctype string
	switch ext {
	case ".js", ".mjs":
		ctype = "text/javascript"
	case ".css":
		ctype = "text/css"
	case ".svg":
		ctype = "image/svg+xml"
	case ".webp":
		ctype = "image/webp"
	case ".png":
		ctype = "image/png"
	case ".ico":
		ctype = "image/x-icon"
	case ".json":
		ctype = "application/json"
	case ".woff2":
		ctype = "font/woff2"
	case ".woff":
		ctype = "font/woff"
	default:
		if strings.HasSuffix(relPath, "favicon") {
			ctype = "image/x-icon"
		} else if strings.HasSuffix(relPath, "icon") {
			ctype = "image/png"
		} else {
			ctype = "application/octet-stream"
		}
	}

	data, err := io.ReadAll(f)
	if err != nil {
		serveApache404(w, r)
		return
	}

	w.Header().Set("Server", "Apache/2.4.68 (Debian)")
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "max-age=15778463")
	w.Header().Set("Vary", "Accept-Encoding")
	w.Header().Set("Last-Modified", "Fri, 04 Sep 2026 05:12:32 GMT")
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func newNextcloudHandler() (http.Handler, error) {
	sub, err := fs.Sub(assetsFS, "assets/nextcloud")
	if err != nil {
		return nil, err
	}

	indexBytes, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return nil, err
	}
	indexTemplateStr := string(indexBytes)

	capabilitiesBytes, err := fs.ReadFile(sub, "capabilities_template.json")
	if err != nil {
		return nil, err
	}
	capabilitiesTemplateStr := string(capabilitiesBytes)

	mux := http.NewServeMux()

	// Static subdirectories: /core/, /dist/, /apps/
	staticHandler := func(w http.ResponseWriter, r *http.Request) {
		serveNextcloudStatic(sub, w, r)
	}
	mux.HandleFunc("/core/", staticHandler)
	mux.HandleFunc("/dist/", staticHandler)
	mux.HandleFunc("/apps/", staticHandler)

	// Status.php probe
	mux.HandleFunc("/status.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"installed":true,"maintenance":false,"needsDbUpgrade":false,"version":"34.0.3.2","versionstring":"34.0.3","edition":"","productname":"Nextcloud","extendedSupport":false}`))
	})

	// 204 Ping probe
	mux.HandleFunc("/index.php/204", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.WriteHeader(http.StatusNoContent)
	})

	// Webcron probe
	mux.HandleFunc("/cron.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	})

	// Robots.txt
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
	})

	// WebDAV & DAV probes (support all methods: GET, PROPFIND, OPTIONS, etc.)
	webdavHandler := func(w http.ResponseWriter, r *http.Request) {
		serveNextcloudWebDAV(w, r)
	}
	mux.HandleFunc("/remote.php/webdav/", webdavHandler)
	mux.HandleFunc("/remote.php/dav/", webdavHandler)
	mux.HandleFunc("/remote.php/webdav", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		http.Redirect(w, r, "/remote.php/webdav/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/remote.php/dav", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		http.Redirect(w, r, "/remote.php/dav/", http.StatusMovedPermanently)
	})

	// Well-known redirects
	wellKnownDavRedirect := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		http.Redirect(w, r, "/remote.php/dav", http.StatusMovedPermanently)
	}
	mux.HandleFunc("/.well-known/webdav", wellKnownDavRedirect)
	mux.HandleFunc("/.well-known/caldav", wellKnownDavRedirect)
	mux.HandleFunc("/.well-known/carddav", wellKnownDavRedirect)

	// Well-known metadata probes
	mux.HandleFunc("/.well-known/nodeinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Nextcloud-Well-Known", "1")
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"nodeinfo not supported"}`))
	})
	mux.HandleFunc("/.well-known/webfinger", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Nextcloud-Well-Known", "1")
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"webfinger not supported"}`))
	})

	// OCS endpoints
	mux.HandleFunc("/ocs/v2.php/cloud/capabilities", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.WriteHeader(http.StatusPreconditionFailed)
		_, _ = w.Write([]byte(`{"message":"CSRF check failed"}`))
	})
	mux.HandleFunc("/ocs/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("<?xml version=\"1.0\"?>\n<ocs>\n <meta>\n  <status>failure</status>\n  <statuscode>997</statuscode>\n  <message>Current user is not logged in</message>\n </meta>\n <data/>\n</ocs>\n"))
	})

	// Login handler
	loginHandler := func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host == "" {
			host = "localhost"
		}

		if r.Method == http.MethodPost {
			simulatedLoginDelay()
			_ = r.ParseForm()
			user := r.FormValue("user")
			if user == "" {
				user = "admin"
			}
			http.SetCookie(w, &http.Cookie{
				Name:     "nc_username",
				Value:    "deleted",
				Path:     "/",
				Expires:  time.Unix(1, 0).UTC(),
				MaxAge:   -1,
				HttpOnly: true,
			})
			http.SetCookie(w, &http.Cookie{
				Name:     "nc_token",
				Value:    "deleted",
				Path:     "/",
				Expires:  time.Unix(1, 0).UTC(),
				MaxAge:   -1,
				HttpOnly: true,
			})
			http.SetCookie(w, &http.Cookie{
				Name:     "nc_session_id",
				Value:    "deleted",
				Path:     "/",
				Expires:  time.Unix(1, 0).UTC(),
				MaxAge:   -1,
				HttpOnly: true,
			})
			w.Header().Set("Server", "Apache/2.4.68 (Debian)")
			w.Header().Set("X-Powered-By", "PHP/8.5.10")
			w.Header().Set("Location", "/login?direct=1&user="+url.QueryEscape(user))
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		// GET login page
		nonce := generate32ByteBase64()
		token := generate32ByteBase64()
		requestToken := token + ":" + nonce
		nowUnix := time.Now().Unix()

		capJSON := strings.ReplaceAll(capabilitiesTemplateStr, "{{NEXTCLOUD_HOST}}", host)
		capB64 := base64.StdEncoding.EncodeToString([]byte(capJSON))

		html := indexTemplateStr
		html = strings.ReplaceAll(html, "{{NEXTCLOUD_HOST}}", host)
		html = strings.ReplaceAll(html, "{{NEXTCLOUD_CAPABILITIES}}", capB64)
		html = strings.ReplaceAll(html, "{{NEXTCLOUD_PAGELOAD}}", strconv.FormatInt(nowUnix, 10))
		html = strings.ReplaceAll(html, "{{NEXTCLOUD_NONCE}}", nonce)
		html = strings.ReplaceAll(html, "{{NEXTCLOUD_REQUESTTOKEN}}", requestToken)

		user := r.URL.Query().Get("user")
		if user != "" {
			userB64 := base64.StdEncoding.EncodeToString([]byte(`"` + user + `"`))
			html = strings.Replace(html, `id="initial-state-core-loginUsername" value="IiI="`, `id="initial-state-core-loginUsername" value="`+userB64+`"`, 1)
			html = strings.Replace(html, `id="initial-state-core-loginThrottleDelay" value="MA=="`, `id="initial-state-core-loginThrottleDelay" value="MTA="`, 1)
		}

		passphraseBytes := make([]byte, 96)
		_, _ = rand.Read(passphraseBytes)
		passphrase := base64.StdEncoding.EncodeToString(passphraseBytes)

		sidBytes := make([]byte, 16)
		_, _ = rand.Read(sidBytes)
		sid := hex.EncodeToString(sidBytes)

		http.SetCookie(w, &http.Cookie{
			Name:     "oc_sessionPassphrase",
			Value:    passphrase,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "ocouaube3hh1",
			Value:    sid,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		expires2100 := time.Date(2100, 12, 31, 23, 59, 59, 0, time.UTC)
		http.SetCookie(w, &http.Cookie{
			Name:     "nc_sameSiteCookielax",
			Value:    "true",
			Path:     "/",
			HttpOnly: true,
			Expires:  expires2100,
			SameSite: http.SameSiteLaxMode,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "nc_sameSiteCookiestrict",
			Value:    "true",
			Path:     "/",
			HttpOnly: true,
			Expires:  expires2100,
			SameSite: http.SameSiteStrictMode,
		})

		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.Header().Set("X-Request-Id", randomToken()[:20])
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self' 'unsafe-inline'; frame-src *; img-src * data: blob:; font-src 'self' data:; media-src *; connect-src *; object-src 'none'; base-uri 'self';", nonce))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(html))
	}

	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/index.php/login", loginHandler)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" || path == "/index.php" || path == "/index.php/" {
			w.Header().Set("Server", "Apache/2.4.68 (Debian)")
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if strings.HasPrefix(path, "/index.php/core/") || strings.HasPrefix(path, "/index.php/dist/") || strings.HasPrefix(path, "/index.php/apps/") {
			r2 := r.Clone(r.Context())
			r2.URL.Path = strings.TrimPrefix(path, "/index.php")
			serveNextcloudStatic(sub, w, r2)
			return
		}
		serveApache404(w, r)
	})

	return mux, nil
}

// -----------------------------------------------------------------------------------------
// Seafile Handler
// -----------------------------------------------------------------------------------------

func newSeafileHandler() (http.Handler, error) {
	sub, err := fs.Sub(assetsFS, "assets/seafile")
	if err != nil {
		return nil, err
	}
	fileServer := http.FileServer(http.FS(sub))

	indexBytes, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return nil, err
	}
	indexStr := string(indexBytes)

	mux := http.NewServeMux()

	// Media assets: /media/...
	mux.Handle("/media/", fileServer)

	// Probes
	mux.HandleFunc("/api2/ping/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("\"pong\""))
	})
	mux.HandleFunc("/seafhttp/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pong"))
	})
	mux.HandleFunc("/api2/server-info/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"version":"11.0.13","encrypted_library_version":2,"features":["seafile-basic"]}`))
	})
	mux.HandleFunc("/api2/auth-token/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		simulatedHashDelay()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"non_field_errors":["Unable to login with provided credentials."]}`))
	})

	// Login page
	mux.HandleFunc("/accounts/login/", func(w http.ResponseWriter, r *http.Request) {
		csrf := randomToken()
		http.SetCookie(w, &http.Cookie{
			Name:     "sfcsrftoken",
			Value:    csrf,
			Path:     "/",
			HttpOnly: false,
			SameSite: http.SameSiteLaxMode,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "sessionid",
			Value:    randomToken(),
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Language", "en")
		w.Header().Set("Vary", "Cookie, Accept-Language")
		w.Header().Set("Cache-Control", "max-age=0, no-cache, no-store, must-revalidate, private")

		if r.Method == http.MethodPost {
			simulatedHashDelay()
			_ = r.ParseForm()
			user := r.FormValue("login")
			html := strings.Replace(indexStr, `<p class="error mt-2 hide"></p>`, `<p class="error mt-2">Incorrect email or password</p>`, 1)
			if user != "" {
				html = strings.Replace(html, `name="login" placeholder="Email or Username" aria-label="Email or Username" title="Email or Username" value=""`, `name="login" placeholder="Email or Username" aria-label="Email or Username" title="Email or Username" value="`+template.HTMLEscapeString(user)+`"`, 1)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(html))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(indexStr))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/accounts/login/?next=/", http.StatusFound)
			return
		}
		fileServer.ServeHTTP(w, r)
	})

	return addCommonHeaders(mux, "nginx"), nil
}


func addCommonHeaders(next http.Handler, serverName string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", serverName)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		next.ServeHTTP(w, r)
	})
}
