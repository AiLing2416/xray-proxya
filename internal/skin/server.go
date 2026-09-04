package skin

import (
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
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

func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
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
		http.NotFound(w, r)
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
// Filebrowser Handler
// -----------------------------------------------------------------------------------------

func newFilebrowserHandler() (http.Handler, error) {
	sub, err := fs.Sub(assetsFS, "assets/filebrowser")
	if err != nil {
		return nil, err
	}
	fileServer := http.FileServer(http.FS(sub))

	indexHTML, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()

	// Static assets: /static/...
	mux.Handle("/static/", fileServer)

	// API and SPA routes
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/api/login" {
			if r.Method != http.MethodPost {
				http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
			simulatedHashDelay()
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("403 Forbidden\n"))
			return
		}
		if path == "/api/public/settings" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"signup":false,"createUserDir":false}`))
			return
		}
		if strings.HasPrefix(path, "/api/resources/") || path == "/api/users" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
			return
		}
		if path == "/health" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{\"status\":\"OK\"}\n"))
			return
		}
		if path == "/manifest.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"File Browser","short_name":"File Browser","start_url":"/","display":"standalone"}`))
			return
		}
		if strings.HasPrefix(path, "/static/") {
			fileServer.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(indexHTML)
	})

	return addCommonHeaders(mux, "Caddy"), nil
}

// -----------------------------------------------------------------------------------------
// Nextcloud Handler
// -----------------------------------------------------------------------------------------

func newNextcloudHandler() (http.Handler, error) {
	sub, err := fs.Sub(assetsFS, "assets/nextcloud")
	if err != nil {
		return nil, err
	}
	fileServer := http.FileServer(http.FS(sub))

	indexBytes, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return nil, err
	}
	indexTemplateStr := string(indexBytes)

	mux := http.NewServeMux()

	// Static subdirectories: /core/, /dist/, /apps/
	mux.Handle("/core/", fileServer)
	mux.Handle("/dist/", fileServer)
	mux.Handle("/apps/", fileServer)

	// Status.php probe
	mux.HandleFunc("/status.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Robots-Tag", "none")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"installed":true,"maintenance":false,"needsDbUpgrade":false,"version":"34.0.3.2","versionstring":"34.0.3","edition":"","productname":"Nextcloud","extendedSupport":false}`))
	})

	// WebDAV & DAV probes
	mux.HandleFunc("/remote.php/webdav/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Www-Authenticate", `Basic realm="Nextcloud"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/carddav", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/remote.php/dav/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/.well-known/caldav", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/remote.php/dav/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/ocs/v2.php/core/getapppassword", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("<?xml version=\"1.0\"?>\n<ocs>\n <meta>\n  <status>failure</status>\n  <statuscode>997</statuscode>\n  <message>Current user is not logged in</message>\n </meta>\n <data/>\n</ocs>\n"))
	})

	// Login handler
	loginHandler := func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		if r.Method == http.MethodPost {
			simulatedHashDelay()
			_ = r.ParseForm()
			user := r.FormValue("user")
			if user == "" {
				user = "admin"
			}
			w.Header().Set("Location", "/login?direct=1&user="+url.QueryEscape(user))
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		// GET handler
		user := r.URL.Query().Get("user")
		html := strings.ReplaceAll(indexTemplateStr, "skin1.ailing.dev", host)
		if user != "" {
			userB64 := base64.StdEncoding.EncodeToString([]byte(`"` + user + `"`))
			html = strings.Replace(html, `id="initial-state-core-loginUsername" value="IiI="`, `id="initial-state-core-loginUsername" value="`+userB64+`"`, 1)
			html = strings.Replace(html, `id="initial-state-core-loginThrottleDelay" value="MA=="`, `id="initial-state-core-loginThrottleDelay" value="MTA="`, 1)
		}

		nonce := randomToken()
		html = strings.ReplaceAll(html, "ZEYkrYLaoOB1dcGpObPe58AwhJ5Z7P0JaMRnG61UliU=", nonce)

		http.SetCookie(w, &http.Cookie{Name: "nc_sameSiteCookielax", Value: "true", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.SetCookie(w, &http.Cookie{Name: "nc_sameSiteCookiestrict", Value: "true", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.SetCookie(w, &http.Cookie{Name: "oc_sessionPassphrase", Value: randomToken() + randomToken(), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})

		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.Header().Set("X-Request-Id", randomToken()[:20])
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(html))
	}

	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/index.php/login", loginHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		fileServer.ServeHTTP(w, r)
	})

	return addNextcloudHeaders(mux), nil
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

func addNextcloudHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		next.ServeHTTP(w, r)
	})
}

func addCommonHeaders(next http.Handler, serverName string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", serverName)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		next.ServeHTTP(w, r)
	})
}
