package skin

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"xray-proxya/internal/config"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ErrSkinDisabled is returned when skin operations are invoked in a slim build.
var ErrSkinDisabled = errors.New("web skin feature is disabled in slim build")

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

const base62Chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func generateBase62(n int) string {
	b := make([]byte, n)
	randBytes := make([]byte, n)
	_, _ = rand.Read(randBytes)
	for i := range b {
		b[i] = base62Chars[randBytes[i]%62]
	}
	return string(b)
}

// NewHandler creates an http.Handler implementing the requested skin camouflage.
func NewHandler(skinType string) (http.Handler, error) {
	if !Enabled {
		return nil, ErrSkinDisabled
	}
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
	if !Enabled {
		return nil, ErrSkinDisabled
	}
	handler, err := NewHandler(skinType)
	if err != nil {
		return nil, err
	}

	port := 0
	if _, pStr, err := net.SplitHostPort(addr); err == nil {
		port, _ = strconv.Atoi(pStr)
	}

	wrapped := hideGoClientFingerprint(disguiseRecovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &sanitizingResponseWriter{ResponseWriter: w, req: r, skinType: skinType, port: port}
		handler.ServeHTTP(sw, r)
	}), func(r *http.Request) string { return skinType }))

	server := &http.Server{
		Addr:              addr,
		Handler:           wrapped,
		ErrorLog:          newSkinErrorLogger(),
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       60 * time.Second,
		WriteTimeout:      0,
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

// StartSkinH3Server spins up an HTTP/3 listener serving the chosen skin.
func StartSkinH3Server(addr string, skinType string, certFile, keyFile string) (*http3.Server, error) {
	if !Enabled {
		return nil, ErrSkinDisabled
	}
	handler, err := NewHandler(skinType)
	if err != nil {
		return nil, err
	}

	if certFile == "" || keyFile == "" {
		return nil, errors.New("HTTP/3 requires TLS certificates")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load skin TLS certificate: %w", err)
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	h3TLSConfig := http3.ConfigureTLSConfig(tlsConf)
	port := 0
	if _, pStr, err := net.SplitHostPort(addr); err == nil {
		port, _ = strconv.Atoi(pStr)
	}

	wrapped := hideGoClientFingerprint(disguiseRecovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &sanitizingResponseWriter{ResponseWriter: w, req: r, skinType: skinType, port: port}
		handler.ServeHTTP(sw, r)
	}), func(r *http.Request) string { return skinType }))

	server := &http3.Server{
		Addr:       addr,
		Port:       port,
		Handler:    wrapped,
		TLSConfig:  h3TLSConfig,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:  30 * time.Second,
			KeepAlivePeriod: 10 * time.Second,
			Allow0RTT:       true,
		},
	}
	return server, nil
}

// DomainSkinMapping configures a domain, skin type, and TLS certificate for multi-domain skin serving.
type DomainSkinMapping struct {
	Domain   string
	SkinType string
	CertPath string
	KeyPath  string
	CertPEM  string
	KeyPEM   string
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
	if ch.certPath == "" && ch.cert != nil {
		cert := ch.cert
		ch.mu.RUnlock()
		return cert, nil
	}
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

	if ch.certPath == "" && ch.cert != nil {
		return ch.cert, nil
	}

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

func buildMultiSkinHandlerAndTLS(addr string, mappings []DomainSkinMapping, defaultSkin string) (http.Handler, *tls.Config, int, error) {
	if !Enabled {
		return nil, nil, 0, ErrSkinDisabled
	}
	handlers := make(map[string]http.Handler)
	certHolders := make(map[string]*certHolder)
	var firstHolder *certHolder
	var firstHandler http.Handler

	domainSkinTypes := make(map[string]string)
	for _, m := range mappings {
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(m.Domain), "."))
		st := strings.ToLower(strings.TrimSpace(m.SkinType))

		if st != "" {
			h, err := NewHandler(st)
			if err != nil {
				return nil, nil, 0, err
			}
			if domain != "" {
				handlers[domain] = h
				domainSkinTypes[domain] = st
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
		} else if domain != "" && m.CertPath == "" && m.CertPEM != "" && m.KeyPEM != "" {
			pair, err := tls.X509KeyPair([]byte(m.CertPEM), []byte(m.KeyPEM))
			if err == nil {
				holder := &certHolder{cert: &pair}
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

	port := 0
	if _, pStr, err := net.SplitHostPort(addr); err == nil {
		port, _ = strconv.Atoi(pStr)
	}

	muxHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))

		effectiveSkin := defaultSkin
		if st, ok := domainSkinTypes[host]; ok {
			effectiveSkin = st
		}

		sw := &sanitizingResponseWriter{ResponseWriter: w, req: r, skinType: effectiveSkin, port: port}

		if h, ok := handlers[host]; ok {
			h.ServeHTTP(sw, r)
			return
		}
		if (host == "127.0.0.1" || host == "localhost" || host == "::1") && firstHandler != nil {
			firstHandler.ServeHTTP(sw, r)
			return
		}
		if effectiveSkin == config.SkinFilebrowser {
			serveFilebrowser404(sw, r)
			return
		}
		if effectiveSkin == config.SkinSeafile {
			serveNginx404(sw)
			return
		}
		serveApache404(sw, r)
	})

	getSkin := func(r *http.Request) string {
		if r == nil {
			return defaultSkin
		}
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if st, ok := domainSkinTypes[host]; ok {
			return st
		}
		return defaultSkin
	}

	wrappedHandler := hideGoClientFingerprint(disguiseRecovery(muxHandler, getSkin))

	var tlsConfig *tls.Config
	if len(certHolders) > 0 {
		tlsConfig = &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				serverName := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hello.ServerName), "."))
				if holder, ok := certHolders[serverName]; ok {
					return holder.getCertificate()
				}
				if firstHolder != nil && (serverName == "" || serverName == "127.0.0.1" || serverName == "localhost") {
					return firstHolder.getCertificate()
				}
				return nil, fmt.Errorf("no certificate found for SNI %q", hello.ServerName)
			},
			MinVersion: tls.VersionTLS12,
		}
	}

	return wrappedHandler, tlsConfig, port, nil
}

// loopbackTLSLogFilter suppresses expected local TLS handshake probe noise generated by Xray REALITY's
// startup post-handshake record detector (CCSDetectConn -> "tls: too many ignored records") and per-connection
// local target fallback probes ("EOF" when REALITY closes its local probe without sending ClientFinished).
type loopbackTLSLogFilter struct {
	out io.Writer
}

func (f *loopbackTLSLogFilter) Write(p []byte) (int, error) {
	msg := string(p)
	if strings.Contains(msg, "http: TLS handshake error from 127.0.0.1:") &&
		(strings.Contains(msg, ": EOF") ||
			strings.Contains(msg, ": tls: too many ignored records") ||
			strings.Contains(msg, ": remote error: tls: bad certificate")) {
		return len(p), nil
	}
	return f.out.Write(p)
}

func newSkinErrorLogger() *log.Logger {
	return log.New(&loopbackTLSLogFilter{out: os.Stderr}, "", log.LstdFlags)
}

// StartMultiSkinServer spins up an HTTPS listener serving Web camouflage skins for multiple domains.
// It uses SNI in the TLS ClientHello to dynamically serve each domain's valid certificate,
// and routes incoming HTTP requests to each domain's configured skin handler.
func StartMultiSkinServer(addr string, mappings []DomainSkinMapping, defaultSkin string) (*http.Server, error) {
	handler, tlsConfig, _, err := buildMultiSkinHandlerAndTLS(addr, mappings, defaultSkin)
	if err != nil {
		return nil, err
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ErrorLog:          newSkinErrorLogger(),
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       60 * time.Second,
		WriteTimeout:      0,
	}
	return server, nil
}

// StartMultiSkinH3Server spins up an HTTP/3 listener serving Web camouflage skins for multiple domains over native H3/QUIC.
func StartMultiSkinH3Server(addr string, mappings []DomainSkinMapping, defaultSkin string) (*http3.Server, error) {
	handler, tlsConfig, port, err := buildMultiSkinHandlerAndTLS(addr, mappings, defaultSkin)
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		return nil, errors.New("cannot start HTTP/3 server without TLS configuration")
	}

	h3TLSConfig := http3.ConfigureTLSConfig(tlsConfig.Clone())
	h3Server := &http3.Server{
		Addr:       addr,
		Port:       port,
		Handler:    handler,
		TLSConfig:  h3TLSConfig,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:  30 * time.Second,
			KeepAlivePeriod: 10 * time.Second,
			Allow0RTT:       true,
		},
	}
	return h3Server, nil
}

// StartMultiSkinServers spins up both TCP HTTPS (H1/H2) and UDP HTTP/3 (H3) listeners on the target address.
func StartMultiSkinServers(addr string, mappings []DomainSkinMapping, defaultSkin string) (*http.Server, *http3.Server, error) {
	tcpSrv, err := StartMultiSkinServer(addr, mappings, defaultSkin)
	if err != nil {
		return nil, nil, err
	}
	h3Srv, err := StartMultiSkinH3Server(addr, mappings, defaultSkin)
	if err != nil {
		return tcpSrv, nil, nil
	}
	return tcpSrv, h3Srv, nil
}

// -----------------------------------------------------------------------------------------
// Fingerprint Hiding & Error Decoys
// -----------------------------------------------------------------------------------------

// staticFileModTime is a fixed modification time for embedded static assets
// so embed.FS zero-time does not suppress Last-Modified headers.
var staticFileModTime = time.Date(2026, 9, 4, 5, 12, 32, 0, time.UTC)

const nginx416HTML = `<html>
<head><title>416 Requested Range Not Satisfiable</title></head>
<body>
<center><h1>416 Requested Range Not Satisfiable</h1></center>
<hr><center>nginx</center>
</body>
</html>
`

const filebrowser416HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>416 Requested Range Not Satisfiable</title>
</head>
<body>
<center><h1>416 Requested Range Not Satisfiable</h1></center>
</body>
</html>
`

func apache416HTML(serverName, port string) []byte {
	return []byte(fmt.Sprintf(`<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>416 Range Not Satisfiable</title>
</head><body>
<h1>Range Not Satisfiable</h1>
<p>None of the range-specifier values in the Range
request-header field overlap the current extent
of the selected resource.</p>
<hr>
<address>Apache/2.4.68 (Debian) Server at %s Port %s</address>
</body></html>
`, html.EscapeString(serverName), html.EscapeString(port)))
}

func getSkin416Body(skinType string, r *http.Request, port int) []byte {
	switch skinType {
	case config.SkinNextcloud:
		host := "localhost"
		if r != nil && r.Host != "" {
			host = r.Host
		}
		serverName := host
		portStr := "443"
		if h, p, err := net.SplitHostPort(host); err == nil {
			serverName = h
			portStr = p
		} else if port > 0 {
			portStr = strconv.Itoa(port)
		}
		return apache416HTML(serverName, portStr)
	case config.SkinSeafile:
		return []byte(nginx416HTML)
	case config.SkinFilebrowser:
		return []byte(filebrowser416HTML)
	default:
		return []byte(filebrowser416HTML)
	}
}

type sanitizingResponseWriter struct {
	http.ResponseWriter
	req          *http.Request
	skinType     string
	port         int
	headerWrote  bool
	is416        bool
	body416      []byte
	wrote416Body bool
}

func (s *sanitizingResponseWriter) WriteHeader(code int) {
	if s.headerWrote {
		return
	}
	s.headerWrote = true
	if code == http.StatusRequestedRangeNotSatisfiable {
		s.is416 = true
		s.body416 = getSkin416Body(s.skinType, s.req, s.port)
		s.sanitizeHeaders()
		switch s.skinType {
		case config.SkinNextcloud:
			s.Header().Set("Content-Type", "text/html; charset=iso-8859-1")
			s.Header().Set("Server", "Apache/2.4.68 (Debian)")
		case config.SkinSeafile:
			s.Header().Set("Content-Type", "text/html")
			s.Header().Set("Server", "nginx")
		case config.SkinFilebrowser:
			s.Header().Set("Content-Type", "text/html; charset=utf-8")
		default:
			s.Header().Set("Content-Type", "text/html; charset=utf-8")
		}
		s.Header().Set("Content-Length", strconv.Itoa(len(s.body416)))
		s.ResponseWriter.WriteHeader(code)
		return
	}
	s.sanitizeHeaders()
	s.ResponseWriter.WriteHeader(code)
}

func (s *sanitizingResponseWriter) Write(b []byte) (int, error) {
	if !s.headerWrote {
		s.WriteHeader(http.StatusOK)
	}
	if s.req != nil && s.req.Method == http.MethodHead {
		return len(b), nil
	}
	if s.is416 {
		if !s.wrote416Body {
			s.wrote416Body = true
			_, err := s.ResponseWriter.Write(s.body416)
			return len(b), err
		}
		return len(b), nil
	}
	return s.ResponseWriter.Write(b)
}

func (s *sanitizingResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	if !s.headerWrote {
		s.WriteHeader(http.StatusOK)
	}
	if s.req != nil && s.req.Method == http.MethodHead {
		return io.Copy(io.Discard, r)
	}
	if s.is416 {
		_, _ = io.Copy(io.Discard, r)
		if !s.wrote416Body {
			s.wrote416Body = true
			n, err := s.ResponseWriter.Write(s.body416)
			return int64(n), err
		}
		return 0, nil
	}
	if rf, ok := s.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(s.ResponseWriter, r)
}

func (s *sanitizingResponseWriter) sanitizeHeaders() {
	h := s.Header()
	// Strip Go fingerprint from X-Powered-By if present, but retain authentic PHP headers for Nextcloud
	if xpb := h.Get("X-Powered-By"); strings.Contains(strings.ToLower(xpb), "go") {
		h.Del("X-Powered-By")
	}

	// Remove any Go client / server fingerprinting from response headers
	for k, vv := range h {
		for _, v := range vv {
			if strings.Contains(strings.ToLower(v), "go-http-client") {
				h.Del(k)
				break
			}
		}
	}

	server := h.Get("Server")
	if strings.Contains(strings.ToLower(server), "go") {
		h.Del("Server")
		server = ""
	}
	if server == "" {
		switch s.skinType {
		case config.SkinNextcloud:
			h.Set("Server", "Apache/2.4.68 (Debian)")
		case config.SkinSeafile:
			h.Set("Server", "nginx")
		}
	}
}

func (s *sanitizingResponseWriter) Flush() {
	if !s.headerWrote {
		s.WriteHeader(http.StatusOK)
	}
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func hideGoClientFingerprint(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if strings.Contains(strings.ToLower(ua), "go-http-client") {
			r.Header.Del("User-Agent")
		}
		next.ServeHTTP(w, r)
	})
}

func disguiseRecovery(next http.Handler, getSkin func(r *http.Request) string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				skinType := ""
				if getSkin != nil {
					skinType = getSkin(r)
				}
				switch skinType {
				case config.SkinSeafile:
					serveNginx500(w)
				case config.SkinFilebrowser:
					serveFilebrowser500(w)
				default:
					serveApache500(w, r)
				}
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func serveApache500(w http.ResponseWriter, r *http.Request) {
	host := "localhost"
	if r != nil && r.Host != "" {
		host = r.Host
	}
	serverName := host
	port := "443"
	if h, p, err := net.SplitHostPort(host); err == nil {
		serverName = h
		port = p
	}
	body := fmt.Sprintf(`<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>500 Internal Server Error</title>
</head><body>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error or
misconfiguration and was unable to complete
your request.</p>
<hr>
<address>Apache/2.4.68 (Debian) Server at %s Port %s</address>
</body></html>
`, html.EscapeString(serverName), html.EscapeString(port))

	w.Header().Set("Server", "Apache/2.4.68 (Debian)")
	w.Header().Set("Content-Type", "text/html; charset=iso-8859-1")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(body))
}

func serveNginx500(w http.ResponseWriter) {
	w.Header().Set("Server", "nginx")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(`<html>
<head><title>500 Internal Server Error</title></head>
<body>
<center><h1>500 Internal Server Error</h1></center>
<hr><center>nginx</center>
</body>
</html>
`))
}

func serveFilebrowser500(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte("500 Internal Server Error\n"))
}

// -----------------------------------------------------------------------------------------
// Filebrowser Handler & Helpers
// -----------------------------------------------------------------------------------------

func serveFilebrowser404(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("404 Not Found\n"))
}

func serveFilebrowserSPA404(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("404 Not Found\n"))
}

func serveFilebrowserAPIError(w http.ResponseWriter, status int, text string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(fmt.Sprintf("%d %s\n", status, text)))
}

func serveFilebrowserStatic404(w http.ResponseWriter, isGet bool) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if isGet {
		w.Header().Set("Cache-Control", "public, max-age=86400")
	} else {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	}
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("404 Not Found\n"))
}

func serveFilebrowserStatic(sub fs.FS, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		serveFilebrowserStatic404(w, false)
		return
	}

	if r.URL.Path == "/static/" {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
		http.Redirect(w, r, "/static/", http.StatusMovedPermanently)
		return
	}

	if strings.HasSuffix(r.URL.Path, "/") {
		serveFilebrowserStatic404(w, true)
		return
	}

	relPath := strings.TrimPrefix(r.URL.Path, "/")
	f, err := sub.Open(relPath)
	if err != nil {
		serveFilebrowserStatic404(w, true)
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		serveFilebrowserStatic404(w, true)
		return
	}

	ext := strings.ToLower(filepath.Ext(relPath))
	var ctype string
	switch ext {
	case ".js", ".mjs":
		ctype = "application/javascript; charset=utf-8"
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

	rs, ok := f.(io.ReadSeeker)
	if !ok {
		data, err := io.ReadAll(f)
		if err != nil {
			serveFilebrowserStatic404(w, true)
			return
		}
		rs = bytes.NewReader(data)
	}

	modTime := fi.ModTime()
	if modTime.IsZero() || modTime.Year() < 2020 {
		modTime = staticFileModTime
	}
	etag := fmt.Sprintf(`"%x-%x"`, fi.Size(), modTime.UnixNano())

	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("ETag", etag)

	http.ServeContent(w, r, path.Base(relPath), modTime, rs)
}

func addFilebrowserHeaders(next http.Handler) http.Handler {
	return next
}

func newFilebrowserHandler() (http.Handler, error) {
	if !Enabled {
		return nil, ErrSkinDisabled
	}
	sub, err := fs.Sub(assetsFS, "assets/filebrowser")
	if err != nil {
		return nil, err
	}

	indexHTML, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()

	// Static assets: /static (404) and /static/... (assets)
	mux.HandleFunc("/static", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found\n"))
	})
	mux.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		serveFilebrowserStatic(sub, w, r)
	})

	// API and SPA routes
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// 1. /health probe (exact 15 bytes, no trailing newline, no nosniff header)
		if path == "/health" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"OK"}`))
			return
		}

		// 2. /api/login: any method returns 403 Forbidden
		if path == "/api/login" {
			if r.Method == http.MethodPost {
				simulatedHashDelay()
			}
			serveFilebrowserAPIError(w, http.StatusForbidden, "Forbidden")
			return
		}

		// 3. /api/signup: 405 Method Not Allowed (when signup disabled)
		if path == "/api/signup" {
			serveFilebrowserAPIError(w, http.StatusMethodNotAllowed, "Method Not Allowed")
			return
		}

		// 4. 301 redirects for directory-like API endpoints without trailing slash
		if path == "/api/resources" ||
			path == "/api/raw" ||
			path == "/api/usage" ||
			path == "/api/tus" ||
			path == "/api/search" ||
			path == "/api/subtitle" ||
			path == "/api/command" ||
			path == "/api/share" {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline';")
			http.Redirect(w, r, path+"/", http.StatusMovedPermanently)
			return
		}

		// 5. Unauthenticated public share/download endpoints: 404 Not Found
		if strings.HasPrefix(path, "/api/public/share") || strings.HasPrefix(path, "/api/public/dl") {
			serveFilebrowserAPIError(w, http.StatusNotFound, "Not Found")
			return
		}

		// 6. Authenticated API endpoints: 401 Unauthorized
		if path == "/api/renew" ||
			path == "/api/settings" ||
			path == "/api/users" || strings.HasPrefix(path, "/api/users/") ||
			path == "/api/shares" || strings.HasPrefix(path, "/api/shares/") ||
			path == "/api/commands" || strings.HasPrefix(path, "/api/commands/") ||
			strings.HasPrefix(path, "/api/share/") ||
			strings.HasPrefix(path, "/api/command/") ||
			strings.HasPrefix(path, "/api/resources/") ||
			strings.HasPrefix(path, "/api/raw/") ||
			strings.HasPrefix(path, "/api/usage/") ||
			strings.HasPrefix(path, "/api/tus/") ||
			strings.HasPrefix(path, "/api/search/") ||
			strings.HasPrefix(path, "/api/subtitle/") ||
			strings.HasPrefix(path, "/api/preview/") {
			serveFilebrowserAPIError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		// 7. SPA and unmatched routes (including GET /manifest.json, /sw.js, /robots.txt, /favicon.ico, unknown /api/*, /files, /login, /):
		// In real File Browser, only GET is accepted; all other methods return 404 Not Found.
		if r.Method != http.MethodGet {
			serveFilebrowserSPA404(w)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(indexHTML)
	})

	return addFilebrowserHeaders(mux), nil
}

// -----------------------------------------------------------------------------------------
// Nextcloud Handler & Decoy Helpers
// -----------------------------------------------------------------------------------------

const base36Chars = "0123456789abcdefghijklmnopqrstuvwxyz"

func nextcloudInstanceIDForHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if sh, _, err := net.SplitHostPort(h); err == nil {
		h = sh
	}
	if h == "" {
		h = "localhost"
	}
	sum := sha256.Sum256([]byte("nextcloud-instance:" + h))
	b := make([]byte, 10)
	for i := 0; i < 10; i++ {
		b[i] = base36Chars[sum[i]%36]
	}
	return "oc" + string(b)
}

func setNextcloudSessionCookies(w http.ResponseWriter, r *http.Request) (string, string) {
	instanceID := nextcloudInstanceIDForHost(r.Host)

	passphraseBytes := make([]byte, 96)
	_, _ = rand.Read(passphraseBytes)
	rawPassphrase := base64.StdEncoding.EncodeToString(passphraseBytes)
	escapedPassphrase := url.QueryEscape(rawPassphrase)

	sidBytes := make([]byte, 16)
	_, _ = rand.Read(sidBytes)
	sid := hex.EncodeToString(sidBytes)

	http.SetCookie(w, &http.Cookie{
		Name:     "oc_sessionPassphrase",
		Value:    escapedPassphrase,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     instanceID,
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
	return instanceID, sid
}

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

func serveNextcloud404(w http.ResponseWriter, r *http.Request, notFoundTemplate string) {
	setNextcloudSessionCookies(w, r)
	nonce := generate32ByteBase64()

	html := notFoundTemplate
	html = strings.ReplaceAll(html, "{{NEXTCLOUD_NONCE}}", nonce)

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Server", "Apache/2.4.68 (Debian)")
	w.Header().Set("X-Powered-By", "PHP/8.5.10")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("X-Request-Id", randomToken()[:20])
	w.Header().Set("Feature-Policy", "autoplay 'self';camera 'none';fullscreen 'self';geolocation 'none';microphone 'none';payment 'none'")
	w.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'none';base-uri 'none';manifest-src 'self';script-src 'nonce-%s';script-src-elem 'strict-dynamic' 'nonce-%s';style-src 'self' 'unsafe-inline';img-src 'self' data: blob: https://*.tile.openstreetmap.org;font-src 'self' data:;connect-src 'self';media-src 'self';frame-src 'self';frame-ancestors 'self';form-action 'self'", nonce, nonce))
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(html))
}

func serveNextcloudWebDAV(w http.ResponseWriter, r *http.Request) {
	setNextcloudSessionCookies(w, r)
	auth := r.Header.Get("Authorization")
	var msg string
	if strings.HasPrefix(auth, "Basic ") {
		simulatedHashDelay()
		msg = "Username or password was incorrect, No 'Authorization: Bearer' header found. Either the client didn't send one, or the server is mis-configured"
	} else if strings.HasPrefix(auth, "Bearer ") {
		simulatedHashDelay()
		msg = "No 'Authorization: Basic' header found. Either the client didn't send one, or the server is misconfigured, Bearer token was incorrect"
	} else {
		msg = "No 'Authorization: Basic' header found. Either the client didn't send one, or the server is misconfigured, No 'Authorization: Bearer' header found. Either the client didn't send one, or the server is mis-configured"
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("WWW-Authenticate", `Basic realm="Nextcloud", charset="UTF-8"`)
	w.Header().Set("Server", "Apache/2.4.68 (Debian)")
	w.Header().Set("X-Powered-By", "PHP/8.5.10")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none';")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<d:error xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns">
  <s:exception>Sabre\DAV\Exception\NotAuthenticated</s:exception>
  <s:message>%s</s:message>
</d:error>
`, msg)
}

func serveNextcloudStatic(sub fs.FS, w http.ResponseWriter, r *http.Request, notFoundTemplate string) {
	relPath := strings.TrimPrefix(r.URL.Path, "/")
	f, err := sub.Open(relPath)
	if err != nil {
		serveNextcloud404(w, r, notFoundTemplate)
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		serveNextcloud404(w, r, notFoundTemplate)
		return
	}

	modTime := fi.ModTime()
	if modTime.IsZero() || modTime.Year() < 2020 {
		modTime = staticFileModTime
	}
	etag := fmt.Sprintf(`"%x-%x"`, fi.Size(), modTime.UnixNano())

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
	case ".gif":
		ctype = "image/gif"
	case ".ico":
		ctype = "image/x-icon"
	case ".json":
		ctype = "application/json"
	case ".woff2":
		ctype = "font/woff2"
	case ".woff":
		ctype = "font/woff"
	case ".otf":
		ctype = "font/otf"
	default:
		if strings.HasSuffix(relPath, "favicon") {
			ctype = "image/x-icon"
		} else if strings.HasSuffix(relPath, "icon") {
			ctype = "image/png"
		} else {
			ctype = "application/octet-stream"
		}
	}

	rs, ok := f.(io.ReadSeeker)
	if !ok {
		data, err := io.ReadAll(f)
		if err != nil {
			serveNextcloud404(w, r, notFoundTemplate)
			return
		}
		rs = bytes.NewReader(data)
	}

	cacheControl := "max-age=15778463"
	if strings.Contains(r.URL.RawQuery, "v=") {
		cacheControl = "max-age=15778463, immutable"
	}

	w.Header().Set("Server", "Apache/2.4.68 (Debian)")
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", cacheControl)
	w.Header().Set("Vary", "Accept-Encoding")
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
	w.Header().Set("Referrer-Policy", "no-referrer")

	http.ServeContent(w, r, path.Base(relPath), modTime, rs)
}

func newNextcloudHandler() (http.Handler, error) {
	if !Enabled {
		return nil, ErrSkinDisabled
	}
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

	notFoundBytes, err := fs.ReadFile(sub, "404.html")
	var notFoundTemplateStr string
	if err == nil {
		notFoundTemplateStr = string(notFoundBytes)
	} else {
		notFoundTemplateStr = `<!DOCTYPE html><html class="ng-csp"><head><meta charset="utf-8"><title>Nextcloud</title></head><body><h2>Page not found</h2><p><a class="button primary" href="/">Back to Nextcloud</a></p></body></html>`
	}

	mux := http.NewServeMux()

	// Static subdirectories: /core/, /dist/, /apps/
	staticHandler := func(w http.ResponseWriter, r *http.Request) {
		serveNextcloudStatic(sub, w, r, notFoundTemplateStr)
	}
	mux.HandleFunc("/core/", staticHandler)
	mux.HandleFunc("/dist/", staticHandler)
	mux.HandleFunc("/apps/", staticHandler)

	// Status.php probe
	mux.HandleFunc("/status.php", func(w http.ResponseWriter, r *http.Request) {
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

		nonce := generate32ByteBase64()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self' 'unsafe-inline'; frame-src *; img-src * data: blob:; font-src 'self' data:; media-src *; connect-src *; object-src 'none'; base-uri 'self';", nonce))
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"installed":true,"maintenance":false,"needsDbUpgrade":false,"version":"34.0.3.2","versionstring":"34.0.3","edition":"","productname":"Nextcloud","extendedSupport":false}`))
	})

	// 204 Ping probe
	mux.HandleFunc("/index.php/204", func(w http.ResponseWriter, r *http.Request) {
		setNextcloudSessionCookies(w, r)
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none';base-uri 'none';manifest-src 'self';frame-ancestors 'none'")
		w.Header().Set("X-Request-Id", randomToken()[:20])
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Feature-Policy", "autoplay 'none';camera 'none';fullscreen 'none';geolocation 'none';microphone 'none';payment 'none'")
		w.WriteHeader(http.StatusNoContent)
	})

	// Webcron probe
	mux.HandleFunc("/cron.php", func(w http.ResponseWriter, r *http.Request) {
		setNextcloudSessionCookies(w, r)
		nonce := generate32ByteBase64()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self' 'unsafe-inline'; frame-src *; img-src * data: blob:; font-src 'self' data:; media-src *; connect-src *; object-src 'none'; base-uri 'self';", nonce))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	})

	// Robots.txt
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
	})

	// WebDAV & DAV probes (support all methods: GET, PROPFIND, OPTIONS, etc.)
	webdavHandler := func(w http.ResponseWriter, r *http.Request) {
		serveNextcloudWebDAV(w, r)
	}
	mux.HandleFunc("/remote.php/webdav", webdavHandler)
	mux.HandleFunc("/remote.php/webdav/", webdavHandler)
	mux.HandleFunc("/remote.php/dav", webdavHandler)
	mux.HandleFunc("/remote.php/dav/", webdavHandler)

	// Well-known endpoints
	mux.HandleFunc("/.well-known/webdav", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Nextcloud-Well-Known", "1")
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"webdav not supported"}`))
	})

	wellKnownDavRedirect := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		http.Redirect(w, r, "/remote.php/dav/", http.StatusMovedPermanently)
	}
	mux.HandleFunc("/.well-known/caldav", wellKnownDavRedirect)
	mux.HandleFunc("/.well-known/carddav", wellKnownDavRedirect)

	mux.HandleFunc("/.well-known/change-password", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		http.Redirect(w, r, "/settings/user/security", http.StatusSeeOther)
	})

	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Contact: https://hackerone.com/nextcloud\nExpires: 2026-12-31T23:00:00.000Z\nAcknowledgments: https://hackerone.com/nextcloud/thanks\nAcknowledgments: https://github.com/nextcloud/security-advisories/security/advisories\nPolicy: https://hackerone.com/nextcloud\nPreferred-Languages: en\n"))
	})

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

	// Login flow v2 (desktop/mobile app flow)
	loginV2Handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			setNextcloudSessionCookies(w, r)
			tokenBytes := make([]byte, 64)
			_, _ = rand.Read(tokenBytes)
			token := hex.EncodeToString(tokenBytes)

			host := r.Host
			if host == "" {
				host = "localhost"
			}
			scheme := "https"
			if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" && (host == "127.0.0.1" || strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1:")) {
				scheme = "http"
			}

			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Server", "Apache/2.4.68 (Debian)")
			w.Header().Set("X-Powered-By", "PHP/8.5.10")
			w.Header().Set("Content-Security-Policy", "default-src 'none';base-uri 'none';manifest-src 'self';frame-ancestors 'none'")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("X-Request-Id", randomToken()[:20])
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"poll":{"token":"%s","endpoint":"%s://%s/login/v2/poll"},"login":"%s://%s/login/v2/flow/%s"}`, token, scheme, host, scheme, host, token)
			return
		}
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	loginV2PollHandler := func(w http.ResponseWriter, r *http.Request) {
		setNextcloudSessionCookies(w, r)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.Header().Set("Content-Security-Policy", "default-src 'none';base-uri 'none';manifest-src 'self';frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("X-Request-Id", randomToken()[:20])
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`[]`))
	}

	mux.HandleFunc("/login/v2", loginV2Handler)
	mux.HandleFunc("/index.php/login/v2", loginV2Handler)
	mux.HandleFunc("/login/v2/poll", loginV2PollHandler)
	mux.HandleFunc("/index.php/login/v2/poll", loginV2PollHandler)

	// OCS endpoints
	serveCapabilities := func(w http.ResponseWriter, r *http.Request, versionMajor int) {
		if r.Header.Get("OCS-APIRequest") != "true" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Server", "Apache/2.4.68 (Debian)")
			w.Header().Set("X-Powered-By", "PHP/8.5.10")
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = w.Write([]byte(`{"message":"CSRF check failed"}`))
			return
		}

		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host == "" {
			host = "localhost"
		}

		capJSON := strings.ReplaceAll(capabilitiesTemplateStr, "{{NEXTCLOUD_HOST}}", host)

		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")

		if r.URL.Query().Get("format") == "json" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			if versionMajor == 1 {
				_, _ = fmt.Fprintf(w, `{"ocs":{"meta":{"status":"ok","statuscode":100,"message":"OK","totalitems":"","itemsperpage":""},"data":{"version":{"major":34,"minor":0,"micro":3,"string":"34.0.3","edition":"","extendedSupport":false},"capabilities":%s}}}`, capJSON)
			} else {
				_, _ = fmt.Fprintf(w, `{"ocs":{"meta":{"status":"ok","statuscode":200,"message":"OK"},"data":{"version":{"major":34,"minor":0,"micro":3,"string":"34.0.3","edition":"","extendedSupport":false},"capabilities":%s}}}`, capJSON)
			}
		} else {
			w.Header().Set("Content-Type", "application/xml; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			statusCode := 200
			if versionMajor == 1 {
				statusCode = 100
			}
			_, _ = fmt.Fprintf(w, `<?xml version="1.0"?>
<ocs>
 <meta>
  <status>ok</status>
  <statuscode>%d</statuscode>
  <message>OK</message>
 </meta>
 <data>
  <version>
   <major>34</major>
   <minor>0</minor>
   <micro>3</micro>
   <string>34.0.3</string>
   <edition></edition>
   <extendedSupport></extendedSupport>
  </version>
  <capabilities>
   <theming>
    <name>Nextcloud</name>
    <url>https://nextcloud.com</url>
    <slogan>a safe home for all your data</slogan>
    <color>#00679e</color>
    <color-text>#ffffff</color-text>
   </theming>
  </capabilities>
 </data>
</ocs>
`, statusCode)
		}
	}

	mux.HandleFunc("/ocs/v1.php/cloud/capabilities", func(w http.ResponseWriter, r *http.Request) {
		serveCapabilities(w, r, 1)
	})
	mux.HandleFunc("/ocs/v2.php/cloud/capabilities", func(w http.ResponseWriter, r *http.Request) {
		serveCapabilities(w, r, 2)
	})

	mux.HandleFunc("/ocs/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.68 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.5.10")
		w.WriteHeader(http.StatusUnauthorized)
		if r.URL.Query().Get("format") == "json" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write([]byte(`{"ocs":{"meta":{"status":"failure","statuscode":997,"message":"Current user is not logged in"},"data":[]}}`))
		} else {
			w.Header().Set("Content-Type", "application/xml; charset=utf-8")
			_, _ = w.Write([]byte("<?xml version=\"1.0\"?>\n<ocs>\n <meta>\n  <status>failure</status>\n  <statuscode>997</statuscode>\n  <message>Current user is not logged in</message>\n </meta>\n <data/>\n</ocs>\n"))
		}
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
			setNextcloudSessionCookies(w, r)
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
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
			w.Header().Set("X-Robots-Tag", "noindex, nofollow")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Content-Security-Policy", "default-src 'none';base-uri 'none';manifest-src 'self';frame-ancestors 'none'")
			w.Header().Set("X-Request-Id", randomToken()[:20])
			w.Header().Set("X-Nextcloud-Bruteforce-Throttled", "6400ms")
			w.Header().Set("Feature-Policy", "autoplay 'none';camera 'none';fullscreen 'none';geolocation 'none';microphone 'none';payment 'none'")
			w.Header().Set("Location", "/login?direct=1&user="+url.QueryEscape(user))
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		// GET login page
		setNextcloudSessionCookies(w, r)
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
		w.Header().Set("Feature-Policy", "autoplay 'self';camera 'none';fullscreen 'self';geolocation 'none';microphone 'none';payment 'none'")
		w.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'none';base-uri 'none';manifest-src 'self';script-src 'nonce-%s';script-src-elem 'strict-dynamic' 'nonce-%s';style-src 'self' 'unsafe-inline';img-src 'self' data: blob: https://*.tile.openstreetmap.org;font-src 'self' data:;connect-src 'self';media-src 'self';frame-src 'self';frame-ancestors 'self';form-action 'self'", nonce, nonce))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(html))
	}

	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/index.php/login", loginHandler)
	mux.HandleFunc("/login/flow", loginHandler)
	mux.HandleFunc("/index.php/login/flow", loginHandler)
	mux.HandleFunc("/login/v2/flow/", loginHandler)
	mux.HandleFunc("/index.php/login/v2/flow/", loginHandler)

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
			serveNextcloudStatic(sub, w, r2, notFoundTemplateStr)
			return
		}
		serveNextcloud404(w, r, notFoundTemplateStr)
	})

	return mux, nil
}

// -----------------------------------------------------------------------------------------
// Seafile Handler & Decoy Helpers
// -----------------------------------------------------------------------------------------

const nginx404HTML = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"

const nginx403HTML = "<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"

const djangoCSRF403HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <meta name="robots" content="NONE,NOARCHIVE">
  <title>403 Forbidden</title>
  <style type="text/css">
    html * { padding:0; margin:0; }
    body * { padding:10px 20px; }
    body * * { padding:0; }
    body { font:small sans-serif; background:#eee; color:#000; }
    body>div { border-bottom:1px solid #ddd; }
    h1 { font-weight:normal; margin-bottom:.4em; }
    h1 span { font-size:60%; color:#666; font-weight:normal; }
    #info { background:#f6f6f6; }
    #info ul { margin: 0.5em 4em; }
    #info p, #summary p { padding-top:10px; }
    #summary { background: #ffc; }
    #explanation { background:#eee; border-bottom: 0px none; }
  </style>
</head>
<body>
<div id="summary">
  <h1>Forbidden <span>(403)</span></h1>
  <p>CSRF verification failed. Request aborted.</p>


  <p>You are seeing this message because this site requires a CSRF cookie when submitting forms. This cookie is required for security reasons, to ensure that your browser is not being hijacked by third parties.</p>
  <p>If you have configured your browser to disable cookies, please re-enable them, at least for this site, or for “same-origin” requests.</p>

</div>

<div id="explanation">
  <p><small>More information is available with DEBUG=True.</small></p>
</div>

</body>
</html>`

func serveNginx404(w http.ResponseWriter) {
	w.Header().Set("Server", "nginx")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(nginx404HTML))
}

func serveNginx403(w http.ResponseWriter) {
	w.Header().Set("Server", "nginx")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(nginx403HTML))
}

func serveSeafileCSRF403(w http.ResponseWriter) {
	w.Header().Set("Server", "nginx")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Language", "en")
	w.Header().Set("Vary", "Accept-Language, Cookie")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(djangoCSRF403HTML))
}

func checkSeafileCSRF(r *http.Request) bool {
	cookie, err := r.Cookie("sfcsrftoken")
	if err != nil || len(cookie.Value) < 16 {
		return false
	}
	_ = r.ParseForm()
	formToken := r.FormValue("csrfmiddlewaretoken")
	headerToken := r.Header.Get("X-CSRFToken")
	if len(formToken) >= 16 || len(headerToken) >= 16 {
		return true
	}
	return false
}

func serveSeafile404(w http.ResponseWriter, body []byte) {
	w.Header().Set("Server", "nginx")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Language", "en")
	w.Header().Set("Vary", "Accept-Language, Cookie")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(body)
}

func serveSeafileStatic(sub fs.FS, w http.ResponseWriter, r *http.Request) {
	cleanPath := path.Clean(r.URL.Path)
	relPath := strings.TrimPrefix(cleanPath, "/")

	f, err := sub.Open(relPath)
	if err != nil {
		serveNginx404(w)
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		serveNginx404(w)
		return
	}
	if fi.IsDir() || strings.HasSuffix(r.URL.Path, "/") {
		serveNginx403(w)
		return
	}

	modTime := fi.ModTime()
	if modTime.IsZero() || modTime.Year() < 2020 {
		modTime = staticFileModTime
	}
	etag := fmt.Sprintf(`"%x-%x"`, fi.Size(), modTime.UnixNano())

	ext := strings.ToLower(filepath.Ext(relPath))
	var ctype string
	switch ext {
	case ".css":
		ctype = "text/css"
	case ".js", ".mjs":
		ctype = "application/javascript"
	case ".png":
		ctype = "image/png"
	case ".jpg", ".jpeg":
		ctype = "image/jpeg"
	case ".gif":
		ctype = "image/gif"
	case ".ico":
		ctype = "image/x-icon"
	case ".svg":
		ctype = "image/svg+xml"
	case ".woff":
		ctype = "font/woff"
	case ".woff2":
		ctype = "font/woff2"
	case ".ttf":
		ctype = "font/ttf"
	case ".eot":
		ctype = "application/vnd.ms-fontobject"
	default:
		ctype = "application/octet-stream"
	}

	rs, ok := f.(io.ReadSeeker)
	if !ok {
		data, err := io.ReadAll(f)
		if err != nil {
			serveNginx404(w)
			return
		}
		rs = bytes.NewReader(data)
	}

	w.Header().Set("Server", "nginx")
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("ETag", etag)

	http.ServeContent(w, r, path.Base(relPath), modTime, rs)
}

var reCsrfToken = regexp.MustCompile(`name="csrfmiddlewaretoken" value="[^"]*"`)
var multiSlashRegex = regexp.MustCompile(`/{2,}`)

func newSeafileHandler() (http.Handler, error) {
	if !Enabled {
		return nil, ErrSkinDisabled
	}
	sub, err := fs.Sub(assetsFS, "assets/seafile")
	if err != nil {
		return nil, err
	}

	indexBytes, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return nil, err
	}
	indexStr := string(indexBytes)

	seafile404Bytes, err := fs.ReadFile(sub, "404.html")
	if err != nil {
		return nil, err
	}

	passwordResetBytes, err := fs.ReadFile(sub, "password_reset.html")
	if err != nil {
		return nil, err
	}
	passwordResetStr := string(passwordResetBytes)

	mux := http.NewServeMux()

	// Media assets: /media/...
	mux.HandleFunc("/media/", func(w http.ResponseWriter, r *http.Request) {
		serveSeafileStatic(sub, w, r)
	})

	// 1. Fileserver endpoints (/seafhttp/...)
	mux.HandleFunc("/seafhttp/protocol-version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"version": 2}`))
	})
	mux.HandleFunc("/seafhttp/", func(w http.ResponseWriter, r *http.Request) {
		// Real seaf-server returns 404 with empty body (0 bytes) for unknown seafhttp endpoints
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusNotFound)
	})

	// 2. Modern API v2.1 (/api/v2.1/...)
	mux.HandleFunc("/api/v2.1/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		w.Header().Set("Content-Language", "en")
		w.Header().Set("Vary", "Accept-Language, Cookie")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"Authentication credentials were not provided."}`))
	})

	// 3. API2 Probes (/api2/ping/ and /api2/server-info/)
	mux.HandleFunc("/api2/ping/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		w.Header().Set("Content-Language", "en")
		w.Header().Set("Vary", "Accept-Language, Cookie")

		if r.Method == http.MethodOptions {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"Ping","description":"","renders":["application/json"],"parses":["application/json","application/x-www-form-urlencoded","multipart/form-data"]}`))
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte(fmt.Sprintf("{\"detail\":\"Method \\\"%s\\\" not allowed.\"}", r.Method)))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("\"pong\""))
	})
	mux.HandleFunc("/api2/server-info/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		w.Header().Set("Content-Language", "en")
		w.Header().Set("Vary", "Accept-Language, Cookie")

		if r.Method == http.MethodOptions {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"Server Info","description":"","renders":["application/json"],"parses":["application/json","application/x-www-form-urlencoded","multipart/form-data"]}`))
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte(fmt.Sprintf("{\"detail\":\"Method \\\"%s\\\" not allowed.\"}", r.Method)))
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"version": "11.0.13", "encrypted_library_version": 2, "features": ["seafile-basic"]}`))
	})

	// 4. /api2/auth-token/
	mux.HandleFunc("/api2/auth-token/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Allow", "POST, OPTIONS")
		w.Header().Set("Content-Language", "en")
		w.Header().Set("Vary", "Accept-Language, Cookie")
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"Obtain Auth Token","description":"","renders":["application/json"],"parses":["application/json","application/x-www-form-urlencoded","multipart/form-data"]}`))
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte(fmt.Sprintf("{\"detail\":\"Method \\\"%s\\\" not allowed.\"}", r.Method)))
			return
		}

		_ = r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" && password == "" && strings.Contains(r.Header.Get("Content-Type"), "json") {
			var payload struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			bodyBytes, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			_ = json.Unmarshal(bodyBytes, &payload)
			username = payload.Username
			password = payload.Password
		}

		if username == "" && password == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"username":["This field is required."],"password":["This field is required."]}`))
			return
		}
		if username == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"username":["This field is required."]}`))
			return
		}
		if password == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"password":["This field is required."]}`))
			return
		}

		simulatedHashDelay()
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"non_field_errors":["Unable to login with provided credentials."]}`))
	})

	// 5. Other /api2/* routes: require authentication -> 403 Forbidden with proper Allow header
	// Even unauthenticated OPTIONS returns 403 Forbidden in DRF
	mux.HandleFunc("/api2/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Language", "en")
		w.Header().Set("Vary", "Accept-Language, Cookie")

		allow := "GET, HEAD, OPTIONS"
		p := r.URL.Path
		if strings.HasPrefix(p, "/api2/repos") {
			allow = "GET, POST, HEAD, OPTIONS"
		} else if strings.HasPrefix(p, "/api2/client-login") {
			allow = "POST, OPTIONS"
		} else if strings.HasPrefix(p, "/api2/account/info") {
			allow = "GET, PUT, HEAD, OPTIONS"
		}
		w.Header().Set("Allow", allow)

		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"Authentication credentials were not provided."}`))
	})

	// 6. Password Reset: /accounts/password/reset/
	mux.HandleFunc("/accounts/password/reset/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if !checkSeafileCSRF(r) {
				serveSeafileCSRF403(w)
				return
			}
			simulatedHashDelay()
		}

		csrf := generateBase62(32)
		formCsrf := generateBase62(64)
		http.SetCookie(w, &http.Cookie{
			Name:     "sfcsrftoken",
			Value:    csrf,
			Path:     "/",
			MaxAge:   31449600,
			Expires:  time.Now().Add(time.Duration(31449600) * time.Second),
			SameSite: http.SameSiteLaxMode,
		})

		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Language", "en")
		w.Header().Set("Vary", "Cookie, Accept-Language")

		html := reCsrfToken.ReplaceAllString(passwordResetStr, `name="csrfmiddlewaretoken" value="`+formCsrf+`"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(html))
	})

	// 7. Language switch: /i18n/
	i18nHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if !checkSeafileCSRF(r) {
				serveSeafileCSRF403(w)
				return
			}
		}

		lang := r.URL.Query().Get("lang")
		if lang == "" && r.Method == http.MethodPost {
			_ = r.ParseForm()
			lang = r.FormValue("language")
		}
		if lang == "" {
			lang = "en"
		}
		http.SetCookie(w, &http.Cookie{
			Name:    "django_language",
			Value:   lang,
			Path:    "/",
			MaxAge:  2592000,
			Expires: time.Now().Add(30 * 24 * time.Hour),
		})

		ref := r.Header.Get("Referer")
		if ref == "" {
			ref = "/"
		}

		w.Header().Set("Server", "nginx")
		w.Header().Set("Location", ref)
		w.Header().Set("Content-Language", "en")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Vary", "Accept-Language, Cookie")
		w.WriteHeader(http.StatusFound)
	}
	mux.HandleFunc("/i18n/", i18nHandler)

	// 8. Login page: /accounts/login/
	mux.HandleFunc("/accounts/login/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if !checkSeafileCSRF(r) {
				serveSeafileCSRF403(w)
				return
			}

			simulatedHashDelay()

			csrf := generateBase62(32)
			formCsrf := generateBase62(64)

			http.SetCookie(w, &http.Cookie{
				Name:     "sfcsrftoken",
				Value:    csrf,
				Path:     "/",
				MaxAge:   31449600,
				Expires:  time.Now().Add(time.Duration(31449600) * time.Second),
				SameSite: http.SameSiteLaxMode,
			})

			w.Header().Set("Server", "nginx")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Language", "en")
			w.Header().Set("Vary", "Cookie, Accept-Language")
			w.Header().Set("Cache-Control", "max-age=0, no-cache, no-store, must-revalidate, private")
			w.Header().Set("Expires", time.Now().UTC().Format(http.TimeFormat))

			html := reCsrfToken.ReplaceAllString(indexStr, `name="csrfmiddlewaretoken" value="`+formCsrf+`"`)
			html = strings.Replace(html, `<p class="error mt-2 hide"></p>`, `<p class="error mt-2">Incorrect email or password</p>`, 1)
			// In real Seahub, value="" is preserved without reflecting login username

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(html))
			return
		}

		// GET login page
		csrf := generateBase62(32)
		sessionID := generateBase62(32)
		formCsrf := generateBase62(64)

		http.SetCookie(w, &http.Cookie{
			Name:     "sfcsrftoken",
			Value:    csrf,
			Path:     "/",
			MaxAge:   31449600,
			Expires:  time.Now().Add(time.Duration(31449600) * time.Second),
			SameSite: http.SameSiteLaxMode,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "sessionid",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400,
			Expires:  time.Now().Add(time.Duration(86400) * time.Second),
			SameSite: http.SameSiteLaxMode,
		})

		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Language", "en")
		w.Header().Set("Vary", "Cookie, Accept-Language")
		w.Header().Set("Cache-Control", "max-age=0, no-cache, no-store, must-revalidate, private")
		w.Header().Set("Expires", time.Now().UTC().Format(http.TimeFormat))

		html := reCsrfToken.ReplaceAllString(indexStr, `name="csrfmiddlewaretoken" value="`+formCsrf+`"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(html))
	})

	// 9. Global root redirect & 404 fallback
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			if r.Method == http.MethodPost {
				if !checkSeafileCSRF(r) {
					serveSeafileCSRF403(w)
					return
				}
			}
			loc := "/accounts/login/?next=/"
			if r.URL.RawQuery != "" {
				escapedQuery := strings.ReplaceAll(url.QueryEscape("?"+r.URL.RawQuery), "%2F", "/")
				loc = "/accounts/login/?next=/" + escapedQuery
			}
			w.Header().Set("Server", "nginx")
			w.Header().Set("Location", loc)
			w.Header().Set("Content-Language", "en")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Vary", "Accept-Language, Cookie")
			w.WriteHeader(http.StatusFound)
			return
		}
		serveSeafile404(w, seafile404Bytes)
	})

	isAppendSlashTarget := func(p string) bool {
		switch p {
		case "/accounts/login", "/accounts/password/reset", "/i18n":
			return true
		}
		if strings.HasPrefix(p, "/api2/") || strings.HasPrefix(p, "/api/v2.1/") {
			return true
		}
		return false
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Collapse multiple consecutive slashes so /media//css/seafile-ui.css
		// doesn't trigger ServeMux redirect, mimicking Nginx merge_slashes on;
		if strings.Contains(r.URL.Path, "//") {
			r.URL.Path = multiSlashRegex.ReplaceAllString(r.URL.Path, "/")
		}

		// 2. Django APPEND_SLASH: 301 Moved Permanently for unslashed endpoints
		if isAppendSlashTarget(r.URL.Path) && !strings.HasSuffix(r.URL.Path, "/") {
			loc := r.URL.Path + "/"
			if r.URL.RawQuery != "" {
				loc += "?" + r.URL.RawQuery
			}
			w.Header().Set("Server", "nginx")
			w.Header().Set("Location", loc)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Language", "en")
			w.Header().Set("Vary", "Accept-Language, Cookie")
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}

		mux.ServeHTTP(w, r)
	}), nil
}
