package sub

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/ipv6rotate"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"
)

func StartSubServer(instance config.SubscriptionServiceConfig) error {
	if instance.Port <= 0 || instance.Port > 65535 {
		return fmt.Errorf("subscription listener port must be between 1 and 65535")
	}
	listen := strings.TrimSpace(instance.Listen)
	if listen == "" {
		listen = "127.0.0.1"
	}
	if ip := net.ParseIP(listen); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("subscription listener must bind to a loopback IP")
	}
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/sub/", httpAdminSubHandler(instance.AdminSub))

	guestMux := http.NewServeMux()
	guestMux.HandleFunc("/guest-sub/", httpGuestSubHandler())

	errCh := make(chan error, 2)

	go func() {
		addr := net.JoinHostPort(listen, strconv.Itoa(instance.Port))
		fmt.Printf("🔓 Admin subscription server listening on http://%s\n", addr)
		errCh <- http.ListenAndServe(addr, adminMux)
	}()

	if instance.GuestPort > 0 {
		if err := validatePrivateBindAddress(instance.GuestBind); err != nil {
			return err
		}
		addr := net.JoinHostPort(instance.GuestBind, strconv.Itoa(instance.GuestPort))
		go func() {
			fmt.Printf("🔓 Guest subscription server listening on http://%s\n", addr)
			errCh <- http.ListenAndServe(addr, guestMux)
		}()
	}

	return <-errCh
}

func httpAdminSubHandler(admin config.AdminSubConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/sub/")
		if token == "" {
			http.Error(w, "Token required", http.StatusBadRequest)
			return
		}

		cfg, err := config.LoadConfig()
		if err != nil {
			http.Error(w, "Failed to load config", http.StatusInternalServerError)
			return
		}

		if admin.Token != "" && admin.Token == token {
			handleAdminSubRequest(w, cfg, admin)
			return
		}

		var legacySub config.Subscription
		found := false
		for _, s := range cfg.Subscriptions {
			if s.Token == token {
				legacySub = s
				found = true
				break
			}
		}

		if !found {
			http.Error(w, "Invalid token", http.StatusNotFound)
			return
		}
		handleLegacySubscriptionRequest(w, cfg, legacySub)
	}
}

func handleAdminSubRequest(w http.ResponseWriter, cfg *config.UserConfig, admin config.AdminSubConfig) {
	addr := admin.Address
	if addr == "" {
		addr = utils.GetSmartIP(false)
	}
	if admin.IPv6Rotation != "" {
		rotated, err := ipv6rotate.Next(ipv6rotate.SocketPath(admin.IPv6Rotation))
		if err != nil {
			log.Printf("IPv6 rotation error: %v", err)
			http.Error(w, "IPv6 rotation unavailable", http.StatusServiceUnavailable)
			return
		}
		addr = rotated
	}

	links := generateSubscriptionLinks(cfg, admin.TargetType, admin.TargetAlias, addr)
	if len(links) == 0 {
		http.Error(w, "No links generated for this subscription", http.StatusInternalServerError)
		return
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(encoded))
}

func handleLegacySubscriptionRequest(w http.ResponseWriter, cfg *config.UserConfig, sub config.Subscription) {
	addr := sub.Address
	if addr == "" {
		addr = utils.GetSmartIP(false)
	}
	links := generateSubscriptionLinks(cfg, sub.TargetType, sub.TargetAlias, addr)
	if len(links) == 0 {
		http.Error(w, "No links generated for this subscription", http.StatusInternalServerError)
		return
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(encoded))
}

func generateSubscriptionLinks(cfg *config.UserConfig, targetType string, targetAlias string, addr string) []string {
	switch targetType {
	case "direct":
		return xray.GenerateLinks(cfg, addr)
	case "outbound":
		var targetOutbound *config.CustomOutbound
		for _, o := range cfg.CustomOutbounds {
			if o.Alias == targetAlias {
				targetOutbound = &o
				break
			}
		}
		if targetOutbound != nil {
			return xray.GenerateRelayLinks(cfg, addr, *targetOutbound)
		}
	case "guest":
		var targetGuest *config.GuestConfig
		for _, g := range cfg.Guests {
			if g.Alias == targetAlias {
				targetGuest = &g
				break
			}
		}
		if targetGuest != nil {
			return xray.GenerateGuestLinks(cfg, addr, targetGuest.UUID, targetGuest.Alias)
		}
	}
	return nil
}

func httpGuestSubHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/guest-sub/")
		if token == "" {
			http.Error(w, "Token required", http.StatusBadRequest)
			return
		}

		cfg, err := config.LoadConfig()
		if err != nil {
			http.Error(w, "Failed to load config", http.StatusInternalServerError)
			return
		}

		var targetGuest *config.GuestConfig
		for i := range cfg.Guests {
			if cfg.Guests[i].SubToken == token {
				targetGuest = &cfg.Guests[i]
				break
			}
		}
		if targetGuest == nil {
			http.Error(w, "Invalid token", http.StatusNotFound)
			return
		}

		addr := resolveGuestSubAddress(r)
		links := xray.GenerateGuestLinks(cfg, addr, targetGuest.UUID, targetGuest.Alias)
		if len(links) == 0 {
			http.Error(w, "No links generated for this guest", http.StatusInternalServerError)
			return
		}

		notifyMode := targetGuest.NormalizedNotifyMode()
		now := time.Now()

		if notifyMode == config.GuestNotifyHeader || notifyMode == config.GuestNotifyAll {
			totalBytes := targetGuest.EffectiveLimitBytes()
			if totalBytes < 0 {
				totalBytes = 0
			}
			expire := targetGuest.NextResetTimestamp(now)
			w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=0; download=%d; total=%d; expire=%d", targetGuest.UsedBytes, totalBytes, expire))
			w.Header().Set("Profile-Update-Interval", "12")
			w.Header().Set("Profile-Title", fmt.Sprintf("Guest-%s", targetGuest.Alias))
		}

		if notifyMode == config.GuestNotifyRemark || notifyMode == config.GuestNotifyAll {
			memorialNode := GenerateMemorialShadowsocksNode(*targetGuest, now)
			links = append([]string{memorialNode}, links...)
		}

		encoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(encoded))
	}
}

func resolveGuestSubAddress(r *http.Request) string {
	for _, header := range []string{"X-Forwarded-Host", "X-Original-Host"} {
		if value := strings.TrimSpace(r.Header.Get(header)); value != "" {
			if host := normalizeRequestHost(strings.Split(value, ",")[0]); host != "" {
				return host
			}
		}
	}
	if host := normalizeRequestHost(r.Host); host != "" {
		return host
	}
	return utils.GetSmartIP(false)
}

func normalizeRequestHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "[") {
		if host, _, err := net.SplitHostPort(raw); err == nil {
			return strings.Trim(host, "[]")
		}
		return strings.Trim(raw, "[]")
	}
	if strings.Count(raw, ":") == 1 {
		if host, _, err := net.SplitHostPort(raw); err == nil {
			return host
		}
	}
	return strings.Trim(raw, "[]")
}

func validatePrivateBindAddress(bind string) error {
	bind = strings.TrimSpace(bind)
	switch bind {
	case "", "localhost":
		return nil
	}
	ip := net.ParseIP(bind)
	if ip == nil {
		return fmt.Errorf("guest subscription bind address must be an IP or localhost: %s", bind)
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return nil
	}
	return errors.New("guest subscription bind address must be loopback or private")
}

const (
	MemorialSSCipher   = "aes-256-gcm"
	MemorialSSPassword = "jun-04-1989"
	MemorialSSAddress  = "127.0.0.1:0"
)

func GenerateMemorialShadowsocksNode(guest config.GuestConfig, now time.Time) string {
	auth := base64.StdEncoding.EncodeToString([]byte(MemorialSSCipher + ":" + MemorialSSPassword))
	remark := formatGuestSubRemark(guest, now)
	return fmt.Sprintf("ss://%s@%s#%s", auth, MemorialSSAddress, url.QueryEscape(remark))
}

func formatGuestSubRemark(guest config.GuestConfig, now time.Time) string {
	days := guest.DaysUntilReset(now)
	limitBytes := guest.EffectiveLimitBytes()
	usedGB := float64(guest.UsedBytes) / float64(config.GigaByte)
	limitGB := float64(limitBytes) / float64(config.GigaByte)
	if !guest.Enabled {
		if guest.DisabledReason == config.GuestDisabledQuotaReached {
			return fmt.Sprintf("EXPIRED: Quota Exceeded (%.2fGB / %.2fGB) | Reset in %dd", usedGB, limitGB, days)
		}
		return "PAUSED: Account Disabled"
	}
	return fmt.Sprintf("TRAFFIC: %.2fGB / %.2fGB | RESET: %dd", usedGB, limitGB, days)
}

func FormatGuestSubRemarkForDisplay(guest config.GuestConfig, now time.Time) string {
	return formatGuestSubRemark(guest, now)
}

func daysUntilReset(resetDay int, now time.Time) int {
	g := config.GuestConfig{ResetDay: resetDay}
	return g.DaysUntilReset(now)
}

func clampResetDay(resetDay int, year int, month time.Month, location *time.Location) int {
	return config.ClampResetDay(resetDay, year, month, location)
}
