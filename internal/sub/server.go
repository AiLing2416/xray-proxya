package sub

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
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
		remark := formatGuestSubRemark(*targetGuest, time.Now())
		links = xray.WithPrimaryRemark(links, remark)

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

func formatGuestSubRemark(guest config.GuestConfig, now time.Time) string {
	return fmt.Sprintf("%s/%s/%dd", formatGuestUsedCompact(guest.UsedBytes), formatGuestQuotaCompact(guest.QuotaGB), daysUntilReset(guest.ResetDay, now))
}

func FormatGuestSubRemarkForDisplay(guest config.GuestConfig, now time.Time) string {
	return formatGuestSubRemark(guest, now)
}

func formatGuestUsedCompact(bytes int64) string {
	return formatCompactGiB(float64(bytes) / (1024 * 1024 * 1024))
}

func formatGuestQuotaCompact(quota float64) string {
	if quota < 0 {
		return "inf"
	}
	return formatCompactGiB(quota)
}

func formatCompactGiB(value float64) string {
	switch {
	case value >= 10:
		return fmt.Sprintf("%.1fGB", value)
	case value >= 1:
		return fmt.Sprintf("%.2fGB", value)
	default:
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.3f", value), "0"), ".") + "GB"
	}
}

func daysUntilReset(resetDay int, now time.Time) int {
	if resetDay < 1 {
		resetDay = 1
	}
	location := now.Location()
	year, month, day := now.Date()
	targetYear, targetMonth := year, month
	targetDay := clampResetDay(resetDay, targetYear, targetMonth, location)
	if day > targetDay {
		nextMonth := now.AddDate(0, 1, 0)
		targetYear, targetMonth, _ = nextMonth.Date()
		targetDay = clampResetDay(resetDay, targetYear, targetMonth, location)
	}
	start := time.Date(year, month, day, 0, 0, 0, 0, location)
	target := time.Date(targetYear, targetMonth, targetDay, 0, 0, 0, 0, location)
	return int(target.Sub(start).Hours() / 24)
}

func clampResetDay(resetDay int, year int, month time.Month, location *time.Location) int {
	lastDay := time.Date(year, month+1, 0, 0, 0, 0, 0, location).Day()
	if resetDay > lastDay {
		return lastDay
	}
	return resetDay
}
