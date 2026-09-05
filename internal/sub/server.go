package sub

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
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
	mux := http.NewServeMux()
	mux.HandleFunc("/", httpUnifiedSubHandler(instance.AdminSub))

	addr := net.JoinHostPort(listen, strconv.Itoa(instance.Port))
	fmt.Printf("🔓 Subscription server listening on http://%s\n", addr)
	return http.ListenAndServe(addr, mux)
}

func httpUnifiedSubHandler(admin config.AdminSubConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.Trim(r.URL.Path, "/")
		if token == "" {
			http.NotFound(w, r)
			return
		}

		cfg, err := config.LoadConfig()
		if err != nil {
			http.Error(w, "Failed to load config", http.StatusInternalServerError)
			return
		}

		// 1. Match Admin Token
		adminToken := admin.Token
		if adminToken == "" {
			adminToken = cfg.AdminSub.Token
		}
		if adminToken != "" && adminToken == token {
			handleAdminSubRequest(w, cfg, admin)
			return
		}

		// 2. Match Guest UUID (or SubToken)
		for i := range cfg.Guests {
			g := &cfg.Guests[i]
			if (g.UUID != "" && g.UUID == token) || (g.SubToken != "" && g.SubToken == token) {
				handleGuestSubRequest(w, cfg, g)
				return
			}
		}

		// 3. Match legacy custom subscriptions
		for _, s := range cfg.Subscriptions {
			if s.Token != "" && s.Token == token {
				handleLegacySubscriptionRequest(w, cfg, s)
				return
			}
		}

		// 4. Not found
		http.NotFound(w, r)
	}
}

func handleAdminSubRequest(w http.ResponseWriter, cfg *config.UserConfig, admin config.AdminSubConfig) {
	addr := ResolveNodeAddress(cfg, admin.AddressNode)
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

func handleGuestSubRequest(w http.ResponseWriter, cfg *config.UserConfig, guest *config.GuestConfig) {
	now := time.Now()

	// If guest is disabled by admin, ONLY output the memorial node
	if !guest.Enabled {
		memorialNode := GenerateMemorialShadowsocksNodeWithRemark(*guest, fmt.Sprintf("%s is disabled", guest.Alias))
		encoded := base64.StdEncoding.EncodeToString([]byte(memorialNode))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(encoded))
		return
	}

	// Guest is enabled: output regular proxy nodes
	addr := ResolveNodeAddress(cfg, guest.OutboundLink)
	links := xray.GenerateGuestLinks(cfg, addr, guest.UUID, guest.Alias)
	if len(links) == 0 {
		http.Error(w, "No links generated for this guest", http.StatusInternalServerError)
		return
	}

	notifyMode := guest.NormalizedNotifyMode()
	if notifyMode == config.GuestNotifyHeader || notifyMode == config.GuestNotifyAll {
		totalBytes := guest.EffectiveLimitBytes()
		if totalBytes < 0 {
			totalBytes = 0
		}
		expire := guest.NextResetTimestamp(now)
		w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=0; download=%d; total=%d; expire=%d", guest.UsedBytes, totalBytes, expire))
		w.Header().Set("Profile-Update-Interval", "12")
		w.Header().Set("Profile-Title", fmt.Sprintf("Guest-%s", guest.Alias))
	}

	if notifyMode == config.GuestNotifyRemark || notifyMode == config.GuestNotifyAll {
		memorialNode := GenerateMemorialShadowsocksNode(*guest, now)
		links = append([]string{memorialNode}, links...)
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(encoded))
}

func handleLegacySubscriptionRequest(w http.ResponseWriter, cfg *config.UserConfig, sub config.Subscription) {
	addr := ResolveNodeAddress(cfg, sub.Address)
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

func ResolveNodeAddress(cfg *config.UserConfig, override ...string) string {
	if len(override) > 0 && strings.TrimSpace(override[0]) != "" {
		return strings.TrimSpace(override[0])
	}
	if cfg != nil {
		if addr := strings.TrimSpace(cfg.AddressNode); addr != "" {
			return addr
		}
		if addr := strings.TrimSpace(cfg.AdminSub.AddressNode); addr != "" {
			return addr
		}
		if addr := strings.TrimSpace(cfg.AdminSub.Address); addr != "" {
			return addr
		}
		if addr := strings.TrimSpace(cfg.GuestSubAddress); addr != "" {
			return addr
		}
	}
	return utils.GetSmartIP(false)
}

func ResolveSubAddress(cfg *config.UserConfig, override ...string) string {
	if len(override) > 0 && strings.TrimSpace(override[0]) != "" {
		return strings.TrimSpace(override[0])
	}
	if cfg != nil {
		if addr := strings.TrimSpace(cfg.AddressSub); addr != "" {
			return addr
		}
		if addr := strings.TrimSpace(cfg.AdminSub.AddressSub); addr != "" {
			return addr
		}
		if addr := strings.TrimSpace(cfg.AdminSub.Address); addr != "" {
			return addr
		}
		if addr := strings.TrimSpace(cfg.GuestSubAddress); addr != "" {
			return addr
		}
	}
	return utils.GetSmartIP(false)
}

func FormatSubURL(hostOrURL string, port int, tokenOrUUID string) string {
	raw := strings.TrimSpace(hostOrURL)
	if raw == "" {
		raw = utils.GetSmartIP(false)
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		u, err := url.Parse(raw)
		if err == nil {
			u.Path = path.Join(u.Path, tokenOrUUID)
			return u.String()
		}
	}
	hostPart := raw
	if _, _, err := net.SplitHostPort(hostPart); err != nil && port > 0 {
		hostPart = net.JoinHostPort(hostPart, strconv.Itoa(port))
	}
	return fmt.Sprintf("http://%s/%s", hostPart, tokenOrUUID)
}

func ValidatePrivateBindAddress(bind string) error {
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
	MemorialSSAddress  = "127.0.0.1:1"
)

func GenerateMemorialShadowsocksNodeWithRemark(guest config.GuestConfig, remark string) string {
	auth := base64.StdEncoding.EncodeToString([]byte(MemorialSSCipher + ":" + MemorialSSPassword))
	return fmt.Sprintf("ss://%s@%s#%s", auth, MemorialSSAddress, url.PathEscape(remark))
}

func GenerateMemorialShadowsocksNode(guest config.GuestConfig, now time.Time) string {
	remark := formatGuestSubRemark(guest, now)
	return GenerateMemorialShadowsocksNodeWithRemark(guest, remark)
}

func formatGuestSubRemark(guest config.GuestConfig, now time.Time) string {
	if !guest.Enabled {
		return fmt.Sprintf("%s is disabled", guest.Alias)
	}
	days := guest.DaysUntilReset(now)
	limitBytes := guest.EffectiveLimitBytes()
	usedStr := config.FormatByteSize(guest.UsedBytes)
	limitStr := config.FormatByteSize(limitBytes)
	if limitBytes > 0 && guest.UsedBytes >= limitBytes {
		return fmt.Sprintf("EXPIRED: Quota Exceeded (%s / %s) | Reset in %dd", usedStr, limitStr, days)
	}
	return fmt.Sprintf("TRAFFIC: %s / %s | RESET: %dd", usedStr, limitStr, days)
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
