package sub

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"
)

var ipMutex sync.Mutex

func StartSubServer(port int, guestBind string, guestPort int) error {
	certPath, keyPath, err := EnsureCertificates()
	if err != nil {
		return fmt.Errorf("failed to ensure certificates: %v", err)
	}

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/sub/", httpAdminSubHandler())

	guestMux := http.NewServeMux()
	guestMux.HandleFunc("/guest-sub/", httpGuestSubHandler())

	errCh := make(chan error, 2)

	go func() {
		fmt.Printf("🔒 Subscription server listening on HTTPS port %d\n", port)
		errCh <- http.ListenAndServeTLS(fmt.Sprintf(":%d", port), certPath, keyPath, adminMux)
	}()

	if guestPort > 0 {
		if err := validatePrivateBindAddress(guestBind); err != nil {
			return err
		}
		addr := net.JoinHostPort(guestBind, strconv.Itoa(guestPort))
		go func() {
			fmt.Printf("🔐 Guest subscription server listening on https://%s\n", addr)
			errCh <- http.ListenAndServeTLS(addr, certPath, keyPath, guestMux)
		}()
	}

	return <-errCh
}

func httpAdminSubHandler() http.HandlerFunc {
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

		var sub config.Subscription
		found := false
		for _, s := range cfg.Subscriptions {
			if s.Token == token {
				sub = s
				found = true
				break
			}
		}

		if !found {
			http.Error(w, "Invalid token", http.StatusNotFound)
			return
		}

		addr := sub.Address
		if addr == "" {
			addr = utils.GetSmartIP(false)
		}

		// IPv6 Rolling Pool Logic
		if cfg.IPv6Pool.Enabled && cfg.IPv6Pool.Subnet != "" && cfg.IPv6Pool.Interface != "" {
			newV6, err := utils.GenerateRandomIPv6(cfg.IPv6Pool.Subnet)
			if err == nil {
				ipMutex.Lock()
				maxLimit := cfg.IPv6Pool.MaxAddresses
				if maxLimit <= 0 {
					maxLimit = 6
				}

				// 1. Load Assigned IPs from Cache
				cachePath := filepath.Join(config.GetConfigDir(), "ipv6_pool.cache")
				data, _ := os.ReadFile(cachePath)
				assignedIPs := []string{}
				if len(data) > 0 {
					for _, v := range strings.Split(string(data), "\n") {
						if v != "" {
							assignedIPs = append(assignedIPs, v)
						}
					}
				}

				// 2. FIFO Rotation: If we're at the limit, remove oldest BEFORE adding new
				// Use >= because we're about to add a new one
				for len(assignedIPs) >= maxLimit && len(assignedIPs) > 0 {
					oldIP := assignedIPs[0]
					assignedIPs = assignedIPs[1:]
					fmt.Printf("♻️  Rotating IPv6: Removing oldest address %s\n", oldIP)
					utils.RemoveIPv6Addr(oldIP, cfg.IPv6Pool.Interface)
				}

				// 3. Add new address to system
				fmt.Printf("🆕 Assigning new IPv6: %s\n", newV6)
				utils.SetupIPv6Addr(newV6, cfg.IPv6Pool.Interface)
				if cfg.IPv6Pool.EnableNDP {
					utils.SetupNDPProxy(newV6, cfg.IPv6Pool.Interface)
				}
				assignedIPs = append(assignedIPs, newV6)

				// 4. Persist updated cache
				os.WriteFile(cachePath, []byte(strings.Join(assignedIPs, "\n")), 0600)

				ipMutex.Unlock()
				addr = newV6
			}
		}

		var links []string
		switch sub.TargetType {
		case "direct":
			links = xray.GenerateLinks(cfg, addr)
		case "outbound":
			var targetOutbound *config.CustomOutbound
			for _, o := range cfg.CustomOutbounds {
				if o.Alias == sub.TargetAlias {
					targetOutbound = &o
					break
				}
			}
			if targetOutbound != nil {
				links = xray.GenerateRelayLinks(cfg, addr, *targetOutbound)
			}
		case "guest":
			var targetGuest *config.GuestConfig
			for _, g := range cfg.Guests {
				if g.Alias == sub.TargetAlias {
					targetGuest = &g
					break
				}
			}
			if targetGuest != nil {
				links = xray.GenerateGuestLinks(cfg, addr, targetGuest.UUID, targetGuest.Alias)
			}
		}

		if len(links) == 0 {
			http.Error(w, "No links generated for this subscription", http.StatusInternalServerError)
			return
		}

		encoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(encoded))
	}
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
