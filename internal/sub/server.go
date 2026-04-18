package sub

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"
)

func StartSubServer(port int) error {
	certPath, keyPath, err := EnsureCertificates()
	if err != nil {
		return fmt.Errorf("failed to ensure certificates: %v", err)
	}

	http.HandleFunc("/sub/", func(w http.ResponseWriter, r *http.Request) {
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

		var sub *config.Subscription
		for _, s := range cfg.Subscriptions {
			if s.Token == token {
				sub = &s
				break
			}
		}

		if sub == nil {
			http.Error(w, "Invalid token", http.StatusNotFound)
			return
		}

		addr := sub.Address
		if addr == "" {
			addr = utils.GetSmartIP(false)
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

		// IPv6 Rotation Integration
		if cfg.IPv6Pool.Enabled && cfg.IPv6Pool.Subnet != "" {
			maxV6 := cfg.IPv6Pool.MaxAddresses
			if maxV6 <= 0 {
				maxV6 = 1
			}
			for i := 0; i < maxV6; i++ {
				v6, err := utils.GenerateRandomIPv6(cfg.IPv6Pool.Subnet)
				if err != nil {
					continue
				}
				// Auto-setup NDP if enabled
				if cfg.IPv6Pool.EnableNDP && cfg.IPv6Pool.Interface != "" {
					utils.SetupIPv6Addr(v6, cfg.IPv6Pool.Interface)
				}

				var v6Links []string
				switch sub.TargetType {
				case "direct":
					v6Links = xray.GenerateLinks(cfg, v6)
				case "outbound":
					// Relay links usually depend on the specific relay node, but we can use the IPv6 as the entry point
					// This assumes Xray is listening on all interfaces including this IPv6
				case "guest":
					var targetGuest *config.GuestConfig
					for _, g := range cfg.Guests {
						if g.Alias == sub.TargetAlias {
							targetGuest = &g
							break
						}
					}
					if targetGuest != nil {
						v6Links = xray.GenerateGuestLinks(cfg, v6, targetGuest.UUID, targetGuest.Alias)
					}
				}
				links = append(links, v6Links...)
			}
		}

		if len(links) == 0 {
			http.Error(w, "No links generated for this subscription", http.StatusInternalServerError)
			return
		}

		encoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(encoded))
	})

	fmt.Printf("🔒 Subscription server listening on HTTPS port %d\n", port)
	return http.ListenAndServeTLS(fmt.Sprintf(":%d", port), certPath, keyPath, nil)
}
