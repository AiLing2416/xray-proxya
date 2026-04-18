package sub

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"
)

var ipMutex sync.Mutex

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
				if maxLimit <= 0 { maxLimit = 6 }

				// 1. Load Assigned IPs from Cache
				cachePath := filepath.Join(config.GetConfigDir(), "ipv6_pool.cache")
				data, _ := os.ReadFile(cachePath)
				assignedIPs := []string{}
				if len(data) > 0 {
					for _, v := range strings.Split(string(data), "\n") {
						if v != "" { assignedIPs = append(assignedIPs, v) }
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
	})

	fmt.Printf("🔒 Subscription server listening on HTTPS port %d\n", port)
	return http.ListenAndServeTLS(fmt.Sprintf(":%d", port), certPath, keyPath, nil)
}
