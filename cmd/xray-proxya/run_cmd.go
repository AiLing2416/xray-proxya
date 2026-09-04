package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"xray-proxya/internal/certmanager"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	"xray-proxya/internal/pathd"
	"xray-proxya/internal/pathtun"
	"xray-proxya/internal/quota"
	proxyaSELinux "xray-proxya/internal/selinux"
	"xray-proxya/internal/skin"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	runAudit bool
)

const guestQuotaCheckInterval = 6 * time.Hour

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run Xray core in foreground",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := os.Stat(config.GetConfigPath()); os.IsNotExist(err) {
			return fmt.Errorf("Xray-Proxya has not been initialized; run 'xray-proxya init' first")
		}

		cfg, err := config.LoadConfig()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		// v0.2.4 Port Policy:
		// By default (especially as a service), we are STRICT.
		// We only allow port drift if --audit is explicitly provided.
		changed := false
		auditPort := func(label string, current *int) error {
			if *current <= 0 {
				return nil
			}
			if !utils.IsPortFree(*current) {
				if runAudit {
					newP, _ := xray.GetFreePort()
					fmt.Printf("⚠️  Warning: %s Port %d occupied, switched to %d\n", label, *current, newP)
					*current = newP
					changed = true
				} else {
					return fmt.Errorf("%s port %d is occupied; use --audit to allow dynamic port selection", label, *current)
				}
			}
			return nil
		}

		if err := auditPort("API", &cfg.APIInbound); err != nil {
			return err
		}
		for i := range cfg.Presets {
			if cfg.Presets[i].Enabled {
				if err := auditPort(string(cfg.Presets[i].Mode), &cfg.Presets[i].Port); err != nil {
					return err
				}
			}
		}

		if changed {
			if err := cfg.Save(); err != nil {
				return fmt.Errorf("save audited config: %w", err)
			}
		}

		confPath := filepath.Join(config.GetConfigDir(), "config.active.json")
		overrides := make(map[string]int)
		pathdPort := 0
		gatewayState := cfg.Gateway.State
		if gatewayState == "" {
			gatewayState = "proxy"
		}
		pathEndpoint, pathRelayAlias, pathErr := selectedGatewayPath(cfg)
		pathdEnabled := pathErr == nil && gatewayState == "proxy" && !config.GatewayTunDisabled()
		if cfg.Role == config.RoleGateway && gatewayState == "proxy" &&
			(cfg.Gateway.LocalEnabled || cfg.Gateway.LANEnabled) && cfg.Gateway.RelayAlias != "" &&
			!config.GatewayTunDisabled() && pathErr != nil {
			fmt.Printf("ℹ️  PathLink unavailable for relay %s: %v\n", cfg.Gateway.RelayAlias, pathErr)
		}
		if pathdEnabled {
			// Retry PathLink when the service is restarted.  If allocation fails,
			// the marker below makes the gateway omit only its optional ICMP path.
			if err := config.SetPathTunDisabled(false); err != nil {
				return fmt.Errorf("clear PathLink runtime state: %w", err)
			}
			port, err := xray.GetFreePort()
			if err != nil {
				fmt.Printf("⚠️  PathLink disabled: allocate SOCKS port: %v\n", err)
				pathdEnabled = false
			} else {
				pathdPort = port
				overrides["pathd-socks"] = port
			}
		}
		if cfg.Role == config.RoleGateway && config.GatewayTunDisabled() {
			overrides["gateway-tun-disabled"] = 1
		}
		quotaMonitor, err := quota.LoadMonitor()
		if err != nil {
			fmt.Printf("⚠️  Failed to load quota monitor state: %v\n", err)
			quotaMonitor = quota.NewMonitor()
		}

		startProcess := func(currentCfg *config.UserConfig) (*exec.Cmd, chan error, error) {
			fmt.Println("🔍 Generating configuration...")
			jsonData, err := xray.GenerateXrayJSON(currentCfg, overrides, "")
			if err != nil {
				return nil, nil, err
			}
			if err := os.WriteFile(confPath, jsonData, 0644); err != nil {
				return nil, nil, err
			}

			fmt.Println("🚀 Starting Xray core in foreground...")
			process, err := xray.StartXray(confPath)
			if err != nil {
				return nil, nil, err
			}
			waitCh := make(chan error, 1)
			go func() {
				waitCh <- process.Wait()
			}()
			return process, waitCh, nil
		}

		stopProcess := func(process *exec.Cmd, waitCh chan error) error {
			if process == nil || process.Process == nil {
				return nil
			}
			_ = process.Process.Signal(syscall.SIGTERM)
			select {
			case err := <-waitCh:
				return err
			case <-time.After(5 * time.Second):
				_ = process.Process.Kill()
				return <-waitCh
			}
		}

		var skinServers []*http.Server
		var pathTunManager *pathtun.Manager
		var pathClient *pathd.IdleClient
		var pathRuntimeStop chan struct{}
		cleanup := func() {
			for _, s := range skinServers {
				_ = s.Close()
			}
			skinServers = nil
			if pathTunManager != nil {
				_ = pathTunManager.Close()
				pathTunManager = nil
			}
			if pathClient != nil {
				if pathRuntimeStop != nil {
					close(pathRuntimeStop)
					pathRuntimeStop = nil
				}
				_ = pathClient.Close()
				pathClient = nil
			}
			_ = os.Remove(pathRuntimePath())
		}

		process, waitCh, err := startProcess(cfg)
		if err != nil {
			return fmt.Errorf("start Xray: %w", err)
		}
		if pathdEnabled {
			idle := time.Duration(pathEndpoint.IdleSeconds) * time.Second
			if idle <= 0 {
				idle = 15 * time.Second
			}
			pathClient = pathd.NewIdleClient(fmt.Sprintf("127.0.0.1:%d", pathdPort), pathEndpoint.Listen, pathEndpoint.Token, idle)
			pathTunManager, err = pathtun.Start(func(destination net.IP, ttl int, echoData []byte, dontFragment bool) pathd.ProbeResult {
				result, err := pathClient.RelayEcho(destination, ttl, echoData, dontFragment)
				if err != nil {
					return pathd.ProbeResult{}
				}
				return result
			})
			if err != nil {
				if markerErr := config.SetPathTunDisabled(true); markerErr != nil {
					_ = stopProcess(process, waitCh)
					cleanup()
					return fmt.Errorf("create PathLink TUN: %w (record runtime state: %v)", err, markerErr)
				}
				_ = pathClient.Close()
				pathClient = nil
				fmt.Printf("⚠️  PathLink disabled for this runtime: %v\n", err)
			} else {
				if markerErr := config.SetPathTunDisabled(false); markerErr != nil {
					_ = pathTunManager.Close()
					pathTunManager = nil
					_ = pathClient.Close()
					pathClient = nil
					_ = stopProcess(process, waitCh)
					cleanup()
					return fmt.Errorf("record PathLink TUN runtime state: %w", markerErr)
				}
				if pathTunManager != nil {
					fmt.Printf("📡 ICMP PathLink TUN enabled through relay %s\n", pathRelayAlias)
				}
			}
			if pathClient != nil {
				pathRuntimeStop = make(chan struct{})
				writePathRuntime(pathClient)
				go func(client *pathd.IdleClient, stop <-chan struct{}) {
					ticker := time.NewTicker(time.Second)
					defer ticker.Stop()
					for {
						select {
						case <-ticker.C:
							writePathRuntime(client)
						case <-stop:
							return
						}
					}
				}(pathClient, pathRuntimeStop)
			}
		}
		// The long-running service must not acquire MAC-transition privileges
		// merely to repair gateway state. Under enforcing SELinux, gateway up,
		// down, and root-initiated restarts delegate those mutations to the
		// short-lived xray_proxya_gateway_t domain. A direct service start is
		// intentionally limited to starting Xray/TUN; the operator then runs
		// `gateway up` to install interception rules.
		if !(cfg.Role == config.RoleGateway && proxyaSELinux.IsEnforcing() && !proxyaSELinux.InGatewayDomain()) {
			if err := gateway.RestoreTunState(cfg); err != nil {
				fmt.Printf("❌ Failed to restore gateway runtime state: %v\n", err)
				_ = stopProcess(process, waitCh)
				cleanup()
				return fmt.Errorf("restore gateway runtime state: %w", err)
			}
		}

		// Start Web skin servers only for presets that have a skin explicitly configured
		var skinMappings []skin.DomainSkinMapping
		for _, m := range cfg.Presets {
			if !m.Enabled || m.Skin == "" {
				continue
			}
			domain := m.SkinDomain
			if domain == "" {
				domain = m.SNI
			}
			if domain == "" {
				continue
			}
			alreadyMapped := false
			for _, sm := range skinMappings {
				if sm.Domain == domain {
					alreadyMapped = true
					break
				}
			}
			if !alreadyMapped {
				cert := cfg.FindCert(domain)
				certPath, keyPath := "", ""
				if cert != nil {
					certPath, keyPath = cert.CertPath, cert.KeyPath
				}
				skinMappings = append(skinMappings, skin.DomainSkinMapping{
					Domain:   domain,
					SkinType: m.Skin,
					CertPath: certPath,
					KeyPath:  keyPath,
				})
			}
		}

		if len(skinMappings) > 0 {
			defaultSkin := skinMappings[0].SkinType
			srv, err := skin.StartMultiSkinServer("127.0.0.1:9443", skinMappings, defaultSkin)
			if err == nil {
				skinServers = append(skinServers, srv)
				go func(s *http.Server) { _ = s.ListenAndServeTLS("", "") }(srv)
				domains := make([]string, 0, len(skinMappings))
				for _, sm := range skinMappings {
					domains = append(domains, fmt.Sprintf("%s (%s)", sm.Domain, sm.SkinType))
				}
				fmt.Printf("🎨 Web Skin HTTPS server listening on 127.0.0.1:9443 for: %s\n", strings.Join(domains, ", "))
			} else {
				fmt.Printf("⚠️  Failed to start Web Skin HTTPS server: %v\n", err)
			}

			// Start port 80 HTTP -> HTTPS redirect server with ACME challenge delegation
			httpRedirectServer := &http.Server{
				Addr: ":80",
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if certmanager.HandleChallenge(w, r) {
						return
					}
					host := r.Host
					if h, _, err := net.SplitHostPort(host); err == nil {
						host = h
					}
					target := "https://" + host + r.URL.RequestURI()
					http.Redirect(w, r, target, http.StatusMovedPermanently)
				}),
			}
			if ln, err := net.Listen("tcp", ":80"); err == nil {
				skinServers = append(skinServers, httpRedirectServer)
				go func() { _ = httpRedirectServer.Serve(ln) }()
				fmt.Println("🌐 Port 80 HTTP -> HTTPS redirect listener started")
			} else {
				fmt.Printf("⚠️  Port 80 redirect listener not started: %v\n", err)
			}
		}

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigChan)
		quotaTicker := time.NewTicker(guestQuotaCheckInterval)
		defer quotaTicker.Stop()
		certTicker := time.NewTicker(12 * time.Hour)
		defer certTicker.Stop()

		for {
			select {
			case <-certTicker.C:
				renewed, expiredFailed, err := certmanager.CheckAndRenewCerts(cfg, false)
				if err != nil {
					fmt.Printf("⚠️  Cert auto-renewal check error: %v\n", err)
				}
				for _, d := range renewed {
					fmt.Printf("✅ Auto-renewed certificate for %s\n", d)
				}
				for _, d := range expiredFailed {
					fmt.Printf("🚨 Alert: Certificate for %s expired and renewal failed. Dependent presets disabled.\n", d)
				}
				if len(renewed) > 0 || len(expiredFailed) > 0 {
					_ = cfg.Save()
				}
			case sig := <-sigChan:
				fmt.Printf("\n🛑 Stopping Xray (%s)...\n", sig)
				_ = stopProcess(process, waitCh)
				cleanup()
				return nil
			case err := <-waitCh:
				cleanup()
				if err != nil {
					fmt.Printf("\n❌ Xray core exited unexpectedly: %v\n", err)
					return fmt.Errorf("Xray core exited unexpectedly: %w", err)
				}
				fmt.Println("\nℹ️ Xray core exited normally.")
				return nil
			case <-quotaTicker.C:
				reloadedCfg, err := config.LoadConfig()
				if err != nil {
					fmt.Printf("⚠️  Failed to reload config for guest quota check: %v\n", err)
					continue
				}
				cfg = reloadedCfg

				update, err := checkGuestQuotaState(cfg, quotaMonitor, time.Now())
				if err != nil {
					fmt.Printf("⚠️  Guest quota check failed: %v\n", err)
					continue
				}
				if !update.Changed {
					continue
				}
				if update.RestartNeeded {
					for _, msg := range update.Messages {
						fmt.Printf("ℹ️  Guest quota: %s\n", msg)
					}
					fmt.Println("🔄 Reloading Xray to apply guest quota changes...")
					restartErr := config.WithLifecycleLock(func() error {
						_ = stopProcess(process, waitCh)
						quotaMonitor.Reset()
						if err := quotaMonitor.Save(); err != nil {
							fmt.Printf("⚠️  Failed to reset quota monitor state: %v\n", err)
						}
						process, waitCh, err = startProcess(cfg)
						if err != nil {
							return fmt.Errorf("restart Xray after quota update: %w", err)
						}
						return gateway.RestoreTunStateLocked(cfg)
					})
					if restartErr != nil {
						fmt.Printf("❌ Failed to restart Xray after quota update: %v\n", restartErr)
						_ = stopProcess(process, waitCh)
						cleanup()
						return fmt.Errorf("restart Xray after quota update: %w", restartErr)
					}
				}
			}
		}
	},
}

func init() {
	runCmd.Flags().BoolVar(&runAudit, "audit", false, "Enable dynamic port negotiation if configured ports are occupied")
	rootCmd.AddCommand(runCmd)
}
