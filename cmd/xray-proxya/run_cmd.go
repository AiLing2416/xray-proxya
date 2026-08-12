package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	"xray-proxya/internal/pathd"
	"xray-proxya/internal/pathtun"
	"xray-proxya/internal/quota"
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
	Run: func(cmd *cobra.Command, args []string) {
		if _, err := os.Stat(config.GetConfigPath()); os.IsNotExist(err) {
			fmt.Println("❌ Error: Xray-Proxya has not been initialized. Please run 'xray-proxya init' first.")
			os.Exit(1)
		}

		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Printf("❌ Failed to load config: %v\n", err)
			os.Exit(1)
		}

		// v0.2.4 Port Policy:
		// By default (especially as a service), we are STRICT.
		// We only allow port drift if --audit is explicitly provided.
		changed := false
		auditPort := func(label string, current *int) {
			if *current <= 0 {
				return
			}
			if !utils.IsPortFree(*current) {
				if runAudit {
					newP, _ := xray.GetFreePort()
					fmt.Printf("⚠️  Warning: %s Port %d occupied, switched to %d\n", label, *current, newP)
					*current = newP
					changed = true
				} else {
					fmt.Printf("❌ Error: %s Port %d is occupied. Use --audit to allow dynamic port selection.\n", label, *current)
					os.Exit(1)
				}
			}
		}

		auditPort("API", &cfg.APIInbound)
		for i := range cfg.Presets {
			if cfg.Presets[i].Enabled {
				auditPort(string(cfg.Presets[i].Mode), &cfg.Presets[i].Port)
			}
		}

		if changed {
			cfg.Save()
		}

		confPath := filepath.Join(config.GetConfigDir(), "config.active.json")
		overrides := make(map[string]int)
		pathdPort := 0
		gatewayState := cfg.Gateway.State
		if gatewayState == "" {
			gatewayState = "proxy"
		}
		pathdEnabled := cfg.Role == config.RoleGateway &&
			gatewayState == "proxy" &&
			(cfg.Gateway.LocalEnabled || cfg.Gateway.LANEnabled) &&
			cfg.Gateway.RelayAlias != "" && !config.GatewayTunDisabled() &&
			cfg.Path.Enabled && cfg.Path.Token != ""
		if pathdEnabled {
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

		var pathTunManager *pathtun.Manager
		var pathClient *pathd.IdleClient
		var pathRuntimeStop chan struct{}
		cleanup := func() {
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
			fmt.Printf("❌ Failed to start Xray: %v\n", err)
			return
		}
		if pathdEnabled {
			idle := time.Duration(cfg.Path.IdleSeconds) * time.Second
			if idle <= 0 {
				idle = 15 * time.Second
			}
			pathTarget := cfg.Path.Listen
			if pathTarget == "" {
				pathTarget = "127.0.0.1:39091"
			}
			pathClient = pathd.NewIdleClient(fmt.Sprintf("127.0.0.1:%d", pathdPort), pathTarget, cfg.Path.Token, idle)
			pathTunManager, err = pathtun.Start(func(destination net.IP, ttl int, echoData []byte, dontFragment bool) pathd.ProbeResult {
				result, err := pathClient.RelayEcho(destination, ttl, echoData, dontFragment)
				if err != nil {
					return pathd.ProbeResult{}
				}
				return result
			})
			if err != nil {
				fmt.Printf("⚠️  PathLink disabled: %v\n", err)
			} else {
				if pathTunManager != nil {
					fmt.Printf("📡 ICMP PathLink TUN enabled through relay %s\n", cfg.Gateway.RelayAlias)
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
		if err := gateway.RestoreTunState(cfg); err != nil {
			fmt.Printf("❌ Failed to restore gateway runtime state: %v\n", err)
			_ = stopProcess(process, waitCh)
			cleanup()
			return
		}

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigChan)
		quotaTicker := time.NewTicker(guestQuotaCheckInterval)
		defer quotaTicker.Stop()

		for {
			select {
			case sig := <-sigChan:
				fmt.Printf("\n🛑 Stopping Xray (%s)...\n", sig)
				_ = stopProcess(process, waitCh)
				cleanup()
				return
			case err := <-waitCh:
				cleanup()
				if err != nil {
					fmt.Printf("\n❌ Xray core exited unexpectedly: %v\n", err)
					if exitErr, ok := err.(*exec.ExitError); ok {
						if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
							os.Exit(status.ExitStatus())
						}
					}
					os.Exit(1)
				}
				fmt.Println("\nℹ️ Xray core exited normally.")
				return
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
						return
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
