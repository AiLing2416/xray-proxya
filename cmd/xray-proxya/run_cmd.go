package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	"xray-proxya/internal/camouflage"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
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

		// Ensure no background/service processes of Xray core are running
		if active, pid := xray.GetXrayStatus(); active {
			fmt.Printf("❌ Error: Xray Core is already running (PID %d) in the background. Stop the background service first.\n", pid)
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

		// Camouflage Setup
		camoPort := 0
		hasSkin := false
		for _, m := range cfg.Presets {
			if m.Enabled && m.Skin {
				hasSkin = true
				break
			}
		}
		if hasSkin {
			camoPort, _ = xray.GetFreePort()
			fmt.Printf("🎭 Starting Camouflage server (TLS) on 127.0.0.1:%d...\n", camoPort)

			// Generate temporary self-signed certs for camouflage
			certPath := filepath.Join(config.GetConfigDir(), "camo.crt")
			keyPath := filepath.Join(config.GetConfigDir(), "camo.key")
			if err := utils.GenerateSelfSignedCert(certPath, keyPath); err != nil {
				fmt.Printf("⚠️  Failed to generate camouflage certs: %v\n", err)
			}

			camoMgr := camouflage.NewManager(cfg.Presets)
			go func() {
				if err := http.ListenAndServeTLS(fmt.Sprintf("127.0.0.1:%d", camoPort), certPath, keyPath, camoMgr); err != nil {
					fmt.Printf("⚠️  Camouflage server error: %v\n", err)
				}
			}()
		}

		confPath := filepath.Join(config.GetConfigDir(), "config.active.json")
		pidPath := filepath.Join(config.GetConfigDir(), "xray.pid")
		overrides := make(map[string]int)
		if camoPort > 0 {
			overrides["camouflage"] = camoPort
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
			if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", process.Process.Pid)), 0600); err != nil {
				process.Process.Kill()
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

		cleanup := func() {
			os.Remove(pidPath)
			if cfg.Role == config.RoleGateway {
				gateway.CleanupFirewall()
			}
		}

		process, waitCh, err := startProcess(cfg)
		if err != nil {
			fmt.Printf("❌ Failed to start Xray: %v\n", err)
			return
		}

		// Apply gateway firewall & routing rules on startup if role is gateway
		if cfg.Role == config.RoleGateway {
			fmt.Println("⚙️  Applying gateway firewall and routing rules...")
			if err := gateway.ApplyFirewall(cfg); err != nil {
				fmt.Printf("⚠️  Failed to apply gateway firewall rules: %v\n", err)
			} else {
				fmt.Println("✅ Gateway firewall and routing rules applied successfully.")
			}
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
					_ = stopProcess(process, waitCh)
					quotaMonitor.Reset()
					if err := quotaMonitor.Save(); err != nil {
						fmt.Printf("⚠️  Failed to reset quota monitor state: %v\n", err)
					}
					process, waitCh, err = startProcess(cfg)
					if err != nil {
						fmt.Printf("❌ Failed to restart Xray after quota update: %v\n", err)
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
