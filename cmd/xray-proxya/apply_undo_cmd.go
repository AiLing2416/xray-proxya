package main

import (
	"fmt"
	"xray-proxya/internal/config"
	"xray-proxya/internal/presets"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

var (
	forceApply bool
	fullApply  bool
)

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Validate and commit staged changes with selective restart",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.StagingExists() {
			fmt.Println("❌ No pending changes in STAGING.")
			return
		}
		activeCfg, err := config.LoadConfigEx(false)
		if err != nil {
			activeCfg = nil
		}
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			fmt.Printf("❌ Failed to load STAGING config: %v\n", err)
			return
		}

		if err := presets.RegenerateMarkedModes(cfg); err != nil {
			fmt.Printf("❌ Failed to regenerate preset secrets: %v\n", err)
			return
		}
		if err := cfg.SaveEx(true); err != nil {
			fmt.Printf("❌ Failed to persist regenerated STAGING config: %v\n", err)
			return
		}

		impact := buildApplyImpact(activeCfg, cfg)
		validateXray := fullApply || impact.XrayConfigChanged

		if !forceApply && validateXray {
			testOverrides := map[string]int{"gateway-tun-disabled": 1}
			fmt.Println("🔍 Stage 1: Static Validation...")
			jsonData, _ := xray.GenerateXrayJSON(cfg, testOverrides, "")
			if err := xray.ValidateConfig(jsonData); err != nil {
				fmt.Printf("❌ Static validation failed: %v\n", err)
				return
			}
			fmt.Println("✅ Syntax OK.")

			fmt.Println("🔍 Stage 2: Runtime Isolation Test...")
			testSocksPort, _ := xray.GetFreePort()
			apiPort, _ := xray.GetFreePort()

			// For all preset modes, if they conflict with main service, we use random ports for the TEST
			overrides := map[string]int{"test-socks": testSocksPort, "api": apiPort, "gateway-tun-disabled": 1}
			for _, m := range cfg.ActiveModes {
				if m.Enabled {
					p, _ := xray.GetFreePort()
					overrides[string(m.Mode)] = p
				}
			}

			testJson, _ := xray.GenerateXrayJSON(cfg, overrides, "")

			_, cleanup, err := xray.StartXrayTemp(testJson)
			if err != nil {
				fmt.Printf("❌ Runtime isolation test failed: %v\n", err)
				return
			}
			cleanup()
			fmt.Println("✅ Runtime isolation test passed (using randomized ports).")
		} else if forceApply {
			fmt.Println("⚠️  Skipping validation due to --force flag.")
		} else {
			fmt.Println("ℹ️  No Xray-facing changes detected; skipping Xray validation.")
		}

		fmt.Println("🚀 Stage 3: Committing changes...")
		if err := config.CommitStaging(); err != nil {
			fmt.Printf("❌ Failed to commit: %v\n", err)
			return
		}

		if len(impact.ChangedSections) > 0 {
			fmt.Printf("ℹ️  Changed sections: %v\n", impact.ChangedSections)
		}

		xrayRestarted := false
		if fullApply || impact.XrayConfigChanged {
			fmt.Println("🔄 Restarting Xray service...")
			if err := xray.RestartXrayService(); err != nil {
				fmt.Printf("❌ Error restarting Xray service: %v\n", err)
			} else {
				xrayRestarted = true
			}
		} else {
			fmt.Println("ℹ️  Xray restart skipped: no Xray-facing changes detected.")
		}

		if fullApply || impact.SubListenerChanged {
			if hasSubServiceInstalled() {
				fmt.Println("🔄 Restarting subscription service...")
				if err := restartSubServiceIfInstalled(); err != nil {
					fmt.Printf("❌ Error restarting subscription service: %v\n", err)
				}
			} else if impact.SubListenerChanged {
				fmt.Println("ℹ️  Subscription listener changed, but no installed subscription service was found.")
			}
		} else if impact.SubContentChanged {
			fmt.Println("ℹ️  Subscription content updated; no restart needed because the sub server reloads config on each request.")
		}

		if !xrayRestarted && !(fullApply || impact.SubListenerChanged) {
			fmt.Println("✅ Changes committed without service restart.")
		} else {
			fmt.Println("✅ All changes applied.")
		}
		if cfg.Role == config.RoleGateway && impact.GatewayRuntimeChanged {
			fmt.Println("ℹ️  Gateway runtime rules are not changed by apply. Use 'sudo xray-proxya gateway up' when gateway system rules need updating.")
		}
	},
}

var undoCmd = &cobra.Command{
	Use:   "undo",
	Short: "Discard all pending changes in STAGING",
	Run: func(cmd *cobra.Command, args []string) {
		if err := config.ClearStaging(); err != nil {
			fmt.Printf("❌ Failed: %v\n", err)
		} else {
			fmt.Println("✅ STAGING changes discarded.")
		}
	},
}

func init() {
	applyCmd.Flags().BoolVarP(&forceApply, "force", "f", false, "Commit changes without validation")
	applyCmd.Flags().BoolVar(&fullApply, "full", false, "Run full Xray validation and restart all managed services regardless of changed sections")
	rootCmd.AddCommand(applyCmd, undoCmd)
}
