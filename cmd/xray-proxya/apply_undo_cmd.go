package main

import (
	"fmt"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	"xray-proxya/internal/presets"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

var (
	forceApply bool
)

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Validate and commit changes from STAGING to production",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfigEx(true)
		if err != nil {
			fmt.Println("❌ No pending changes in STAGING.")
			return
		}

		if err := presets.RegenerateMarkedModes(cfg); err != nil {
			fmt.Printf("❌ Failed to regenerate preset secrets: %v\n", err)
			return
		}

		if !forceApply {
			fmt.Println("🔍 Stage 1: Static Validation...")
			jsonData, _ := xray.GenerateXrayJSON(cfg, nil, "")
			if err := xray.ValidateConfig(jsonData); err != nil {
				fmt.Printf("❌ Static validation failed: %v\n", err)
				return
			}
			fmt.Println("✅ Syntax OK.")

			fmt.Println("🔍 Stage 2: Runtime Isolation Test...")
			testSocksPort, _ := xray.GetFreePort()
			apiPort, _ := xray.GetFreePort()

			// For all preset modes, if they conflict with main service, we use random ports for the TEST
			overrides := map[string]int{"test-socks": testSocksPort, "api": apiPort}
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
		} else {
			fmt.Println("⚠️  Skipping validation due to --force flag.")
		}

		fmt.Println("🚀 Stage 3: Committing changes...")
		if err := config.CommitStaging(); err != nil {
			fmt.Printf("❌ Failed to commit: %v\n", err)
			return
		}

		fmt.Println("🔄 Restarting Xray service...")
		if err := xray.RestartXrayService(); err != nil {
			fmt.Printf("❌ Error restarting service: %v\n", err)
		}

		fmt.Println("✅ All changes applied and service updated.")

		// Apply gateway rules if needed
		newCfg, _ := config.LoadConfig()
		if newCfg != nil && (newCfg.Role == config.RoleGateway) {
			fmt.Println("🛡️  Synchronizing transparent gateway rules...")
			gateway.SyncFirewall(newCfg)
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
	rootCmd.AddCommand(applyCmd, undoCmd)
}
