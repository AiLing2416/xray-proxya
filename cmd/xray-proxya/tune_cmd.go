package main

import (
	"fmt"
	"os"
	"strings"
	"xray-proxya/internal/tune"

	"github.com/spf13/cobra"
)

func requireRoot() bool {
	if os.Geteuid() != 0 {
		fmt.Println("❌ This command requires root.")
		return false
	}
	return true
}

var tuneCmd = &cobra.Command{
	Use:   "tune",
	Short: "Apply temporary root-only kernel tuning profiles",
}

var tuneShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current kernel tuning state and runtime session info",
	Run: func(cmd *cobra.Command, args []string) {
		data := tune.ShowDataForKeys()
		fmt.Printf("Kernel: %s\n", data.KernelVersion)
		if len(data.AvailableCC) > 0 {
			fmt.Printf("Available CC: %s\n", strings.Join(data.AvailableCC, ", "))
		} else {
			fmt.Println("Available CC: N/A")
		}
		if data.RuntimeState != nil {
			fmt.Printf("Runtime Tune: %s @ %s\n", data.RuntimeState.Profile, data.RuntimeState.AppliedAt.Format("2006-01-02 15:04:05"))
		} else {
			fmt.Println("Runtime Tune: none")
		}
		fmt.Printf("\n%-40s | %-12s | %-s\n", "KEY", "STATUS", "VALUE")
		fmt.Println("------------------------------------------------------------------------------------------------")
		for _, entry := range data.Values {
			value := entry.Current
			if value == "" {
				value = "-"
			}
			if entry.Error != "" {
				value = entry.Error
			}
			fmt.Printf("%-40s | %-12s | %-s\n", entry.Key, entry.Status, value)
		}
	},
}

var tuneProfilesCmd = &cobra.Command{
	Use:   "profiles",
	Short: "List available kernel tuning profiles",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("\n%-10s | %-s\n", "PROFILE", "DESCRIPTION")
		fmt.Println("----------------------------------------------------------------")
		for _, profile := range tune.Profiles() {
			fmt.Printf("%-10s | %-s\n", profile.Name, profile.Description)
		}
		fmt.Println()
	},
}

var tuneDiffCmd = &cobra.Command{
	Use:   "diff [profile]",
	Short: "Show the current-vs-target diff for a tuning profile",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		profile, ok := tune.GetProfile(args[0])
		if !ok {
			fmt.Printf("❌ Unknown profile '%s'.\n", args[0])
			return
		}
		fmt.Printf("Profile: %s\n", profile.Name)
		fmt.Printf("Description: %s\n\n", profile.Description)
		fmt.Printf("%-40s | %-12s | %-18s | %-18s\n", "KEY", "STATUS", "CURRENT", "TARGET")
		fmt.Println("----------------------------------------------------------------------------------------------------------------")
		for _, entry := range tune.DiffProfile(profile) {
			current := entry.Current
			if current == "" {
				current = "-"
			}
			if entry.Error != "" {
				current = entry.Error
			}
			fmt.Printf("%-40s | %-12s | %-18s | %-18s\n", entry.Key, entry.Status, current, entry.Target)
		}
	},
}

var tuneApplyCmd = &cobra.Command{
	Use:   "apply [profile]",
	Short: "Apply a temporary kernel tuning profile with sysctl -w",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if !requireRoot() {
			return
		}
		profile, ok := tune.GetProfile(args[0])
		if !ok {
			fmt.Printf("❌ Unknown profile '%s'.\n", args[0])
			return
		}
		state, err := tune.ApplyProfile(profile)
		fmt.Printf("Applied profile: %s\n\n", profile.Name)
		fmt.Printf("%-40s | %-12s | %-18s | %-18s\n", "KEY", "STATUS", "OLD", "NEW")
		fmt.Println("----------------------------------------------------------------------------------------------------------------")
		for _, entry := range state.Entries {
			oldValue := entry.OldValue
			if oldValue == "" {
				oldValue = "-"
			}
			newValue := entry.NewValue
			if newValue == "" {
				newValue = "-"
			}
			if entry.Error != "" {
				newValue = entry.Error
			}
			fmt.Printf("%-40s | %-12s | %-18s | %-18s\n", entry.Key, entry.Status, oldValue, newValue)
		}
		if err != nil {
			fmt.Printf("\n⚠️  Apply completed with errors: %v\n", err)
			return
		}
		fmt.Println("\n✅ Apply completed.")
	},
}

var tuneVerifyCmd = &cobra.Command{
	Use:   "verify [profile]",
	Short: "Verify whether current kernel values match a tuning profile",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		profile, ok := tune.GetProfile(args[0])
		if !ok {
			fmt.Printf("❌ Unknown profile '%s'.\n", args[0])
			return
		}
		fmt.Printf("Profile: %s\n\n", profile.Name)
		fmt.Printf("%-40s | %-12s | %-18s | %-18s\n", "KEY", "STATUS", "CURRENT", "TARGET")
		fmt.Println("----------------------------------------------------------------------------------------------------------------")
		mismatch := false
		for _, entry := range tune.VerifyProfile(profile) {
			current := entry.Current
			if current == "" {
				current = "-"
			}
			if entry.Error != "" {
				current = entry.Error
			}
			if entry.Status != "ok" {
				mismatch = true
			}
			fmt.Printf("%-40s | %-12s | %-18s | %-18s\n", entry.Key, entry.Status, current, entry.Target)
		}
		if mismatch {
			fmt.Println("\n⚠️  Profile is not fully active.")
			return
		}
		fmt.Println("\n✅ Profile is active.")
	},
}

var tuneRollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Rollback the last tune apply session using recorded old values",
	Run: func(cmd *cobra.Command, args []string) {
		if !requireRoot() {
			return
		}
		state, err := tune.LoadRuntimeState()
		if err != nil {
			fmt.Println("❌ No runtime tune state found. Reboot is the only guaranteed reset.")
			return
		}
		results, rollbackErr := tune.RollbackRuntimeState(state)
		fmt.Printf("Rollback profile: %s\n\n", state.Profile)
		fmt.Printf("%-40s | %-12s | %-18s | %-18s\n", "KEY", "STATUS", "CURRENT", "TARGET")
		fmt.Println("----------------------------------------------------------------------------------------------------------------")
		for _, entry := range results {
			current := entry.OldValue
			if current == "" {
				current = "-"
			}
			target := entry.NewValue
			if target == "" {
				target = "-"
			}
			if entry.Error != "" {
				target = entry.Error
			}
			fmt.Printf("%-40s | %-12s | %-18s | %-18s\n", entry.Key, entry.Status, current, target)
		}
		if rollbackErr != nil {
			fmt.Printf("\n⚠️  Rollback completed with errors: %v\n", rollbackErr)
			return
		}
		fmt.Println("\n✅ Rollback completed.")
	},
}

func init() {
	profileCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return tune.ProfileNames(), cobra.ShellCompDirectiveNoFileComp
	}

	tuneDiffCmd.ValidArgsFunction = profileCompletion
	tuneApplyCmd.ValidArgsFunction = profileCompletion
	tuneVerifyCmd.ValidArgsFunction = profileCompletion

	tuneCmd.AddCommand(tuneShowCmd, tuneProfilesCmd, tuneDiffCmd, tuneApplyCmd, tuneVerifyCmd, tuneRollbackCmd)
	rootCmd.AddCommand(tuneCmd)
}
