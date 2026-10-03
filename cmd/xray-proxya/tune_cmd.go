package main

import (
	"fmt"
	"strings"
	"xray-proxya/internal/tune"
	"xray-proxya/internal/ui"
	"xray-proxya/pkg/utils"

	"github.com/spf13/cobra"
)

func formatTuneStatus(status string, colorEnabled bool) string {
	switch strings.ToLower(status) {
	case "ok", "applied", "rolled_back":
		return ui.Green(status, colorEnabled)
	case "diff", "suboptimal", "skipped", "unsupported":
		return ui.Yellow(status, colorEnabled)
	case "failed", "error":
		return ui.Red(status, colorEnabled)
	default:
		return status
	}
}

func requireRoot() bool {
	if err := utils.RequireRootOnly("tune"); err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

var tuneCmd = &cobra.Command{
	Use:   "tune",
	Short: "Manage root-only kernel tuning profiles (runtime sysctl adjustments)",
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
		colorEnabled := ui.IsColorEnabled()
		t := ui.NewTable("KEY", "STATUS", "VALUE")
		t.SetAlignment(1, ui.AlignCenter)
		for _, entry := range data.Values {
			value := entry.Current
			if value == "" {
				value = ui.Gray("-", colorEnabled)
			}
			if entry.Error != "" {
				value = ui.Red(entry.Error, colorEnabled)
			}
			t.AddRow(entry.Key, formatTuneStatus(entry.Status, colorEnabled), value)
		}
		fmt.Println()
		fmt.Print(t.Render())
		fmt.Println()
	},
}

var tuneProfilesCmd = &cobra.Command{
	Use:   "profiles",
	Short: "List available kernel tuning profiles",
	Run: func(cmd *cobra.Command, args []string) {
		t := ui.NewTable("PROFILE", "DESCRIPTION")
		for _, profile := range tune.Profiles() {
			t.AddRow(profile.Name, profile.Description)
		}
		fmt.Println()
		fmt.Print(t.Render())
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
		colorEnabled := ui.IsColorEnabled()
		t := ui.NewTable("KEY", "STATUS", "CURRENT", "TARGET")
		t.SetAlignment(1, ui.AlignCenter)
		for _, entry := range tune.DiffProfile(profile) {
			current := entry.Current
			if current == "" {
				current = ui.Gray("-", colorEnabled)
			}
			if entry.Error != "" {
				current = ui.Red(entry.Error, colorEnabled)
			}
			t.AddRow(entry.Key, formatTuneStatus(entry.Status, colorEnabled), current, entry.Target)
		}
		fmt.Print(t.Render())
		fmt.Println()
	},
}

var tuneUseCmd = &cobra.Command{
	Use:   "use [profile]",
	Short: "Apply a kernel tuning profile for the current runtime",
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

		colorEnabled := ui.IsColorEnabled()
		fmt.Printf("Applied profile: %s\n\n", profile.Name)
		t := ui.NewTable("KEY", "STATUS", "OLD", "NEW")
		t.SetAlignment(1, ui.AlignCenter)
		for _, entry := range state.Entries {
			oldValue := entry.OldValue
			if oldValue == "" {
				oldValue = ui.Gray("-", colorEnabled)
			}
			newValue := entry.NewValue
			if newValue == "" {
				newValue = ui.Gray("-", colorEnabled)
			}
			if entry.Error != "" {
				newValue = ui.Red(entry.Error, colorEnabled)
			}
			t.AddRow(entry.Key, formatTuneStatus(entry.Status, colorEnabled), oldValue, newValue)
		}
		fmt.Print(t.Render())
		if err != nil {
			fmt.Printf("\n⚠️  Apply completed with errors: %v\n", err)
			return
		}
		fmt.Println("\n✅ Apply completed.")
	},
}

func runTuneVerify(cmd *cobra.Command, args []string) error {
	profile, ok := tune.GetProfile(args[0])
	if !ok {
		return fmt.Errorf("❌ Unknown profile '%s'.", args[0])
	}
	colorEnabled := ui.IsColorEnabled()
	fmt.Printf("Profile: %s\n\n", profile.Name)
	t := ui.NewTable("KEY", "STATUS", "CURRENT", "TARGET")
	t.SetAlignment(1, ui.AlignCenter)
	mismatch := false
	for _, entry := range tune.VerifyProfile(profile) {
		current := entry.Current
		if current == "" {
			current = ui.Gray("-", colorEnabled)
		}
		if entry.Error != "" {
			current = ui.Red(entry.Error, colorEnabled)
		}
		if entry.Status != "ok" {
			mismatch = true
		}
		t.AddRow(entry.Key, formatTuneStatus(entry.Status, colorEnabled), current, entry.Target)
	}
	fmt.Print(t.Render())
	if mismatch {
		return fmt.Errorf("⚠️  Profile is not fully active.")
	}
	fmt.Println("\n✅ Profile is active.")
	return nil
}

var tuneVerifyCmd = &cobra.Command{
	Use:   "verify [profile]",
	Short: "Verify whether current kernel values match a tuning profile",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_ = runTuneVerify(cmd, args)
	},
	RunE: runTuneVerify,
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

		colorEnabled := ui.IsColorEnabled()
		fmt.Printf("Rollback profile: %s\n\n", state.Profile)
		t := ui.NewTable("KEY", "STATUS", "CURRENT", "TARGET")
		t.SetAlignment(1, ui.AlignCenter)
		for _, entry := range results {
			current := entry.OldValue
			if current == "" {
				current = ui.Gray("-", colorEnabled)
			}
			target := entry.NewValue
			if target == "" {
				target = ui.Gray("-", colorEnabled)
			}
			if entry.Error != "" {
				target = ui.Red(entry.Error, colorEnabled)
			}
			t.AddRow(entry.Key, formatTuneStatus(entry.Status, colorEnabled), current, target)
		}
		fmt.Print(t.Render())
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
	tuneUseCmd.ValidArgsFunction = profileCompletion
	tuneVerifyCmd.ValidArgsFunction = profileCompletion

	tuneCmd.AddCommand(tuneShowCmd, tuneProfilesCmd, tuneDiffCmd, tuneUseCmd, tuneVerifyCmd, tuneRollbackCmd)
	rootCmd.AddCommand(tuneCmd)
}
