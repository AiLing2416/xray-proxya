package main

import (
	"context"
	"fmt"
	"time"

	"xray-proxya/internal/doctor"

	"github.com/spf13/cobra"
)

var (
	doctorCheckJSON     bool
	doctorCheckVerbose  bool
	doctorCheckRole     string
	doctorCheckTimeoutS int
)

var doctorCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Run host, system, and network health checks",
	Long: `Execute automated health diagnostics for Xray-Proxya.
Inspects core binary version, port bindings, clock skew, kernel modules,
system limits, public multi-protocol UDP reachability, and modern web protocols.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := doctor.Options{
			RoleOverride: doctorCheckRole,
			Verbose:      doctorCheckVerbose,
			Timeout:      time.Duration(doctorCheckTimeoutS) * time.Second,
		}

		report := doctor.RunDiagnostics(context.Background(), opts)

		if doctorCheckJSON {
			jsonOut, err := doctor.RenderJSON(report)
			if err != nil {
				return fmt.Errorf("failed to format json: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), jsonOut)
		} else {
			fmt.Fprint(cmd.OutOrStdout(), doctor.RenderTerminal(report, doctorCheckVerbose))
		}

		if report.Summary.Failed > 0 {
			return fmt.Errorf("diagnostic check failed with %d error(s)", report.Summary.Failed)
		}
		return nil
	},
}

func init() {
	doctorCheckCmd.Flags().BoolVar(&doctorCheckJSON, "json", false, "Output diagnostic report in JSON format")
	doctorCheckCmd.Flags().BoolVarP(&doctorCheckVerbose, "verbose", "v", false, "Show verbose check metrics and details")
	doctorCheckCmd.Flags().StringVar(&doctorCheckRole, "role", "", "Override inspection role (server, gateway, or generic)")
	doctorCheckCmd.Flags().IntVar(&doctorCheckTimeoutS, "timeout", 12, "Diagnostic execution timeout in seconds")

	_ = doctorCheckCmd.RegisterFlagCompletionFunc("role", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"server", "gateway", "generic"}, cobra.ShellCompDirectiveNoFileComp
	})

	doctorCmd.AddCommand(doctorCheckCmd)
}
