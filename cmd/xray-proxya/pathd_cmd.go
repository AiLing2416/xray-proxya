package main

import (
	"os"
	"xray-proxya/internal/pathd"

	"github.com/spf13/cobra"
)

var pathdExitFunc = os.Exit

var pathdCmd = &cobra.Command{
	Use:                "pathd [command] [flags]",
	Short:              "Run the private PathLink ICMP companion daemon (multi-call entrypoint)",
	Long:               "Run the private PathLink ICMP companion daemon. Accepts standard pathd arguments such as 'serve --config <path>'.",
	DisableFlagParsing: true,
	SilenceUsage:       true,
	SilenceErrors:      true,
	RunE: func(cmd *cobra.Command, args []string) error {
		code := pathd.RunCLICustom(args, cmd.OutOrStdout(), cmd.ErrOrStderr(), nil)
		if code != 0 {
			pathdExitFunc(code)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(pathdCmd)
}
