package main

import (
	"fmt"
	"strings"
	"xray-proxya/internal/service"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

var (
	logsFollow bool
	logsLines  int
)

func runServiceLogs(cmd *cobra.Command, args []string) error {
	input := "core"
	if len(args) == 1 {
		input = args[0]
	}
	unit, err := service.NormalizeUnitName(input)
	if err != nil {
		return err
	}
	follow, _ := cmd.Flags().GetBool("follow")
	lines, _ := cmd.Flags().GetInt("lines")
	if lines <= 0 {
		lines = 40
	}
	if follow {
		return xray.FollowJournal(unit, lines)
	}
	body, err := xray.JournalTail(unit, lines)
	if err != nil {
		return err
	}
	fmt.Print(body)
	return nil
}

var serviceLogsCmd = &cobra.Command{
	Use:   "logs [unit-name]",
	Short: "Show logs for a managed systemd unit",
	Long: strings.TrimSpace(`
Show logs for a managed service from the systemd journal. Use --follow to stream new entries.
`),
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeManagedServiceUnits,
	Run: func(cmd *cobra.Command, args []string) {
		_ = runServiceLogs(cmd, args)
	},
	RunE: runServiceLogs,
}

var logsCmd = &cobra.Command{
	Use:   "logs [unit-name]",
	Short: "Show Xray-Proxya logs from the systemd journal",
	Long: strings.TrimSpace(`
Show the managed service journal. Use --follow to stream new entries.
`),
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeManagedServiceUnits,
	Run: func(cmd *cobra.Command, args []string) {
		_ = runServiceLogs(cmd, args)
	},
	RunE: runServiceLogs,
}

func tailLogContent(content string, lines int) string {
	if lines <= 0 || content == "" {
		return ""
	}
	hasTrailingNewline := strings.HasSuffix(content, "\n")
	parts := strings.Split(content, "\n")
	if hasTrailingNewline {
		parts = parts[:len(parts)-1]
	}
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	out := strings.Join(parts, "\n")
	if hasTrailingNewline {
		out += "\n"
	}
	return out
}

func init() {
	serviceLogsCmd.Flags().BoolVarP(&logsFollow, "follow", "f", false, "Follow the log output")
	serviceLogsCmd.Flags().IntVarP(&logsLines, "lines", "n", 40, "Show the last N journal lines")
	serviceCmd.AddCommand(serviceLogsCmd)

	logsCmd.Flags().BoolVarP(&logsFollow, "follow", "f", false, "Follow the log output")
	logsCmd.Flags().IntVarP(&logsLines, "lines", "n", 40, "Show the last N journal lines")
	rootCmd.AddCommand(logsCmd)
}
