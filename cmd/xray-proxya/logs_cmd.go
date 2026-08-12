package main

import (
	"fmt"
	"strings"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

var (
	logsFollow bool
	logsLines  int
)

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Show Xray-Proxya logs from the systemd journal",
	Long: strings.TrimSpace(`
Show the managed service journal. Use --follow to stream new entries.
`),
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if logsFollow {
			return xray.FollowJournal(xray.MainServiceUnit, logsLines)
		}
		body, err := xray.JournalTail(xray.MainServiceUnit, logsLines)
		if err != nil {
			return err
		}
		fmt.Print(body)
		return nil
	},
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
	logsCmd.Flags().BoolVarP(&logsFollow, "follow", "f", false, "Follow the log output")
	logsCmd.Flags().IntVarP(&logsLines, "lines", "n", 40, "Show the last N journal lines")
	rootCmd.AddCommand(logsCmd)
}
