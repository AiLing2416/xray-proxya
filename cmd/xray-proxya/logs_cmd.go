package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

var (
	logsFollow bool
	logsLines  int
)

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Show the unified Xray log file",
	Long: strings.TrimSpace(`
Show the unified Xray log file used by both rootless and managed service runs.

Use --follow to keep streaming appended log lines.
`),
	Example: strings.TrimSpace(`
  xray-proxya logs
  xray-proxya logs -n 200
  xray-proxya logs -f
`),
	Args: cobra.NoArgs,
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		logPath := xray.GetXrayLogPath()
		data, err := os.ReadFile(logPath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("❌ Log file not found: %s\n", logPath)
				return
			}
			fmt.Printf("❌ Failed to read log file: %v\n", err)
			return
		}

		tail := tailLogContent(string(data), logsLines)
		if tail != "" {
			fmt.Print(tail)
			if !strings.HasSuffix(tail, "\n") {
				fmt.Println()
			}
		}
		if !logsFollow {
			return
		}

		f, err := os.Open(logPath)
		if err != nil {
			fmt.Printf("❌ Failed to open log file for follow: %v\n", err)
			return
		}
		defer f.Close()

		if _, err := f.Seek(int64(len(data)), io.SeekStart); err != nil {
			fmt.Printf("❌ Failed to seek log file: %v\n", err)
			return
		}

		for {
			buf := make([]byte, 4096)
			n, err := f.Read(buf)
			if n > 0 {
				fmt.Print(string(buf[:n]))
			}
			if err == io.EOF {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			if err != nil {
				fmt.Printf("\n❌ Log follow stopped: %v\n", err)
				return
			}
		}
	},
}

func tailLogContent(content string, lines int) string {
	if lines <= 0 || content == "" {
		return ""
	}
	hasTrailingNewline := strings.HasSuffix(content, "\n")
	parts := strings.Split(content, "\n")
	if hasTrailingNewline && len(parts) > 0 {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return ""
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
	logsCmd.Flags().IntVarP(&logsLines, "lines", "n", 40, "Show the last N lines before following")
	rootCmd.AddCommand(logsCmd)
}
