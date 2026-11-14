package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"xray-proxya/internal/buildinfo"
	"xray-proxya/internal/config"
	"xray-proxya/internal/ui"
	"xray-proxya/internal/xray"

	"github.com/spf13/cobra"
)

var Version = buildinfo.GetVersion()
var versionVerbose bool

var rootCmd = &cobra.Command{
	Use:               "xray-proxya",
	Short:             "Xray-Proxya: A modern, role-based proxy manager and transparent gateway",
	SilenceUsage:      true,
	SilenceErrors:     true,
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	Long:              "Xray-Proxya is a Go-based successor to the archive bash scripts.\nIt features a staging-based configuration system with mandatory normalization.",
}

// SilentError wraps an error that has already been reported to output
// (e.g., structured JSON diagnostics) and should exit non-zero without extra text.
type SilentError struct {
	Err error
}

func (e *SilentError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *SilentError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Silent marks this error as already reported.
func (e *SilentError) Silent() bool {
	return true
}

func isSilentError(err error) bool {
	var silent interface{ Silent() bool }
	return errors.As(err, &silent) && silent.Silent()
}

func isJSONMode(cmd *cobra.Command, args []string) bool {
	if cmd != nil {
		if f := cmd.Flags().Lookup("json"); f != nil && f.Value.String() == "true" {
			return true
		}
	}
	for _, arg := range args {
		if arg == "--json" || strings.HasPrefix(arg, "--json=") && strings.TrimPrefix(arg, "--json=") != "false" {
			return true
		}
	}
	return false
}

func cleanErrorText(msg string) string {
	msg = strings.TrimSpace(msg)
	prefixes := []string{
		"❌", "✖", "⚠️", "⚠", "✅", "✔", "ℹ️", "ℹ", "▲", "🚀", "🔄", "🔍",
		"Error:", "error:",
	}
	for {
		matched := false
		for _, p := range prefixes {
			if strings.HasPrefix(msg, p) {
				msg = strings.TrimSpace(strings.TrimPrefix(msg, p))
				matched = true
				break
			}
		}
		if !matched {
			break
		}
	}
	return msg
}

func executeRoot(root *cobra.Command, args []string, stdout, stderr io.Writer) int {
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)

	cmd, err := root.ExecuteC()
	if err == nil {
		return 0
	}

	if isSilentError(err) {
		return 1
	}

	clean := cleanErrorText(err.Error())
	if isJSONMode(cmd, args) {
		payload := struct {
			Exit  int    `json:"exit"`
			Error string `json:"error"`
		}{
			Exit:  1,
			Error: clean,
		}
		if b, mErr := json.Marshal(payload); mErr == nil {
			fmt.Fprintln(stdout, string(b))
		} else {
			fmt.Fprintf(stdout, `{"exit":1,"error":%q}`+"\n", clean)
		}
		return 1
	}

	fmt.Fprintf(stderr, "%s Error: %s\n", ui.Red(ui.SymCross, ui.IsColorEnabled()), clean)
	return 1
}

func Execute() {
	if code := executeRoot(rootCmd, os.Args[1:], os.Stdout, os.Stderr); code != 0 {
		os.Exit(code)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolP("help", "", false, "Help for this command")
	rootCmd.Version = Version
	rootCmd.SetVersionTemplate("Xray-Proxya v{{.Version}}\n")
	versionCmd.Flags().BoolVarP(&versionVerbose, "verbose", "V", false, "Show detailed runtime and build environment info")
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Printf("Xray-Proxya v%s\n", Version)
		if !versionVerbose {
			return
		}

		goVer := runtime.Version()
		arch := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
		cmd.Printf("  Profile    : %s\n", buildinfo.Profile)
		cmd.Printf("  Go Runtime : %s (%s, static)\n", goVer, arch)

		xrayVer := "not found"
		candidates := []string{
			xray.GetXrayBinaryPath(),
			filepath.Join(os.Getenv("HOME"), ".local", "share", "xray-proxya", "bin", "xray"),
			"/usr/local/bin/xray",
			"/usr/bin/xray",
		}
		if lp, err := exec.LookPath("xray"); err == nil {
			candidates = append([]string{lp}, candidates...)
		}

		for _, bin := range candidates {
			if bin == "" {
				continue
			}
			if info, err := os.Stat(bin); err == nil && !info.IsDir() {
				cmdXray := exec.Command(bin, "version")
				cmdXray.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(bin))
				if out, err := cmdXray.Output(); err == nil {
					fields := strings.Fields(string(out))
					if len(fields) >= 2 {
						xrayVer = "v" + strings.TrimPrefix(fields[1], "v")
						break
					}
				}
			}
		}
		cmd.Printf("  Xray Core  : %s\n", xrayVer)

		cfgPath := config.GetConfigPath()
		roleStr := "uninitialized"
		if cfg, err := config.LoadConfig(); err == nil && cfg != nil {
			roleStr = string(cfg.Role)
		}
		cmd.Printf("  Config Dir : %s (Role: %s)\n", filepath.Dir(cfgPath), roleStr)
	},
}
