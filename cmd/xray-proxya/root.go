package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"xray-proxya/internal/buildinfo"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

var Version = buildinfo.Version
var versionVerbose bool

var rootCmd = &cobra.Command{
	Use:               "xray-proxya",
	Short:             "Xray-Proxya: A modern, role-based proxy manager and transparent gateway",
	SilenceUsage:      true,
	SilenceErrors:     true,
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	Long:              "Xray-Proxya is a Go-based successor to the archive bash scripts.\nIt features a staging-based configuration system with mandatory normalization.",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
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
		cmd.Printf("  Go Runtime : %s (%s, static)\n", goVer, arch)

		xrayVer := "not found"
		if path, err := exec.LookPath("xray"); err == nil {
			if out, err := exec.Command(path, "version").Output(); err == nil {
				fields := strings.Fields(string(out))
				if len(fields) >= 2 {
					xrayVer = fields[1]
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
