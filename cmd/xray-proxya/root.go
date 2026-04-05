package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	Version       = "0.1.3"
	shellOverride string
	setupRC       bool
)

var rootCmd = &cobra.Command{
	Use:   "xray-proxya",
	Short: "Xray-Proxya: A modern, role-based proxy manager and transparent gateway",
	Long: `Xray-Proxya is a Go-based successor to the archive bash scripts. 
It features a staging-based configuration system with mandatory normalization.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|install|uninstall]",
	Short: "Generate or manage shell autocompletion",
	ValidArgs: []string{"bash", "zsh", "fish", "install", "uninstall"},
}

var compInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install completion scripts to local share",
	Run: func(cmd *cobra.Command, args []string) {
		handleCompletion(true, setupRC)
	},
}

var compUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove completion scripts and optionally clean RC files",
	Run: func(cmd *cobra.Command, args []string) {
		handleCompletion(false, setupRC)
	},
}

func handleCompletion(install bool, modifyRC bool) {
	shell := shellOverride
	if shell == "" {
		shell = filepath.Base(os.Getenv("SHELL"))
	}

	home, _ := os.UserHomeDir()
	if os.Geteuid() == 0 { home = "/root" }
	dir := filepath.Join(home, ".local", "share", "xray-proxya", "completions")
	
	rcFile := filepath.Join(home, ".bashrc")
	compFile := filepath.Join(dir, "xray-proxya.bash")
	sourceLine := fmt.Sprintf("[ -f %s ] && . %s", compFile, compFile)

	if shell == "zsh" {
		rcFile = filepath.Join(home, ".zshrc")
		compFile = filepath.Join(dir, "xray-proxya.zsh")
		sourceLine = fmt.Sprintf("[ -f %s ] && source %s", compFile, compFile)
	}

	if install {
		os.MkdirAll(dir, 0755)
		if shell == "zsh" {
			rootCmd.GenZshCompletionFile(compFile)
		} else {
			rootCmd.GenBashCompletionFile(compFile)
		}
		fmt.Printf("✅ Completion script saved to %s\n", compFile)

		if modifyRC {
			data, _ := os.ReadFile(rcFile)
			if !strings.Contains(string(data), compFile) {
				f, _ := os.OpenFile(rcFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				defer f.Close()
				f.WriteString("\n# Xray-Proxya Completion\n" + sourceLine + "\n")
				fmt.Printf("✅ Added sourcing to %s\n", rcFile)
			}
		}
	} else {
		// Uninstall
		os.Remove(compFile)
		fmt.Printf("🗑️ Removed %s\n", compFile)

		if modifyRC {
			cleanRC(rcFile, compFile)
		}
	}
}

func cleanRC(rcPath, marker string) {
	file, err := os.Open(rcPath)
	if err != nil { return }
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "# Xray-Proxya Completion") {
			continue
		}
		if strings.Contains(line, marker) {
			continue
		}
		lines = append(lines, line)
	}
	
	os.WriteFile(rcPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)
	fmt.Printf("🧹 Cleaned RC file: %s\n", rcPath)
}

func init() {
	rootCmd.AddCommand(versionCmd)
	
	compInstallCmd.Flags().StringVarP(&shellOverride, "shell", "s", "", "Shell type")
	compInstallCmd.Flags().BoolVarP(&setupRC, "completion", "c", false, "Also setup/modify RC files")
	
	compUninstallCmd.Flags().StringVarP(&shellOverride, "shell", "s", "", "Shell type")
	compUninstallCmd.Flags().BoolVarP(&setupRC, "completion", "c", false, "Also clean RC files")

	completionCmd.AddCommand(compInstallCmd, compUninstallCmd)
	
	// Legacy support for direct gen
	completionCmd.Run = func(cmd *cobra.Command, args []string) {
		if len(args) == 0 { cmd.Help(); return }
		switch args[0] {
		case "bash": rootCmd.GenBashCompletion(os.Stdout)
		case "zsh": rootCmd.GenZshCompletion(os.Stdout)
		case "fish": rootCmd.GenFishCompletion(os.Stdout, true)
		}
	}

	rootCmd.AddCommand(completionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Xray-Proxya v%s\n", Version)
	},
}
