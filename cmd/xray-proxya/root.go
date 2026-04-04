package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	Version       = "0.1.1"
	shellOverride string
)

var rootCmd = &cobra.Command{
	Use:   "xray-proxya",
	Short: "Xray-Proxya: A modern, role-based proxy manager and transparent gateway",
	Long: `Xray-Proxya is a Go-based successor to the archive bash scripts. 
It features a staging-based configuration system, ensuring all changes are 
validated before being applied to the production environment.

Supports Server (Reality/KEM) and Gateway (TUN/TPROXY) roles.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(versionCmd)
	completionCmd.Flags().StringVarP(&shellOverride, "shell", "s", "", "Manually specify shell type (bash, zsh, fish)")
	rootCmd.AddCommand(completionCmd)
}

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|install]",
	Short: "Generate or install shell autocompletion scripts",
	Long: `To load completions in your current shell session:
	Bash: source <(xray-proxya completion bash)
	Zsh: source <(xray-proxya completion zsh)
	
To install permanently, run: xray-proxya completion install [--shell bash|zsh]`,
	ValidArgs: []string{"bash", "zsh", "fish", "install"},
	Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			rootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			rootCmd.GenFishCompletion(os.Stdout, true)
		case "install":
			installCompletion(shellOverride)
		}
	},
}

func installCompletion(override string) {
	shell := override
	if shell == "" {
		shell = filepath.Base(os.Getenv("SHELL"))
	}
	
	home, _ := os.UserHomeDir()
	compDir := filepath.Join(home, ".local", "share", "xray-proxya", "completions")
	os.MkdirAll(compDir, 0755)

	fmt.Printf("🐚 Target shell: %s\n", shell)
	
	var rcFile string
	var compFile string
	var sourceLine string

	switch shell {
	case "bash":
		rcFile = filepath.Join(home, ".bashrc")
		compFile = filepath.Join(compDir, "xray-proxya.bash")
		rootCmd.GenBashCompletionFile(compFile)
		sourceLine = fmt.Sprintf("[ -f %s ] && . %s", compFile, compFile)
	case "zsh":
		rcFile = filepath.Join(home, ".zshrc")
		compFile = filepath.Join(compDir, "xray-proxya.zsh")
		rootCmd.GenZshCompletionFile(compFile)
		sourceLine = fmt.Sprintf("[ -f %s ] && source %s", compFile, compFile)
	default:
		fmt.Printf("❌ Installation for '%s' is not supported. Try 'xray-proxya completion install --shell bash'.\n", shell)
		return
	}

	// Set permissions
	os.Chmod(compFile, 0644)

	// Update RC file
	data, _ := os.ReadFile(rcFile)
	if !strings.Contains(string(data), compFile) {
		f, err := os.OpenFile(rcFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			f.WriteString("\n# Xray-Proxya Completion\n" + sourceLine + "\n")
			fmt.Printf("✅ Completion script installed to %s\n", compFile)
			fmt.Printf("✅ Sourcing line added to %s\n", rcFile)
			fmt.Println("🚀 Please run 'source " + rcFile + "' or restart your shell.")
		}
	} else {
		fmt.Println("ℹ️ Completion is already configured in your shell RC file.")
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Xray-Proxya v%s\n", Version)
	},
}
