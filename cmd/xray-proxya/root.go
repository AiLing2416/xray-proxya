package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	Version       = "0.2.0"
	shellOverride string
	setupDeps     bool
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

// Completion related commands
var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|install|uninstall]",
	Short: "Generate or manage shell autocompletion",
	ValidArgs: []string{"bash", "zsh", "fish", "install", "uninstall"},
}

var compInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install completion scripts and full environment to user directory",
	Run: func(cmd *cobra.Command, args []string) {
		handleCompletion(true, setupDeps)
	},
}

var compUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove completion scripts and private environment",
	Run: func(cmd *cobra.Command, args []string) {
		handleCompletion(false, setupDeps)
	},
}

func handleCompletion(install bool, manageDeps bool) {
	shell := shellOverride
	if shell == "" {
		shell = filepath.Base(os.Getenv("SHELL"))
	}

	home, _ := os.UserHomeDir()
	if os.Geteuid() == 0 { home = "/root" }

	baseDir := filepath.Join(home, ".local", "share", "bash-completion")
	baseScript := filepath.Join(baseDir, "bash_completion.sh")
	compDir := filepath.Join(baseDir, "completions")
	compFile := filepath.Join(compDir, "xray-proxya")
	rcFile := filepath.Join(home, ".bashrc")
	
	baseDepLine := fmt.Sprintf("[ -f %s ] && . %s", baseScript, baseScript)

	if shell == "zsh" {
		compDir = filepath.Join(home, ".local", "share", "zsh", "site-functions")
		compFile = filepath.Join(compDir, "_xray-proxya")
		rcFile = filepath.Join(home, ".zshrc")
		baseDepLine = "autoload -Uz compinit && compinit"
	}

	if install {
		os.MkdirAll(compDir, 0755)
		
		if shell == "zsh" {
			rootCmd.GenZshCompletionFile(compFile)
		} else {
			rootCmd.GenBashCompletionFile(compFile)
		}
		fmt.Printf("✅ [%s] Completion script saved to %s\n", Version, compFile)

		if manageDeps && shell == "bash" {
			fmt.Println("🌐 Downloading full bash-completion base set...")
			url := "https://raw.githubusercontent.com/scop/bash-completion/master/bash_completion"
			if err := downloadFile(url, baseScript); err != nil {
				fmt.Printf("⚠️  Failed to download base set: %v\n", err)
			} else {
				fmt.Printf("✅ Base completion tools installed to %s\n", baseScript)
			}
		}

		if manageDeps {
			data, _ := os.ReadFile(rcFile)
			content := string(data)
			var newBlocks strings.Builder

			if !strings.Contains(content, "bash_completion.sh") && !strings.Contains(content, "compinit") {
				newBlocks.WriteString("\n# Base Shell Completion Support\n" + baseDepLine + "\n")
			}
			
			sourceLine := fmt.Sprintf("[ -f %s ] && . %s", compFile, compFile)
			if shell == "zsh" { 
				sourceLine = fmt.Sprintf("fpath=(%s $fpath)\nautoload -Uz _xray-proxya", compDir) 
			}
			
			if !strings.Contains(content, "xray-proxya") {
				newBlocks.WriteString("\n# Xray-Proxya Completion\n" + sourceLine + "\n")
			}

			if newBlocks.Len() > 0 {
				f, _ := os.OpenFile(rcFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				defer f.Close()
				f.WriteString(newBlocks.String())
				fmt.Printf("✅ Updated RC file: %s\n", rcFile)
			}
			fmt.Println("🚀 IMPORTANT: Run 'complete -r xray-proxya' then 'source ~/.bashrc' to activate.")
		}
	} else {
		os.Remove(compFile)
		fmt.Printf("🗑️ Removed %s\n", compFile)
		if manageDeps {
			os.Remove(baseScript)
			cleanRC(rcFile, "xray-proxya")
			fmt.Printf("🧹 Cleaned completion environment from %s\n", rcFile)
		}
	}
}

func downloadFile(url string, path string) error {
	os.MkdirAll(filepath.Dir(path), 0755)
	resp, err := http.Get(url)
	if err != nil { return err }
	defer resp.Body.Close()
	out, err := os.Create(path)
	if err != nil { return err }
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func cleanRC(rcPath, marker string) {
	file, err := os.Open(rcPath)
	if err != nil { return }
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, marker) || 
		   strings.Contains(line, "# Xray-Proxya Completion") ||
		   strings.Contains(line, "# Base Shell Completion Support") ||
		   strings.Contains(line, "bash_completion.sh") ||
		   strings.Contains(line, "compinit") {
			continue
		}
		lines = append(lines, line)
	}
	os.WriteFile(rcPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func init() {
	rootCmd.AddCommand(versionCmd)
	
	compInstallCmd.Flags().StringVarP(&shellOverride, "shell", "s", "", "Shell type")
	compInstallCmd.Flags().BoolVarP(&setupDeps, "completion", "c", false, "Install full completion script set")
	
	compUninstallCmd.Flags().StringVarP(&shellOverride, "shell", "s", "", "Shell type")
	compUninstallCmd.Flags().BoolVarP(&setupDeps, "completion", "c", false, "Uninstall full completion set")
	
	completionCmd.AddCommand(compInstallCmd, compUninstallCmd)
	rootCmd.AddCommand(completionCmd)
	
	completionCmd.Run = func(cmd *cobra.Command, args []string) {
		if len(args) == 0 { cmd.Help(); return }
		switch args[0] {
		case "bash": rootCmd.GenBashCompletion(os.Stdout)
		case "zsh": rootCmd.GenZshCompletion(os.Stdout)
		case "fish": rootCmd.GenFishCompletion(os.Stdout, true)
		}
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Xray-Proxya v%s\n", Version)
	},
}
