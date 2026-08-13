package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"xray-proxya/internal/config"

	"github.com/spf13/cobra"
)

const (
	completionStartMarker = "# >>> xray-proxya completion >>>"
	completionEndMarker   = "# <<< xray-proxya completion <<<"
)

var completionHomeDir = config.GetHomeDir

type completionLayout struct {
	shell           string
	directory       string
	file            string
	profile         string
	legacyProfileID string
}

var doctorCompletionCmd = &cobra.Command{
	Use:   "completion",
	Short: "Install or remove shell completion for the detected shell",
	Long: `Install or remove completion for the login shell detected from $SHELL.
Supported shells are bash, zsh, and fish. No network download is required.`,
	Args: cobra.NoArgs,
}

var doctorCompletionInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Generate and install completion for the detected shell",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		layout, err := detectedCompletionLayout()
		if err != nil {
			return err
		}
		if err := installCompletion(layout); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "✅ Installed %s completion: %s\n", layout.shell, layout.file)
		if layout.profile != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "✅ Updated shell profile: %s\n", layout.profile)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Open a new shell or reload its profile to activate completion.")
		return nil
	},
}

var doctorCompletionUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove completion for the detected shell",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		layout, err := detectedCompletionLayout()
		if err != nil {
			return err
		}
		if err := uninstallCompletion(layout); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "✅ Removed %s completion.\n", layout.shell)
		return nil
	},
}

func detectedCompletionLayout() (completionLayout, error) {
	shell, err := detectShell()
	if err != nil {
		return completionLayout{}, err
	}
	return completionLayoutFor(shell, completionHomeDir())
}

func detectShell() (string, error) {
	if shell := filepath.Base(strings.TrimSpace(os.Getenv("SHELL"))); isSupportedShell(shell) {
		return shell, nil
	}

	// Non-interactive callers may not have SHELL. Fall back to the login shell
	// recorded for the effective user when getent is available.
	if out, err := exec.Command("getent", "passwd", fmt.Sprint(os.Getuid())).Output(); err == nil {
		fields := strings.Split(strings.TrimSpace(string(out)), ":")
		if len(fields) >= 7 {
			if shell := filepath.Base(fields[len(fields)-1]); isSupportedShell(shell) {
				return shell, nil
			}
		}
	}
	return "", fmt.Errorf("unable to detect a supported login shell; set SHELL to bash, zsh, or fish")
}

func isSupportedShell(shell string) bool {
	return shell == "bash" || shell == "zsh" || shell == "fish"
}

func completionLayoutFor(shell, home string) (completionLayout, error) {
	switch shell {
	case "bash":
		directory := filepath.Join(home, ".local", "share", "bash-completion", "completions")
		return completionLayout{shell: shell, directory: directory, file: filepath.Join(directory, "xray-proxya"), profile: filepath.Join(home, ".bashrc"), legacyProfileID: directory}, nil
	case "zsh":
		directory := filepath.Join(home, ".local", "share", "zsh", "site-functions")
		return completionLayout{shell: shell, directory: directory, file: filepath.Join(directory, "_xray-proxya"), profile: filepath.Join(home, ".zshrc"), legacyProfileID: directory}, nil
	case "fish":
		directory := filepath.Join(home, ".config", "fish", "completions")
		return completionLayout{shell: shell, directory: directory, file: filepath.Join(directory, "xray-proxya.fish")}, nil
	default:
		return completionLayout{}, fmt.Errorf("unsupported shell %q (supported: bash, zsh, fish)", shell)
	}
}

func installCompletion(layout completionLayout) error {
	if err := os.MkdirAll(layout.directory, 0755); err != nil {
		return fmt.Errorf("create completion directory: %w", err)
	}
	if err := generateCompletion(layout); err != nil {
		return err
	}
	if layout.profile == "" {
		return nil
	}
	if err := updateCompletionProfile(layout, true); err != nil {
		return err
	}
	return nil
}

func uninstallCompletion(layout completionLayout) error {
	if err := os.Remove(layout.file); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove completion file: %w", err)
	}
	if layout.profile == "" {
		return nil
	}
	if err := updateCompletionProfile(layout, false); err != nil {
		return err
	}
	return nil
}

func generateCompletion(layout completionLayout) error {
	var err error
	switch layout.shell {
	case "bash":
		err = rootCmd.GenBashCompletionFile(layout.file)
	case "zsh":
		err = rootCmd.GenZshCompletionFile(layout.file)
	case "fish":
		err = rootCmd.GenFishCompletionFile(layout.file, true)
	default:
		return fmt.Errorf("unsupported shell %q", layout.shell)
	}
	if err != nil {
		return fmt.Errorf("generate %s completion: %w", layout.shell, err)
	}
	return nil
}

func updateCompletionProfile(layout completionLayout, install bool) error {
	data, err := os.ReadFile(layout.profile)
	if err != nil {
		if os.IsNotExist(err) && !install {
			return nil
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("read shell profile: %w", err)
		}
	}
	content := stripCompletionBlock(string(data))
	content = stripLegacyCompletionProfile(content, layout)
	if install {
		content = strings.TrimRight(content, "\n") + "\n\n" + completionProfileBlock(layout) + "\n"
	}
	if err := os.WriteFile(layout.profile, []byte(content), 0644); err != nil {
		return fmt.Errorf("write shell profile: %w", err)
	}
	return nil
}

func completionProfileBlock(layout completionLayout) string {
	switch layout.shell {
	case "bash":
		return strings.Join([]string{
			completionStartMarker,
			"if ! declare -F _get_comp_words_by_ref >/dev/null; then",
			"  for completion_base in /usr/share/bash-completion/bash_completion /etc/bash_completion; do",
			"    [ -r \"$completion_base\" ] && . \"$completion_base\" && break",
			"  done",
			"fi",
			fmt.Sprintf("[ -r %q ] && . %q", layout.file, layout.file),
			completionEndMarker,
		}, "\n")
	case "zsh":
		return strings.Join([]string{
			completionStartMarker,
			fmt.Sprintf("fpath=(%q $fpath)", layout.directory),
			"autoload -Uz compinit && compinit",
			completionEndMarker,
		}, "\n")
	default:
		return ""
	}
}

func stripCompletionBlock(content string) string {
	start := strings.Index(content, completionStartMarker)
	if start < 0 {
		return content
	}
	end := strings.Index(content[start:], completionEndMarker)
	if end < 0 {
		return content
	}
	end += start + len(completionEndMarker)
	if end < len(content) && content[end] == '\n' {
		end++
	}
	return content[:start] + content[end:]
}

// stripLegacyCompletionProfile removes only the profile lines created by the
// pre-v0.4.0 top-level completion command. It intentionally leaves a user's
// general bash-completion or compinit setup untouched.
func stripLegacyCompletionProfile(content string, layout completionLayout) string {
	lines := strings.Split(content, "\n")
	var kept []string
	for index := 0; index < len(lines); index++ {
		if lines[index] != "# Xray-Proxya Completion" {
			kept = append(kept, lines[index])
			continue
		}
		if index+1 < len(lines) && strings.Contains(lines[index+1], layout.legacyProfileID) {
			index++
			if layout.shell == "zsh" && index+1 < len(lines) && strings.TrimSpace(lines[index+1]) == "autoload -Uz _xray-proxya" {
				index++
			}
			continue
		}
		kept = append(kept, lines[index])
	}
	return strings.Join(kept, "\n")
}

func init() {
	doctorCompletionCmd.AddCommand(doctorCompletionInstallCmd, doctorCompletionUninstallCmd)
}
