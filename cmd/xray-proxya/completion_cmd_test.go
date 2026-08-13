package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorCompletionIsRegisteredAndLegacyTopLevelCommandIsRemoved(t *testing.T) {
	if !rootCmd.CompletionOptions.DisableDefaultCmd {
		t.Fatal("Cobra's default top-level completion command must be disabled")
	}
	command, _, err := doctorCmd.Find([]string{"completion"})
	if err != nil {
		t.Fatalf("find doctor completion: %v", err)
	}
	if command != doctorCompletionCmd {
		t.Fatalf("doctor completion command = %q, want %q", command.Name(), doctorCompletionCmd.Name())
	}
	for _, command := range rootCmd.Commands() {
		if command.Name() == "completion" {
			t.Fatal("legacy top-level completion command is still registered")
		}
	}
}

func TestCompletionLayoutForEachSupportedShell(t *testing.T) {
	home := t.TempDir()
	for _, test := range []struct {
		shell, wantFile string
	}{
		{"bash", ".local/share/bash-completion/completions/xray-proxya"},
		{"zsh", ".local/share/zsh/site-functions/_xray-proxya"},
		{"fish", ".config/fish/completions/xray-proxya.fish"},
	} {
		layout, err := completionLayoutFor(test.shell, home)
		if err != nil {
			t.Fatalf("layout for %s: %v", test.shell, err)
		}
		if got := strings.TrimPrefix(layout.file, home+string(filepath.Separator)); got != test.wantFile {
			t.Fatalf("%s file = %q, want %q", test.shell, got, test.wantFile)
		}
	}
}

func TestGenerateCompletionForEachSupportedShell(t *testing.T) {
	home := t.TempDir()
	for _, shell := range []string{"bash", "zsh", "fish"} {
		layout, err := completionLayoutFor(shell, filepath.Join(home, shell))
		if err != nil {
			t.Fatalf("layout for %s: %v", shell, err)
		}
		if err := installCompletion(layout); err != nil {
			t.Fatalf("install %s completion: %v", shell, err)
		}
		script, err := os.ReadFile(layout.file)
		if err != nil {
			t.Fatalf("read %s completion: %v", shell, err)
		}
		if len(script) == 0 || !strings.Contains(string(script), "xray-proxya") {
			t.Fatalf("generated %s completion is invalid", shell)
		}
		if err := uninstallCompletion(layout); err != nil {
			t.Fatalf("uninstall %s completion: %v", shell, err)
		}
	}
}

func TestInstallAndUninstallBashCompletionPreservesUserProfile(t *testing.T) {
	home := t.TempDir()
	previousHome := completionHomeDir
	completionHomeDir = func() string { return home }
	t.Cleanup(func() { completionHomeDir = previousHome })

	layout, err := completionLayoutFor("bash", home)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.profile, []byte("alias ll='ls -la'\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := installCompletion(layout); err != nil {
		t.Fatalf("install completion: %v", err)
	}
	script, err := os.ReadFile(layout.file)
	if err != nil {
		t.Fatalf("read generated completion: %v", err)
	}
	if !strings.Contains(string(script), "doctor") || !strings.Contains(string(script), "completion") {
		t.Fatal("generated bash completion does not include doctor completion commands")
	}
	profile, err := os.ReadFile(layout.profile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(profile), completionStartMarker) || !strings.Contains(string(profile), "/usr/share/bash-completion/bash_completion") || !strings.Contains(string(profile), "alias ll='ls -la'") {
		t.Fatalf("profile missing managed block or user configuration:\n%s", profile)
	}
	if err := uninstallCompletion(layout); err != nil {
		t.Fatalf("uninstall completion: %v", err)
	}
	if _, err := os.Stat(layout.file); !os.IsNotExist(err) {
		t.Fatalf("completion file remains after uninstall: %v", err)
	}
	profile, err = os.ReadFile(layout.profile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(profile), completionStartMarker) || !strings.Contains(string(profile), "alias ll='ls -la'") {
		t.Fatalf("uninstall did not preserve user profile:\n%s", profile)
	}
}

func TestStripLegacyZshCompletionPreservesCompinit(t *testing.T) {
	layout, err := completionLayoutFor("zsh", "/home/test")
	if err != nil {
		t.Fatal(err)
	}
	content := strings.Join([]string{
		"autoload -Uz compinit && compinit",
		"# Xray-Proxya Completion",
		"fpath=(/home/test/.local/share/zsh/site-functions $fpath)",
		"autoload -Uz _xray-proxya",
		"alias ll='ls -la'",
	}, "\n")
	cleaned := stripLegacyCompletionProfile(content, layout)
	if strings.Contains(cleaned, "# Xray-Proxya Completion") || strings.Contains(cleaned, "_xray-proxya") {
		t.Fatalf("legacy completion remains:\n%s", cleaned)
	}
	if !strings.Contains(cleaned, "compinit") || !strings.Contains(cleaned, "alias ll='ls -la'") {
		t.Fatalf("user zsh configuration was removed:\n%s", cleaned)
	}
}

func containsCompletion(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
