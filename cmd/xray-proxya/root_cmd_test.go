package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanRCPreservesCompinitAndUserConfig(t *testing.T) {
	dir := t.TempDir()
	rcFile := filepath.Join(dir, ".zshrc")

	initialContent := `export PATH=$PATH:/usr/local/bin
autoload -Uz compinit && compinit
# Xray-Proxya Completion
fpath=(/root/.local/share/zsh/site-functions $fpath)
autoload -Uz _xray-proxya
# Base Shell Completion Support
[ -f /root/.local/share/bash-completion/bash_completion.sh ] && . /root/.local/share/bash-completion/bash_completion.sh
alias ll='ls -la'
`

	if err := os.WriteFile(rcFile, []byte(initialContent), 0644); err != nil {
		t.Fatalf("Failed to create mock rc file: %v", err)
	}

	cleanRC(rcFile, "xray-proxya")

	data, err := os.ReadFile(rcFile)
	if err != nil {
		t.Fatalf("Failed to read cleaned rc file: %v", err)
	}

	cleaned := string(data)
	if !strings.Contains(cleaned, "compinit") {
		t.Errorf("cleanRC removed 'compinit' from .zshrc! Cleaned content:\n%s", cleaned)
	}
	if !strings.Contains(cleaned, "alias ll='ls -la'") {
		t.Errorf("cleanRC removed user alias! Cleaned content:\n%s", cleaned)
	}
	if strings.Contains(cleaned, "# Xray-Proxya Completion") {
		t.Errorf("cleanRC failed to remove Xray-Proxya completion header")
	}
}
