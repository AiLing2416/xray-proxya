package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestIsPathdMultiCall(t *testing.T) {
	tests := []struct {
		name     string
		prog     string
		expected bool
	}{
		{"exact pathd", "pathd", true},
		{"exact xray-proxya-pathd", "xray-proxya-pathd", true},
		{"linux path pathd", "/root/.local/share/xray-proxya/bin/pathd", true},
		{"usr local bin pathd", "/usr/local/bin/pathd", true},
		{"usr bin xray-proxya-pathd", "/usr/bin/xray-proxya-pathd", true},
		{"windows pathd.exe", "pathd.exe", true},
		{"windows path pathd.exe", `C:\Program Files\xray-proxya\pathd.exe`, true},
		{"windows xray-proxya-pathd.exe", "xray-proxya-pathd.exe", true},
		{"main binary xray-proxya", "xray-proxya", false},
		{"main binary path", "/root/.local/bin/xray-proxya", false},
		{"another binary", "curl", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPathdMultiCall(tt.prog)
			if got != tt.expected {
				t.Errorf("isPathdMultiCall(%q) = %v; want %v", tt.prog, got, tt.expected)
			}
		})
	}
}

func TestPathdSubcommandExecution(t *testing.T) {
	origExit := pathdExitFunc
	defer func() { pathdExitFunc = origExit }()

	var capturedExitCode int
	pathdExitFunc = func(code int) {
		capturedExitCode = code
	}

	rootCmd.SetArgs([]string{"pathd", "serve", "--invalid-test-flag"})
	var outBuf, errBuf bytes.Buffer
	rootCmd.SetOut(&outBuf)
	rootCmd.SetErr(&errBuf)

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected cobra error: %v", err)
	}

	if capturedExitCode != 2 {
		t.Fatalf("expected exit code 2 from pathd invalid args, got %d", capturedExitCode)
	}
}

func TestPathdSubcommandHelp(t *testing.T) {
	origExit := pathdExitFunc
	defer func() { pathdExitFunc = origExit }()

	var capturedExitCode int
	pathdExitFunc = func(code int) {
		capturedExitCode = code
	}

	// Invoking without args should trigger pathd usage
	rootCmd.SetArgs([]string{"pathd"})
	var outBuf, errBuf bytes.Buffer
	rootCmd.SetOut(&outBuf)
	rootCmd.SetErr(&errBuf)

	_ = rootCmd.Execute()
	if capturedExitCode != 2 {
		t.Fatalf("expected exit code 2 for pathd without args, got %d", capturedExitCode)
	}
	if !strings.Contains(errBuf.String(), "usage: xray-proxya-pathd serve") {
		t.Fatalf("expected usage error output, got %q", errBuf.String())
	}
}
