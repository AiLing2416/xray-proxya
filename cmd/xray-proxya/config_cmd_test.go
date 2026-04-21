package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigUpgradeDryRunDoesNotModifyFile(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configPath := filepath.Join(tmpHome, ".config", "xray-proxya", "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	original := `{"custom_outbounds":[{"alias":"relay-a","enabled":true,"config":{}}],"guests":[{"alias":"guest-a","reset_day":0}]}`
	if err := os.WriteFile(configPath, []byte(original), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	configUpgradeStaging = false
	configUpgradeDryRun = true
	t.Cleanup(func() {
		configUpgradeStaging = false
		configUpgradeDryRun = false
	})

	output := captureStdout(t, func() {
		configUpgradeCmd.Run(configUpgradeCmd, nil)
	})

	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(after) != original {
		t.Fatalf("config file changed during dry-run\nbefore: %s\nafter:  %s", original, string(after))
	}

	if !strings.Contains(output, "Dry run") {
		t.Fatalf("output = %q, want dry-run banner", output)
	}
	if !strings.Contains(output, "No files were modified.") {
		t.Fatalf("output = %q, want no-write confirmation", output)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	data, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	return string(data)
}
