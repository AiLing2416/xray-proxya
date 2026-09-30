package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

func resetPurgeFlags() {
	purgeInclude = nil
	if f := purgeCmd.Flags().Lookup("include"); f != nil {
		f.Changed = false
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			_ = sv.Replace(nil)
		}
	}
	if f := purgeCmd.Flags().Lookup("dry-run"); f != nil {
		f.Changed = false
		_ = f.Value.Set("false")
	}
	if f := purgeCmd.Flags().Lookup("force"); f != nil {
		f.Changed = false
		_ = f.Value.Set("false")
	}
}

func TestPurgeCmdRequiresIncludeFlag(t *testing.T) {
	resetPurgeFlags()
	cmd := rootCmd
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"purge"})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error when -i flag is omitted, got nil")
	}
	if !strings.Contains(err.Error(), "no target types specified") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestPurgeCmdAmbiguousPathFails(t *testing.T) {
	resetPurgeFlags()
	cmd := rootCmd
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"purge", "-i", "path"})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error for -i path, got nil")
	}
	if !strings.Contains(err.Error(), "ambiguous target \"path\"") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestPurgeCmdDryRun(t *testing.T) {
	resetPurgeFlags()
	t.Setenv("XRAY_PROXYA_TEST_ENV", "1")
	tempDir := t.TempDir()
	cfgDir := filepath.Join(tempDir, "config")
	_ = os.MkdirAll(cfgDir, 0700)
	_ = os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte("{}"), 0600)

	t.Setenv("XRAY_PROXYA_CONFIG_DIR", cfgDir)

	cmd := rootCmd
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"purge", "-i", "config", "-d"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute purge -i config -d failed: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "[DRY-RUN]") {
		t.Fatalf("expected [DRY-RUN] in output:\n%s", out)
	}
	if !strings.Contains(out, "config.json") {
		t.Fatalf("expected config.json in dry-run plan:\n%s", out)
	}

	// Verify file was NOT deleted in dry-run
	if _, err := os.Stat(filepath.Join(cfgDir, "config.json")); err != nil {
		t.Fatalf("config.json should still exist after dry-run, got err: %v", err)
	}
}

func TestPurgeCmdForce(t *testing.T) {
	resetPurgeFlags()
	t.Setenv("XRAY_PROXYA_TEST_ENV", "1")
	tempDir := t.TempDir()
	cfgDir := filepath.Join(tempDir, "config")
	_ = os.MkdirAll(cfgDir, 0700)
	_ = os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte("{}"), 0600)

	t.Setenv("XRAY_PROXYA_CONFIG_DIR", cfgDir)

	cmd := rootCmd
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"purge", "-i", "config", "-f"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute purge -i config -f failed: %v", err)
	}

	// Verify file was deleted
	if _, err := os.Stat(filepath.Join(cfgDir, "config.json")); !os.IsNotExist(err) {
		t.Fatalf("config.json should be deleted after force purge")
	}
}

func TestPurgeCmdInteractiveCancelled(t *testing.T) {
	resetPurgeFlags()
	t.Setenv("XRAY_PROXYA_TEST_ENV", "1")
	tempDir := t.TempDir()
	cfgDir := filepath.Join(tempDir, "config")
	_ = os.MkdirAll(cfgDir, 0700)
	_ = os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte("{}"), 0600)

	t.Setenv("XRAY_PROXYA_CONFIG_DIR", cfgDir)

	cmd := rootCmd
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetIn(strings.NewReader("n\n")) // User enters 'n'
	cmd.SetArgs([]string{"purge", "-i", "config"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute purge failed: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "Purge cancelled.") {
		t.Fatalf("expected 'Purge cancelled.' in output:\n%s", out)
	}

	// Verify file still exists
	if _, err := os.Stat(filepath.Join(cfgDir, "config.json")); err != nil {
		t.Fatalf("config.json should still exist after cancellation, got err: %v", err)
	}
}

func TestPurgeCmdFlagCompletion(t *testing.T) {
	resetPurgeFlags()
	cmd := rootCmd
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"__complete", "purge", "-i", ""})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("completion failed: %v", err)
	}

	out := stdout.String()
	for _, target := range []string{"config", "cert", "core", "service", "bin", "data", "cache", "backup", "completion", "profile", "all"} {
		if !strings.Contains(out, target) {
			t.Errorf("completion output missing %q:\n%s", target, out)
		}
	}

	// Test comma prefix completion
	stdout.Reset()
	cmd.SetArgs([]string{"__complete", "purge", "-i", "config,"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("comma completion failed: %v", err)
	}
	outComma := stdout.String()
	if !strings.Contains(outComma, "config,cert") {
		t.Errorf("comma completion output missing 'config,cert':\n%s", outComma)
	}
	if strings.Contains(outComma, "config,config") {
		t.Errorf("comma completion unexpectedly suggested already selected 'config,config':\n%s", outComma)
	}
}

