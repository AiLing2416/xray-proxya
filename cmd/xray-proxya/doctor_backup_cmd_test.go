package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorBackupCmd_Registration(t *testing.T) {
	command, _, err := doctorCmd.Find([]string{"backup"})
	if err != nil {
		t.Fatalf("find doctor backup: %v", err)
	}
	if command != doctorBackupCmd {
		t.Fatalf("doctor backup command = %q, want %q", command.Name(), doctorBackupCmd.Name())
	}
}

func TestDoctorBackupCmd_ExecutionAndRollback(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", tempDir)

	// Create test config.json
	testCfg := `{"role":"server","api_inbound":10085,"uuid":"test-uuid-123"}`
	if err := os.WriteFile(filepath.Join(tempDir, "config.json"), []byte(testCfg), 0600); err != nil {
		t.Fatal(err)
	}

	// 1. Run backup
	buf := new(bytes.Buffer)
	doctorBackupCmd.SetOut(buf)
	doctorBackupCmd.SetErr(buf)
	doctorBackupRollPath = ""

	err := doctorBackupCmd.RunE(doctorBackupCmd, []string{})
	if err != nil {
		t.Fatalf("doctor backup failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Configuration backup created successfully") {
		t.Fatalf("unexpected backup output: %s", out)
	}

	// Find the created backup file
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	var backupFile string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tar.gz") {
			backupFile = e.Name()
			break
		}
	}
	if backupFile == "" {
		t.Fatal("no backup file found in tempDir")
	}

	// 2. Corrupt or change config.json
	if err := os.WriteFile(filepath.Join(tempDir, "config.json"), []byte(`{"role":"corrupted"}`), 0600); err != nil {
		t.Fatal(err)
	}

	// 3. Rollback using relative filename in config dir
	buf.Reset()
	doctorBackupRollPath = backupFile
	err = doctorBackupCmd.RunE(doctorBackupCmd, []string{})
	if err != nil {
		t.Fatalf("doctor backup rollback failed: %v", err)
	}

	rollbackOut := buf.String()
	if !strings.Contains(rollbackOut, "Successfully restored configuration") {
		t.Fatalf("unexpected rollback output: %s", rollbackOut)
	}

	restored, err := os.ReadFile(filepath.Join(tempDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != testCfg {
		t.Fatalf("config not restored properly: got %s, want %s", string(restored), testCfg)
	}

	// Reset flag
	doctorBackupRollPath = ""
}
