package doctor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateAndRestoreBackup(t *testing.T) {
	tempDir := t.TempDir()
	configDir := filepath.Join(tempDir, "config")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	// 1. Without config.json, CreateBackup should fail
	if _, err := CreateBackup(configDir, ""); err == nil {
		t.Fatal("expected error when config.json does not exist")
	}

	// 2. Setup mock configuration files
	mainCfgContent := `{"role":"server","api_inbound":10085,"uuid":"test-uuid"}`
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(mainCfgContent), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "pathd.json"), []byte(`{"token":"secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	certDir := filepath.Join(configDir, "certs", "example.com")
	if err := os.MkdirAll(certDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "fullchain.cer"), []byte("CERT_DATA"), 0600); err != nil {
		t.Fatal(err)
	}
	// Temporary file that should be excluded
	if err := os.WriteFile(filepath.Join(configDir, "gateway.tun.disabled"), []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}

	// 3. Create backup
	res, err := CreateBackup(configDir, "")
	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}
	if _, err := os.Stat(res.BackupPath); err != nil {
		t.Fatalf("backup file not created at %s: %v", res.BackupPath, err)
	}
	foundTunDisabled := false
	for _, f := range res.ArchivedFiles {
		if f == "gateway.tun.disabled" {
			foundTunDisabled = true
		}
	}
	if foundTunDisabled {
		t.Fatal("expected temporary file gateway.tun.disabled to be excluded from backup")
	}

	// 4. Test ListBackupFiles
	backups, err := ListBackupFiles(configDir)
	if err != nil {
		t.Fatalf("ListBackupFiles failed: %v", err)
	}
	if len(backups) == 0 {
		t.Fatal("expected at least one backup file listed")
	}
	if filepath.Base(res.BackupPath) != backups[0] {
		t.Fatalf("expected latest backup %s, got %s", filepath.Base(res.BackupPath), backups[0])
	}

	// 5. Modify configDir to simulate corruption or changes
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(`{"role":"corrupted"}`), 0600); err != nil {
		t.Fatal(err)
	}

	// 6. Restore backup
	restoreRes, err := RestoreBackup(res.BackupPath, configDir)
	if err != nil {
		t.Fatalf("RestoreBackup failed: %v", err)
	}
	if len(restoreRes.RestoredFiles) == 0 {
		t.Fatal("expected restored files, got none")
	}

	restoredContent, err := os.ReadFile(filepath.Join(configDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(restoredContent) != mainCfgContent {
		t.Fatalf("restored content mismatch: got %s, want %s", string(restoredContent), mainCfgContent)
	}

	// 7. Restore with filename-only (relative to configDir)
	restoreRel, err := RestoreBackup(filepath.Base(res.BackupPath), configDir)
	if err != nil {
		t.Fatalf("RestoreBackup with relative filename failed: %v", err)
	}
	if len(restoreRel.RestoredFiles) == 0 {
		t.Fatal("expected restored files from relative path")
	}
}
