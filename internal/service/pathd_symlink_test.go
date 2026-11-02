package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsurePathdSymlinkAt(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Create a dummy executable representing xray-proxya
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	dummyExe := filepath.Join(binDir, "xray-proxya")
	if err := os.WriteFile(dummyExe, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	targetPath := filepath.Join(tmpDir, "share", "bin", "pathd")

	// Pre-condition: targetPath does not exist
	if _, err := os.Lstat(targetPath); err == nil {
		t.Fatalf("expected targetPath to not exist initially")
	}

	// 2. Ensure symlink creation
	created, err := EnsurePathdSymlinkAt(targetPath)
	if err != nil {
		t.Fatalf("EnsurePathdSymlinkAt failed: %v", err)
	}
	if created != targetPath {
		t.Errorf("created = %q, want %q", created, targetPath)
	}

	// Verify targetPath is a symlink
	lfi, err := os.Lstat(targetPath)
	if err != nil {
		t.Fatalf("failed to lstat targetPath: %v", err)
	}
	if lfi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected targetPath to be a symlink")
	}

	// Verify symlink resolves to an executable file
	target, err := filepath.EvalSymlinks(targetPath)
	if err != nil {
		t.Fatalf("failed to eval symlink: %v", err)
	}
	tfi, err := os.Stat(target)
	if err != nil || tfi.IsDir() || tfi.Mode().Perm()&0111 == 0 {
		t.Fatalf("symlink target is not an executable file: %v", target)
	}

	// 3. Test idempotency (calling again should preserve existing valid symlink)
	created2, err := EnsurePathdSymlinkAt(targetPath)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if created2 != targetPath {
		t.Errorf("second created = %q, want %q", created2, targetPath)
	}

	// 4. Test broken symlink auto-healing
	// Intentionally point the symlink to a non-existent file
	_ = os.Remove(targetPath)
	if err := os.Symlink(filepath.Join(tmpDir, "missing-file"), targetPath); err != nil {
		t.Fatal(err)
	}

	healed, err := EnsurePathdSymlinkAt(targetPath)
	if err != nil {
		t.Fatalf("EnsurePathdSymlinkAt failed to heal broken symlink: %v", err)
	}
	if healed != targetPath {
		t.Errorf("healed = %q, want %q", healed, targetPath)
	}
	healedTarget, err := filepath.EvalSymlinks(targetPath)
	if err != nil {
		t.Fatalf("failed to eval healed symlink: %v", err)
	}
	if _, err := os.Stat(healedTarget); err != nil {
		t.Fatalf("healed symlink does not resolve: %v", err)
	}

	// 5. Test regular standalone binary preservation
	_ = os.Remove(targetPath)
	if err := os.WriteFile(targetPath, []byte("#!/bin/sh\necho standalone\n"), 0755); err != nil {
		t.Fatal(err)
	}
	regResult, err := EnsurePathdSymlinkAt(targetPath)
	if err != nil {
		t.Fatalf("call failed on existing regular file: %v", err)
	}
	if regResult != targetPath {
		t.Errorf("regResult = %q, want %q", regResult, targetPath)
	}
	regFi, err := os.Lstat(targetPath)
	if err != nil || regFi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("expected regular file to be preserved as regular file")
	}
}
