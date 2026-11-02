package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"xray-proxya/internal/config"
)

// FindXrayProxyaBinary resolves a valid, executable xray-proxya binary path
// suitable to be symlinked.
func FindXrayProxyaBinary() (string, error) {
	isValid := func(p string) bool {
		base := strings.TrimSuffix(filepath.Base(p), ".exe")
		if base == "pathd" || base == "xray-proxya-pathd" {
			return false
		}
		info, err := os.Stat(p)
		return err == nil && !info.IsDir() && info.Mode().Perm()&0111 != 0
	}

	// 1. Check standard installed locations first
	candidates := []string{
		filepath.Join(config.GetHomeDir(), ".local", "bin", "xray-proxya"),
		RootManagerBinary,
		"/usr/local/bin/xray-proxya",
		"/usr/bin/xray-proxya",
	}
	if lp, err := exec.LookPath("xray-proxya"); err == nil {
		candidates = append([]string{lp}, candidates...)
	}

	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		if realPath, err := filepath.EvalSymlinks(cand); err == nil && isValid(realPath) {
			return realPath, nil
		}
	}

	// 2. Check current running executable
	if self, err := os.Executable(); err == nil && self != "" {
		if realPath, err := filepath.EvalSymlinks(self); err == nil && isValid(realPath) {
			return realPath, nil
		}
	}

	// 3. Fallback to os.Executable() if executable (e.g. test binary or build output)
	if self, err := os.Executable(); err == nil && self != "" {
		if info, err := os.Stat(self); err == nil && !info.IsDir() && info.Mode().Perm()&0111 != 0 {
			return self, nil
		}
	}

	return "", fmt.Errorf("unable to locate xray-proxya binary")
}

// EnsurePathdSymlink ensures that PathdBinaryPath() exists and points to a valid executable.
// If it does not exist or is a broken symlink, it creates a symlink pointing to
// the current xray-proxya binary.
func EnsurePathdSymlink() (string, error) {
	return EnsurePathdSymlinkAt(PathdBinaryPath())
}

// EnsurePathdSymlinkAt ensures that a pathd binary or symlink exists at targetPath.
func EnsurePathdSymlinkAt(targetPath string) (string, error) {
	cleanPath := filepath.Clean(targetPath)

	// Check if already present and valid
	if fi, err := os.Lstat(cleanPath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			// Symlink: verify target exists and is executable
			target, err := filepath.EvalSymlinks(cleanPath)
			if err == nil {
				if tfi, err := os.Stat(target); err == nil && !tfi.IsDir() && tfi.Mode().Perm()&0111 != 0 {
					return cleanPath, nil
				}
			}
			// Broken or invalid symlink -> remove to recreate
			_ = os.Remove(cleanPath)
		} else if fi.Mode().IsRegular() && fi.Mode().Perm()&0111 != 0 {
			// Standalone regular executable already exists and is executable
			return cleanPath, nil
		} else {
			// Non-executable or corrupted regular file -> clean up
			_ = os.Remove(cleanPath)
		}
	}

	// Resolve the target binary to link to
	targetBin, err := FindXrayProxyaBinary()
	if err != nil {
		return "", err
	}

	// Ensure parent directory exists
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create pathd bin directory: %w", err)
	}

	// Atomic symlink creation via temporary file
	tmpSymlink := filepath.Join(dir, fmt.Sprintf(".pathd.tmp.%d", os.Getpid()))
	_ = os.Remove(tmpSymlink)
	if err := os.Symlink(targetBin, tmpSymlink); err != nil {
		return "", fmt.Errorf("create symlink %s -> %s: %w", tmpSymlink, targetBin, err)
	}
	if err := os.Rename(tmpSymlink, cleanPath); err != nil {
		_ = os.Remove(tmpSymlink)
		return "", fmt.Errorf("replace symlink %s: %w", cleanPath, err)
	}

	return cleanPath, nil
}
