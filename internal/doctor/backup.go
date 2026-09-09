package doctor

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BackupResult holds information about a completed backup.
type BackupResult struct {
	BackupPath    string   `json:"backup_path"`
	ArchivedFiles []string `json:"archived_files"`
}

// RestoreResult holds information about a restored backup.
type RestoreResult struct {
	BackupPath    string   `json:"backup_path"`
	RestoredFiles []string `json:"restored_files"`
}

// CreateBackup archives active configuration files into a single .tar.gz archive.
func CreateBackup(configDir, targetPath string) (*BackupResult, error) {
	if configDir == "" {
		return nil, fmt.Errorf("config directory cannot be empty")
	}

	mainConfig := filepath.Join(configDir, "config.json")
	if _, err := os.Stat(mainConfig); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no active config.json found in %s; nothing to backup", configDir)
		}
		return nil, fmt.Errorf("stat main config: %w", err)
	}

	destPath := strings.TrimSpace(targetPath)
	if destPath == "" {
		timestamp := time.Now().Format("20060102-150405")
		destPath = filepath.Join(configDir, fmt.Sprintf("xray-proxya-backup-%s.tar.gz", timestamp))
	} else if !filepath.IsAbs(destPath) && !strings.Contains(destPath, string(filepath.Separator)) {
		destPath = filepath.Join(configDir, destPath)
	}

	if !strings.HasSuffix(destPath, ".tar.gz") && !strings.HasSuffix(destPath, ".tgz") {
		destPath += ".tar.gz"
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0700); err != nil {
		return nil, fmt.Errorf("create backup parent directory: %w", err)
	}

	outF, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("create backup archive file: %w", err)
	}
	defer outF.Close()

	gw := gzip.NewWriter(outF)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	var archived []string

	// Walk config directory and select relevant configuration files
	err = filepath.Walk(configDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == configDir {
			return nil
		}

		rel, err := filepath.Rel(configDir, path)
		if err != nil {
			return err
		}

		// Skip temporary files, runtime locks/sockets, and existing backup archives
		base := filepath.Base(path)
		if strings.HasSuffix(base, ".tar.gz") || strings.HasSuffix(base, ".tgz") || strings.HasSuffix(base, ".bak") {
			return nil
		}
		if strings.HasSuffix(base, ".sock") || strings.HasSuffix(base, ".lock") || strings.HasSuffix(base, ".disabled") {
			return nil
		}
		if strings.HasPrefix(base, "xray-proxya-") && strings.HasSuffix(base, ".nft") {
			return nil
		}

		if info.IsDir() {
			// Only backup certs subfolder or other relevant config subfolders
			if rel != "certs" && !strings.HasPrefix(rel, "certs"+string(filepath.Separator)) {
				return filepath.SkipDir
			}
			return nil
		}

		// Only include regular files
		if !info.Mode().IsRegular() {
			return nil
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("create tar header for %s: %w", rel, err)
		}
		header.Name = filepath.ToSlash(rel)

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("write tar header for %s: %w", rel, err)
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open file for backup %s: %w", path, err)
		}
		defer f.Close()

		if _, err := io.Copy(tw, f); err != nil {
			return fmt.Errorf("archive content of %s: %w", rel, err)
		}

		archived = append(archived, header.Name)
		return nil
	})

	if err != nil {
		_ = os.Remove(destPath)
		return nil, fmt.Errorf("walk and archive config files: %w", err)
	}

	return &BackupResult{
		BackupPath:    destPath,
		ArchivedFiles: archived,
	}, nil
}

// RestoreBackup unpacks a previously created backup archive into configDir.
func RestoreBackup(backupPath, configDir string) (*RestoreResult, error) {
	if strings.TrimSpace(backupPath) == "" {
		return nil, fmt.Errorf("backup path cannot be empty")
	}

	targetPath := backupPath
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		// If not found as-is, try looking in configDir
		candidate := filepath.Join(configDir, backupPath)
		if _, err := os.Stat(candidate); err == nil {
			targetPath = candidate
		} else {
			return nil, fmt.Errorf("backup file not found: %s", backupPath)
		}
	}

	inF, err := os.Open(targetPath)
	if err != nil {
		return nil, fmt.Errorf("open backup file: %w", err)
	}
	defer inF.Close()

	gr, err := gzip.NewReader(inF)
	if err != nil {
		return nil, fmt.Errorf("decompress backup file (must be gzip): %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	// Pre-scan: ensure archive contains a valid config.json and no Zip Slip traversal
	var hasMainConfig bool
	var mainConfigData []byte
	type fileEntry struct {
		name    string
		mode    os.FileMode
		content []byte
	}
	var entries []fileEntry

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar entry: %w", err)
		}

		cleanedName := filepath.Clean(hdr.Name)
		if strings.HasPrefix(cleanedName, "..") || filepath.IsAbs(cleanedName) {
			return nil, fmt.Errorf("illegal relative path in backup archive: %s", hdr.Name)
		}

		if hdr.FileInfo().IsDir() {
			continue
		}

		content, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read entry content %s: %w", hdr.Name, err)
		}

		if cleanedName == "config.json" {
			hasMainConfig = true
			mainConfigData = content
		}

		entries = append(entries, fileEntry{
			name:    cleanedName,
			mode:    hdr.FileInfo().Mode(),
			content: content,
		})
	}

	if !hasMainConfig {
		return nil, fmt.Errorf("invalid backup archive: missing required config.json")
	}

	// Validate config.json syntax
	var dummy map[string]interface{}
	if err := json.Unmarshal(mainConfigData, &dummy); err != nil {
		return nil, fmt.Errorf("invalid config.json in backup archive: %w", err)
	}

	// Extract files into configDir
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, fmt.Errorf("ensure config directory: %w", err)
	}

	var restored []string
	for _, entry := range entries {
		destFile := filepath.Join(configDir, entry.name)
		if err := os.MkdirAll(filepath.Dir(destFile), 0700); err != nil {
			return nil, fmt.Errorf("create directory for %s: %w", entry.name, err)
		}

		perm := entry.mode.Perm()
		if perm == 0 {
			perm = 0600
		}
		if err := os.WriteFile(destFile, entry.content, perm); err != nil {
			return nil, fmt.Errorf("write restored file %s: %w", entry.name, err)
		}
		restored = append(restored, entry.name)
	}

	return &RestoreResult{
		BackupPath:    targetPath,
		RestoredFiles: restored,
	}, nil
}

// ListBackupFiles returns all backup archive filenames in configDir, sorted by modification time (newest first).
func ListBackupFiles(configDir string) ([]string, error) {
	if configDir == "" {
		return nil, nil
	}

	entries, err := os.ReadDir(configDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	type fileWithTime struct {
		name    string
		modTime time.Time
	}
	var matches []fileWithTime

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz") {
			info, err := e.Info()
			if err == nil {
				matches = append(matches, fileWithTime{name: name, modTime: info.ModTime()})
			} else {
				matches = append(matches, fileWithTime{name: name})
			}
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].modTime.After(matches[j].modTime)
	})

	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.name)
	}
	return names, nil
}
