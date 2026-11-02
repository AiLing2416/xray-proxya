package xray

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type mockFileInfo struct {
	name  string
	isDir bool
	mode  os.FileMode
}

func (m mockFileInfo) Name() string       { return m.name }
func (m mockFileInfo) Size() int64        { return 1024 }
func (m mockFileInfo) Mode() os.FileMode  { return m.mode }
func (m mockFileInfo) ModTime() time.Time { return time.Now() }
func (m mockFileInfo) IsDir() bool        { return m.isDir }
func (m mockFileInfo) Sys() interface{}   { return nil }

func TestParseXrayVersion(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{
			name: "official full version banner",
			raw:  "Xray 26.10.31 (Xray, Penetrates Everything.) Custom (go1.25.1 linux/amd64)\nA unified platform for anti-censorship.",
			want: "v26.10.31",
		},
		{
			name: "version banner with leading v",
			raw:  "Xray v26.10.31 (Xray, Penetrates Everything.) Custom",
			want: "v26.10.31",
		},
		{
			name: "version banner with Core prefix",
			raw:  "Xray Core 26.10.31 (Xray, Penetrates Everything.)",
			want: "v26.10.31",
		},
		{
			name: "legacy 1.x version",
			raw:  "Xray 1.8.24 (Xray, Penetrates Everything.) 1234567 (go1.22.0 linux/amd64)",
			want: "v1.8.24",
		},
		{
			name: "newer CalVer version banner",
			raw:  "Xray 26.11.0 (Xray, Penetrates Everything.)",
			want: "v26.11.0",
		},
		{
			name: "version banner with prerelease suffix",
			raw:  "Xray 26.10.31-beta.1 (Xray, Penetrates Everything.)",
			want: "v26.10.31-beta.1",
		},
		{
			name: "standalone version with v prefix",
			raw:  "v26.10.31",
			want: "v26.10.31",
		},
		{
			name: "standalone version without v prefix",
			raw:  "26.10.31",
			want: "v26.10.31",
		},
		{
			name: "standalone version 1.8.24",
			raw:  "1.8.24",
			want: "v1.8.24",
		},
		{
			name: "standalone version with prerelease",
			raw:  "v26.10.31-rc1",
			want: "v26.10.31-rc1",
		},
		{
			name: "version banner preceded by log line",
			raw:  "2026/11/02 12:00:00 [Info] Init\nXray 26.10.31 (Xray, Penetrates Everything.)",
			want: "v26.10.31",
		},
		{
			name:    "empty string",
			raw:     "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			raw:     "   \t\n",
			wantErr: true,
		},
		{
			name:    "arbitrary text",
			raw:     "command not found: xray",
			wantErr: true,
		},
		{
			name:    "xray unknown",
			raw:     "Xray unknown version",
			wantErr: true,
		},
		{
			name:    "just v",
			raw:     "v",
			wantErr: true,
		},
		{
			name:    "go runtime string without xray",
			raw:     "go1.25.1 linux/amd64",
			wantErr: true,
		},
		{
			name:    "malformed non-numeric component",
			raw:     "Xray 1.a.2",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseXrayVersion(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseXrayVersion(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseXrayVersion(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name    string
		v1      string
		v2      string
		want    int
		wantErr bool
	}{
		{
			name: "v26.10.31 vs v26.10.21 (same year and month, higher day)",
			v1:   "v26.10.31",
			v2:   "v26.10.21",
			want: 1,
		},
		{
			name: "v26.10.31 vs v26.11.0 (same year, lower month)",
			v1:   "v26.10.31",
			v2:   "v26.11.0",
			want: -1,
		},
		{
			name: "v1.8.24 vs v26.10.31 (major 1 vs 26)",
			v1:   "v1.8.24",
			v2:   "v26.10.31",
			want: -1,
		},
		{
			name: "v26.10.31 vs v1.8.24 (major 26 vs 1)",
			v1:   "v26.10.31",
			v2:   "v1.8.24",
			want: 1,
		},
		{
			name: "identical versions with v prefix",
			v1:   "v26.10.31",
			v2:   "v26.10.31",
			want: 0,
		},
		{
			name: "with and without v prefix",
			v1:   "26.10.31",
			v2:   "v26.10.31",
			want: 0,
		},
		{
			name: "full output vs version tag",
			v1:   "Xray 26.10.31 (Xray, Penetrates Everything.)",
			v2:   "v26.10.31",
			want: 0,
		},
		{
			name: "patch revision greater",
			v1:   "v26.10.31.1",
			v2:   "v26.10.31",
			want: 1,
		},
		{
			name: "shorter version equal with trailing zero",
			v1:   "v26.10",
			v2:   "v26.10.0",
			want: 0,
		},
		{
			name: "shorter version less than trailing non-zero",
			v1:   "v26.10",
			v2:   "v26.10.1",
			want: -1,
		},
		{
			name: "release vs pre-release",
			v1:   "v26.10.31",
			v2:   "v26.10.31-beta.1",
			want: 1,
		},
		{
			name: "pre-release vs release",
			v1:   "v26.10.31-beta.1",
			v2:   "v26.10.31",
			want: -1,
		},
		{
			name: "pre-release comparison",
			v1:   "v26.10.31-beta.2",
			v2:   "v26.10.31-beta.1",
			want: 1,
		},
		{
			name:    "first version invalid",
			v1:      "invalid",
			v2:      "v26.10.31",
			wantErr: true,
		},
		{
			name:    "second version invalid",
			v1:      "v26.10.31",
			v2:      "corrupt",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CompareVersions(tt.v1, tt.v2)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CompareVersions(%q, %q) error = %v, wantErr %v", tt.v1, tt.v2, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

func TestIsVersionAtLeast(t *testing.T) {
	tests := []struct {
		name    string
		ver     string
		floor   string
		want    bool
		wantErr bool
	}{
		{"exact match", "v26.10.31", "v26.10.31", true, false},
		{"exact match without v", "26.10.31", "v26.10.31", true, false},
		{"newer month", "v26.11.0", "v26.10.31", true, false},
		{"newer year", "v27.1.1", "v26.10.31", true, false},
		{"subpatch", "v26.10.31.2", "v26.10.31", true, false},
		{"older day", "v26.10.21", "v26.10.31", false, false},
		{"older major", "v1.8.24", "v26.10.31", false, false},
		{"pre-release of floor", "v26.10.31-beta", "v26.10.31", false, false},
		{"invalid candidate", "unknown", "v26.10.31", false, true},
		{"invalid floor", "v26.10.31", "unknown", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsVersionAtLeast(tt.ver, tt.floor)
			if (err != nil) != tt.wantErr {
				t.Fatalf("IsVersionAtLeast(%q, %q) error = %v, wantErr %v", tt.ver, tt.floor, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("IsVersionAtLeast(%q, %q) = %v, want %v", tt.ver, tt.floor, got, tt.want)
			}
		})
	}
}

func TestResolveBinary_XRayBinEnvOverride(t *testing.T) {
	fileMap := map[string]os.FileInfo{
		"/custom/bin/xray": mockFileInfo{name: "xray", mode: 0755},
	}

	t.Run("XRAY_BIN set and file exists", func(t *testing.T) {
		r := &Resolver{
			Getenv: func(k string) string {
				if k == "XRAY_BIN" {
					return "/custom/bin/xray"
				}
				return ""
			},
			Stat: func(name string) (os.FileInfo, error) {
				if fi, ok := fileMap[name]; ok {
					return fi, nil
				}
				return nil, os.ErrNotExist
			},
			Candidates:    []string{"/usr/bin/xray"},
			HomeDir:       "/home/test",
			PinnedVersion: "v26.10.31",
		}

		got := r.ResolveBinary()
		if got != "/custom/bin/xray" {
			t.Errorf("expected /custom/bin/xray, got %q", got)
		}
	})

	t.Run("XRAY_BIN set but file does not exist falls back to system probe", func(t *testing.T) {
		r := &Resolver{
			Getenv: func(k string) string {
				if k == "XRAY_BIN" {
					return "/nonexistent/xray"
				}
				return ""
			},
			Stat: func(name string) (os.FileInfo, error) {
				if name == "/usr/bin/xray" {
					return mockFileInfo{name: "xray", mode: 0755}, nil
				}
				return nil, os.ErrNotExist
			},
			ExecVersion: func(path string) (string, error) {
				if path == "/usr/bin/xray" {
					return "Xray 26.10.31 (Xray, Penetrates Everything.)", nil
				}
				return "", errors.New("command failed")
			},
			Candidates:    []string{"/usr/bin/xray"},
			HomeDir:       "/home/test",
			PinnedVersion: "v26.10.31",
		}

		got := r.ResolveBinary()
		if got != "/usr/bin/xray" {
			t.Errorf("expected /usr/bin/xray, got %q", got)
		}
	})
}

func TestResolveBinary_SystemProbe(t *testing.T) {
	t.Run("qualified system binary selected", func(t *testing.T) {
		r := &Resolver{
			Getenv: func(k string) string { return "" },
			Stat: func(name string) (os.FileInfo, error) {
				if name == "/usr/bin/xray" {
					return mockFileInfo{name: "xray", mode: 0755}, nil
				}
				return nil, os.ErrNotExist
			},
			ExecVersion: func(path string) (string, error) {
				if path == "/usr/bin/xray" {
					return "Xray 26.10.31 (Xray, Penetrates Everything.)", nil
				}
				return "", errors.New("command failed")
			},
			Candidates:    []string{"/usr/bin/xray", "/usr/local/bin/xray"},
			HomeDir:       "/home/test",
			PinnedVersion: "v26.10.31",
		}

		got := r.ResolveBinary()
		if got != "/usr/bin/xray" {
			t.Errorf("expected /usr/bin/xray, got %q", got)
		}
	})

	t.Run("higher version system binary selected", func(t *testing.T) {
		r := &Resolver{
			Getenv: func(k string) string { return "" },
			Stat: func(name string) (os.FileInfo, error) {
				if name == "/usr/bin/xray" {
					return mockFileInfo{name: "xray", mode: 0755}, nil
				}
				return nil, os.ErrNotExist
			},
			ExecVersion: func(path string) (string, error) {
				if path == "/usr/bin/xray" {
					return "Xray 26.11.0 (Xray, Penetrates Everything.)", nil
				}
				return "", errors.New("command failed")
			},
			Candidates:    []string{"/usr/bin/xray"},
			HomeDir:       "/home/test",
			PinnedVersion: "v26.10.31",
		}

		got := r.ResolveBinary()
		if got != "/usr/bin/xray" {
			t.Errorf("expected /usr/bin/xray, got %q", got)
		}
	})

	t.Run("outdated system binary skipped and next qualified candidate selected", func(t *testing.T) {
		r := &Resolver{
			Getenv: func(k string) string { return "" },
			Stat: func(name string) (os.FileInfo, error) {
				if name == "/usr/bin/xray" || name == "/usr/local/bin/xray" {
					return mockFileInfo{name: "xray", mode: 0755}, nil
				}
				return nil, os.ErrNotExist
			},
			ExecVersion: func(path string) (string, error) {
				if path == "/usr/bin/xray" {
					return "Xray 1.8.24 (legacy)", nil
				}
				if path == "/usr/local/bin/xray" {
					return "Xray 26.10.31 (qualifying)", nil
				}
				return "", errors.New("not found")
			},
			Candidates:    []string{"/usr/bin/xray", "/usr/local/bin/xray"},
			HomeDir:       "/home/test",
			PinnedVersion: "v26.10.31",
		}

		got := r.ResolveBinary()
		if got != "/usr/local/bin/xray" {
			t.Errorf("expected /usr/local/bin/xray, got %q", got)
		}
	})

	t.Run("system binary without execute permission skipped", func(t *testing.T) {
		privatePath := "/home/test/.local/share/xray-proxya/bin/xray"
		r := &Resolver{
			Getenv: func(k string) string { return "" },
			Stat: func(name string) (os.FileInfo, error) {
				if name == "/usr/bin/xray" {
					return mockFileInfo{name: "xray", mode: 0644}, nil // Not executable
				}
				if name == privatePath {
					return mockFileInfo{name: "xray", mode: 0755}, nil
				}
				return nil, os.ErrNotExist
			},
			ExecVersion: func(path string) (string, error) {
				return "Xray 26.10.31", nil
			},
			Candidates:    []string{"/usr/bin/xray"},
			HomeDir:       "/home/test",
			PinnedVersion: "v26.10.31",
		}

		got := r.ResolveBinary()
		if got != privatePath {
			t.Errorf("expected %q, got %q", privatePath, got)
		}
	})

	t.Run("system binary execution error skipped", func(t *testing.T) {
		privatePath := "/home/test/.local/share/xray-proxya/bin/xray"
		r := &Resolver{
			Getenv: func(k string) string { return "" },
			Stat: func(name string) (os.FileInfo, error) {
				if name == "/usr/bin/xray" || name == privatePath {
					return mockFileInfo{name: "xray", mode: 0755}, nil
				}
				return nil, os.ErrNotExist
			},
			ExecVersion: func(path string) (string, error) {
				return "", errors.New("exec error: cannot execute binary file: Exec format error")
			},
			Candidates:    []string{"/usr/bin/xray"},
			HomeDir:       "/home/test",
			PinnedVersion: "v26.10.31",
		}

		got := r.ResolveBinary()
		if got != privatePath {
			t.Errorf("expected %q, got %q", privatePath, got)
		}
	})
}

func TestResolveBinary_LookPath(t *testing.T) {
	t.Run("LookPath finds custom path that qualifies", func(t *testing.T) {
		r := &Resolver{
			Getenv: func(k string) string { return "" },
			LookPath: func(file string) (string, error) {
				return "/opt/bin/xray", nil
			},
			Stat: func(name string) (os.FileInfo, error) {
				if name == "/opt/bin/xray" {
					return mockFileInfo{name: "xray", mode: 0755}, nil
				}
				return nil, os.ErrNotExist
			},
			ExecVersion: func(path string) (string, error) {
				if path == "/opt/bin/xray" {
					return "Xray 26.10.31", nil
				}
				return "", errors.New("not found")
			},
			Candidates:    []string{"/usr/bin/xray"},
			HomeDir:       "/home/test",
			PinnedVersion: "v26.10.31",
		}

		got := r.ResolveBinary()
		if got != "/opt/bin/xray" {
			t.Errorf("expected /opt/bin/xray, got %q", got)
		}
	})

	t.Run("LookPath returns private binary path and is not probed as system candidate", func(t *testing.T) {
		privatePath := "/home/test/.local/share/xray-proxya/bin/xray"
		probedSystem := false

		r := &Resolver{
			Getenv: func(k string) string { return "" },
			LookPath: func(file string) (string, error) {
				return privatePath, nil
			},
			Stat: func(name string) (os.FileInfo, error) {
				if name == privatePath {
					return mockFileInfo{name: "xray", mode: 0755}, nil
				}
				return nil, os.ErrNotExist
			},
			ExecVersion: func(path string) (string, error) {
				if path == privatePath {
					probedSystem = true
				}
				return "Xray 26.10.31", nil
			},
			Candidates:    []string{"/usr/bin/xray"},
			HomeDir:       "/home/test",
			PinnedVersion: "v26.10.31",
		}

		got := r.ResolveBinary()
		if got != privatePath {
			t.Errorf("expected %q, got %q", privatePath, got)
		}
		if probedSystem {
			t.Errorf("private binary should not have been probed via ExecVersion in system pass")
		}
	})
}

func TestResolveBinary_PrivateAndFallback(t *testing.T) {
	privatePath := "/home/test/.local/share/xray-proxya/bin/xray"

	t.Run("system outdated and private exists", func(t *testing.T) {
		r := &Resolver{
			Getenv: func(k string) string { return "" },
			Stat: func(name string) (os.FileInfo, error) {
				if name == "/usr/bin/xray" || name == privatePath {
					return mockFileInfo{name: "xray", mode: 0755}, nil
				}
				return nil, os.ErrNotExist
			},
			ExecVersion: func(path string) (string, error) {
				if path == "/usr/bin/xray" {
					return "Xray 1.8.24", nil
				}
				return "", errors.New("not found")
			},
			Candidates:    []string{"/usr/bin/xray"},
			HomeDir:       "/home/test",
			PinnedVersion: "v26.10.31",
		}

		got := r.ResolveBinary()
		if got != privatePath {
			t.Errorf("expected %q, got %q", privatePath, got)
		}
	})

	t.Run("neither system nor private exists falls back to private path", func(t *testing.T) {
		r := &Resolver{
			Getenv: func(k string) string { return "" },
			Stat: func(name string) (os.FileInfo, error) {
				return nil, os.ErrNotExist
			},
			Candidates:    []string{"/usr/bin/xray", "/usr/local/bin/xray"},
			HomeDir:       "/home/test",
			PinnedVersion: "v26.10.31",
		}

		got := r.ResolveBinary()
		if got != privatePath {
			t.Errorf("expected %q, got %q", privatePath, got)
		}
	})
}

func TestResolveAsset(t *testing.T) {
	privateAssetDir := "/home/test/.local/share/xray-proxya/bin"

	t.Run("XRAY_LOCATION_ASSET priority", func(t *testing.T) {
		r := &Resolver{
			Getenv: func(k string) string {
				if k == "XRAY_LOCATION_ASSET" {
					return "/custom/assets"
				}
				return ""
			},
			HomeDir: "/home/test",
		}

		got := r.ResolveAsset("/usr/bin/xray")
		if got != "/custom/assets" {
			t.Errorf("expected /custom/assets, got %q", got)
		}
	})

	t.Run("binary directory has dat files", func(t *testing.T) {
		r := &Resolver{
			Getenv: func(k string) string { return "" },
			Stat: func(name string) (os.FileInfo, error) {
				if name == "/usr/local/bin/geoip.dat" {
					return mockFileInfo{name: "geoip.dat", mode: 0644}, nil
				}
				return nil, os.ErrNotExist
			},
			HomeDir: "/home/test",
		}

		got := r.ResolveAsset("/usr/local/bin/xray")
		if got != "/usr/local/bin" {
			t.Errorf("expected /usr/local/bin, got %q", got)
		}
	})

	t.Run("system asset dir /usr/share/xray has dat files", func(t *testing.T) {
		r := &Resolver{
			Getenv: func(k string) string { return "" },
			Stat: func(name string) (os.FileInfo, error) {
				if name == "/usr/share/xray/geosite.dat" {
					return mockFileInfo{name: "geosite.dat", mode: 0644}, nil
				}
				return nil, os.ErrNotExist
			},
			SystemAssetDirs: []string{"/usr/share/xray", "/usr/share/v2ray"},
			HomeDir:         "/home/test",
		}

		got := r.ResolveAsset("/usr/bin/xray")
		if got != "/usr/share/xray" {
			t.Errorf("expected /usr/share/xray, got %q", got)
		}
	})

	t.Run("system asset dir /usr/share/v2ray has dat files", func(t *testing.T) {
		r := &Resolver{
			Getenv: func(k string) string { return "" },
			Stat: func(name string) (os.FileInfo, error) {
				if name == "/usr/share/v2ray/geoip.dat" {
					return mockFileInfo{name: "geoip.dat", mode: 0644}, nil
				}
				return nil, os.ErrNotExist
			},
			SystemAssetDirs: []string{"/usr/share/xray", "/usr/share/v2ray"},
			HomeDir:         "/home/test",
		}

		got := r.ResolveAsset("/usr/bin/xray")
		if got != "/usr/share/v2ray" {
			t.Errorf("expected /usr/share/v2ray, got %q", got)
		}
	})

	t.Run("no assets in binary dir or system dirs falls back to private asset dir", func(t *testing.T) {
		r := &Resolver{
			Getenv: func(k string) string { return "" },
			Stat: func(name string) (os.FileInfo, error) {
				return nil, os.ErrNotExist
			},
			SystemAssetDirs: []string{"/usr/share/xray", "/usr/share/v2ray"},
			HomeDir:         "/home/test",
		}

		got := r.ResolveAsset("/usr/bin/xray")
		if got != privateAssetDir {
			t.Errorf("expected %q, got %q", privateAssetDir, got)
		}
	})
}

func TestGetXrayBinaryPathAndCache(t *testing.T) {
	ResetResolverCache()
	defer ResetResolverCache()

	// Initial resolution should return a non-empty path
	path1 := GetXrayBinaryPath()
	if path1 == "" {
		t.Fatalf("expected non-empty path from GetXrayBinaryPath")
	}

	// Repeated call should return cached path
	path2 := GetXrayBinaryPath()
	if path1 != path2 {
		t.Errorf("expected cached path %q, got %q", path1, path2)
	}

	// Reset cache
	ResetResolverCache()

	// Asset path
	assetPath1 := GetXrayAssetPath()
	if assetPath1 == "" {
		t.Fatalf("expected non-empty asset path from GetXrayAssetPath")
	}

	assetPath2 := GetXrayAssetPath()
	if assetPath1 != assetPath2 {
		t.Errorf("expected cached asset path %q, got %q", assetPath1, assetPath2)
	}
}

func TestRealFilesystemIntegration(t *testing.T) {
	tmpDir := t.TempDir()

	binDir := filepath.Join(tmpDir, "bin")
	shareDir := filepath.Join(tmpDir, "share", "xray")
	privateDir := filepath.Join(tmpDir, "home", ".local", "share", "xray-proxya", "bin")

	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(shareDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(privateDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create mock system binary
	mockXray := filepath.Join(binDir, "xray")
	scriptContent := "#!/bin/sh\necho 'Xray 26.10.31 (Xray, Penetrates Everything.)'\n"
	if err := os.WriteFile(mockXray, []byte(scriptContent), 0755); err != nil {
		t.Fatal(err)
	}

	// Create mock asset dat in shareDir
	mockGeoIP := filepath.Join(shareDir, "geoip.dat")
	if err := os.WriteFile(mockGeoIP, []byte("fake geoip"), 0644); err != nil {
		t.Fatal(err)
	}

	r := &Resolver{
		Getenv: func(k string) string { return "" },
		Stat:   os.Stat,
		ExecVersion: func(path string) (string, error) {
			if path == mockXray {
				return "Xray 26.10.31 (Xray, Penetrates Everything.)", nil
			}
			return "", errors.New("failed")
		},
		HomeDir:         filepath.Join(tmpDir, "home"),
		Candidates:      []string{mockXray},
		SystemAssetDirs: []string{shareDir},
		PinnedVersion:   "v26.10.31",
	}

	resolvedBin := r.ResolveBinary()
	if resolvedBin != mockXray {
		t.Errorf("expected %q, got %q", mockXray, resolvedBin)
	}

	resolvedAsset := r.ResolveAsset(resolvedBin)
	if resolvedAsset != shareDir {
		t.Errorf("expected %q, got %q", shareDir, resolvedAsset)
	}
}
