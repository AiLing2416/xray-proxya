package purge

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTargets(t *testing.T) {
	tests := []struct {
		name      string
		inputs    []string
		wantTypes []TargetType
		wantErr   bool
	}{
		{
			name:      "single target",
			inputs:    []string{"config"},
			wantTypes: []TargetType{TypeConfig},
		},
		{
			name:      "comma-separated targets",
			inputs:    []string{"config,core,service,cert"},
			wantTypes: []TargetType{TypeConfig, TypeCore, TypeService, TypeCert},
		},
		{
			name:      "multiple flags and aliases",
			inputs:    []string{"configs", "certs,services", "binary"},
			wantTypes: []TargetType{TypeConfig, TypeCert, TypeService, TypeBin},
		},
		{
			name:      "all target expands to all",
			inputs:    []string{"all"},
			wantTypes: []TargetType{TypeConfig, TypeCert, TypeCore, TypeService, TypeBin, TypeData, TypeCache, TypeBackup, TypeCompletion, TypeProfile},
		},
		{
			name:    "ambiguous path target",
			inputs:  []string{"path"},
			wantErr: true,
		},
		{
			name:    "unknown target",
			inputs:  []string{"unknown-xyz"},
			wantErr: true,
		},
		{
			name:    "empty inputs",
			inputs:  []string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets, err := ParseTargets(tt.inputs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseTargets() err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			for _, want := range tt.wantTypes {
				if !targets[want] {
					t.Errorf("ParseTargets() missing expected target %v", want)
				}
			}
		})
	}
}

func TestBuildPlanPreservesCertAndBackupWhenOnlyConfigSpecified(t *testing.T) {
	tempDir := t.TempDir()
	configDir := filepath.Join(tempDir, "config")
	homeDir := filepath.Join(tempDir, "home")
	installDir := filepath.Join(homeDir, ".local", "bin")

	// Setup directories and dummy files
	if err := os.MkdirAll(filepath.Join(configDir, "certs"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "certs", "cert.pem"), []byte("cert"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.staging.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "xray-proxya-backup-2026.tar.gz"), []byte("bak"), 0600); err != nil {
		t.Fatal(err)
	}

	// 1. Test -i config: MUST NOT include certs or backup
	opts := Options{
		Targets:    []string{"config"},
		ConfigDir:  configDir,
		HomeDir:    homeDir,
		InstallDir: installDir,
	}

	plan, err := BuildPlan(opts)
	if err != nil {
		t.Fatalf("BuildPlan() err = %v", err)
	}

	for _, item := range plan.Items {
		if strings.Contains(item.Target, "certs") {
			t.Errorf("BuildPlan(-i config) unexpectedly planned deletion of certs: %s", item.Target)
		}
		if strings.Contains(item.Target, "xray-proxya-backup") {
			t.Errorf("BuildPlan(-i config) unexpectedly planned deletion of backup: %s", item.Target)
		}
	}

	// Verify preserved list mentions certs and backup
	preservedText := strings.Join(plan.Preserved, "\n")
	if !strings.Contains(preservedText, "certs") {
		t.Errorf("plan.Preserved does not mention certs: %v", plan.Preserved)
	}
	if !strings.Contains(preservedText, "backup") {
		t.Errorf("plan.Preserved does not mention backups: %v", plan.Preserved)
	}

	// 2. Execute plan
	var buf bytes.Buffer
	if err := Execute(plan, configDir, homeDir, installDir, &buf); err != nil {
		t.Fatalf("Execute() err = %v", err)
	}

	// Verify config was removed
	if _, err := os.Stat(filepath.Join(configDir, "config.json")); !os.IsNotExist(err) {
		t.Errorf("config.json should be removed")
	}
	// Verify certs was preserved
	if _, err := os.Stat(filepath.Join(configDir, "certs", "cert.pem")); err != nil {
		t.Errorf("certs/cert.pem should be preserved, but got err: %v", err)
	}
	// Verify backup was preserved
	if _, err := os.Stat(filepath.Join(configDir, "xray-proxya-backup-2026.tar.gz")); err != nil {
		t.Errorf("backup archive should be preserved, but got err: %v", err)
	}
}

func TestExecuteCleansSpecifiedTypes(t *testing.T) {
	tempDir := t.TempDir()
	configDir := filepath.Join(tempDir, "config")
	homeDir := filepath.Join(tempDir, "home")
	installDir := filepath.Join(homeDir, ".local", "bin")

	// Setup directories
	coreDir := filepath.Join(homeDir, ".local", "share", "xray-proxya", "bin")
	if err := os.MkdirAll(coreDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(configDir, "certs"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(installDir, 0755); err != nil {
		t.Fatal(err)
	}

	xrayBin := filepath.Join(coreDir, "xray")
	pathdBin := filepath.Join(coreDir, "pathd")
	certFile := filepath.Join(configDir, "certs", "server.crt")
	mainBin := filepath.Join(installDir, "xray-proxya")

	_ = os.WriteFile(xrayBin, []byte("xray"), 0755)
	_ = os.WriteFile(pathdBin, []byte("pathd"), 0755)
	_ = os.WriteFile(certFile, []byte("crt"), 0600)
	_ = os.WriteFile(mainBin, []byte("main"), 0755)

	// Purge only core and cert
	opts := Options{
		Targets:    []string{"core,cert"},
		ConfigDir:  configDir,
		HomeDir:    homeDir,
		InstallDir: installDir,
	}

	plan, err := BuildPlan(opts)
	if err != nil {
		t.Fatalf("BuildPlan() err = %v", err)
	}

	var buf bytes.Buffer
	if err := Execute(plan, configDir, homeDir, installDir, &buf); err != nil {
		t.Fatalf("Execute() err = %v", err)
	}

	// xray and certs must be gone
	if _, err := os.Stat(xrayBin); !os.IsNotExist(err) {
		t.Errorf("xray core binary should be deleted")
	}
	if _, err := os.Stat(certFile); !os.IsNotExist(err) {
		t.Errorf("cert file should be deleted")
	}

	// pathd and mainBin must be intact
	if _, err := os.Stat(pathdBin); err != nil {
		t.Errorf("pathd binary should NOT be deleted when only core was targeted")
	}
	if _, err := os.Stat(mainBin); err != nil {
		t.Errorf("main binary should NOT be deleted when bin was not targeted")
	}
}

func TestCleanProfileSeparation(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), ".bashrc")
	installDir := "/opt/test/bin"
	content := `# User custom config
export FOO=bar
# >>> xray-proxya completion >>>
source /some/completion
# <<< xray-proxya completion <<<
export PATH=$PATH:/opt/test/bin
export OTHER_PATH=$PATH:/usr/local/custom/bin
export BAZ=qux
`
	if err := os.WriteFile(tempFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// 1. Clean completion only: PATH and others must remain intact
	if err := cleanProfileCompletion(tempFile); err != nil {
		t.Fatalf("cleanProfileCompletion() err = %v", err)
	}

	afterComp, err := os.ReadFile(tempFile)
	if err != nil {
		t.Fatal(err)
	}
	textComp := string(afterComp)
	if strings.Contains(textComp, "xray-proxya completion") {
		t.Errorf("profile still contains completion block:\n%s", textComp)
	}
	if !strings.Contains(textComp, "export PATH=$PATH:/opt/test/bin") {
		t.Errorf("cleanProfileCompletion accidentally removed PATH line:\n%s", textComp)
	}
	if !strings.Contains(textComp, "export OTHER_PATH=$PATH:/usr/local/custom/bin") {
		t.Errorf("cleanProfileCompletion removed unrelated PATH line:\n%s", textComp)
	}

	// Verify permissions preserved (0600)
	fi, _ := os.Stat(tempFile)
	if fi.Mode().Perm() != 0600 {
		t.Errorf("expected mode 0600, got %v", fi.Mode().Perm())
	}

	// 2. Clean PATH export: accurately remove only installDir line
	if err := cleanProfilePath(tempFile, installDir); err != nil {
		t.Fatalf("cleanProfilePath() err = %v", err)
	}

	afterPath, err := os.ReadFile(tempFile)
	if err != nil {
		t.Fatal(err)
	}
	textPath := string(afterPath)
	if strings.Contains(textPath, "export PATH=$PATH:/opt/test/bin") {
		t.Errorf("cleanProfilePath did not remove target PATH export:\n%s", textPath)
	}
	if !strings.Contains(textPath, "export OTHER_PATH=$PATH:/usr/local/custom/bin") {
		t.Errorf("cleanProfilePath accidentally removed unrelated PATH export:\n%s", textPath)
	}
	if !strings.Contains(textPath, "export FOO=bar") || !strings.Contains(textPath, "export BAZ=qux") {
		t.Errorf("cleanProfilePath wiped unrelated environment variables:\n%s", textPath)
	}
}
