package gatewayconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func skipIfRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("config dir is fixed for root")
	}
}

// A v0.5.x config.json carries the Gateway settings inline; loading it must
// create gateway.conf/gateway.active.conf and preserve those settings.
func TestLoadConfig_MigratesV05InlineGateway(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", dir)
	legacy := `{"role":"gateway","gateway":{"mode":"tproxy","wan_interface":"eth0","lan_interfaces":["eth1"],"lan_enabled":true,"local_enabled":true,"bypass_countries":["cn"]}}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.LoadConfigEx(false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway.WANInterface != "eth0" || !cfg.Gateway.LANEnabled || len(cfg.Gateway.BypassCountries) != 1 {
		t.Fatalf("legacy settings lost after migration: %+v", cfg.Gateway)
	}
	if !config.GatewayConfExists() || !config.GatewayActiveConfExists() {
		t.Fatal("expected gateway.conf and gateway.active.conf to be created")
	}
	if config.GatewayConfStaged() {
		t.Fatal("migrated gateway.conf must not appear as staged change")
	}

	// Saving drops the inline copy, yet settings survive via gateway.conf.
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	cfg2, err := config.LoadConfigEx(false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Gateway.WANInterface != "eth0" || len(cfg2.Gateway.BypassCountries) != 1 {
		t.Fatalf("settings lost after re-save: %+v", cfg2.Gateway)
	}
}

func TestLoadConfig_MigratesV05InlineTunModeToTProxyPlusTun(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", dir)
	legacy := `{"role":"gateway","gateway":{"mode":"tun","wan_interface":"eth0","lan_interfaces":["eth1"],"lan_enabled":true,"local_enabled":true}}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.LoadConfigEx(false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway.EffectiveMode() != "tproxy" {
		t.Fatalf("migrated EffectiveMode() = %q, want tproxy", cfg.Gateway.EffectiveMode())
	}
	if !cfg.Gateway.TUNEnabled || !cfg.Gateway.EffectiveTUNEnabled() {
		t.Fatalf("migrated TUNEnabled = %v, want true", cfg.Gateway.TUNEnabled)
	}
}

// CommitStaging must promote gateway.conf intact (not clobber it with the
// gateway-less staging JSON).
func TestCommitStaging_PreservesGatewayConf(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", dir)
	cfg := &config.UserConfig{Role: config.RoleGateway}
	cfg.Gateway = config.GatewayConfig{Mode: "tproxy", WANInterface: "eth0", LANInterfaces: []string{"eth1"}, LANEnabled: true}
	if err := os.WriteFile(config.GetGatewayConfPath(), []byte(Generate(&cfg.Gateway)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatal(err)
	}
	if err := config.CommitStaging(); err != nil {
		t.Fatal(err)
	}
	got, err := config.LoadConfigEx(false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Gateway.WANInterface != "eth0" || !got.Gateway.LANEnabled {
		t.Fatalf("active gateway config clobbered by commit: %+v", got.Gateway)
	}
}

func TestGatewayConfigSaver_DoesNotCreatePhantomStagingOrDestroyAST(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", dir)

	customConf := `# Handcrafted declarative gateway configuration
def zone wan eth0
def zone lan eth1
def device myphone mac=52:54:00:84:00:11 zone=lan
def group family myphone

set state proxy
local -> direct
device myphone -> direct
`
	initCfg := &config.UserConfig{Role: config.RoleGateway}
	if err := initCfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.GetGatewayConfPath(), []byte(customConf), 0600); err != nil {
		t.Fatal(err)
	}

	// Load config from active
	cfg, err := config.LoadConfigEx(false)
	if err != nil {
		t.Fatalf("LoadConfigEx failed: %v", err)
	}

	// 1. Calling SaveEx(true) without modifying gateway settings should NOT create gateway.conf.staging
	cfg.Guests = append(cfg.Guests, config.GuestConfig{Alias: "alice"})
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("SaveEx(true) failed: %v", err)
	}

	if config.GatewayConfStaged() {
		t.Fatalf("gateway.conf.staging was unexpectedly created when gateway configuration was unchanged")
	}

	// Active gateway.conf must be completely untouched
	activeBytes, err := os.ReadFile(config.GetGatewayConfPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(activeBytes) != customConf {
		t.Fatalf("active gateway.conf was altered:\n%s", string(activeBytes))
	}

	// 2. Calling SaveEx(true) with modified gateway settings SHOULD create staging,
	// but based on active gateway.conf (preserving AST defs & comments)
	cfg.Gateway.State = "disabled"
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("SaveEx(true) with state change failed: %v", err)
	}
	if !config.GatewayConfStaged() {
		t.Fatalf("expected gateway.conf.staging to be created when gateway settings changed")
	}

	stgBytes, err := os.ReadFile(config.GetGatewayConfPathEx(true))
	if err != nil {
		t.Fatal(err)
	}
	stgStr := string(stgBytes)
	if !strings.Contains(stgStr, "def device myphone") || !strings.Contains(stgStr, "def group family") {
		t.Fatalf("staging configuration clobbered AST defs:\n%s", stgStr)
	}
	if !strings.Contains(stgStr, "Handcrafted declarative gateway configuration") {
		t.Fatalf("staging configuration clobbered header comment:\n%s", stgStr)
	}
	if !strings.Contains(stgStr, "set state disabled") {
		t.Fatalf("staging configuration missing 'set state disabled':\n%s", stgStr)
	}
}
