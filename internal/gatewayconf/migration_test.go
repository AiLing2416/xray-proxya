package gatewayconf

import (
	"os"
	"path/filepath"
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
