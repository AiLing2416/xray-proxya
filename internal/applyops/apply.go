package applyops

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gateway"
	"xray-proxya/internal/pathd"
	"xray-proxya/internal/presets"
	"xray-proxya/internal/xray"
)

type Impact struct {
	XrayConfigChanged     bool
	SubListenerChanged    bool
	SubContentChanged     bool
	IPv6RotationChanged   bool
	GatewayRuntimeChanged bool
	PathdConfigChanged    bool
	ChangedSections       []string
}

type Options struct {
	Force bool
	Full  bool
}

func ApplyPending(opts Options) ([]string, error) {
	var result []string
	var applyErr error
	if err := config.WithLifecycleLock(func() error {
		result, applyErr = applyPendingLocked(opts)
		return applyErr
	}); err != nil {
		return result, err
	}
	return result, applyErr
}

func applyPendingLocked(opts Options) ([]string, error) {
	if !config.StagingExists() {
		return []string{"❌ No pending changes in STAGING."}, nil
	}

	activeCfg, err := config.LoadConfigEx(false)
	if err != nil {
		activeCfg = nil
	}
	cfg, err := config.LoadConfigEx(true)
	if err != nil {
		return nil, fmt.Errorf("failed to load STAGING config: %w", err)
	}

	if err := presets.RegenerateMarkedModes(cfg); err != nil {
		return nil, fmt.Errorf("failed to regenerate preset secrets: %w", err)
	}
	if err := cfg.SaveEx(true); err != nil {
		return nil, fmt.Errorf("failed to persist regenerated STAGING config: %w", err)
	}

	impact := BuildImpact(activeCfg, cfg)
	gatewaySyncRequired := cfg.Role == config.RoleGateway && impact.GatewayRuntimeChanged
	validateXray := opts.Full || impact.XrayConfigChanged
	lines := make([]string, 0, 16)

	if !opts.Force && validateXray {
		testOverrides := map[string]int{"gateway-tun-disabled": 1}
		lines = append(lines, "🔍 Stage 1: Static Validation...")
		jsonData, _ := xray.GenerateXrayJSON(cfg, testOverrides, "")
		if err := xray.ValidateConfig(jsonData); err != nil {
			return lines, fmt.Errorf("static validation failed: %w", err)
		}
		lines = append(lines, "✅ Syntax OK.")

		lines = append(lines, "🔍 Stage 2: Runtime Isolation Test...")
		testSocksPort, _ := xray.GetFreePort()
		apiPort, _ := xray.GetFreePort()
		overrides := map[string]int{"test-socks": testSocksPort, "api": apiPort, "gateway-tun-disabled": 1}
		for _, m := range cfg.Presets {
			if m.Enabled {
				p, _ := xray.GetFreePort()
				overrides[string(m.Mode)] = p
			}
		}
		for _, co := range cfg.CustomOutbounds {
			if co.InternalProxyPort > 0 {
				p, _ := xray.GetFreePort()
				overrides["outbound-"+co.Alias] = p
			}
		}
		testJSON, _ := xray.GenerateXrayJSON(cfg, overrides, "")
		cmd, cleanup, err := xray.StartXrayTemp(testJSON)
		if err != nil {
			return lines, fmt.Errorf("runtime isolation test failed: %w", err)
		}
		// Give it a tiny bit of time to start and check if it is still running
		time.Sleep(100 * time.Millisecond)
		if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
			cleanup()
			return lines, fmt.Errorf("runtime isolation test failed: temporary xray instance exited prematurely")
		}
		cleanup()
		lines = append(lines, "✅ Runtime isolation test passed (using randomized ports).")
	} else if opts.Force {
		lines = append(lines, "⚠️  Skipping validation due to --force flag.")
	} else {
		lines = append(lines, "ℹ️  No Xray-facing changes detected; skipping Xray validation.")
	}

	lines = append(lines, "🚀 Stage 3: Committing changes...")
	if err := config.CommitStaging(); err != nil {
		return lines, fmt.Errorf("failed to commit: %w", err)
	}
	if len(impact.ChangedSections) > 0 {
		lines = append(lines, fmt.Sprintf("ℹ️  Changed sections: %v", impact.ChangedSections))
	}
	if impact.PathdConfigChanged {
		if err := syncPathdConfig(cfg); err != nil {
			return lines, fmt.Errorf("synchronize Pathd configuration: %w", err)
		}
		lines = append(lines, "✅ Pathd configuration synchronized.")
	}
	if impact.IPv6RotationChanged {
		if err := RestartIPv6RotateServiceIfInstalled(); err != nil {
			lines = append(lines, fmt.Sprintf("❌ Error reloading IPv6 rotation service: %v", err))
		} else {
			lines = append(lines, "🔄 IPv6 rotation service reloaded if active.")
		}
	}

	xrayRestarted := false
	if opts.Full || impact.XrayConfigChanged {
		if gatewaySyncRequired {
			lines = append(lines, "🔄 Restarting Xray and synchronizing Gateway runtime...")
		} else {
			lines = append(lines, "🔄 Restarting Xray service...")
			if err := xray.RestartXrayServiceWithoutHook(); err != nil {
				lines = append(lines, fmt.Sprintf("❌ Error restarting Xray service: %v", err))
			} else {
				if err := gateway.RestoreTunStateLocked(cfg); err != nil {
					lines = append(lines, fmt.Sprintf("❌ Error restoring Gateway runtime: %v", err))
					return lines, fmt.Errorf("failed to restore gateway runtime: %w", err)
				}
				xrayRestarted = true
			}
		}
	} else {
		lines = append(lines, "ℹ️  Xray restart skipped: no Xray-facing changes detected.")
	}

	if opts.Full || impact.SubListenerChanged {
		if HasSubServiceInstalled() {
			lines = append(lines, "🔄 Restarting subscription service...")
			if err := RestartSubServiceIfInstalled(); err != nil {
				lines = append(lines, fmt.Sprintf("❌ Error restarting subscription service: %v", err))
			}
		} else if impact.SubListenerChanged {
			lines = append(lines, "ℹ️  Subscription listener changed, but no installed subscription service was found.")
		}
	} else if impact.SubContentChanged {
		lines = append(lines, "ℹ️  Subscription content updated; no restart needed because the sub server reloads config on each request.")
	}

	if gatewaySyncRequired {
		if err := gateway.SyncDesiredLocked(cfg); err != nil {
			lines = append(lines, fmt.Sprintf("❌ Failed to synchronize gateway runtime: %v", err))
			return lines, fmt.Errorf("failed to synchronize gateway runtime: %w", err)
		} else {
			xrayRestarted = true
			lines = append(lines, "✅ Gateway runtime synchronized with active configuration.")
		}
	}
	if !xrayRestarted && !(opts.Full || impact.SubListenerChanged) {
		lines = append(lines, "✅ Changes committed without service restart.")
	} else {
		lines = append(lines, "✅ All changes applied.")
	}

	return lines, nil
}

func ClearPending() error {
	return config.ClearStaging()
}

func BuildImpact(activeCfg, stagingCfg *config.UserConfig) Impact {
	impact := Impact{}
	if stagingCfg == nil {
		return impact
	}
	if activeCfg == nil {
		impact.XrayConfigChanged = true
		impact.SubListenerChanged = stagingCfg.AdminSub.Port > 0 || stagingCfg.SubPort > 0
		impact.SubContentChanged = stagingCfg.AdminSub.Token != "" || len(stagingCfg.Subscriptions) > 0
		impact.GatewayRuntimeChanged = stagingCfg.Gateway.LocalEnabled || stagingCfg.Gateway.LANEnabled
		impact.PathdConfigChanged = stagingCfg.Role == config.RoleServer && stagingCfg.Path.Token != ""
		impact.ChangedSections = []string{"initial_apply"}
		return impact
	}

	mark := func(section string) {
		for _, existing := range impact.ChangedSections {
			if existing == section {
				return
			}
		}
		impact.ChangedSections = append(impact.ChangedSections, section)
	}

	if activeCfg.Role != stagingCfg.Role {
		impact.XrayConfigChanged = true
		impact.SubContentChanged = true
		mark("role")
	}
	if activeCfg.UUID != stagingCfg.UUID {
		impact.XrayConfigChanged = true
		impact.SubContentChanged = true
		mark("uuid")
	}
	if activeCfg.APIInbound != stagingCfg.APIInbound {
		impact.XrayConfigChanged = true
		mark("api_inbound")
	}
	if activeCfg.TestInbound != stagingCfg.TestInbound {
		impact.XrayConfigChanged = true
		mark("test_inbound")
	}
	if !reflect.DeepEqual(activeCfg.Presets, stagingCfg.Presets) {
		impact.XrayConfigChanged = true
		impact.SubContentChanged = true
		mark("presets")
	}
	if customOutboundsAffectXray(activeCfg.CustomOutbounds, stagingCfg.CustomOutbounds) {
		impact.XrayConfigChanged = true
		impact.SubContentChanged = true
		mark("custom_outbounds")
	}
	if relayPathCredentialsChanged(activeCfg, stagingCfg) {
		mark("relay.path")
		if activeCfg.Gateway.RelayAlias == stagingCfg.Gateway.RelayAlias &&
			stagingCfg.Gateway.RelayAlias != "" &&
			selectedRelayPathChanged(activeCfg, stagingCfg) {
			impact.XrayConfigChanged = true
			impact.GatewayRuntimeChanged = true
		}
	}
	if guestsAffectXray(activeCfg.Guests, stagingCfg.Guests) {
		impact.XrayConfigChanged = true
		mark("guests")
	}
	if guestsAffectGuestSub(activeCfg.Guests, stagingCfg.Guests) {
		impact.SubContentChanged = true
		mark("guest_sub")
	}
	if activeCfg.Gateway.RelayAlias != stagingCfg.Gateway.RelayAlias {
		impact.XrayConfigChanged = true
		impact.GatewayRuntimeChanged = true
		impact.SubContentChanged = true
		mark("gateway.relay_alias")
	}
	if !reflect.DeepEqual(activeCfg.Gateway.BypassCountries, stagingCfg.Gateway.BypassCountries) {
		impact.XrayConfigChanged = true
		impact.GatewayRuntimeChanged = true
		mark("gateway.bypass_countries")
	}
	if !reflect.DeepEqual(activeCfg.Path, stagingCfg.Path) {
		if stagingCfg.Role == config.RoleServer {
			impact.PathdConfigChanged = true
			mark("pathd")
		} else {
			mark("path")
		}
	}
	if !reflect.DeepEqual(activeCfg.AdminSub, stagingCfg.AdminSub) {
		impact.SubListenerChanged = true
		impact.SubContentChanged = true
		mark("admin_sub")
	}
	if activeCfg.SubPort != stagingCfg.SubPort {
		impact.SubListenerChanged = true
		mark("sub_port")
	}
	if activeCfg.GuestSubPort != stagingCfg.GuestSubPort || activeCfg.GuestSubBind != stagingCfg.GuestSubBind {
		impact.SubListenerChanged = true
		mark("guest_sub_listener")
	}
	if !reflect.DeepEqual(activeCfg.Subscriptions, stagingCfg.Subscriptions) {
		impact.SubContentChanged = true
		mark("subscriptions")
	}
	if !reflect.DeepEqual(activeCfg.IPv6Pool, stagingCfg.IPv6Pool) || !reflect.DeepEqual(activeCfg.IPv6Rotations, stagingCfg.IPv6Rotations) {
		impact.SubContentChanged = true
		impact.IPv6RotationChanged = true
		mark("ipv6_pool")
	}

	if activeCfg.Gateway.LocalEnabled != stagingCfg.Gateway.LocalEnabled ||
		activeCfg.Gateway.LANEnabled != stagingCfg.Gateway.LANEnabled ||
		activeCfg.Gateway.Mode != stagingCfg.Gateway.Mode ||
		activeCfg.Gateway.LANInterface != stagingCfg.Gateway.LANInterface ||
		activeCfg.Gateway.State != stagingCfg.Gateway.State ||
		!reflect.DeepEqual(activeCfg.Gateway.BypassDNS, stagingCfg.Gateway.BypassDNS) {
		impact.GatewayRuntimeChanged = true
		impact.XrayConfigChanged = true
		mark("gateway.runtime")
	}

	return impact
}

func customOutboundsAffectXray(active, staging []config.CustomOutbound) bool {
	activeCopy := append([]config.CustomOutbound(nil), active...)
	stagingCopy := append([]config.CustomOutbound(nil), staging...)
	for i := range activeCopy {
		activeCopy[i].Path = nil
	}
	for i := range stagingCopy {
		stagingCopy[i].Path = nil
	}
	return !reflect.DeepEqual(activeCopy, stagingCopy)
}

func relayPathCredentialsChanged(active, staging *config.UserConfig) bool {
	if active == nil || staging == nil {
		return false
	}
	byAlias := make(map[string]*config.PathConfig, len(active.CustomOutbounds))
	for i := range active.CustomOutbounds {
		byAlias[active.CustomOutbounds[i].Alias] = active.CustomOutbounds[i].Path
	}
	for i := range staging.CustomOutbounds {
		outbound := &staging.CustomOutbounds[i]
		if !reflect.DeepEqual(byAlias[outbound.Alias], outbound.Path) {
			return true
		}
		delete(byAlias, outbound.Alias)
	}
	return len(byAlias) != 0
}

func selectedRelayPathChanged(active, staging *config.UserConfig) bool {
	if active == nil || staging == nil || active.Gateway.RelayAlias == "" ||
		active.Gateway.RelayAlias != staging.Gateway.RelayAlias {
		return false
	}
	return !reflect.DeepEqual(pathForRelay(active, active.Gateway.RelayAlias), pathForRelay(staging, staging.Gateway.RelayAlias))
}

func pathForRelay(cfg *config.UserConfig, alias string) *config.PathConfig {
	for i := range cfg.CustomOutbounds {
		if cfg.CustomOutbounds[i].Alias == alias {
			return cfg.CustomOutbounds[i].Path
		}
	}
	return nil
}

func syncPathdConfig(cfg *config.UserConfig) error {
	if cfg == nil || cfg.Role != config.RoleServer {
		return nil
	}
	path := filepath.Join(config.GetConfigDir(), "pathd.json")
	if cfg.Path.Token == "" {
		if os.Geteuid() == 0 && exec.Command("systemctl", "is-active", "--quiet", "xray-proxya-pathd.service").Run() == nil {
			return fmt.Errorf("Pathd is active; disable or stop it with the service command before removing its configuration")
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if cfg.Path.Listen == "" || cfg.Path.IdleSeconds <= 0 {
		return fmt.Errorf("incomplete Pathd configuration")
	}
	if err := pathd.ValidateListenAddress(cfg.Path.Listen); err != nil {
		return err
	}
	data, err := json.MarshalIndent(struct {
		Listen      string `json:"listen"`
		Token       string `json:"token"`
		IdleSeconds int    `json:"idle_seconds"`
	}{cfg.Path.Listen, cfg.Path.Token, cfg.Path.IdleSeconds}, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pathd.json-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if os.Geteuid() == 0 && exec.Command("systemctl", "is-active", "--quiet", "xray-proxya-pathd.service").Run() == nil {
		if err := exec.Command("systemctl", "restart", "xray-proxya-pathd.service").Run(); err != nil {
			return fmt.Errorf("restart active Pathd service: %w", err)
		}
	}
	return nil
}

func HasSubServiceInstalled() bool {
	return fileExists(subServicePath())
}

func RestartSubServiceIfInstalled() error {
	if os.Geteuid() != 0 {
		return nil
	}
	if !HasSubServiceInstalled() {
		return nil
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	args := []string{"try-restart", "xray-proxya-sub@default"}
	if os.Geteuid() != 0 {
		args = append([]string{"--user"}, args...)
	}
	return exec.Command("systemctl", args...).Run()
}

func RestartIPv6RotateServiceIfInstalled() error {
	if os.Geteuid() != 0 || !fileExists(ipv6RotateServicePath()) {
		return nil
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	return exec.Command("systemctl", "try-restart", "xray-proxya-ipv6-rotate@default").Run()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func subServicePath() string {
	if os.Geteuid() == 0 {
		return "/etc/systemd/system/xray-proxya-sub@.service"
	}
	return filepath.Join(config.GetHomeDir(), ".config", "systemd", "user", "xray-proxya-sub@.service")
}

func ipv6RotateServicePath() string {
	if os.Geteuid() == 0 {
		return "/etc/systemd/system/xray-proxya-ipv6-rotate@.service"
	}
	return ""
}

func guestsAffectXray(activeGuests, stagingGuests []config.GuestConfig) bool {
	if len(activeGuests) != len(stagingGuests) {
		return true
	}
	for i := range activeGuests {
		a := activeGuests[i]
		b := stagingGuests[i]
		if a.Alias != b.Alias ||
			a.UUID != b.UUID ||
			a.Enabled != b.Enabled ||
			a.OutboundLink != b.OutboundLink ||
			!reflect.DeepEqual(a.OutboundConf, b.OutboundConf) {
			return true
		}
	}
	return false
}

func guestsAffectGuestSub(activeGuests, stagingGuests []config.GuestConfig) bool {
	if len(activeGuests) != len(stagingGuests) {
		return true
	}
	for i := range activeGuests {
		if !reflect.DeepEqual(activeGuests[i], stagingGuests[i]) {
			return true
		}
	}
	return false
}
