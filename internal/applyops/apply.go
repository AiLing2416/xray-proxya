package applyops

import (
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"xray-proxya/internal/config"
	"xray-proxya/internal/presets"
	"xray-proxya/internal/xray"
)

type Impact struct {
	XrayConfigChanged     bool
	SubListenerChanged    bool
	SubContentChanged     bool
	GatewayRuntimeChanged bool
	ChangedSections       []string
}

type Options struct {
	Force bool
	Full  bool
}

func ApplyPending(opts Options) ([]string, error) {
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
		testJSON, _ := xray.GenerateXrayJSON(cfg, overrides, "")
		_, cleanup, err := xray.StartXrayTemp(testJSON)
		if err != nil {
			return lines, fmt.Errorf("runtime isolation test failed: %w", err)
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

	xrayRestarted := false
	if opts.Full || impact.XrayConfigChanged {
		lines = append(lines, "🔄 Restarting Xray service...")
		if err := xray.RestartXrayService(); err != nil {
			lines = append(lines, fmt.Sprintf("❌ Error restarting Xray service: %v", err))
		} else {
			xrayRestarted = true
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

	if !xrayRestarted && !(opts.Full || impact.SubListenerChanged) {
		lines = append(lines, "✅ Changes committed without service restart.")
	} else {
		lines = append(lines, "✅ All changes applied.")
	}
	if cfg.Role == config.RoleGateway && impact.GatewayRuntimeChanged {
		lines = append(lines, "ℹ️  Gateway runtime rules are not changed by apply. Use 'xray-proxya gateway up' when gateway system rules need updating.")
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
		impact.SubContentChanged = stagingCfg.AdminSub.Enabled || len(stagingCfg.Subscriptions) > 0
		impact.GatewayRuntimeChanged = stagingCfg.Gateway.LocalEnabled || stagingCfg.Gateway.LANEnabled
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
	if !reflect.DeepEqual(activeCfg.CustomOutbounds, stagingCfg.CustomOutbounds) {
		impact.XrayConfigChanged = true
		impact.SubContentChanged = true
		mark("custom_outbounds")
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
		impact.SubContentChanged = true
		mark("gateway.relay_alias")
	}
	if !reflect.DeepEqual(activeCfg.Gateway.BypassCountries, stagingCfg.Gateway.BypassCountries) {
		impact.XrayConfigChanged = true
		mark("gateway.bypass_countries")
	}
	if !reflect.DeepEqual(activeCfg.AdminSub, stagingCfg.AdminSub) {
		if activeCfg.AdminSub.Port != stagingCfg.AdminSub.Port {
			impact.SubListenerChanged = true
			mark("admin_sub.port")
		}
		if activeCfg.AdminSub != stagingCfg.AdminSub {
			impact.SubContentChanged = true
			mark("admin_sub")
		}
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
	if !reflect.DeepEqual(activeCfg.IPv6Pool, stagingCfg.IPv6Pool) {
		impact.SubContentChanged = true
		mark("ipv6_pool")
	}

	if activeCfg.Gateway.LocalEnabled != stagingCfg.Gateway.LocalEnabled ||
		activeCfg.Gateway.LANEnabled != stagingCfg.Gateway.LANEnabled ||
		activeCfg.Gateway.Mode != stagingCfg.Gateway.Mode ||
		activeCfg.Gateway.LANInterface != stagingCfg.Gateway.LANInterface {
		impact.GatewayRuntimeChanged = true
		mark("gateway.runtime")
	}

	return impact
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
	return exec.Command("systemctl", "restart", "xray-proxya-sub").Run()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func subServicePath() string {
	return "/etc/systemd/system/xray-proxya-sub.service"
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
