package applyops

import (
	"fmt"
	"os"
	"reflect"
	"xray-proxya/internal/config"
	"xray-proxya/internal/presets"
	"xray-proxya/internal/service"
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

	actx := &ApplyContext{
		Options:             opts,
		ActiveCfg:           activeCfg,
		StagingCfg:          cfg,
		Impact:              impact,
		GatewaySyncRequired: gatewaySyncRequired,
		Lines:               make([]string, 0, 16),
	}

	// Record validation hints
	validateXray := opts.Full || impact.XrayConfigChanged
	if opts.Force {
		actx.AppendLine("⚠️  Skipping validation due to --force flag.")
	} else if !validateXray {
		actx.AppendLine("ℹ️  No Xray-facing changes detected; skipping Xray validation.")
	}

	pipeline := NewApplyPipeline()
	if err := pipeline.Execute(actx); err != nil {
		return actx.Lines, err
	}

	if !actx.XrayRestarted && !actx.SubRestarted {
		actx.AppendLine("✅ Changes committed without service restart.")
	} else {
		actx.AppendLine("✅ All changes applied.")
	}

	return actx.Lines, nil
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
	if activeCfg.SkinPort != stagingCfg.SkinPort {
		impact.XrayConfigChanged = true
		mark("skin_port")
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
	if activeCfg.GuestSubAddress != stagingCfg.GuestSubAddress {
		impact.SubContentChanged = true
		mark("guest_sub_address")
	}
	if activeCfg.AddressSub != stagingCfg.AddressSub || activeCfg.AddressNode != stagingCfg.AddressNode {
		impact.SubContentChanged = true
		mark("address_sub_node")
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
	path := service.PathdConfigPath()
	if cfg.Path.Token == "" {
		if os.Geteuid() == 0 && service.IsUnitActive(service.PathdUnit) {
			return fmt.Errorf("Pathd is active; disable or stop it with the service command before removing its configuration")
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := service.WritePathdConfig(cfg); err != nil {
		return err
	}
	if os.Geteuid() == 0 && service.IsUnitActive(service.PathdUnit) {
		if err := service.Restart(service.PathdUnit); err != nil {
			return fmt.Errorf("restart active Pathd service: %w", err)
		}
	}
	return nil
}

func HasSubServiceInstalled() bool {
	return service.IsUnitInstalled(service.SubUnit)
}

func RestartSubServiceIfInstalled() error {
	if !HasSubServiceInstalled() {
		return nil
	}
	return service.Restart(service.SubUnit)
}

func RestartIPv6RotateServiceIfInstalled() error {
	if os.Geteuid() != 0 || !service.IsUnitInstalled(service.RotateUnit) {
		return nil
	}
	return service.Restart(service.RotateUnit)
}

func AnySubServiceActive() bool {
	return service.IsUnitActive(service.SubUnit)
}

func IsIPv6RotateServiceActive() bool {
	if os.Geteuid() != 0 {
		return false
	}
	return service.IsUnitActive(service.RotateUnit)
}

func IsPathdServiceActive() bool {
	if os.Geteuid() != 0 {
		return false
	}
	return service.IsUnitActive(service.PathdUnit)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func subServicePath() string {
	return service.ManagedUnitPath(service.SubUnit)
}

func ipv6RotateServicePath() string {
	if os.Geteuid() == 0 {
		return service.ManagedUnitPath(service.RotateUnit)
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
