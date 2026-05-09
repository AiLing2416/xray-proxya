package main

import (
	"os"
	"os/exec"
	"reflect"
	"xray-proxya/internal/config"
)

type applyImpact struct {
	XrayConfigChanged     bool
	SubListenerChanged    bool
	SubContentChanged     bool
	GatewayRuntimeChanged bool
	ChangedSections       []string
}

func buildApplyImpact(activeCfg, stagingCfg *config.UserConfig) applyImpact {
	impact := applyImpact{}
	if stagingCfg == nil {
		return impact
	}
	if activeCfg == nil {
		impact.XrayConfigChanged = true
		impact.SubListenerChanged = stagingCfg.SubPort > 0
		impact.SubContentChanged = len(stagingCfg.Subscriptions) > 0
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
	if !reflect.DeepEqual(activeCfg.ActiveModes, stagingCfg.ActiveModes) {
		impact.XrayConfigChanged = true
		impact.SubContentChanged = true
		mark("active_modes")
	}
	if !reflect.DeepEqual(activeCfg.CustomOutbounds, stagingCfg.CustomOutbounds) {
		impact.XrayConfigChanged = true
		impact.SubContentChanged = true
		mark("custom_outbounds")
	}
	if !reflect.DeepEqual(activeCfg.Guests, stagingCfg.Guests) {
		impact.XrayConfigChanged = true
		impact.SubContentChanged = true
		mark("guests")
	}
	if activeCfg.Gateway.RelayAlias != stagingCfg.Gateway.RelayAlias {
		impact.XrayConfigChanged = true
		impact.SubContentChanged = true
		mark("gateway.relay_alias")
	}
	if activeCfg.SubPort != stagingCfg.SubPort {
		impact.SubListenerChanged = true
		mark("sub_port")
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
		activeCfg.Gateway.LANInterface != stagingCfg.Gateway.LANInterface ||
		!reflect.DeepEqual(activeCfg.Gateway.Blacklist, stagingCfg.Gateway.Blacklist) ||
		!reflect.DeepEqual(activeCfg.Gateway.BlacklistIPs, stagingCfg.Gateway.BlacklistIPs) {
		impact.GatewayRuntimeChanged = true
		mark("gateway.runtime")
	}

	return impact
}

func hasSubServiceInstalled() bool {
	return fileExists(getSubServicePath())
}

func restartSubServiceIfInstalled() error {
	if os.Geteuid() != 0 {
		return nil
	}
	if !hasSubServiceInstalled() {
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
