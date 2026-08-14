package applyops

import (
	"testing"

	"xray-proxya/internal/config"
)

func TestBuildImpactDetectsPathdChanges(t *testing.T) {
	active := &config.UserConfig{Role: config.RoleServer}
	staging := &config.UserConfig{Role: config.RoleServer}
	staging.Path = config.PathConfig{Listen: "127.0.0.1:19090", Token: "token", IdleSeconds: 20}

	impact := BuildImpact(active, staging)
	if !impact.PathdConfigChanged || impact.XrayConfigChanged || impact.GatewayRuntimeChanged {
		t.Fatalf("path change impact = %#v", impact)
	}
	for _, section := range impact.ChangedSections {
		if section == "pathd" {
			return
		}
	}
	t.Fatalf("path change was not marked: %#v", impact.ChangedSections)
}

func TestBuildImpactRestartsGatewayOnlyForSelectedRelayPath(t *testing.T) {
	active := &config.UserConfig{
		Role:    config.RoleGateway,
		Gateway: config.GatewayConfig{RelayAlias: "a"},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "a", Path: &config.PathConfig{Token: "token-a"}},
			{Alias: "b", Path: &config.PathConfig{Token: "token-b"}},
		},
	}
	staging := *active
	staging.CustomOutbounds = append([]config.CustomOutbound(nil), active.CustomOutbounds...)
	endpoint := *staging.CustomOutbounds[1].Path
	endpoint.Token = "rotated-token-b"
	staging.CustomOutbounds[1].Path = &endpoint

	impact := BuildImpact(active, &staging)
	if impact.XrayConfigChanged || impact.GatewayRuntimeChanged {
		t.Fatalf("non-selected relay PathLink change should not restart Gateway: %#v", impact)
	}

	endpoint = *staging.CustomOutbounds[0].Path
	endpoint.Token = "rotated-token-a"
	staging.CustomOutbounds[0].Path = &endpoint
	impact = BuildImpact(active, &staging)
	if !impact.XrayConfigChanged || !impact.GatewayRuntimeChanged {
		t.Fatalf("selected relay PathLink change must restart Gateway: %#v", impact)
	}
}
