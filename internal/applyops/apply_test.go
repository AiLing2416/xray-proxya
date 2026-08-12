package applyops

import (
	"testing"

	"xray-proxya/internal/config"
)

func TestBuildImpactDetectsPathChanges(t *testing.T) {
	active := &config.UserConfig{}
	staging := &config.UserConfig{}
	staging.Path = config.PathConfig{Enabled: true, Listen: "127.0.0.1:19090", Token: "token"}

	impact := BuildImpact(active, staging)
	if !impact.XrayConfigChanged || !impact.GatewayRuntimeChanged {
		t.Fatalf("path change impact = %#v", impact)
	}
	for _, section := range impact.ChangedSections {
		if section == "path" {
			return
		}
	}
	t.Fatalf("path change was not marked: %#v", impact.ChangedSections)
}
