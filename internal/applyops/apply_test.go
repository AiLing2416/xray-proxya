package applyops

import (
	"strings"
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

func TestBuildDryRunPreview(t *testing.T) {
	impact := Impact{
		XrayConfigChanged:  true,
		SubListenerChanged: true,
		ChangedSections:    []string{"presets", "custom_outbounds"},
	}
	lines := BuildDryRunPreview(nil, nil, impact, Options{DryRun: true})
	fullText := strings.Join(lines, "\n")

	if !strings.Contains(fullText, "DRY-RUN: Changes preview") {
		t.Fatalf("missing dry-run header: %s", fullText)
	}
	if !strings.Contains(fullText, "Changed Sections : [presets custom_outbounds]") {
		t.Fatalf("missing changed sections: %s", fullText)
	}
	if !strings.Contains(fullText, "Core Service") {
		t.Fatalf("missing Core Service action: %s", fullText)
	}
	if !strings.Contains(fullText, "Subscription Service") {
		t.Fatalf("missing Subscription Service action: %s", fullText)
	}
}

func TestApplyPendingDryRunDoesNotCommit(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", tempDir)

	active := &config.UserConfig{Role: config.RoleServer, UUID: "orig-uuid"}
	staging := &config.UserConfig{Role: config.RoleServer, UUID: "new-uuid"}
	if err := active.SaveEx(false); err != nil {
		t.Fatalf("save active: %v", err)
	}
	if err := staging.SaveEx(true); err != nil {
		t.Fatalf("save staging: %v", err)
	}

	lines, err := ApplyPending(Options{DryRun: true})
	if err != nil {
		t.Fatalf("ApplyPending dry-run failed: %v", err)
	}

	fullText := strings.Join(lines, "\n")
	if !strings.Contains(fullText, "DRY-RUN: Changes preview") {
		t.Fatalf("expected dry-run preview, got:\n%s", fullText)
	}
	if !strings.Contains(fullText, "uuid") {
		t.Fatalf("expected uuid in changed sections, got:\n%s", fullText)
	}

	// Staging must still exist!
	if !config.StagingExists() {
		t.Fatal("staging file should not have been removed or committed by dry-run")
	}

	loadedActive, err := config.LoadConfigEx(false)
	if err != nil {
		t.Fatalf("load active: %v", err)
	}
	if loadedActive.UUID != "orig-uuid" {
		t.Fatalf("active config should remain untouched, got UUID=%s", loadedActive.UUID)
	}
}

func TestStoppedServiceActionableHints(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", tempDir)

	active := &config.UserConfig{Role: config.RoleServer, UUID: "old-uuid"}
	staging := &config.UserConfig{Role: config.RoleServer, UUID: "new-uuid"}
	if err := active.SaveEx(false); err != nil {
		t.Fatalf("save active: %v", err)
	}
	if err := staging.SaveEx(true); err != nil {
		t.Fatalf("save staging: %v", err)
	}

	lines, err := ApplyPending(Options{Force: true})
	if err != nil {
		t.Fatalf("ApplyPending failed: %v", err)
	}

	fullText := strings.Join(lines, "\n")
	if !strings.Contains(fullText, "xray-proxya service start core") {
		t.Fatalf("expected actionable hint for stopped core service, got:\n%s", fullText)
	}
}

func TestBuildImpactDetectsEndpointChanges(t *testing.T) {
	active := &config.UserConfig{
		Role: config.RoleServer,
		Endpoints: map[string]config.EndpointConfig{
			"default":   {Type: config.EndpointTypeAuto, Family: "v4"},
			"to-remove": {Type: config.EndpointTypeStatic, Host: "old.example.com"},
			"to-modify": {Type: config.EndpointTypeStatic, Host: "mod1.example.com"},
		},
	}
	staging := &config.UserConfig{
		Role: config.RoleServer,
		Endpoints: map[string]config.EndpointConfig{
			"default":   {Type: config.EndpointTypeAuto, Family: "v4"},
			"to-modify": {Type: config.EndpointTypeStatic, Host: "mod2.example.com"},
			"to-add":    {Type: config.EndpointTypeStatic, Host: "new.example.com"},
		},
	}

	impact := BuildImpact(active, staging)
	if !impact.SubContentChanged {
		t.Fatal("expected SubContentChanged to be true on endpoint changes")
	}
	foundEndpointsSection := false
	for _, s := range impact.ChangedSections {
		if s == "endpoints" {
			foundEndpointsSection = true
			break
		}
	}
	if !foundEndpointsSection {
		t.Fatalf("expected 'endpoints' in changed sections, got %v", impact.ChangedSections)
	}

	diffText := strings.Join(impact.EndpointDiffs, "\n")
	if !strings.Contains(diffText, "Added endpoint 'to-add'") {
		t.Errorf("expected added endpoint diff, got: %s", diffText)
	}
	if !strings.Contains(diffText, "Modified endpoint 'to-modify'") {
		t.Errorf("expected modified endpoint diff, got: %s", diffText)
	}
	if !strings.Contains(diffText, "Removed endpoint 'to-remove'") {
		t.Errorf("expected removed endpoint diff, got: %s", diffText)
	}
}

func TestDryRunPreviewDisplaysEndpointDiffs(t *testing.T) {
	impact := Impact{
		ChangedSections: []string{"endpoints"},
		EndpointDiffs: []string{
			"Added endpoint 'hk-node' (static, target: hk.example.com)",
		},
	}
	lines := BuildDryRunPreview(nil, nil, impact, Options{DryRun: true})
	fullText := strings.Join(lines, "\n")

	if !strings.Contains(fullText, "Endpoint Changes :") {
		t.Fatalf("expected 'Endpoint Changes :' in dry-run preview, got:\n%s", fullText)
	}
	if !strings.Contains(fullText, "Added endpoint 'hk-node'") {
		t.Fatalf("expected 'Added endpoint 'hk-node'' in dry-run preview, got:\n%s", fullText)
	}
}

func TestApplyPendingDisplaysEndpointChanges(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", tempDir)

	active := &config.UserConfig{
		Role: config.RoleServer,
		UUID: "test-uuid-apply-ep",
		Endpoints: map[string]config.EndpointConfig{
			"default": {Type: config.EndpointTypeAuto, Family: "v4"},
		},
	}
	staging := &config.UserConfig{
		Role: config.RoleServer,
		UUID: "test-uuid-apply-ep",
		Endpoints: map[string]config.EndpointConfig{
			"default": {Type: config.EndpointTypeAuto, Family: "v4"},
			"my-ep":   {Type: config.EndpointTypeStatic, Host: "ep.example.com"},
		},
	}
	if err := active.SaveEx(false); err != nil {
		t.Fatalf("save active: %v", err)
	}
	if err := staging.SaveEx(true); err != nil {
		t.Fatalf("save staging: %v", err)
	}

	lines, err := ApplyPending(Options{Force: true})
	if err != nil {
		t.Fatalf("ApplyPending failed: %v", err)
	}

	fullText := strings.Join(lines, "\n")
	if !strings.Contains(fullText, "Endpoint changes:") {
		t.Fatalf("expected 'Endpoint changes:' in apply output, got:\n%s", fullText)
	}
	if !strings.Contains(fullText, "Added endpoint 'my-ep'") {
		t.Fatalf("expected 'Added endpoint 'my-ep'' in apply output, got:\n%s", fullText)
	}
}
