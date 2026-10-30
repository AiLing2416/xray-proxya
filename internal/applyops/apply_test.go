package applyops

import (
	"os"
	"path/filepath"
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

func TestBuildImpactDetectsGatewayDNSAndTProxyPortChanges(t *testing.T) {
	baseActive := func() *config.UserConfig {
		return &config.UserConfig{
			Role: config.RoleGateway,
			Gateway: config.GatewayConfig{
				Mode:        "tproxy",
				State:       "proxy",
				TProxyPort:  12345,
				DNSListen:   ":53",
				DNSStrategy: "UseIP",
				DNSServers:  []string{"1.1.1.1"},
				DNSRecords:  map[string][]string{"router.lan": {"10.0.82.1"}},
			},
		}
	}

	// 1. TProxyPort change
	{
		active := baseActive()
		staging := baseActive()
		staging.Gateway.TProxyPort = 12346
		impact := BuildImpact(active, staging)
		if !impact.GatewayRuntimeChanged || !impact.XrayConfigChanged {
			t.Errorf("TProxyPort change: expected GatewayRuntimeChanged and XrayConfigChanged to be true, got: %+v", impact)
		}
	}

	// 2. DNSListen change
	{
		active := baseActive()
		staging := baseActive()
		staging.Gateway.DNSListen = ":5353"
		impact := BuildImpact(active, staging)
		if !impact.GatewayRuntimeChanged || !impact.XrayConfigChanged {
			t.Errorf("DNSListen change: expected GatewayRuntimeChanged and XrayConfigChanged to be true, got: %+v", impact)
		}
	}

	// 3. DNSStrategy change
	{
		active := baseActive()
		staging := baseActive()
		staging.Gateway.DNSStrategy = "UseIPv4"
		impact := BuildImpact(active, staging)
		if !impact.XrayConfigChanged {
			t.Errorf("DNSStrategy change: expected XrayConfigChanged to be true, got: %+v", impact)
		}
		found := false
		for _, s := range impact.ChangedSections {
			if s == "gateway.dns" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected 'gateway.dns' in ChangedSections, got: %v", impact.ChangedSections)
		}
	}

	// 4. DNSServers change
	{
		active := baseActive()
		staging := baseActive()
		staging.Gateway.DNSServers = []string{"8.8.8.8"}
		impact := BuildImpact(active, staging)
		if !impact.XrayConfigChanged {
			t.Errorf("DNSServers change: expected XrayConfigChanged to be true, got: %+v", impact)
		}
	}

	// 5. DNSRecords change
	{
		active := baseActive()
		staging := baseActive()
		staging.Gateway.DNSRecords = map[string][]string{"router.lan": {"10.0.82.1", "fd00:82::1"}}
		impact := BuildImpact(active, staging)
		if !impact.XrayConfigChanged {
			t.Errorf("DNSRecords change: expected XrayConfigChanged to be true, got: %+v", impact)
		}
	}

	// 6. Initial apply with DNSListen
	{
		staging := &config.UserConfig{
			Role: config.RoleGateway,
			Gateway: config.GatewayConfig{
				DNSListen: ":53",
			},
		}
		impact := BuildImpact(nil, staging)
		if !impact.GatewayRuntimeChanged {
			t.Errorf("Initial apply with DNSListen: expected GatewayRuntimeChanged to be true, got: %+v", impact)
		}
	}
}

func TestBuildImpactGatewayRouter(t *testing.T) {
	baseActive := func() *config.UserConfig {
		return &config.UserConfig{
			Role: config.RoleGateway,
			Gateway: config.GatewayConfig{
				State:        "proxy",
				LANEnabled:   true,
				LANInterface: "eth1",
				WANInterface: "eth0",
				NATDisabled:  false,
				Rules:        []config.GatewayRule{{Interface: "eth1", Target: "direct"}},
			},
		}
	}

	// 1. LANInterfaces change
	{
		active := baseActive()
		staging := baseActive()
		staging.Gateway.LANInterface = "eth1,eth2"
		staging.Gateway.LANInterfaces = []string{"eth1", "eth2"}
		impact := BuildImpact(active, staging)
		if !impact.GatewayRuntimeChanged || !impact.XrayConfigChanged {
			t.Errorf("LANInterfaces change: expected GatewayRuntimeChanged and XrayConfigChanged true, got: %+v", impact)
		}
	}

	// 2. WANInterface change
	{
		active := baseActive()
		staging := baseActive()
		staging.Gateway.WANInterface = "eth3"
		impact := BuildImpact(active, staging)
		if !impact.GatewayRuntimeChanged || !impact.XrayConfigChanged {
			t.Errorf("WANInterface change: expected GatewayRuntimeChanged and XrayConfigChanged true, got: %+v", impact)
		}
	}

	// 3. NATDisabled change
	{
		active := baseActive()
		staging := baseActive()
		staging.Gateway.NATDisabled = true
		impact := BuildImpact(active, staging)
		if !impact.GatewayRuntimeChanged || !impact.XrayConfigChanged {
			t.Errorf("NATDisabled change: expected GatewayRuntimeChanged and XrayConfigChanged true, got: %+v", impact)
		}
	}

	// 4. Rules change
	{
		active := baseActive()
		staging := baseActive()
		staging.Gateway.Rules = append(staging.Gateway.Rules, config.GatewayRule{MAC: "52:54:00:83:00:11", Target: "block"})
		impact := BuildImpact(active, staging)
		if !impact.GatewayRuntimeChanged || !impact.XrayConfigChanged {
			t.Errorf("Rules change: expected GatewayRuntimeChanged and XrayConfigChanged true, got: %+v", impact)
		}
	}

	// 5. Initial apply with Rules
	{
		staging := &config.UserConfig{
			Role: config.RoleGateway,
			Gateway: config.GatewayConfig{
				Rules: []config.GatewayRule{{Interface: "eth1", Target: "direct"}},
			},
		}
		impact := BuildImpact(nil, staging)
		if !impact.GatewayRuntimeChanged {
			t.Errorf("Initial apply with Rules: expected GatewayRuntimeChanged true, got: %+v", impact)
		}
	}

	// 6. IsolatedInterfaces change
	{
		active := baseActive()
		staging := baseActive()
		staging.Gateway.IsolatedInterfaces = []string{"eth1"}
		impact := BuildImpact(active, staging)
		if !impact.GatewayRuntimeChanged || !impact.XrayConfigChanged {
			t.Errorf("IsolatedInterfaces change: expected GatewayRuntimeChanged and XrayConfigChanged true, got: %+v", impact)
		}
	}

	// 7. Initial apply with IsolatedInterfaces
	{
		staging := &config.UserConfig{
			Role: config.RoleGateway,
			Gateway: config.GatewayConfig{
				IsolatedInterfaces: []string{"eth1"},
			},
		}
		impact := BuildImpact(nil, staging)
		if !impact.GatewayRuntimeChanged {
			t.Errorf("Initial apply with IsolatedInterfaces: expected GatewayRuntimeChanged true, got: %+v", impact)
		}
	}
}

func TestApplyPending_GatewayConfSync(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", tmpDir)

	active := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:         "tproxy",
			WANInterface: "eth0",
			LANInterfaces: []string{"eth1"},
			LocalEnabled: true,
			LANEnabled:   true,
			RelayAlias:   "relay-a",
		},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "relay-a", Enabled: true},
			{Alias: "relay-b", Enabled: true},
		},
	}
	if err := active.SaveEx(false); err != nil {
		t.Fatalf("failed to save active config: %v", err)
	}

	// 1. Initial check: clean
	lines, err := ApplyPending(Options{})
	if err != nil {
		t.Fatalf("ApplyPending failed: %v", err)
	}
	if len(lines) == 0 || !strings.Contains(lines[0], "clean") {
		t.Fatalf("expected clean message, got: %v", lines)
	}

	// 2. Create gateway.conf with a new rule
	confText := `# Gateway config test
def zone wan eth0
def zone lan eth1
def device test-dev mac=52:54:00:84:00:11
local -> relay-a
zone lan -> relay-a
device test-dev -> relay-b
`
	confPath := filepath.Join(tmpDir, "gateway.conf")
	if err := os.WriteFile(confPath, []byte(confText), 0600); err != nil {
		t.Fatalf("failed to write gateway.conf: %v", err)
	}

	// 3. DryRun test: must detect changes without committing
	dryLines, err := ApplyPending(Options{DryRun: true})
	if err != nil {
		t.Fatalf("ApplyPending dry-run failed: %v", err)
	}
	fullDry := strings.Join(dryLines, "\n")
	if !strings.Contains(fullDry, "DRY-RUN: Changes preview") {
		t.Errorf("expected dry-run preview, got:\n%s", fullDry)
	}

	// 4. Force apply: commits the gateway.conf to active configuration
	_, err = ApplyPending(Options{Force: true})
	if err != nil {
		t.Fatalf("ApplyPending force failed: %v", err)
	}

	// 5. Verify active config has the new rule from gateway.conf
	loaded, err := config.LoadConfigEx(false)
	if err != nil {
		t.Fatalf("failed to reload active config: %v", err)
	}
	if len(loaded.Gateway.Rules) != 1 {
		t.Fatalf("expected 1 rule in active config, got %d: %+v", len(loaded.Gateway.Rules), loaded.Gateway.Rules)
	}
	rule := loaded.Gateway.Rules[0]
	if rule.MAC != "52:54:00:84:00:11" || rule.Target != "relay-b" {
		t.Errorf("expected rule MAC 52:54:00:84:00:11 -> relay-b, got: %+v", rule)
	}
}
