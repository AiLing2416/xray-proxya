package gatewayconf

import (
	"reflect"
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func TestGenerate_Basic(t *testing.T) {
	gw := &config.GatewayConfig{
		WANInterface:  "eth0",
		LANInterfaces: []string{"eth1", "eth2"},
		LocalEnabled:  true,
		LANEnabled:    true,
		RelayAlias:    "relay-hk",
		Rules: []config.GatewayRule{
			{MAC: "52:54:00:84:00:11", Target: "direct"},
			{Interface: "eth2", Target: "block"},
			{MAC: "52:54:00:84:00:22", Interface: "eth1", Target: "relay-us"},
			{IP: "192.168.1.95", Target: "direct"},
			{IP: "10.0.0.0/24", Interface: "eth1", Target: "relay-us"},
		},
		PortForwards: []config.PortForwardRule{
			{WANPort: 8080, TargetIP: "192.168.1.100", TargetPort: 80, Proto: "tcp"},
			{WANPort: 5353, TargetIP: "192.168.1.53", TargetPort: 53, Proto: "tcp,udp"},
		},
	}

	text := Generate(gw)

	// Verify key lines exist in output
	expectedSubstrings := []string{
		"def zone wan eth0",
		"def zone lan eth1, eth2",
		"local -> relay-hk",
		"zone lan -> relay-hk",
		"mac 52:54:00:84:00:11 -> direct",
		"interface eth2 -> block",
		"mac 52:54:00:84:00:22 -> relay-us interface=eth1",
		"# Port Forwarding Rules",
		"forward 8080 -> 192.168.1.100:80 proto=tcp",
		"forward 5353 -> 192.168.1.53:53 proto=tcp,udp",
	}

	for _, s := range expectedSubstrings {
		if !strings.Contains(text, s) {
			t.Errorf("generated output missing expected line %q:\n%s", s, text)
		}
	}
}

func TestGenerateFromUserConfig(t *testing.T) {
	userCfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			WANInterface:  "eth0",
			LANInterfaces: []string{"eth1"},
			LocalEnabled:  false,
			LANEnabled:    true,
			RelayAlias:    "relay-hk",
		},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "relay-hk", Enabled: true},
			{Alias: "relay-backup", Enabled: false},
		},
	}

	text := GenerateFromUserConfig(userCfg)

	if !strings.Contains(text, "relay-hk         (enabled)") {
		t.Errorf("expected enabled relay-hk in comments, got:\n%s", text)
	}
	if !strings.Contains(text, "relay-backup     (disabled)") {
		t.Errorf("expected disabled relay-backup in comments, got:\n%s", text)
	}
	if !strings.Contains(text, "local -> direct") {
		t.Errorf("expected local -> direct when LocalEnabled is false, got:\n%s", text)
	}
	if !strings.Contains(text, "zone lan -> relay-hk") {
		t.Errorf("expected zone lan -> relay-hk, got:\n%s", text)
	}
}

func TestGenerateFromAST(t *testing.T) {
	ast := &ConfigAST{
		Zones: []ZoneDef{
			{Name: "wan", Interfaces: []string{"eth0"}, Line: 1},
			{Name: "lan", Interfaces: []string{"eth1", "vmbr0"}, Subnets: []string{"192.168.1.0/24"}, Line: 2},
		},
		Devices: []DeviceDef{
			{Name: "tv", MAC: "52:54:00:84:00:11", Zone: "lan", IP: "192.168.1.50", Line: 3},
		},
		Groups: []GroupDef{
			{Name: "streaming", Items: []string{"tv", "pad"}, Line: 4},
		},
		Rules: []RuleAST{
			{Kind: SubjectLocal, Target: "relay-main", Options: []RuleOption{{Key: "dns", Value: "relay"}}, Line: 5},
			{Kind: SubjectDevice, SubjectValue: "tv", Target: "relay-jp", Line: 6},
		},
		Forwards: []ForwardAST{
			{WANPort: 8080, Target: "tv", TargetPort: 80, Proto: "tcp", Line: 7},
		},
	}

	text := GenerateFromAST(ast)

	expected := []string{
		"def zone wan eth0",
		"def zone lan eth1, vmbr0 subnet=192.168.1.0/24",
		"def device tv mac=52:54:00:84:00:11 zone=lan ip=192.168.1.50",
		"def group streaming tv, pad",
		"local -> relay-main dns=relay",
		"device tv -> relay-jp",
		"# --- Port Forwarding Rules ---",
		"forward 8080 -> tv:80 proto=tcp",
	}

	for _, s := range expected {
		if !strings.Contains(text, s) {
			t.Errorf("GenerateFromAST output missing %q:\n%s", s, text)
		}
	}
}

func TestRoundTrip_GatewayConfigConsistency(t *testing.T) {
	original := &config.GatewayConfig{
		WANInterface:       "eth0",
		LANInterfaces:      []string{"eth1", "eth2"},
		IsolatedInterfaces: []string{"eth2"},
		LocalEnabled:       true,
		LANEnabled:         true,
		RelayAlias:         "relay-default",
		Mode:               "tproxy",
		Rules: []config.GatewayRule{
			{MAC: "52:54:00:84:00:11", Target: "direct"},
			{Interface: "eth2", Target: "block"},
			{MAC: "52:54:00:84:00:22", Interface: "eth1", Target: "relay-us"},
			{IP: "192.168.1.95", Target: "direct"},
			{IP: "10.0.0.0/24", Interface: "eth1", Target: "relay-us"},
		},
		PortForwards: []config.PortForwardRule{
			{WANPort: 8080, TargetIP: "192.168.1.100", TargetPort: 80, Proto: "tcp"},
			{WANPort: 9090, TargetIP: "192.168.1.200", TargetPort: 90, Proto: "udp"},
		},
	}

	// Step 1: Export GatewayConfig to text
	text := Generate(original)

	// Step 2: Parse text back to AST
	ast, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse failed in round-trip: %v", err)
	}

	// Step 3: Compile AST back to GatewayConfig
	recompiled, err := Compile(ast)
	if err != nil {
		t.Fatalf("Compile failed in round-trip: %v", err)
	}

	// Step 4: Verify equality
	if recompiled.WANInterface != original.WANInterface {
		t.Errorf("WANInterface = %q, want %q", recompiled.WANInterface, original.WANInterface)
	}
	if !reflect.DeepEqual(recompiled.LANInterfaces, original.LANInterfaces) {
		t.Errorf("LANInterfaces = %v, want %v", recompiled.LANInterfaces, original.LANInterfaces)
	}
	if !reflect.DeepEqual(recompiled.EffectiveIsolatedInterfaces(), original.EffectiveIsolatedInterfaces()) {
		t.Errorf("IsolatedInterfaces = %v, want %v", recompiled.EffectiveIsolatedInterfaces(), original.EffectiveIsolatedInterfaces())
	}
	if recompiled.LocalEnabled != original.LocalEnabled {
		t.Errorf("LocalEnabled = %v, want %v", recompiled.LocalEnabled, original.LocalEnabled)
	}
	if recompiled.LANEnabled != original.LANEnabled {
		t.Errorf("LANEnabled = %v, want %v", recompiled.LANEnabled, original.LANEnabled)
	}
	if recompiled.RelayAlias != original.RelayAlias {
		t.Errorf("RelayAlias = %q, want %q", recompiled.RelayAlias, original.RelayAlias)
	}
	if len(recompiled.Rules) != len(original.Rules) {
		t.Fatalf("Rules length = %d, want %d", len(recompiled.Rules), len(original.Rules))
	}

	for i := range original.Rules {
		rWant := original.Rules[i]
		rGot := recompiled.Rules[i]
		if rGot.MAC != rWant.MAC || rGot.Interface != rWant.Interface || rGot.Target != rWant.Target {
			t.Errorf("Rule[%d] = %+v, want %+v", i, rGot, rWant)
		}
	}

	if len(recompiled.PortForwards) != len(original.PortForwards) {
		t.Fatalf("PortForwards length = %d, want %d", len(recompiled.PortForwards), len(original.PortForwards))
	}
	for i := range original.PortForwards {
		pfWant := original.PortForwards[i]
		pfGot := recompiled.PortForwards[i]
		if pfGot != pfWant {
			t.Errorf("PortForward[%d] = %+v, want %+v", i, pfGot, pfWant)
		}
	}
}

func TestRoundTrip_ASTConsistency(t *testing.T) {
	origAST := &ConfigAST{
		Zones: []ZoneDef{
			{Name: "wan", Interfaces: []string{"eth0"}},
			{Name: "lan", Interfaces: []string{"eth1", "vmbr0"}, Subnets: []string{"192.168.1.0/24"}},
			{Name: "guest", Interfaces: []string{"vmbr1"}, Isolate: true},
		},
		Devices: []DeviceDef{
			{Name: "tv", MAC: "52:54:00:84:00:11", Zone: "lan", IP: "192.168.1.50"},
			{Name: "pad", MAC: "52:54:00:84:00:12", Zone: "lan"},
		},
		Groups: []GroupDef{
			{Name: "streaming", Items: []string{"tv", "pad"}},
		},
		Rules: []RuleAST{
			{Kind: SubjectLocal, Target: "relay-main", Options: []RuleOption{{Key: "dns", Value: "relay"}}},
			{Kind: SubjectZone, SubjectValue: "lan", Target: "relay-main"},
			{Kind: SubjectDevice, SubjectValue: "tv", Target: "relay-jp", Options: []RuleOption{{Key: "backup", Value: "relay-us"}}},
			{Kind: SubjectGroup, SubjectValue: "streaming", Target: "relay-hk"},
			{Kind: SubjectMAC, SubjectValue: "52:54:00:12:34:56", Target: "direct"},
			{Kind: SubjectInterface, SubjectValue: "eth1", Target: "block"},
			{Kind: SubjectIP, SubjectValue: "192.168.1.50", Target: "relay-jp"},
		},
		Forwards: []ForwardAST{
			{WANPort: 8080, Target: "tv", TargetPort: 80, Proto: "tcp"},
			{WANPort: 9090, Target: "192.168.1.200", TargetPort: 90, Proto: "udp"},
		},
	}

	// 1. AST -> Text
	text := GenerateFromAST(origAST)

	// 2. Text -> AST
	reparsed, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse error in AST round-trip: %v", err)
	}

	// 3. Compare Zones
	if len(reparsed.Zones) != len(origAST.Zones) {
		t.Fatalf("Zones count = %d, want %d", len(reparsed.Zones), len(origAST.Zones))
	}
	for i := range origAST.Zones {
		zWant := origAST.Zones[i]
		zGot := reparsed.Zones[i]
		if zGot.Name != zWant.Name || !reflect.DeepEqual(zGot.Interfaces, zWant.Interfaces) || !reflect.DeepEqual(zGot.Subnets, zWant.Subnets) || zGot.Isolate != zWant.Isolate {
			t.Errorf("Zone[%d] = %+v, want %+v", i, zGot, zWant)
		}
	}

	// 4. Compare Devices
	if len(reparsed.Devices) != len(origAST.Devices) {
		t.Fatalf("Devices count = %d, want %d", len(reparsed.Devices), len(origAST.Devices))
	}
	for i := range origAST.Devices {
		dWant := origAST.Devices[i]
		dGot := reparsed.Devices[i]
		if dGot.Name != dWant.Name || dGot.MAC != dWant.MAC || dGot.Zone != dWant.Zone || dGot.IP != dWant.IP {
			t.Errorf("Device[%d] = %+v, want %+v", i, dGot, dWant)
		}
	}

	// 5. Compare Groups
	if len(reparsed.Groups) != len(origAST.Groups) {
		t.Fatalf("Groups count = %d, want %d", len(reparsed.Groups), len(origAST.Groups))
	}
	for i := range origAST.Groups {
		gWant := origAST.Groups[i]
		gGot := reparsed.Groups[i]
		if gGot.Name != gWant.Name || !reflect.DeepEqual(gGot.Items, gWant.Items) {
			t.Errorf("Group[%d] = %+v, want %+v", i, gGot, gWant)
		}
	}

	// 6. Compare Rules
	if len(reparsed.Rules) != len(origAST.Rules) {
		t.Fatalf("Rules count = %d, want %d", len(reparsed.Rules), len(origAST.Rules))
	}
	for i := range origAST.Rules {
		rWant := origAST.Rules[i]
		rGot := reparsed.Rules[i]
		if rGot.Kind != rWant.Kind || rGot.SubjectValue != rWant.SubjectValue || rGot.Target != rWant.Target {
			t.Errorf("Rule[%d] = %+v, want %+v", i, rGot, rWant)
		}
		if len(rGot.Options) != len(rWant.Options) {
			t.Errorf("Rule[%d] options len = %d, want %d", i, len(rGot.Options), len(rWant.Options))
		}
	}

	// 7. Compare Forwards
	if len(reparsed.Forwards) != len(origAST.Forwards) {
		t.Fatalf("Forwards count = %d, want %d", len(reparsed.Forwards), len(origAST.Forwards))
	}
	for i := range origAST.Forwards {
		fWant := origAST.Forwards[i]
		fGot := reparsed.Forwards[i]
		if fGot.WANPort != fWant.WANPort || fGot.Target != fWant.Target || fGot.TargetPort != fWant.TargetPort || fGot.Proto != fWant.Proto {
			t.Errorf("Forward[%d] = %+v, want %+v", i, fGot, fWant)
		}
	}
}
