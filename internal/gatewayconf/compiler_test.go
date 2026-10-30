package gatewayconf

import (
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func TestCompile_Basic(t *testing.T) {
	input := `
def zone wan eth0
def zone lan eth1, eth2
local -> relay-main
zone lan -> relay-main
`
	ast, err := Parse(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	cfg, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if cfg.WANInterface != "eth0" {
		t.Errorf("WANInterface = %q, want eth0", cfg.WANInterface)
	}
	if len(cfg.LANInterfaces) != 2 || cfg.LANInterfaces[0] != "eth1" || cfg.LANInterfaces[1] != "eth2" {
		t.Errorf("LANInterfaces = %v, want [eth1 eth2]", cfg.LANInterfaces)
	}
	if !cfg.LocalEnabled {
		t.Errorf("LocalEnabled = false, want true")
	}
	if !cfg.LANEnabled {
		t.Errorf("LANEnabled = false, want true")
	}
	if cfg.RelayAlias != "relay-main" {
		t.Errorf("RelayAlias = %q, want relay-main", cfg.RelayAlias)
	}
	if len(cfg.Rules) != 0 {
		t.Errorf("expected 0 specific rules, got %d", len(cfg.Rules))
	}
}

func TestCompile_DeviceAliasExpansion(t *testing.T) {
	input := `
def zone wan eth0
def zone lan eth1
def device tv mac=52:54:00:84:00:11 zone=lan
def device pad mac=52:54:00:84:00:12

device tv -> relay-jp
device pad -> direct interface=eth1
`
	ast, err := Parse(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	cfg, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if len(cfg.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(cfg.Rules))
	}

	r0 := cfg.Rules[0]
	if r0.MAC != "52:54:00:84:00:11" || r0.Interface != "" || r0.Target != "relay-jp" {
		t.Errorf("r0 = %+v, want MAC=52:54:00:84:00:11, Interface='', Target=relay-jp", r0)
	}

	r1 := cfg.Rules[1]
	if r1.MAC != "52:54:00:84:00:12" || r1.Interface != "eth1" || r1.Target != "direct" {
		t.Errorf("r1 = %+v, want MAC=52:54:00:84:00:12, Interface=eth1, Target=direct", r1)
	}
}

func TestCompile_GroupExpansion(t *testing.T) {
	input := `
def zone wan eth0
def zone lan eth1
def device tv mac=52:54:00:84:00:11
def device pad mac=52:54:00:84:00:12
def group streaming tv, pad

group streaming -> relay-hk
`
	ast, err := Parse(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	cfg, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if len(cfg.Rules) != 2 {
		t.Fatalf("expected 2 rules expanded from group, got %d", len(cfg.Rules))
	}

	if cfg.Rules[0].MAC != "52:54:00:84:00:11" || cfg.Rules[0].Target != "relay-hk" {
		t.Errorf("rule[0] = %+v", cfg.Rules[0])
	}
	if cfg.Rules[1].MAC != "52:54:00:84:00:12" || cfg.Rules[1].Target != "relay-hk" {
		t.Errorf("rule[1] = %+v", cfg.Rules[1])
	}
}

func TestCompile_NestedAndDeduplicatedGroupExpansion(t *testing.T) {
	input := `
def zone lan eth1
def device dev1 mac=52:54:00:84:00:01
def device dev2 mac=52:54:00:84:00:02
def device dev3 mac=52:54:00:84:00:03

def group sub1 dev1, dev2
def group all_devs sub1, dev2, dev3

group all_devs -> block
`
	ast, err := Parse(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	cfg, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// dev2 is present in both sub1 and all_devs, so deduplicated to 3 rules
	if len(cfg.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(cfg.Rules))
	}
	expectedMACs := []string{"52:54:00:84:00:01", "52:54:00:84:00:02", "52:54:00:84:00:03"}
	for i, mac := range expectedMACs {
		if cfg.Rules[i].MAC != mac || cfg.Rules[i].Target != "block" {
			t.Errorf("rule[%d] = %+v, want MAC=%s, Target=block", i, cfg.Rules[i], mac)
		}
	}
}

func TestCompile_CircularGroupDetection(t *testing.T) {
	input := `
def device tv mac=52:54:00:84:00:11
def group groupA groupB
def group groupB groupA

group groupA -> block
`
	ast, err := Parse(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	_, err = Compile(ast)
	if err == nil {
		t.Fatalf("expected circular group error, got nil")
	}

	if !strings.Contains(err.Error(), "circular group reference") {
		t.Errorf("expected circular reference error, got %q", err.Error())
	}
}

func TestCompile_TargetValidation(t *testing.T) {
	inputValid := `
def zone lan eth1
local -> relay-us
zone lan -> direct
`
	astValid, _ := Parse(inputValid)
	_, err := Compile(astValid, WithValidRelays([]string{"relay-us"}))
	if err != nil {
		t.Fatalf("expected valid compile, got error: %v", err)
	}

	inputInvalid := `
def zone lan eth1
local -> non-existent-relay
`
	astInvalid, _ := Parse(inputInvalid)
	_, err = Compile(astInvalid, WithValidRelays([]string{"relay-us"}))
	if err == nil {
		t.Fatalf("expected invalid relay error, got nil")
	}
	if !strings.Contains(err.Error(), "target relay \"non-existent-relay\" does not exist or is disabled") {
		t.Errorf("expected missing relay error, got: %v", err)
	}
}

func TestCompile_UserConfigValidation(t *testing.T) {
	userCfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode: "tproxy",
		},
		CustomOutbounds: []config.CustomOutbound{
			{Alias: "relay-jp", Enabled: true},
			{Alias: "relay-disabled", Enabled: false},
		},
	}

	input := `
def zone lan eth1
local -> relay-disabled
`
	ast, _ := Parse(input)
	_, err := Compile(ast, WithUserConfig(userCfg))
	if err == nil {
		t.Fatalf("expected error referencing disabled relay, got nil")
	}
	if !strings.Contains(err.Error(), "does not exist or is disabled") {
		t.Errorf("expected disabled relay error, got: %v", err)
	}
}

func TestCompile_ZoneRules(t *testing.T) {
	input := `
def zone wan eth0
def zone lan eth1
def zone guest eth2
def zone iot eth3

local -> relay-main
zone lan -> relay-main
zone guest -> direct
zone iot -> block
`
	ast, err := Parse(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	cfg, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if len(cfg.Rules) != 2 {
		t.Fatalf("expected 2 rules for guest and iot, got %d", len(cfg.Rules))
	}

	if cfg.Rules[0].Interface != "eth2" || cfg.Rules[0].Target != "direct" {
		t.Errorf("guest rule = %+v, want eth2 -> direct", cfg.Rules[0])
	}
	if cfg.Rules[1].Interface != "eth3" || cfg.Rules[1].Target != "block" {
		t.Errorf("iot rule = %+v, want eth3 -> block", cfg.Rules[1])
	}
}

func TestCompile_IPRules(t *testing.T) {
	input := `
def zone lan eth1 subnet=192.168.1.0/24
def zone iot eth2 subnet=192.168.2.0/24
def device tv mac=52:54:00:84:00:11 ip=192.168.1.50
def device printer mac=52:54:00:84:00:22 ip=192.168.2.80

# 1. IP matches device tv
ip 192.168.1.50 -> relay-jp
# 2. IP matches zone iot subnet
ip 192.168.2.0/24 -> block
`
	ast, err := Parse(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	cfg, err := Compile(ast)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if len(cfg.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(cfg.Rules))
	}

	if cfg.Rules[0].MAC != "52:54:00:84:00:11" || cfg.Rules[0].Target != "relay-jp" {
		t.Errorf("rule[0] = %+v, want tv MAC", cfg.Rules[0])
	}
	if cfg.Rules[1].Interface != "eth2" || cfg.Rules[1].Target != "block" {
		t.Errorf("rule[1] = %+v, want eth2 from iot subnet", cfg.Rules[1])
	}
}

func TestCompile_CompileErrors(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		errContains string
	}{
		{
			name: "device undefined zone",
			input: `
def zone lan eth1
def device tv mac=52:54:00:84:00:11 zone=nonexistent
`,
			errContains: "references undefined zone \"nonexistent\"",
		},
		{
			name: "device in WAN zone",
			input: `
def zone wan eth0
def device tv mac=52:54:00:84:00:11 zone=wan
`,
			errContains: "cannot belong to WAN zone",
		},
		{
			name: "WAN and LAN interface collision",
			input: `
def zone wan eth0
def zone lan eth0, eth1
`,
			errContains: "WAN interface \"eth0\" cannot also be configured as a LAN interface",
		},
		{
			name: "rule references undefined device",
			input: `
def zone lan eth1
device unknown_dev -> direct
`,
			errContains: "undefined device \"unknown_dev\"",
		},
		{
			name: "rule references undefined group",
			input: `
def zone lan eth1
group unknown_grp -> direct
`,
			errContains: "undefined group \"unknown_grp\"",
		},
		{
			name: "group references undefined item",
			input: `
def group g1 nonexistent
`,
			errContains: "references undefined item \"nonexistent\"",
		},
		{
			name: "rule references undefined zone",
			input: `
zone nonexistent -> direct
`,
			errContains: "references undefined zone \"nonexistent\"",
		},
		{
			name: "zone rule on WAN zone",
			input: `
def zone wan eth0
zone wan -> direct
`,
			errContains: "cannot apply gateway routing rule to WAN zone",
		},
		{
			name: "unresolvable IP",
			input: `
def zone lan eth1
ip 10.99.99.99 -> direct
`,
			errContains: "cannot resolve IP or CIDR \"10.99.99.99\"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ast, err := Parse(tc.input)
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}
			_, err = Compile(ast)
			if err == nil {
				t.Fatalf("expected compile error containing %q, got nil", tc.errContains)
			}
			if !strings.Contains(err.Error(), tc.errContains) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.errContains)
			}
		})
	}
}
