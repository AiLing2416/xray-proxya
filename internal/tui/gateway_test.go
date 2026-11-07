package tui

import (
	"reflect"
	"strings"
	"testing"

	"xray-proxya/internal/config"
)

func newTestGatewayConfig() *config.UserConfig {
	return &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			State:           "proxy",
			LocalEnabled:    true,
			LANEnabled:      true,
			LANInterface:    "eth0",
			BypassCountries: []string{"CN"},
		},
	}
}

func TestHasGatewayStagedChanges(t *testing.T) {
	active := newTestGatewayConfig()
	staging := newTestGatewayConfig()

	if HasGatewayStagedChanges(active, staging) {
		t.Fatal("expected no staged changes for identical configs")
	}

	staging.Gateway.State = "forward-only"
	if !HasGatewayStagedChanges(active, staging) {
		t.Fatal("expected staged changes after modifying Gateway.State")
	}

	staging = newTestGatewayConfig()
	staging.Gateway.TUNEnabled = true
	if !HasGatewayStagedChanges(active, staging) {
		t.Fatal("expected staged changes after modifying Gateway.TUNEnabled")
	}

	staging = newTestGatewayConfig()
	staging.Gateway.LocalEnabled = !active.Gateway.LocalEnabled
	if !HasGatewayStagedChanges(active, staging) {
		t.Fatal("expected staged changes after modifying Gateway.LocalEnabled")
	}

	staging = newTestGatewayConfig()
	staging.Gateway.BypassCountries = []string{"CN", "US"}
	if !HasGatewayStagedChanges(active, staging) {
		t.Fatal("expected staged changes after modifying Gateway.BypassCountries")
	}
}

func TestBuildGatewayReport(t *testing.T) {
	active := newTestGatewayConfig()
	staging := newTestGatewayConfig()
	staging.Gateway.State = "proxy"
	staging.Gateway.TUNEnabled = true
	staging.Gateway.LocalEnabled = true
	staging.Gateway.LANEnabled = true
	staging.Gateway.LANInterface = "eth0"
	staging.Gateway.BypassCountries = []string{"CN"}

	for row := 0; row <= gwRowMax; row++ {
		report := BuildGatewayReport(active, staging, row, true, true, true, true, "198.51.100.1", "203.0.113.1")
		if report == "" {
			t.Fatalf("row %d: report should not be empty", row)
		}
	}
}

func TestRenderGateway(t *testing.T) {
	active := newTestGatewayConfig()
	staging := newTestGatewayConfig()
	staging.Gateway.TUNEnabled = true

	out := RenderGateway(active, staging, 1, 90, true, true, true, true, "10.0.82.21", "10.0.82.22")
	if out == "" {
		t.Fatal("RenderGateway output should not be empty")
	}
	if !strings.Contains(out, "TPROXY") {
		t.Fatal("RenderGateway should display TPROXY badge in header")
	}
	if !strings.Contains(out, "TUN") {
		t.Fatal("RenderGateway should display TUN badge in header")
	}
	if !strings.Contains(out, "TUN Adapter") {
		t.Fatal("RenderGateway should render TUN Adapter row")
	}
}

func TestValidateCountryCodes(t *testing.T) {
	tests := []struct {
		input   string
		want    []string
		wantErr bool
	}{
		{"CN", []string{"CN"}, false},
		{"cn, us , hk", []string{"CN", "US", "HK"}, false},
		{"", nil, false},
		{"   ", nil, false},
		{"C", nil, true},
		{"CHN", nil, true},
		{"12", nil, true},
		{"C1", nil, true},
	}

	for _, tt := range tests {
		got, err := validateCountryCodes(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateCountryCodes(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
			t.Errorf("validateCountryCodes(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestInterfaceChoicesKeepsMissingChecked(t *testing.T) {
	choices, checked := interfaceChoices([]string{"eth0", "eth1"}, []string{"eth1", "gone0"})
	want := []string{"eth0", "eth1", "gone0" + missingSuffix}
	if !reflect.DeepEqual(choices, want) {
		t.Fatalf("choices = %v, want %v", choices, want)
	}
	if checked[0] || !checked[1] || !checked[2] {
		t.Fatalf("unexpected checked map: %v", checked)
	}
	got := joinChecked(choices, checked)
	if !reflect.DeepEqual(got, []string{"eth1", "gone0"}) {
		t.Fatalf("joinChecked = %v (suffix must not leak into config)", got)
	}
}

func TestRenderMultiChoiceList(t *testing.T) {
	lines := RenderMultiChoiceList([]string{"eth1", "eth2", "wlan0"}, map[int]bool{0: true, 1: true}, 2, 0)
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"[x] eth1", "[x] eth2", "[ ] wlan0"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
	if got := RenderMultiChoiceList([]string{"a", "b", "c", "d"}, nil, 3, 2); len(got) != 2 {
		t.Fatalf("expected windowed 2 lines, got %d", len(got))
	}
}

func TestStagedChangesCoverWANAndNAT(t *testing.T) {
	active := newTestGatewayConfig()
	staging := newTestGatewayConfig()
	staging.Gateway.NATDisabled = true
	if !HasGatewayStagedChanges(active, staging) {
		t.Fatal("NAT change should be staged")
	}
	staging = newTestGatewayConfig()
	staging.Gateway.WANInterface = "eth9"
	if !HasGatewayStagedChanges(active, staging) {
		t.Fatal("WAN change should be staged")
	}
	staging = newTestGatewayConfig()
	staging.Gateway.WANInterface = "auto"
	if HasGatewayStagedChanges(active, staging) {
		t.Fatal("empty and 'auto' WAN must be equivalent")
	}
	staging = newTestGatewayConfig()
	staging.Gateway.LANInterface = "eth0,eth1"
	if !HasGatewayStagedChanges(active, staging) {
		t.Fatal("multi LAN interface change should be staged")
	}
}

func TestGatewayRowsRenderNewEntries(t *testing.T) {
	active := newTestGatewayConfig()
	staging := newTestGatewayConfig()
	staging.Gateway.NATDisabled = true
	staging.Gateway.LANInterface = "eth0,eth1"
	staging.Gateway.Rules = []config.GatewayRule{{MAC: "52:54:00:83:00:11", Target: "direct"}}
	out := RenderGateway(active, staging, 0, 140, false, false, false, false, "", "")
	for _, want := range []string{"WAN Interface", "NAT", "Rules", "1 rules", "eth0, eth1", "DISABLE"} {
		if !strings.Contains(out, want) {
			t.Fatalf("RenderGateway missing %q:\n%s", want, out)
		}
	}
	report := BuildGatewayReport(active, staging, gwRowRuleList, false, false, false, false, "", "")
	if !strings.Contains(report, "mac=52:54:00:83:00:11 -> direct") {
		t.Fatalf("rules report missing entry:\n%s", report)
	}
}

func TestConfirmMultiSelectWritesLANInterfaces(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	staging := newTestGatewayConfig()
	staging.Gateway.LANInterfaces = []string{"stale0"}
	m := Model{
		staging:           staging,
		infoSelectMode:    true,
		infoSelectMulti:   true,
		infoSelectTarget:  "gw-iface",
		infoSelectChoices: []string{"eth0", "eth1", "gone0" + missingSuffix},
		infoSelectChecked: map[int]bool{0: true, 2: true},
	}
	res, _ := m.confirmInfoSelect()
	got := res.(Model)
	if got.staging.Gateway.LANInterface != "eth0,gone0" {
		t.Fatalf("LANInterface = %q", got.staging.Gateway.LANInterface)
	}
	if !reflect.DeepEqual(got.staging.Gateway.LANInterfaces, []string{"eth0", "gone0"}) {
		t.Fatalf("stale legacy interfaces must not survive, got %v", got.staging.Gateway.LANInterfaces)
	}
	if got.infoSelectMode || got.infoSelectMulti {
		t.Fatal("expected select mode closed")
	}

	m.infoSelectMode, m.infoSelectMulti = true, true
	m.infoSelectChecked = map[int]bool{}
	res, _ = m.confirmInfoSelect()
	if res.(Model).staging.Gateway.LANInterface != "" {
		t.Fatal("empty selection should clear LANInterface")
	}
}

func TestConfirmWANSelect(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	staging := newTestGatewayConfig()
	m := Model{staging: staging, infoSelectMode: true, infoSelectTarget: "gw-wan",
		infoSelectChoices: []string{"auto", "eth9" + missingSuffix}, infoSelectIdx: 1}
	res, _ := m.confirmInfoSelect()
	if got := res.(Model).staging.Gateway.WANInterface; got != "eth9" {
		t.Fatalf("WANInterface = %q, want eth9", got)
	}
	m.infoSelectMode, m.infoSelectIdx = true, 0
	res, _ = m.confirmInfoSelect()
	if got := res.(Model).staging.Gateway.WANInterface; got != "" {
		t.Fatalf("auto should store empty, got %q", got)
	}
}
