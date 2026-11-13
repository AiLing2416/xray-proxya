package gatewayconf

import (
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func TestUpdateSet_InPlaceAndAppend(t *testing.T) {
	initial := `# Top Comment
def zone wan eth0
def zone lan eth1,eth2
def device pc mac=52:54:00:12:34:56

set state disabled
set wan eth0
# Middle Comment
local -> direct
`

	// 1. Update existing key 'state'
	res1 := UpdateSet(initial, "state", "proxy")
	if !strings.Contains(res1, "set state proxy") {
		t.Fatalf("expected 'set state proxy', got:\n%s", res1)
	}
	if strings.Contains(res1, "set state disabled") {
		t.Fatalf("expected old 'set state disabled' to be replaced, got:\n%s", res1)
	}
	if !strings.Contains(res1, "def zone wan eth0") || !strings.Contains(res1, "# Middle Comment") {
		t.Fatalf("def or comment was altered:\n%s", res1)
	}

	// 2. Append new key 'tproxy_port'
	res2 := UpdateSet(res1, "tproxy_port", "12345")
	if !strings.Contains(res2, "set tproxy_port 12345") {
		t.Fatalf("expected 'set tproxy_port 12345', got:\n%s", res2)
	}
	lines := strings.Split(strings.TrimSpace(res2), "\n")
	lastLine := lines[len(lines)-1]
	if lastLine != "set tproxy_port 12345" {
		t.Fatalf("expected newly added set to be at the end, got last line: %q", lastLine)
	}

	// 3. Delete key
	res3 := DeleteSet(res2, "wan")
	if strings.Contains(res3, "set wan") {
		t.Fatalf("expected 'set wan' to be deleted, got:\n%s", res3)
	}
	if !strings.Contains(res3, "def zone wan eth0") {
		t.Fatalf("def zone wan eth0 should remain untouched")
	}
}

func TestUpdateDNSRecord_InPlaceAndAppend(t *testing.T) {
	initial := `# DNS test
def zone wan eth0
dns test.lan -> 10.0.0.1
`

	// 1. Update existing domain
	res1 := UpdateDNSRecord(initial, "test.lan", []string{"10.0.0.2", "fd00::2"})
	if !strings.Contains(res1, "dns test.lan -> 10.0.0.2, fd00::2") {
		t.Fatalf("expected updated record, got:\n%s", res1)
	}
	if strings.Contains(res1, "10.0.0.1") {
		t.Fatalf("expected old IP to be replaced, got:\n%s", res1)
	}

	// 2. Append new domain
	res2 := UpdateDNSRecord(res1, "router.lan", []string{"10.0.82.1"})
	if !strings.Contains(res2, "dns router.lan -> 10.0.82.1") {
		t.Fatalf("expected new record appended, got:\n%s", res2)
	}

	// 3. Delete domain
	res3 := DeleteDNSRecord(res2, "test.lan")
	if strings.Contains(res3, "test.lan") {
		t.Fatalf("expected test.lan to be deleted, got:\n%s", res3)
	}
	if !strings.Contains(res3, "router.lan") {
		t.Fatalf("expected router.lan to remain")
	}

	// 4. Clear records
	res4 := ClearDNSRecords(res3)
	if strings.Contains(res4, "dns router.lan") {
		t.Fatalf("expected all records to be cleared, got:\n%s", res4)
	}
	if !strings.Contains(res4, "def zone wan eth0") {
		t.Fatalf("def zone should remain")
	}
}

func TestUpdateRule_InPlaceAndAppend(t *testing.T) {
	initial := `# Rules test
def zone lan eth1
mac 52:54:00:83:00:11 -> direct
`

	// 1. Update single-criteria rule in place
	rule1 := config.GatewayRule{
		MAC:    "52:54:00:83:00:11",
		Target: "relay-node1",
	}
	res1 := UpdateRule(initial, rule1)
	if !strings.Contains(res1, "mac 52:54:00:83:00:11 -> relay-node1") {
		t.Fatalf("expected in-place rule update, got:\n%s", res1)
	}
	if strings.Contains(res1, "-> direct") {
		t.Fatalf("old target should be replaced")
	}

	// 2. Append multi-criteria rule
	rule2 := config.GatewayRule{
		IP:        "10.0.0.1",
		MAC:       "52:54:00:83:00:12",
		Interface: "eth1",
		Target:    "relay-node2",
	}
	res2 := UpdateRule(res1, rule2)
	if !strings.Contains(res2, "rule mac=52:54:00:83:00:12 ip=10.0.0.1 interface=eth1 -> relay-node2") {
		t.Fatalf("expected multi-criteria rule appended, got:\n%s", res2)
	}

	// 3. Update multi-criteria rule in place
	rule2Updated := config.GatewayRule{
		IP:        "10.0.0.1",
		MAC:       "52:54:00:83:00:12",
		Interface: "eth1",
		Target:    "block",
	}
	res3 := UpdateRule(res2, rule2Updated)
	if !strings.Contains(res3, "rule mac=52:54:00:83:00:12 ip=10.0.0.1 interface=eth1 -> block") {
		t.Fatalf("expected multi-criteria rule in-place update, got:\n%s", res3)
	}
	if strings.Contains(res3, "relay-node2") {
		t.Fatalf("old target relay-node2 should be gone")
	}

	// 4. Delete rule
	res4 := DeleteRule(res3, rule1)
	if strings.Contains(res4, "52:54:00:83:00:11") {
		t.Fatalf("expected rule1 to be deleted")
	}
	if !strings.Contains(res4, "52:54:00:83:00:12") {
		t.Fatalf("expected rule2 to remain")
	}
}

func TestUpdater_NeverTouchesDef(t *testing.T) {
	initial := `# Complex config with defs
def zone wan eth0
def zone lan eth1, eth2 isolate=true
def device tv mac=52:54:00:11:22:33 zone=lan ip=10.0.1.50
def group home tv

set state proxy
local -> direct
`

	// Attempt to set keys or rules
	res := UpdateSet(initial, "state", "forward-only")
	res = UpdateSet(res, "wan", "eth0")
	res = UpdateDNSRecord(res, "home.lan", []string{"10.0.1.1"})

	// Verify all defs are identical
	if !strings.Contains(res, "def zone wan eth0") ||
		!strings.Contains(res, "def zone lan eth1, eth2 isolate=true") ||
		!strings.Contains(res, "def device tv mac=52:54:00:11:22:33 zone=lan ip=10.0.1.50") ||
		!strings.Contains(res, "def group home tv") {
		t.Fatalf("def directives were modified:\n%s", res)
	}
}

func TestClearRules_ClearsAliasesAndPreservesDefs(t *testing.T) {
	initial := `# Complex config with rules and defs
def zone wan eth0
def zone lan eth1
def zone guest eth2
def device tv mac=52:54:00:11:22:33 zone=lan
def group streaming tv

set state proxy
local -> direct
zone guest -> direct
device tv -> proxy
group streaming -> proxy
mac 52:54:00:99:99:99 -> block
ip 10.0.0.0/24 -> direct
interface eth1 -> proxy
`
	res := ClearRules(initial)

	// Verify defs, sets, comments, and local rule are preserved
	if !strings.Contains(res, "def zone wan eth0") ||
		!strings.Contains(res, "def zone lan eth1") ||
		!strings.Contains(res, "def zone guest eth2") ||
		!strings.Contains(res, "def device tv mac=52:54:00:11:22:33 zone=lan") ||
		!strings.Contains(res, "def group streaming tv") ||
		!strings.Contains(res, "set state proxy") ||
		!strings.Contains(res, "local -> direct") {
		t.Fatalf("defs or local were unexpectedly removed:\n%s", res)
	}

	// Verify alias and client rules are cleared
	for _, removed := range []string{
		"zone guest -> direct",
		"device tv -> proxy",
		"group streaming -> proxy",
		"mac 52:54:00:99:99:99 -> block",
		"ip 10.0.0.0/24 -> direct",
		"interface eth1 -> proxy",
	} {
		if strings.Contains(res, removed) {
			t.Errorf("expected %q to be cleared from config, but it remains:\n%s", removed, res)
		}
	}
}

func TestDeleteRule_Aliases(t *testing.T) {
	initial := `def zone lan eth1
def zone guest eth2
def device tv mac=52:54:00:11:22:33 zone=lan
def group streaming tv

device tv -> proxy
zone guest -> direct
mac 52:54:00:99:99:99 -> block
`
	// Delete device tv by strict MAC+Interface selector
	res1 := DeleteRule(initial, config.GatewayRule{MAC: "52:54:00:11:22:33", Interface: "eth1"})
	if strings.Contains(res1, "device tv -> proxy") {
		t.Fatalf("expected device tv rule to be deleted by MAC+Interface selector:\n%s", res1)
	}
	if !strings.Contains(res1, "zone guest -> direct") {
		t.Fatalf("zone rule should remain:\n%s", res1)
	}

	// Delete zone guest by interface selector
	res2 := DeleteRule(res1, config.GatewayRule{Interface: "eth2"})
	if strings.Contains(res2, "zone guest -> direct") {
		t.Fatalf("expected zone guest rule to be deleted by interface selector:\n%s", res2)
	}
	if !strings.Contains(res2, "mac 52:54:00:99:99:99 -> block") {
		t.Fatalf("mac rule should remain:\n%s", res2)
	}
}

func TestDeleteRule_CatchAllRule(t *testing.T) {
	initial := `def zone lan eth1
local -> direct
rule -> block
mac 52:54:00:11:22:33 -> proxy
`
	// Delete catch-all rule using empty selector
	res := DeleteRule(initial, config.GatewayRule{})
	if strings.Contains(res, "rule -> block") {
		t.Fatalf("expected catch-all 'rule -> block' to be deleted:\n%s", res)
	}
	if !strings.Contains(res, "local -> direct") {
		t.Errorf("local rule should remain:\n%s", res)
	}
	if !strings.Contains(res, "mac 52:54:00:11:22:33 -> proxy") {
		t.Errorf("mac rule should remain:\n%s", res)
	}
}

func TestDeleteRule_NestedAndCircularGroup(t *testing.T) {
	initial := `def zone lan eth1
def device phone mac=52:54:00:11:22:33 zone=lan
def group mobile phone
def group all mobile
def group loop1 loop2
def group loop2 loop1

group all -> proxy
group loop1 -> direct
`
	// Delete nested group rule by strict member MAC+Interface selector
	res := DeleteRule(initial, config.GatewayRule{MAC: "52:54:00:11:22:33", Interface: "eth1"})
	if strings.Contains(res, "group all -> proxy") {
		t.Fatalf("expected nested group rule to be deleted by member MAC+Interface:\n%s", res)
	}
	// Circular group should not hang and loop1 should remain
	if !strings.Contains(res, "group loop1 -> direct") {
		t.Fatalf("loop1 should remain:\n%s", res)
	}
}

func TestDeleteRule_StrictMatchingDoesNotWildcard(t *testing.T) {
	initial := `def zone lan enp1s0
def device dev1 mac=aa:bb:cc:dd:ee:01 zone=lan
def device dev2 mac=aa:bb:cc:dd:ee:02 zone=lan
def group vip dev1, dev2

mac aa:bb:cc:dd:ee:01 -> block interface=enp1s0
group vip -> direct
`
	// Empty Interface selector must not wildcard-delete interface-scoped MAC rule or multi-device group
	res1 := DeleteRule(initial, config.GatewayRule{MAC: "aa:bb:cc:dd:ee:01"})
	if !strings.Contains(res1, "mac aa:bb:cc:dd:ee:01 -> block interface=enp1s0") || !strings.Contains(res1, "group vip -> direct") {
		t.Fatalf("strict DeleteRule unexpectedly deleted rules:\n%s", res1)
	}

	// Strict Interface-only selector must not delete MAC rules on that interface
	res2 := DeleteRule(initial, config.GatewayRule{Interface: "enp1s0"})
	if !strings.Contains(res2, "mac aa:bb:cc:dd:ee:01 -> block interface=enp1s0") || !strings.Contains(res2, "group vip -> direct") {
		t.Fatalf("Interface-only DeleteRule unexpectedly deleted MAC/group rules:\n%s", res2)
	}

	// Exact MAC+Interface selector deletes only the MAC rule, preserving group vip
	res3 := DeleteRule(initial, config.GatewayRule{MAC: "aa:bb:cc:dd:ee:01", Interface: "enp1s0"})
	if strings.Contains(res3, "mac aa:bb:cc:dd:ee:01 -> block interface=enp1s0") {
		t.Fatalf("expected exact MAC+Interface rule to be deleted:\n%s", res3)
	}
	if !strings.Contains(res3, "group vip -> direct") {
		t.Fatalf("group vip must remain intact:\n%s", res3)
	}
}

func TestUpdateGatewayContent_ClearsAndHandlesAliasesAndFailOpen(t *testing.T) {
	initial := `def zone lan eth1
set state proxy
set wan_interface eth0
set nat_disabled false
set tproxy_port 7893
set bypass_countries CN
set dns_servers 1.1.1.1
set fail_open false
local -> direct
`
	gw := &config.GatewayConfig{
		State:       "proxy",
		Mode:        "tproxy",
		WANInterface: "",
		NATDisabled: true,
		TProxyPort:  12345,
		FailOpen:    true,
	}
	updated := updateGatewayContent(initial, gw)
	if !strings.Contains(updated, "set wan_interface auto") {
		t.Errorf("expected wan_interface alias updated to auto:\n%s", updated)
	}
	if !strings.Contains(updated, "set nat_disabled true") {
		t.Errorf("expected nat_disabled inverted to true:\n%s", updated)
	}
	if !strings.Contains(updated, "set tproxy_port 12345") {
		t.Errorf("expected tproxy_port updated to 12345:\n%s", updated)
	}
	if !strings.Contains(updated, "set fail_open true") {
		t.Errorf("expected fail_open updated to true:\n%s", updated)
	}
	if strings.Contains(updated, "bypass_countries") || strings.Contains(updated, "dns_servers") {
		t.Errorf("expected cleared bypass_countries and dns_servers to be removed:\n%s", updated)
	}
}
