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
