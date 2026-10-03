package relaytest

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderTerminalSimpleSinglePass(t *testing.T) {
	res := &TestResult{
		Alias:  "hk-01",
		Mode:   ModeSimple,
		Status: StatusPass,
		Transport: TransportResult{
			TCPStatus: StatusPass,
			TCPRTTMs:  28,
			UDPStatus: StatusPass,
			UDPRTTMs:  32,
		},
		ExitIP: ExitIPResult{
			IPv4:       "103.21.244.15",
			IPv6:       "2400:cb00::1",
			IPv4Status: StatusPass,
			IPv6Status: StatusPass,
		},
	}

	out := RenderTerminalStyled([]*TestResult{res}, false)
	if !strings.Contains(out, "[hk-01] (Mode: Simple)") {
		t.Errorf("missing header in single card:\n%s", out)
	}
	if !strings.Contains(out, "Transport : TCP: 28ms | UDP: 32ms") {
		t.Errorf("missing transport in single card:\n%s", out)
	}
	if !strings.Contains(out, "Exit IP   : IPv4: 103.21.244.15 | IPv6: 2400:cb00::1") {
		t.Errorf("missing exit ip in single card:\n%s", out)
	}
	if !strings.Contains(out, "Status    : PASS") {
		t.Errorf("missing status in single card:\n%s", out)
	}
}

func TestRenderTerminalSimplePartialFail(t *testing.T) {
	res := &TestResult{
		Alias:  "hk-01",
		Mode:   ModeSimple,
		Status: StatusWarn,
		Transport: TransportResult{
			TCPStatus: StatusPass,
			TCPRTTMs:  35,
			UDPStatus: StatusFail,
		},
		ExitIP: ExitIPResult{
			IPv4:       "103.21.244.15",
			IPv4Status: StatusPass,
			IPv6Status: StatusFail,
		},
	}

	out := RenderTerminalStyled([]*TestResult{res}, false)
	if !strings.Contains(out, "Transport : TCP: 35ms | UDP: FAIL") {
		t.Errorf("unexpected transport:\n%s", out)
	}
	if !strings.Contains(out, "Exit IP   : IPv4: 103.21.244.15 | IPv6: FAIL") {
		t.Errorf("unexpected exit ip:\n%s", out)
	}
	if !strings.Contains(out, "Status    : WARN") {
		t.Errorf("unexpected status:\n%s", out)
	}
}

func TestRenderTerminalSimpleTotalFail(t *testing.T) {
	res := &TestResult{
		Alias:  "hk-01",
		Mode:   ModeSimple,
		Status: StatusFail,
		Error:  "dial tcp: i/o timeout",
		Transport: TransportResult{
			TCPStatus: StatusFail,
			UDPStatus: StatusFail,
		},
		ExitIP: ExitIPResult{
			IPv4Status: StatusFail,
			IPv6Status: StatusFail,
		},
	}

	out := RenderTerminalStyled([]*TestResult{res}, false)
	if !strings.Contains(out, "[hk-01] (Mode: Simple)") {
		t.Errorf("missing alias in card:\n%s", out)
	}
	if !strings.Contains(out, "FAIL: dial tcp: i/o timeout") {
		t.Errorf("missing fail error in card:\n%s", out)
	}
}

func TestRenderTerminalFullModeWithWarn(t *testing.T) {
	res := &TestResult{
		Alias:  "hk-01",
		Mode:   ModeFull,
		Status: StatusWarn,
		Transport: TransportResult{
			TCPStatus: StatusPass,
			TCPRTTMs:  28,
			UDPStatus: StatusPass,
			UDPRTTMs:  32,
		},
		ExitIP: ExitIPResult{
			IPv4:       "103.21.244.15",
			IPv6:       "2400:cb00::1",
			IPv4Status: StatusPass,
			IPv6Status: StatusPass,
		},
		ModernProtocols: &CategoryResult{
			Status:      StatusWarn,
			MaxRTTMs:    52,
			FailedItems: []string{"HTTP/3", "ECH"},
		},
		UDPCapabilities: &CategoryResult{
			Status:   StatusPass,
			MaxRTTMs: 32,
		},
	}

	out := RenderTerminalStyled([]*TestResult{res}, false)
	if !strings.Contains(out, "[hk-01] (Mode: Full Diagnostics)") {
		t.Errorf("missing full mode header:\n%s", out)
	}
	if !strings.Contains(out, "Modern Web: WARN (52ms) [Failed: HTTP/3, ECH]") {
		t.Errorf("missing modern web in card:\n%s", out)
	}
	if !strings.Contains(out, "UDP Stack : PASS (32ms)") {
		t.Errorf("missing udp stack in card:\n%s", out)
	}
}

func TestRenderTerminalMultiNodes(t *testing.T) {
	r1 := &TestResult{
		Alias:  "hk-01",
		Mode:   ModeSimple,
		Status: StatusWarn,
		Transport: TransportResult{
			TCPStatus: StatusPass,
			TCPRTTMs:  28,
			UDPStatus: StatusPass,
			UDPRTTMs:  32,
		},
		ExitIP: ExitIPResult{
			IPv4:       "103.21.244.15",
			IPv4Status: StatusPass,
			IPv6Status: StatusFail,
		},
	}
	r2 := &TestResult{
		Alias:  "jp-02",
		Mode:   ModeSimple,
		Status: StatusFail,
		Error:  "connection refused",
		Transport: TransportResult{
			TCPStatus: StatusFail,
			UDPStatus: StatusFail,
		},
		ExitIP: ExitIPResult{
			IPv4Status: StatusFail,
			IPv6Status: StatusFail,
		},
	}

	out := RenderTerminalStyled([]*TestResult{r1, r2}, false)
	if !strings.Contains(out, "ALIAS") || !strings.Contains(out, "STATUS") {
		t.Errorf("missing table headers in multi-node output:\n%s", out)
	}
	if !strings.Contains(out, "hk-01") || !strings.Contains(out, "103.21.244.15") {
		t.Errorf("missing row 1 data in table:\n%s", out)
	}
	if !strings.Contains(out, "jp-02") || !strings.Contains(out, "connection refused") {
		t.Errorf("missing row 2 spanned failure in table:\n%s", out)
	}
}

func TestRenderJSON(t *testing.T) {
	r := &TestResult{
		Alias: "hk-01",
		Mode:  ModeSimple,
	}

	out, err := RenderJSON(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var res TestResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}
	if res.Alias != "hk-01" {
		t.Errorf("alias mismatch, got %s", res.Alias)
	}
}
