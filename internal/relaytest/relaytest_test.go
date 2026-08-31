package relaytest

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderTerminalSimpleSinglePass(t *testing.T) {
	res := &TestResult{
		Alias: "hk-01",
		Mode:  ModeSimple,
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

	out := RenderTerminal([]*TestResult{res})
	expected := "TCP: 28ms | UDP: 32ms\nIPv4: 103.21.244.15 | IPv6: 2400:cb00::1"
	if strings.TrimSpace(out) != expected {
		t.Fatalf("got:\n%s\nwant:\n%s", out, expected)
	}
}

func TestRenderTerminalSimplePartialFail(t *testing.T) {
	res := &TestResult{
		Alias: "hk-01",
		Mode:  ModeSimple,
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

	out := RenderTerminal([]*TestResult{res})
	expected := "TCP: 35ms | UDP: FAIL\nIPv4: 103.21.244.15 | IPv6: FAIL"
	if strings.TrimSpace(out) != expected {
		t.Fatalf("got:\n%s\nwant:\n%s", out, expected)
	}
}

func TestRenderTerminalSimpleTotalFail(t *testing.T) {
	res := &TestResult{
		Alias: "hk-01",
		Mode:  ModeSimple,
		Transport: TransportResult{
			TCPStatus: StatusFail,
			UDPStatus: StatusFail,
		},
		ExitIP: ExitIPResult{
			IPv4Status: StatusFail,
			IPv6Status: StatusFail,
		},
	}

	out := RenderTerminal([]*TestResult{res})
	expected := "TCP: FAIL | UDP: FAIL\nFAIL"
	if strings.TrimSpace(out) != expected {
		t.Fatalf("got:\n%s\nwant:\n%s", out, expected)
	}
}

func TestRenderTerminalFullModeWithWarn(t *testing.T) {
	res := &TestResult{
		Alias: "hk-01",
		Mode:  ModeFull,
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

	out := RenderTerminal([]*TestResult{res})
	expected := "TCP: 28ms | UDP: 32ms\nIPv4: 103.21.244.15 | IPv6: 2400:cb00::1\nModern Web: WARN (52ms) [Failed: HTTP/3, ECH]\nUDP Stack : PASS (32ms)"
	if strings.TrimSpace(out) != expected {
		t.Fatalf("got:\n%s\nwant:\n%s", out, expected)
	}
}

func TestRenderTerminalMultiNodes(t *testing.T) {
	r1 := &TestResult{
		Alias: "hk-01",
		Mode:  ModeSimple,
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
		Alias: "jp-02",
		Mode:  ModeSimple,
		Transport: TransportResult{
			TCPStatus: StatusFail,
			UDPStatus: StatusFail,
		},
		ExitIP: ExitIPResult{
			IPv4Status: StatusFail,
			IPv6Status: StatusFail,
		},
	}

	out := RenderTerminal([]*TestResult{r1, r2})
	expected := "[hk-01]\nTCP: 28ms | UDP: 32ms\nIPv4: 103.21.244.15 | IPv6: FAIL\n\n[jp-02]\nTCP: FAIL | UDP: FAIL\nFAIL"
	if strings.TrimSpace(out) != expected {
		t.Fatalf("got:\n%s\nwant:\n%s", out, expected)
	}
}

func TestRenderJSON(t *testing.T) {
	r := &TestResult{
		Alias: "hk-01",
		Mode:  ModeSimple,
		Transport: TransportResult{
			TCPStatus: StatusPass,
			TCPRTTMs:  28,
			UDPStatus: StatusPass,
			UDPRTTMs:  32,
		},
	}

	jsonStr, err := RenderJSON(r)
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}

	var decoded TestResult
	if err := json.Unmarshal([]byte(jsonStr), &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if decoded.Alias != "hk-01" || decoded.Transport.TCPRTTMs != 28 {
		t.Fatalf("decoded result mismatch: %+v", decoded)
	}
}
