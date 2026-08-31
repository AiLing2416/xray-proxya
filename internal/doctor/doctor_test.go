package doctor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"xray-proxya/internal/config"
)

func TestSummaryCalculation(t *testing.T) {
	report := &Report{
		Results: []CheckResult{
			{Status: StatusPass},
			{Status: StatusPass},
			{Status: StatusWarn},
			{Status: StatusSkip},
			{Status: StatusFail},
		},
	}
	calculateSummary(report)

	if report.Summary.Total != 5 {
		t.Errorf("expected total 5, got %d", report.Summary.Total)
	}
	if report.Summary.Passed != 2 {
		t.Errorf("expected passed 2, got %d", report.Summary.Passed)
	}
	if report.Summary.Warning != 1 {
		t.Errorf("expected warning 1, got %d", report.Summary.Warning)
	}
	if report.Summary.Skipped != 1 {
		t.Errorf("expected skipped 1, got %d", report.Summary.Skipped)
	}
	if report.Summary.Failed != 1 {
		t.Errorf("expected failed 1, got %d", report.Summary.Failed)
	}
	if report.Summary.Healthy {
		t.Errorf("expected healthy false when failed > 0")
	}
}

func TestRenderTerminal(t *testing.T) {
	report := &Report{
		Role: "server",
		Results: []CheckResult{
			{
				Category: "Core & Assets",
				Name:     "Xray Binary & Version",
				Status:   StatusPass,
				Detail:   "v26.3.27 (matches pinned)",
			},
			{
				Category: "Kernel Capabilities",
				Name:     "Gateway Modules",
				Status:   StatusSkip,
				Detail:   "Not required for Server role",
			},
			{
				Category:    "Port Bindings",
				Name:        "Preset Port (443)",
				Status:      StatusFail,
				Detail:      "Occupied by nginx",
				Remediation: "Stop nginx",
			},
		},
	}
	calculateSummary(report)

	out := RenderTerminal(report, false)
	if !strings.Contains(out, "PASS") || !strings.Contains(out, "SKIP") || !strings.Contains(out, "FAIL") {
		t.Errorf("terminal output missing status labels: %s", out)
	}
	if strings.Contains(out, "[PASS]") || strings.Contains(out, "[SKIP]") {
		t.Errorf("terminal output should not contain brackets around statuses: %s", out)
	}
	if !strings.Contains(out, "Fix: Stop nginx") {
		t.Errorf("terminal output should contain remediation for failures: %s", out)
	}
}

func TestRenderJSON(t *testing.T) {
	report := &Report{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Role:      "server",
		Results: []CheckResult{
			{
				Category: "Core & Assets",
				Name:     "Xray Binary",
				Status:   StatusPass,
				Detail:   "installed",
			},
		},
	}
	calculateSummary(report)

	jsonStr, err := RenderJSON(report)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	var parsed Report
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("Failed to parse rendered JSON: %v", err)
	}

	if parsed.Summary.Passed != 1 || parsed.Role != "server" {
		t.Errorf("Unexpected parsed JSON content: %+v", parsed)
	}
}

func TestCheckPortConflicts_NilConfig(t *testing.T) {
	results := CheckPortConflicts(context.Background(), nil)
	if len(results) == 0 {
		t.Fatalf("expected at least 1 result for nil config")
	}
	if results[0].Status != StatusPass {
		t.Errorf("expected StatusPass for nil config, got %s", results[0].Status)
	}
}

func TestCheckKernel_ServerRole(t *testing.T) {
	results := CheckKernel(context.Background(), config.RoleServer)
	hasGatewaySkip := false
	hasIPFwdSkip := false

	for _, r := range results {
		if r.Name == "Gateway Network Modules" && r.Status == StatusSkip {
			hasGatewaySkip = true
		}
		if r.Name == "IPv4 Forwarding" && r.Status == StatusSkip {
			hasIPFwdSkip = true
		}
	}

	if !hasGatewaySkip {
		t.Errorf("expected Gateway Network Modules to be SKIP on Server role")
	}
	if !hasIPFwdSkip {
		t.Errorf("expected IPv4 Forwarding to be SKIP on Server role")
	}
}

func TestCheckUDPCapabilities_NonServer(t *testing.T) {
	result := CheckUDPCapabilities(context.Background(), config.RoleGateway)
	if result.Status != StatusSkip {
		t.Errorf("expected UDP check to be SKIP on Gateway role, got %s", result.Status)
	}
}

func TestCheckModernProtocols_NonServer(t *testing.T) {
	result := CheckModernProtocols(context.Background(), config.RoleGateway)
	if result.Status != StatusSkip {
		t.Errorf("expected Modern Protocols check to be SKIP on Gateway role, got %s", result.Status)
	}
}
