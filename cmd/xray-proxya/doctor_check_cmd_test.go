package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"xray-proxya/internal/doctor"
)

func TestDoctorCheckCmd_Registration(t *testing.T) {
	command, _, err := doctorCmd.Find([]string{"check"})
	if err != nil {
		t.Fatalf("find doctor check: %v", err)
	}
	if command != doctorCheckCmd {
		t.Fatalf("doctor check command = %q, want %q", command.Name(), doctorCheckCmd.Name())
	}
}

func TestDoctorCheckCmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"doctor", "check", "--help"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("help failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "health diagnostics") {
		t.Errorf("expected help output to mention health diagnostics, got: %s", out)
	}
}

func TestDoctorCheckCmd_JSONOutput(t *testing.T) {
	buf := new(bytes.Buffer)
	doctorCheckJSON = true
	doctorCheckRole = "server"
	doctorCheckTimeoutS = 5

	doctorCheckCmd.SetOut(buf)
	doctorCheckCmd.SetErr(buf)

	_ = doctorCheckCmd.RunE(doctorCheckCmd, []string{})

	out := buf.String()
	var report doctor.Report
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("Failed to parse JSON output: %v (output was: %s)", err, out)
	}

	if report.Role != "server" {
		t.Errorf("expected role 'server', got %s", report.Role)
	}
	if report.Summary.Total == 0 {
		t.Errorf("expected diagnostic results in report, got 0")
	}

	// Reset flags
	doctorCheckJSON = false
	doctorCheckRole = ""
	doctorCheckTimeoutS = 12
}
