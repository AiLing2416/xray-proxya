package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDoctorLingerCommandStructure(t *testing.T) {
	command, _, err := doctorCmd.Find([]string{"linger"})
	if err != nil {
		t.Fatalf("find doctor linger: %v", err)
	}
	if command != doctorLingerCmd {
		t.Fatalf("doctor linger command = %q, want %q", command.Name(), doctorLingerCmd.Name())
	}

	enableCmd, _, err := doctorCmd.Find([]string{"linger", "enable"})
	if err != nil {
		t.Fatalf("find doctor linger enable: %v", err)
	}
	if enableCmd != doctorLingerEnableCmd {
		t.Fatalf("doctor linger enable command = %q, want %q", enableCmd.Name(), doctorLingerEnableCmd.Name())
	}

	disableCmd, _, err := doctorCmd.Find([]string{"linger", "disable"})
	if err != nil {
		t.Fatalf("find doctor linger disable: %v", err)
	}
	if disableCmd != doctorLingerDisableCmd {
		t.Fatalf("doctor linger disable command = %q, want %q", disableCmd.Name(), doctorLingerDisableCmd.Name())
	}
}

func TestParseLingerOutput(t *testing.T) {
	tests := []struct {
		input       string
		wantEnabled bool
		wantOk      bool
	}{
		{"Linger=yes\n", true, true},
		{"Linger=no\n", false, true},
		{"Id=1000\nName=ailing\nLinger=yes\nState=active\n", true, true},
		{"Id=1000\nName=ailing\nLinger=no\nState=active\n", false, true},
		{"UnknownOutput\n", false, false},
		{"", false, false},
	}

	for _, tc := range tests {
		gotEnabled, gotOk := parseLingerOutput(tc.input)
		if gotEnabled != tc.wantEnabled || gotOk != tc.wantOk {
			t.Errorf("parseLingerOutput(%q) = (%v, %v), want (%v, %v)", tc.input, gotEnabled, gotOk, tc.wantEnabled, tc.wantOk)
		}
	}
}

func TestDoctorLingerOutputFormatting(t *testing.T) {
	buf := new(bytes.Buffer)
	doctorLingerCmd.SetOut(buf)

	// Test executing doctor linger (will query current system or fallback)
	err := doctorLingerCmd.RunE(doctorLingerCmd, nil)
	if err != nil {
		t.Fatalf("doctor linger failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "User lingering is") {
		t.Fatalf("expected linger status output, got: %q", out)
	}
}
