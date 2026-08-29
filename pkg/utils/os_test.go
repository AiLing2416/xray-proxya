package utils

import (
	"strings"
	"testing"
)

func TestIsRootShellCommand(t *testing.T) {
	valid := []string{
		"/bin/bash",
		"/usr/bin/bash",
		"/bin/sh",
		"/bin/zsh",
		"/usr/bin/zsh -l",
		"/usr/bin/fish",
		"/bin/dash",
		"/bin/ksh",
		"/bin/csh",
		"/bin/tcsh",
		"/usr/bin/nu",
		"/usr/bin/xonsh",
		"/usr/bin/elvish",
		"/bin/su",
		"/usr/bin/su",
		"/usr/bin/su -",
		"/usr/bin/su - root",
	}
	for _, cmd := range valid {
		if !IsRootShellCommand(cmd) {
			t.Errorf("IsRootShellCommand(%q) = false, want true", cmd)
		}
	}

	invalid := []string{
		"",
		"/usr/local/bin/xray-proxya service install",
		"/root/.local/bin/xray-proxya gateway up",
		"/usr/bin/systemctl restart xray-proxya",
		"/usr/bin/python3 script.py",
	}
	for _, cmd := range invalid {
		if IsRootShellCommand(cmd) {
			t.Errorf("IsRootShellCommand(%q) = true, want false", cmd)
		}
	}
}

func TestRequireRootShellFor(t *testing.T) {
	tests := []struct {
		name                           string
		euid                           int
		sudoUser, sudoUID, sudoCommand string
		op                             string
		wantError                      bool
	}{
		{name: "direct root login", euid: 0, wantError: false},
		{name: "non-root user", euid: 1000, wantError: true},
		{name: "sudo -i bash", euid: 0, sudoUser: "ailing", sudoUID: "1000", sudoCommand: "/bin/bash", wantError: false},
		{name: "sudo -i zsh", euid: 0, sudoUser: "ailing", sudoUID: "1000", sudoCommand: "/bin/zsh", wantError: false},
		{name: "sudo su", euid: 0, sudoUser: "ailing", sudoUID: "1000", sudoCommand: "/bin/su", wantError: false},
		{name: "sudo su -", euid: 0, sudoUser: "ailing", sudoUID: "1000", sudoCommand: "/usr/bin/su -", wantError: false},
		{name: "direct sudo single command", euid: 0, sudoUser: "ailing", sudoUID: "1000", sudoCommand: "/root/.local/bin/xray-proxya service install", wantError: true},
		{name: "empty sudo command with sudo user", euid: 0, sudoUser: "ailing", sudoUID: "1000", sudoCommand: "", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RequireRootShellFor(tt.euid, tt.sudoUser, tt.sudoUID, tt.sudoCommand, tt.op)
			if (err != nil) != tt.wantError {
				t.Fatalf("RequireRootShellFor(%d, %q, %q, %q, %q) = %v, wantError=%v", tt.euid, tt.sudoUser, tt.sudoUID, tt.sudoCommand, tt.op, err, tt.wantError)
			}
			if err != nil {
				if !strings.Contains(err.Error(), ColorYellow) || !strings.Contains(err.Error(), ColorReset) {
					t.Errorf("error output %q missing yellow ANSI escape sequences", err.Error())
				}
			}
		})
	}
}

func TestRequireRootOnlyFor(t *testing.T) {
	tests := []struct {
		name      string
		euid      int
		op        string
		wantError bool
	}{
		{name: "root user", euid: 0, op: "tune", wantError: false},
		{name: "non-root user", euid: 1000, op: "tune", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RequireRootOnlyFor(tt.euid, tt.op)
			if (err != nil) != tt.wantError {
				t.Fatalf("RequireRootOnlyFor(%d, %q) = %v, wantError=%v", tt.euid, tt.op, err, tt.wantError)
			}
			if err != nil {
				if !strings.Contains(err.Error(), ColorYellow) || !strings.Contains(err.Error(), ColorReset) {
					t.Errorf("error output %q missing yellow ANSI escape sequences", err.Error())
				}
			}
		})
	}
}
