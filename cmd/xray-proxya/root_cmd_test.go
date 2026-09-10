package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootVersionFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"flag --version", []string{"--version"}},
		{"shorthand flag -v", []string{"-v"}},
		{"subcommand version", []string{"version"}},
	}

	expectedPrefix := "Xray-Proxya v" + Version

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			rootCmd.SetOut(buf)
			rootCmd.SetErr(buf)
			rootCmd.SetArgs(tt.args)

			err := rootCmd.Execute()
			if err != nil {
				t.Fatalf("rootCmd.Execute() with %v returned error: %v", tt.args, err)
			}

			out := strings.TrimSpace(buf.String())
			if !strings.HasPrefix(out, expectedPrefix) {
				t.Fatalf("expected output prefix %q, got %q", expectedPrefix, out)
			}
		})
	}
}
