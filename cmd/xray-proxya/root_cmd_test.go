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
		{"subcommand version verbose", []string{"version", "--verbose"}},
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

func TestRootHelpShorthandDisabled(t *testing.T) {
	t.Run("long_help_works", func(t *testing.T) {
		buf := new(bytes.Buffer)
		rootCmd.SetOut(buf)
		rootCmd.SetErr(buf)
		rootCmd.SetArgs([]string{"--help"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("expected --help to succeed, got error: %v", err)
		}
		if !strings.Contains(buf.String(), "Usage:") {
			t.Errorf("expected Usage in --help output, got: %q", buf.String())
		}
	})

	t.Run("short_h_not_occupied_globally", func(t *testing.T) {
		if rootCmd.PersistentFlags().ShorthandLookup("h") != nil {
			t.Fatalf("expected rootCmd PersistentFlags not to occupy -h shorthand")
		}
		if rootCmd.Flags().ShorthandLookup("h") != nil {
			t.Fatalf("expected rootCmd Flags not to occupy -h shorthand")
		}
		if f := endpointSetCmd.Flags().ShorthandLookup("h"); f == nil || f.Name != "host" {
			t.Fatalf("expected endpointSetCmd -h to bind to --host, got %+v", f)
		}
	})
}
