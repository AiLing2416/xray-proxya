package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestTailLogContent(t *testing.T) {
	content := "line1\nline2\nline3\n"
	got := tailLogContent(content, 2)
	want := "line2\nline3\n"
	if got != want {
		t.Fatalf("tailLogContent() = %q, want %q", got, want)
	}
}

func TestTailLogContentWithoutTrailingNewline(t *testing.T) {
	content := "line1\nline2\nline3"
	got := tailLogContent(content, 1)
	want := "line3"
	if got != want {
		t.Fatalf("tailLogContent() = %q, want %q", got, want)
	}
}

func TestTailLogContentHandlesLargeN(t *testing.T) {
	content := "line1\nline2\n"
	got := tailLogContent(content, 10)
	if got != content {
		t.Fatalf("tailLogContent() = %q, want %q", got, content)
	}
}

func TestServiceLogsCmdRegistrationAndFlags(t *testing.T) {
	// Verify service logs is registered under serviceCmd
	found := false
	for _, cmd := range serviceCmd.Commands() {
		if cmd.Name() == "logs" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected 'logs' subcommand to be registered under serviceCmd")
	}

	// Verify flags on serviceLogsCmd
	for _, cmd := range []*cobra.Command{serviceLogsCmd, logsCmd} {
		fFlag := cmd.Flags().Lookup("follow")
		if fFlag == nil || fFlag.Shorthand != "f" {
			t.Fatalf("expected -f/--follow flag on %s", cmd.Name())
		}
		nFlag := cmd.Flags().Lookup("lines")
		if nFlag == nil || nFlag.Shorthand != "n" || nFlag.DefValue != "40" {
			t.Fatalf("expected -n/--lines flag with default 40 on %s", cmd.Name())
		}
		if cmd.ValidArgsFunction == nil {
			t.Fatalf("expected ValidArgsFunction on %s", cmd.Name())
		}
	}
}

func TestLogsInvalidUnit(t *testing.T) {
	if err := serviceLogsCmd.RunE(serviceLogsCmd, []string{"nonexistent-unit"}); err == nil {
		t.Fatal("expected error for nonexistent unit in serviceLogsCmd")
	}
	if err := logsCmd.RunE(logsCmd, []string{"nonexistent-unit"}); err == nil {
		t.Fatal("expected error for nonexistent unit in logsCmd")
	}
}

func TestServiceLogsCompletion(t *testing.T) {
	completions, directive := serviceLogsCmd.ValidArgsFunction(serviceLogsCmd, nil, "")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("expected NoFileComp, got %v", directive)
	}
	for _, wantPrefix := range []string{"core\t", "sub\t", "pathd\t"} {
		matched := false
		for _, c := range completions {
			if strings.HasPrefix(c, wantPrefix) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("expected completion with prefix %q in %v", wantPrefix, completions)
		}
	}
}
