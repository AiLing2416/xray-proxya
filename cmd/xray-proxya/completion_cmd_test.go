package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestTopLevelCompletionRegisteredAndStdoutSupported(t *testing.T) {
	command, _, err := doctorCmd.Find([]string{"completion"})
	if err != nil {
		t.Fatalf("find doctor completion: %v", err)
	}
	if command != doctorCompletionCmd {
		t.Fatalf("doctor completion command = %q, want %q", command.Name(), doctorCompletionCmd.Name())
	}

	topCmd, _, err := rootCmd.Find([]string{"completion"})
	if err != nil {
		t.Fatalf("find top-level completion: %v", err)
	}
	if topCmd != completionCmd {
		t.Fatalf("top-level completion command = %v, want %v", topCmd, completionCmd)
	}

	for _, shell := range []string{"bash", "zsh", "fish"} {
		output := captureStdout(t, func() {
			if err := completionCmd.RunE(completionCmd, []string{shell}); err != nil {
				t.Fatalf("completionCmd error for %s: %v", shell, err)
			}
		})
		if len(output) == 0 || !strings.Contains(output, "xray-proxya") {
			t.Fatalf("expected valid %s completion script, got %d bytes", shell, len(output))
		}
	}

	// Unsupported shell should return error
	if err := completionCmd.RunE(completionCmd, []string{"unsupported-shell"}); err == nil {
		t.Fatal("expected error for unsupported shell")
	}
}

func TestCompletionLayoutForEachSupportedShell(t *testing.T) {
	home := t.TempDir()
	for _, test := range []struct {
		shell, wantFile string
	}{
		{"bash", ".local/share/bash-completion/completions/xray-proxya"},
		{"zsh", ".local/share/zsh/site-functions/_xray-proxya"},
		{"fish", ".config/fish/completions/xray-proxya.fish"},
	} {
		layout, err := completionLayoutFor(test.shell, home)
		if err != nil {
			t.Fatalf("layout for %s: %v", test.shell, err)
		}
		if got := strings.TrimPrefix(layout.file, home+string(filepath.Separator)); got != test.wantFile {
			t.Fatalf("%s file = %q, want %q", test.shell, got, test.wantFile)
		}
	}
}

func TestGenerateCompletionForEachSupportedShell(t *testing.T) {
	home := t.TempDir()
	for _, shell := range []string{"bash", "zsh", "fish"} {
		layout, err := completionLayoutFor(shell, filepath.Join(home, shell))
		if err != nil {
			t.Fatalf("layout for %s: %v", shell, err)
		}
		if err := installCompletion(layout); err != nil {
			t.Fatalf("install %s completion: %v", shell, err)
		}
		script, err := os.ReadFile(layout.file)
		if err != nil {
			t.Fatalf("read %s completion: %v", shell, err)
		}
		if len(script) == 0 || !strings.Contains(string(script), "xray-proxya") {
			t.Fatalf("generated %s completion is invalid", shell)
		}
		if err := uninstallCompletion(layout); err != nil {
			t.Fatalf("uninstall %s completion: %v", shell, err)
		}
	}
}

func TestInstallAndUninstallBashCompletionPreservesUserProfile(t *testing.T) {
	home := t.TempDir()
	previousHome := completionHomeDir
	completionHomeDir = func() string { return home }
	t.Cleanup(func() { completionHomeDir = previousHome })

	layout, err := completionLayoutFor("bash", home)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.profile, []byte("alias ll='ls -la'\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := installCompletion(layout); err != nil {
		t.Fatalf("install completion: %v", err)
	}
	script, err := os.ReadFile(layout.file)
	if err != nil {
		t.Fatalf("read generated completion: %v", err)
	}
	if !strings.Contains(string(script), "doctor") || !strings.Contains(string(script), "completion") {
		t.Fatal("generated bash completion does not include doctor completion commands")
	}
	profile, err := os.ReadFile(layout.profile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(profile), completionStartMarker) || !strings.Contains(string(profile), "/usr/share/bash-completion/bash_completion") || !strings.Contains(string(profile), "alias ll='ls -la'") {
		t.Fatalf("profile missing managed block or user configuration:\n%s", profile)
	}
	if err := uninstallCompletion(layout); err != nil {
		t.Fatalf("uninstall completion: %v", err)
	}
	if _, err := os.Stat(layout.file); !os.IsNotExist(err) {
		t.Fatalf("completion file remains after uninstall: %v", err)
	}
	profile, err = os.ReadFile(layout.profile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(profile), completionStartMarker) || !strings.Contains(string(profile), "alias ll='ls -la'") {
		t.Fatalf("uninstall did not preserve user profile:\n%s", profile)
	}
}

func TestStripLegacyZshCompletionPreservesCompinit(t *testing.T) {
	layout, err := completionLayoutFor("zsh", "/home/test")
	if err != nil {
		t.Fatal(err)
	}
	content := strings.Join([]string{
		"autoload -Uz compinit && compinit",
		"# Xray-Proxya Completion",
		"fpath=(/home/test/.local/share/zsh/site-functions $fpath)",
		"autoload -Uz _xray-proxya",
		"alias ll='ls -la'",
	}, "\n")
	cleaned := stripLegacyCompletionProfile(content, layout)
	if strings.Contains(cleaned, "# Xray-Proxya Completion") || strings.Contains(cleaned, "_xray-proxya") {
		t.Fatalf("legacy completion remains:\n%s", cleaned)
	}
	if !strings.Contains(cleaned, "compinit") || !strings.Contains(cleaned, "alias ll='ls -la'") {
		t.Fatalf("user zsh configuration was removed:\n%s", cleaned)
	}
}

func containsCompletion(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestCLIAutocompletionCoverage(t *testing.T) {
	// 1. Verify doctor subcommands completion
	doctorSubCmds := make(map[string]bool)
	for _, c := range doctorCmd.Commands() {
		doctorSubCmds[c.Name()] = true
	}
	for _, want := range []string{"completion", "linger", "selinux"} {
		if !doctorSubCmds[want] {
			t.Errorf("doctor missing subcommand %q", want)
		}
	}

	// 2. Verify doctor linger subcommands
	lingerSubCmds := make(map[string]bool)
	for _, c := range doctorLingerCmd.Commands() {
		lingerSubCmds[c.Name()] = true
	}
	for _, want := range []string{"enable", "disable"} {
		if !lingerSubCmds[want] {
			t.Errorf("doctor linger missing subcommand %q", want)
		}
	}

	// 3. Verify sub commands have ValidArgsFunction registered
	for _, subCommand := range []*cobra.Command{subSetCmd, subShowCmd, subRunCmd, subValidateCmd} {
		if subCommand.ValidArgsFunction == nil {
			t.Errorf("sub command %q missing ValidArgsFunction for positional arg completion", subCommand.Name())
		}
	}

	// 4. Verify presets set completion
	if presetsSetCmd.ValidArgsFunction == nil {
		t.Error("presets set missing ValidArgsFunction")
	}

	// 5. Verify service commands completion
	for _, action := range []string{"start", "stop", "restart", "status", "enable", "disable"} {
		cmd, _, err := serviceCmd.Find([]string{action})
		if err != nil || cmd.ValidArgsFunction == nil {
			t.Errorf("service command %q missing ValidArgsFunction", action)
		}
	}

	// 6. Verify init command flag completion
	if fn, ok := initCmd.GetFlagCompletionFunc("role"); !ok || fn == nil {
		t.Error("init missing --role completion")
	} else {
		candidates, directive := fn(initCmd, nil, "")
		if directive != cobra.ShellCompDirectiveNoFileComp || !containsCompletion(candidates, "server") || !containsCompletion(candidates, "gateway") {
			t.Errorf("init --role completion unexpected: %v, %v", candidates, directive)
		}
	}

	// 7. Verify path commands completions
	if fn, ok := pathSetCmd.GetFlagCompletionFunc("relay"); !ok || fn == nil {
		t.Error("path set missing --relay completion")
	}
	if fn, ok := pathUnsetCmd.GetFlagCompletionFunc("relay"); !ok || fn == nil {
		t.Error("path unset missing --relay completion")
	}
	for _, pathCmd := range []*cobra.Command{pathPingCmd, pathTraceCmd, pathMTUCmd} {
		if pathCmd.ValidArgsFunction == nil {
			t.Errorf("path command %q missing ValidArgsFunction", pathCmd.Name())
		}
	}

	// 8. Verify guests commands completion
	for _, guestCommand := range []*cobra.Command{
		guestsRemoveCmd, guestsSetCmd, guestsPauseCmd, guestsResumeCmd, guestsInfoCmd,
		guestsSubEnableCmd, guestsSubDisableCmd, guestsSubRotateCmd, guestsSubShowCmd,
	} {
		if guestCommand.ValidArgsFunction == nil {
			t.Errorf("guest command %q missing ValidArgsFunction", guestCommand.Name())
		}
	}
	if fn, ok := guestsSetCmd.GetFlagCompletionFunc("quota"); !ok || fn == nil {
		t.Error("guests set missing --quota completion")
	}

	// 9. Verify proxy commands completion
	for _, proxyCommand := range []*cobra.Command{proxySetCmd, proxyUnsetCmd, proxyRunCmd, proxyTestCmd} {
		if proxyCommand.ValidArgsFunction == nil {
			t.Errorf("proxy command %q missing ValidArgsFunction", proxyCommand.Name())
		}
	}

	// 10. Verify relay/outbound commands completion
	for _, relayCommand := range []*cobra.Command{
		testOutboundCmd, infoOutboundCmd, speedOutboundCmd, removeOutboundCmd,
		bindInterfaceCmd, setDNSRelayCmd, setPrivateTargetsRelayCmd,
		probeLocalOutboundCmd, resolveOutboundCmd,
	} {
		if relayCommand.ValidArgsFunction == nil {
			t.Errorf("relay command %q missing ValidArgsFunction", relayCommand.Name())
		}
	}

	// 11. Verify tune commands completion
	for _, tuneCommand := range []*cobra.Command{tuneDiffCmd, tuneUseCmd, tuneVerifyCmd} {
		if tuneCommand.ValidArgsFunction == nil {
			t.Errorf("tune command %q missing ValidArgsFunction", tuneCommand.Name())
		}
	}

	// 12. Verify gateway set flag completions
	for _, flag := range []string{"relay", "lan", "state", "bypass-countries"} {
		if fn, ok := gatewaySetCmd.GetFlagCompletionFunc(flag); !ok || fn == nil {
			t.Errorf("gateway set missing --%s completion", flag)
		}
	}
}

func TestListenFlagCompletionReturnsIPAddresses(t *testing.T) {
	for _, cmd := range []*cobra.Command{proxySetCmd, proxyRunCmd, subSetCmd} {
		fn, ok := cmd.GetFlagCompletionFunc("listen")
		if !ok || fn == nil {
			t.Fatalf("command %s missing --listen completion", cmd.Name())
		}
		candidates, directive := fn(cmd, nil, "")
		if directive != cobra.ShellCompDirectiveNoFileComp {
			t.Errorf("command %s unexpected directive: %v", cmd.Name(), directive)
		}

		containsIP := func(ip string) bool {
			for _, c := range candidates {
				parts := strings.SplitN(c, "\t", 2)
				if parts[0] == ip {
					return true
				}
			}
			return false
		}

		if !containsIP("127.0.0.1") {
			t.Errorf("command %s candidates missing 127.0.0.1: %v", cmd.Name(), candidates)
		}
		if !containsIP("0.0.0.0") {
			t.Errorf("command %s candidates missing 0.0.0.0: %v", cmd.Name(), candidates)
		}
		for _, c := range candidates {
			parts := strings.SplitN(c, "\t", 2)
			ipStr := parts[0]
			if net.ParseIP(ipStr) == nil {
				t.Errorf("command %s candidate %q is not a valid IP address", cmd.Name(), ipStr)
			}
		}
	}
}
