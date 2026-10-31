package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"xray-proxya/internal/config"
	"xray-proxya/internal/gatewayconf"

	"github.com/spf13/pflag"
)

func TestGatewayDNSStatusTextAndJSON(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:        "tproxy",
			State:       "proxy",
			DNSListen:   ":53",
			DNSStrategy: "UseIPv4",
			DNSServers:  []string{"1.1.1.1", "8.8.8.8"},
			DNSRecords: map[string][]string{
				"router.lan": {"10.0.82.1"},
			},
		},
	}
	if err := cfg.SaveEx(false); err != nil {
		t.Fatalf("SaveEx(false) failed: %v", err)
	}
	if err := cfg.SaveEx(true); err != nil {
		t.Fatalf("SaveEx(true) failed: %v", err)
	}

	// 1. Text output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	gatewayDNSStatusJSON = false
	err := gatewayDNSStatusCmd.RunE(gatewayDNSStatusCmd, []string{})

	_ = w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("gatewayDNSStatusCmd failed: %v", err)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	textOutput := buf.String()

	if !strings.Contains(textOutput, "GATEWAY DNS CONFIGURATION") {
		t.Errorf("expected header, got:\n%s", textOutput)
	}
	if !strings.Contains(textOutput, "Listen:      :53") {
		t.Errorf("expected listen :53, got:\n%s", textOutput)
	}
	if !strings.Contains(textOutput, "Strategy:    UseIPv4") {
		t.Errorf("expected strategy UseIPv4, got:\n%s", textOutput)
	}
	if !strings.Contains(textOutput, "router.lan") {
		t.Errorf("expected router.lan record, got:\n%s", textOutput)
	}

	// 2. JSON output
	r, w, _ = os.Pipe()
	os.Stdout = w

	gatewayDNSStatusJSON = true
	err = gatewayDNSStatusCmd.RunE(gatewayDNSStatusCmd, []string{})

	_ = w.Close()
	os.Stdout = oldStdout
	gatewayDNSStatusJSON = false

	if err != nil {
		t.Fatalf("gatewayDNSStatusCmd JSON failed: %v", err)
	}

	buf.Reset()
	_, _ = io.Copy(&buf, r)
	jsonOutput := buf.String()

	if !strings.Contains(jsonOutput, `"listen": ":53"`) || !strings.Contains(jsonOutput, `"strategy": "UseIPv4"`) {
		t.Errorf("expected valid JSON with listen and strategy, got:\n%s", jsonOutput)
	}
}

func TestGatewayDNSSetFlags(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:  "tproxy",
			State: "proxy",
		},
	}
	_ = cfg.SaveEx(false)
	_ = cfg.SaveEx(true)

	resetFlags := func() {
		gatewayDNSSetCmd.Flags().VisitAll(func(f *pflag.Flag) {
			f.Changed = false
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		})
		dnsSetListen = ""
		dnsSetPort = 0
		dnsSetOff = false
		dnsSetServers = nil
		dnsSetStrategy = ""
		dnsSetReset = false
	}

	// Case 1: No flags specified -> error
	resetFlags()
	err := gatewayDNSSetCmd.RunE(gatewayDNSSetCmd, []string{})
	if err == nil {
		t.Fatal("expected error when no flags changed")
	}

	// Case 2: Set listen and strategy
	resetFlags()
	if err := gatewayDNSSetCmd.ParseFlags([]string{"--listen", ":53", "--strategy", "useipv4", "--servers", "1.1.1.1,tcp://8.8.8.8:53"}); err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}
	if err := gatewayDNSSetCmd.RunE(gatewayDNSSetCmd, []string{}); err != nil {
		t.Fatalf("runGatewayDNSSet failed: %v", err)
	}

	loaded, err := config.LoadConfigEx(true)
	if err != nil {
		t.Fatalf("LoadConfigEx failed: %v", err)
	}
	if loaded.Gateway.DNSListen != ":53" {
		t.Errorf("DNSListen = %q, want :53", loaded.Gateway.DNSListen)
	}
	if loaded.Gateway.DNSStrategy != "UseIPv4" {
		t.Errorf("DNSStrategy = %q, want UseIPv4", loaded.Gateway.DNSStrategy)
	}
	if len(loaded.Gateway.DNSServers) != 2 || loaded.Gateway.DNSServers[0] != "1.1.1.1" || loaded.Gateway.DNSServers[1] != "tcp://8.8.8.8:53" {
		t.Errorf("DNSServers = %v, want [1.1.1.1, tcp://8.8.8.8:53]", loaded.Gateway.DNSServers)
	}

	// Case 3: Set port updates existing listen
	resetFlags()
	if err := gatewayDNSSetCmd.ParseFlags([]string{"--port", "5353"}); err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}
	if err := gatewayDNSSetCmd.RunE(gatewayDNSSetCmd, []string{}); err != nil {
		t.Fatalf("runGatewayDNSSet with port failed: %v", err)
	}
	loaded, _ = config.LoadConfigEx(true)
	if loaded.Gateway.DNSListen != ":5353" {
		t.Errorf("DNSListen = %q, want :5353", loaded.Gateway.DNSListen)
	}

	// Case 4: --off disables listener
	resetFlags()
	if err := gatewayDNSSetCmd.ParseFlags([]string{"--off"}); err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}
	if err := gatewayDNSSetCmd.RunE(gatewayDNSSetCmd, []string{}); err != nil {
		t.Fatalf("runGatewayDNSSet with --off failed: %v", err)
	}
	loaded, _ = config.LoadConfigEx(true)
	if loaded.Gateway.DNSListen != "" {
		t.Errorf("DNSListen = %q, want empty after --off", loaded.Gateway.DNSListen)
	}

	// Case 5: --reset resets all
	resetFlags()
	if err := gatewayDNSSetCmd.ParseFlags([]string{"--reset"}); err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}
	if err := gatewayDNSSetCmd.RunE(gatewayDNSSetCmd, []string{}); err != nil {
		t.Fatalf("runGatewayDNSSet with --reset failed: %v", err)
	}
	loaded, _ = config.LoadConfigEx(true)
	if loaded.Gateway.DNSListen != "" || loaded.Gateway.DNSStrategy != "" || len(loaded.Gateway.DNSServers) > 0 {
		t.Errorf("expected clean reset, got: %+v", loaded.Gateway)
	}
}

func TestGatewayDNSRecordCommands(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:  "tproxy",
			State: "proxy",
		},
	}
	_ = cfg.SaveEx(true)

	// 1. Record set
	if err := gatewayDNSRecordSetCmd.RunE(gatewayDNSRecordSetCmd, []string{"router.lan", "10.0.82.1", "fd00:82::1"}); err != nil {
		t.Fatalf("record set failed: %v", err)
	}

	loaded, _ := config.LoadConfigEx(true)
	ips, ok := loaded.Gateway.DNSRecords["router.lan"]
	if !ok || len(ips) != 2 || ips[0] != "10.0.82.1" || ips[1] != "fd00:82::1" {
		t.Fatalf("record set failed, got: %v", ips)
	}

	// 2. Record list
	if err := gatewayDNSRecordListCmd.RunE(gatewayDNSRecordListCmd, []string{}); err != nil {
		t.Fatalf("record list failed: %v", err)
	}

	// 3. Completion test
	comps, directive := completeDNSRecordDomains(gatewayDNSRecordDelCmd, []string{}, "route")
	if len(comps) != 1 || comps[0] != "router.lan" {
		t.Errorf("completion = %v, want [router.lan]", comps)
	}
	if directive != 4 { // cobra.ShellCompDirectiveNoFileComp = 4
		t.Errorf("directive = %v, want ShellCompDirectiveNoFileComp", directive)
	}

	// 4. Record del
	if err := gatewayDNSRecordDelCmd.RunE(gatewayDNSRecordDelCmd, []string{"router.lan"}); err != nil {
		t.Fatalf("record del failed: %v", err)
	}
	loaded, _ = config.LoadConfigEx(true)
	if _, ok := loaded.Gateway.DNSRecords["router.lan"]; ok {
		t.Fatal("expected router.lan to be deleted")
	}

	// Record del nonexistent
	if err := gatewayDNSRecordDelCmd.RunE(gatewayDNSRecordDelCmd, []string{"nonexistent.lan"}); err == nil {
		t.Fatal("expected error deleting nonexistent domain")
	}

	// 5. Record clear
	_ = gatewayDNSRecordSetCmd.RunE(gatewayDNSRecordSetCmd, []string{"a.lan", "10.0.82.1"})
	_ = gatewayDNSRecordSetCmd.RunE(gatewayDNSRecordSetCmd, []string{"b.lan", "10.0.82.2"})
	if err := gatewayDNSRecordClearCmd.RunE(gatewayDNSRecordClearCmd, []string{}); err != nil {
		t.Fatalf("record clear failed: %v", err)
	}
	loaded, _ = config.LoadConfigEx(true)
	if len(loaded.Gateway.DNSRecords) != 0 {
		t.Fatalf("expected empty records after clear, got %d", len(loaded.Gateway.DNSRecords))
	}
}

func TestGatewayDNSRecordDirectFlags(t *testing.T) {
	setupTestConfigDir(t)

	cfg := &config.UserConfig{
		Role: config.RoleGateway,
		Gateway: config.GatewayConfig{
			Mode:  "tproxy",
			State: "proxy",
		},
	}
	_ = cfg.SaveEx(true)

	// 1. Direct record add: gateway dns --record-add admin.lan 10.0.1.1
	resetCmdFlags(gatewayDNSCmd)
	dnsRecordAddSlice = nil
	if err := gatewayDNSCmd.ParseFlags([]string{"--record-add", "admin.lan", "10.0.1.1,10.0.1.2"}); err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}
	err := runGatewayDNS(gatewayDNSCmd, gatewayDNSCmd.Flags().Args())
	if err != nil {
		t.Fatalf("runGatewayDNS --record-add failed: %v", err)
	}

	loaded, _ := config.LoadConfigEx(true)
	if ips, ok := loaded.Gateway.DNSRecords["admin.lan"]; !ok || len(ips) != 2 || ips[0] != "10.0.1.1" {
		t.Fatalf("expected admin.lan -> [10.0.1.1 10.0.1.2], got: %v", ips)
	}

	// 2. Direct record del: gateway dns --record-del admin.lan
	resetCmdFlags(gatewayDNSCmd)
	if err := gatewayDNSCmd.ParseFlags([]string{"--record-del", "admin.lan"}); err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}
	err = runGatewayDNS(gatewayDNSCmd, []string{})
	if err != nil {
		t.Fatalf("runGatewayDNS --record-del failed: %v", err)
	}

	loaded, _ = config.LoadConfigEx(true)
	if _, ok := loaded.Gateway.DNSRecords["admin.lan"]; ok {
		t.Fatal("expected admin.lan to be deleted")
	}

	// 3. Direct record clear: gateway dns --record-clear
	_ = gatewayconf.ModifyGatewayConf(func(content string) string {
		content = gatewayconf.UpdateDNSRecord(content, "x.lan", []string{"1.1.1.1"})
		return gatewayconf.UpdateDNSRecord(content, "y.lan", []string{"2.2.2.2"})
	})
	resetCmdFlags(gatewayDNSCmd)
	if err := gatewayDNSCmd.ParseFlags([]string{"--record-clear"}); err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}
	err = runGatewayDNS(gatewayDNSCmd, []string{})
	if err != nil {
		t.Fatalf("runGatewayDNS --record-clear failed: %v", err)
	}

	loaded, _ = config.LoadConfigEx(true)
	if len(loaded.Gateway.DNSRecords) != 0 {
		t.Fatalf("expected 0 dns records, got %d", len(loaded.Gateway.DNSRecords))
	}
}
