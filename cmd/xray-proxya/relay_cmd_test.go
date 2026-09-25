package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"xray-proxya/internal/config"
	"xray-proxya/pkg/utils"
)

func TestRelayListInternalHttpPortDisplay(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, ".config", "xray-proxya")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("MkdirAll error: %v", err)
	}

	cfg := &config.UserConfig{
		Role: config.RoleServer,
		CustomOutbounds: []config.CustomOutbound{
			{
				Alias:             "node-custom",
				Enabled:           true,
				InternalProxyPort: 10808,
				InternalHttpPort:  10815,
				Config:            map[string]interface{}{"protocol": "freedom"},
			},
			{
				Alias:             "node-default",
				Enabled:           true,
				InternalProxyPort: 20808,
				InternalHttpPort:  0,
				Config:            map[string]interface{}{"protocol": "freedom"},
			},
		},
	}
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json.staging"), cfgBytes, 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	// 1. Test JSON output
	oldJSON := relayListJSON
	relayListJSON = true
	defer func() { relayListJSON = oldJSON }()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = runListOutbound(listOutboundCmd, []string{})
	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("runListOutbound error: %v", err)
	}

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	var items []RelayListItemJSON
	if err := json.Unmarshal(buf.Bytes(), &items); err != nil {
		t.Fatalf("unmarshal JSON error: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].InternalProxy != "socks:10808 http:10815" {
		t.Errorf("node-custom InternalProxy = %q, want %q", items[0].InternalProxy, "socks:10808 http:10815")
	}
	if items[1].InternalProxy != "socks:20808 http:20809" {
		t.Errorf("node-default InternalProxy = %q, want %q", items[1].InternalProxy, "socks:20808 http:20809")
	}

	// 2. Test Table output
	relayListJSON = false
	r2, w2, _ := os.Pipe()
	os.Stdout = w2

	err = runListOutbound(listOutboundCmd, []string{})
	w2.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("runListOutbound table error: %v", err)
	}
	var buf2 bytes.Buffer
	_, _ = io.Copy(&buf2, r2)
	tableOut := buf2.String()
	if !strings.Contains(tableOut, "socks:10808 http:10815") {
		t.Errorf("table output missing custom port socks:10808 http:10815\noutput:\n%s", tableOut)
	}
	if !strings.Contains(tableOut, "socks:20808 http:20809") {
		t.Errorf("table output missing default fallback socks:20808 http:20809\noutput:\n%s", tableOut)
	}
}

func TestRelayProbeLocalTargetAddress(t *testing.T) {
	testCases := []struct {
		name         string
		co           config.CustomOutbound
		expectedHost string
		expectedS    int
		expectedH    int
	}{
		{
			name: "wildcard listen with custom http",
			co: config.CustomOutbound{
				InternalProxyPort:  10808,
				InternalHttpPort:   10815,
				InternalListenAddr: "0.0.0.0",
			},
			expectedHost: "127.0.0.1",
			expectedS:    10808,
			expectedH:    10815,
		},
		{
			name: "empty listen with default http",
			co: config.CustomOutbound{
				InternalProxyPort:  10808,
				InternalHttpPort:   0,
				InternalListenAddr: "",
			},
			expectedHost: "127.0.0.1",
			expectedS:    10808,
			expectedH:    10809,
		},
		{
			name: "lan IP listen with custom http",
			co: config.CustomOutbound{
				InternalProxyPort:  10810,
				InternalHttpPort:   10820,
				InternalListenAddr: "192.168.1.50",
			},
			expectedHost: "192.168.1.50",
			expectedS:    10810,
			expectedH:    10820,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			listenHost := tc.co.InternalListenAddr
			if listenHost == "" || utils.IsWildcardIP(listenHost) {
				listenHost = "127.0.0.1"
			}
			httpPort := tc.co.InternalHttpPort
			if httpPort <= 0 {
				httpPort = tc.co.InternalProxyPort + 1
			}
			socksTarget := net.JoinHostPort(listenHost, strconv.Itoa(tc.co.InternalProxyPort))
			httpTarget := net.JoinHostPort(listenHost, strconv.Itoa(httpPort))

			expectedSocks := fmt.Sprintf("%s:%d", tc.expectedHost, tc.expectedS)
			expectedHttp := fmt.Sprintf("%s:%d", tc.expectedHost, tc.expectedH)

			if socksTarget != expectedSocks {
				t.Errorf("socksTarget = %q, want %q", socksTarget, expectedSocks)
			}
			if httpTarget != expectedHttp {
				t.Errorf("httpTarget = %q, want %q", httpTarget, expectedHttp)
			}
		})
	}
}
