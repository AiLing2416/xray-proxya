package pathd

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRunCLIMissingServeArg(t *testing.T) {
	var stderr bytes.Buffer
	code := RunCLICustom([]string{}, nil, &stderr, nil)
	if code != 2 {
		t.Fatalf("expected code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "usage: xray-proxya-pathd serve") {
		t.Fatalf("unexpected stderr output: %s", stderr.String())
	}

	stderr.Reset()
	code = RunCLICustom([]string{"invalid"}, nil, &stderr, nil)
	if code != 2 {
		t.Fatalf("expected code 2 for invalid subcommand, got %d", code)
	}
}

func TestRunCLIInvalidFlags(t *testing.T) {
	var stderr bytes.Buffer
	code := RunCLICustom([]string{"serve", "--invalid-unknown-flag"}, nil, &stderr, nil)
	if code != 2 {
		t.Fatalf("expected code 2 for unknown flag, got %d", code)
	}
}

func TestRunCLIMissingConfigFile(t *testing.T) {
	var stderr bytes.Buffer
	code := RunCLICustom([]string{"serve", "--config", "/nonexistent/path/to/missing.json"}, nil, &stderr, nil)
	if code != 1 {
		t.Fatalf("expected code 1 for missing config file, got %d", code)
	}
	if !strings.Contains(stderr.String(), "pathd config:") {
		t.Fatalf("unexpected stderr output: %s", stderr.String())
	}
}

func TestRunCLIInvalidJSONConfig(t *testing.T) {
	tmpDir := t.TempDir()
	badConfig := filepath.Join(tmpDir, "bad.json")
	if err := os.WriteFile(badConfig, []byte("{not-valid-json"), 0600); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	code := RunCLICustom([]string{"serve", "--config", badConfig}, nil, &stderr, nil)
	if code != 1 {
		t.Fatalf("expected code 1 for invalid JSON, got %d", code)
	}
	if !strings.Contains(stderr.String(), "pathd config:") {
		t.Fatalf("unexpected stderr output: %s", stderr.String())
	}
}

func TestRunCLINonLoopbackAddress(t *testing.T) {
	var stderr bytes.Buffer
	code := RunCLICustom([]string{"serve", "--listen", "192.168.1.1:2828", "--token", "secret"}, nil, &stderr, nil)
	if code != 1 {
		t.Fatalf("expected code 1 for non-loopback listen address, got %d", code)
	}
	if !strings.Contains(stderr.String(), "pathd:") {
		t.Fatalf("unexpected stderr output: %s", stderr.String())
	}
}

func TestRunCLISuccessfulLifecycleWithMockListener(t *testing.T) {
	origListen := listenFunc
	defer func() { listenFunc = origListen }()

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "pathd.json")
	cfgContent := `{"listen":"127.0.0.1:2828","token":"mocktoken","idle_seconds":15}`
	if err := os.WriteFile(configFile, []byte(cfgContent), 0600); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create tcp listener: %v", err)
	}

	mockServer := &Server{
		listener:    listener,
		token:       "mocktoken",
		idle:        15 * time.Second,
		inFlight:    make(chan struct{}, maxGlobalInFlight),
		connections: make(chan struct{}, maxConnections),
		closed:      make(chan struct{}),
	}

	var capturedListen string
	var capturedToken string
	var capturedIdle time.Duration
	listenFunc = func(address, token string, idle time.Duration) (*Server, error) {
		capturedListen = address
		capturedToken = token
		capturedIdle = idle
		return mockServer, nil
	}

	var stdout, stderr bytes.Buffer
	stopCh := make(chan struct{})

	var wg sync.WaitGroup
	var exitCode int
	wg.Add(1)
	go func() {
		defer wg.Done()
		exitCode = RunCLICustom([]string{"serve", "--config", configFile}, &stdout, &stderr, stopCh)
	}()

	time.Sleep(50 * time.Millisecond)

	if capturedListen != "127.0.0.1:2828" {
		t.Errorf("expected listen 127.0.0.1:2828, got %s", capturedListen)
	}
	if capturedToken != "mocktoken" {
		t.Errorf("expected token mocktoken, got %s", capturedToken)
	}
	if capturedIdle != 15*time.Second {
		t.Errorf("expected idle 15s, got %v", capturedIdle)
	}

	close(stopCh)
	wg.Wait()

	if exitCode != 0 {
		t.Fatalf("expected exit code 0 on graceful shutdown, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "pathd listening on") {
		t.Errorf("expected stdout to announce listener, got: %s", stdout.String())
	}
}
