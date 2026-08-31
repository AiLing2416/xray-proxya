package relaytest

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"
)

// TestSession represents an isolated, running temporary Xray test proxy instance.
type TestSession struct {
	Alias      string
	SOCKSAddr  string
	Dialer     *utils.SOCKS5Dialer
	HTTPClient *http.Client

	cleanupOnce sync.Once
	cleanupFunc func()
}

// Close terminates and cleans up the temporary Xray instance and resources.
func (s *TestSession) Close() {
	if s == nil {
		return
	}
	s.cleanupOnce.Do(func() {
		if s.cleanupFunc != nil {
			s.cleanupFunc()
		}
	})
}

// StartTestSession spins up an isolated temporary Xray instance for the given relay outbound.
func StartTestSession(ctx context.Context, cfg *config.UserConfig, alias string) (*TestSession, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config provided")
	}

	bin := xray.GetXrayBinaryPath()
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		if err := xray.DownloadXray(); err != nil {
			return nil, fmt.Errorf("failed to download xray core: %w", err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	testSocksPort, err := xray.GetFreePort()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate socks port: %w", err)
	}
	apiPort, err := xray.GetFreePort()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate api port: %w", err)
	}

	testCfg := *cfg
	testCfg.Role = config.RoleServer
	testCfg.Gateway = config.GatewayConfig{}

	overrides := map[string]int{"test-socks": testSocksPort, "api": apiPort}
	for _, m := range testCfg.Presets {
		if m.Enabled {
			p, err := xray.GetFreePort()
			if err != nil {
				return nil, fmt.Errorf("failed to allocate preset port: %w", err)
			}
			overrides[string(m.Mode)] = p
		}
	}

	jsonData, err := xray.GenerateXrayJSON(&testCfg, overrides, alias)
	if err != nil {
		return nil, fmt.Errorf("generate xray json: %w", err)
	}

	_, cleanup, err := xray.StartXrayTemp(jsonData)
	if err != nil {
		return nil, fmt.Errorf("start xray temp: %w", err)
	}

	socksAddr := fmt.Sprintf("127.0.0.1:%d", testSocksPort)
	if err := waitForListener(ctx, socksAddr, 5*time.Second); err != nil {
		cleanup()
		return nil, fmt.Errorf("test listener %s not ready: %w", socksAddr, err)
	}

	dialer, err := utils.NewSOCKS5Dialer(socksAddr)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("build socks5 dialer: %w", err)
	}

	transport := &http.Transport{
		Dial:                  dialer.Dial,
		DisableCompression:    true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   0, // Individual timeouts handled via context
	}

	return &TestSession{
		Alias:       alias,
		SOCKSAddr:   socksAddr,
		Dialer:      dialer,
		HTTPClient:  httpClient,
		cleanupFunc: cleanup,
	}, nil
}

func waitForListener(ctx context.Context, address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn, err := net.DialTimeout("tcp", address, 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timeout waiting for %s", address)
	}
	return lastErr
}
