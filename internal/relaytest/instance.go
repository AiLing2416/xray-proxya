package relaytest

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"
)

// SessionOption configures an isolated temporary Xray test session.
type SessionOption func(*sessionConfig)

type sessionConfig struct {
	enableSOCKS bool
	enableDNS   bool
	overrides   map[string]int
}

// WithDNS enables and allocates a dedicated DNS TCP test listener ("dns-in") for the session.
func WithDNS() SessionOption {
	return func(sc *sessionConfig) {
		sc.enableDNS = true
	}
}

// WithoutSOCKS disables creating the default SOCKS5 test inbound.
func WithoutSOCKS() SessionOption {
	return func(sc *sessionConfig) {
		sc.enableSOCKS = false
	}
}

// WithOverrides passes additional port overrides to the test configuration.
func WithOverrides(overrides map[string]int) SessionOption {
	return func(sc *sessionConfig) {
		for k, v := range overrides {
			sc.overrides[k] = v
		}
	}
}

// TestSession represents an isolated, running temporary Xray test proxy instance.
type TestSession struct {
	Alias      string
	SOCKSAddr  string
	DNSAddr    string
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

// ResolveDNS resolves a domain via the session's temporary DNS listener with retry.
func (s *TestSession) ResolveDNS(domain string, qtype uint16, attempts int) ([]string, time.Duration, error) {
	if s.DNSAddr == "" {
		return nil, 0, fmt.Errorf("DNS listener is not enabled for this session (use WithDNS())")
	}
	if attempts < 1 {
		attempts = 1
	}
	var lastAnswers []string
	var lastDuration time.Duration
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		answers, duration, err := xray.ResolveDNSTCP(s.DNSAddr, domain, qtype)
		lastAnswers, lastDuration, lastErr = answers, duration, err
		if err == nil {
			return answers, duration, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return lastAnswers, lastDuration, lastErr
}

// StartTestSession spins up an isolated temporary Xray instance for the given relay outbound.
func StartTestSession(ctx context.Context, cfg *config.UserConfig, alias string, opts ...SessionOption) (*TestSession, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config provided")
	}

	sc := sessionConfig{
		enableSOCKS: true,
		enableDNS:   false,
		overrides:   make(map[string]int),
	}
	for _, opt := range opts {
		opt(&sc)
	}

	bin := xray.GetXrayBinaryPath()
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		if err := xray.DownloadXray(); err != nil {
			return nil, fmt.Errorf("failed to download xray core: %w", err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	overrides := make(map[string]int)
	for k, v := range sc.overrides {
		overrides[k] = v
	}

	var testSocksPort, dnsPort int
	var err error

	if sc.enableSOCKS {
		testSocksPort, err = utils.GetFreePort()
		if err != nil {
			return nil, fmt.Errorf("failed to allocate socks port: %w", err)
		}
		overrides["test-socks"] = testSocksPort
	}

	if sc.enableDNS {
		dnsPort, err = utils.GetFreePort()
		if err != nil {
			return nil, fmt.Errorf("failed to allocate dns port: %w", err)
		}
		overrides["dns-in"] = dnsPort
	}

	apiPort, err := utils.GetFreePort()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate api port: %w", err)
	}
	overrides["api"] = apiPort

	testCfg := *cfg
	testCfg.Role = config.RoleServer
	testCfg.Gateway = config.GatewayConfig{}

	for _, m := range testCfg.Presets {
		if m.Enabled {
			p, err := utils.GetFreePort()
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

	session := &TestSession{
		Alias:       alias,
		cleanupFunc: cleanup,
	}

	if sc.enableSOCKS {
		socksAddr := fmt.Sprintf("127.0.0.1:%d", testSocksPort)
		if err := utils.WaitForTCPPort(ctx, socksAddr, 5*time.Second); err != nil {
			cleanup()
			return nil, fmt.Errorf("test socks listener %s not ready: %w", socksAddr, err)
		}
		session.SOCKSAddr = socksAddr

		dialer, err := utils.NewSOCKS5Dialer(socksAddr)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("build socks5 dialer: %w", err)
		}
		session.Dialer = dialer

		transport := &http.Transport{
			Dial:                  dialer.Dial,
			DisableCompression:    true,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
		}
		session.HTTPClient = &http.Client{
			Transport: transport,
			Timeout:   0, // Individual timeouts handled via context
		}
	}

	if sc.enableDNS {
		dnsAddr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
		if err := utils.WaitForTCPPort(ctx, dnsAddr, 5*time.Second); err != nil {
			cleanup()
			return nil, fmt.Errorf("test dns listener %s not ready: %w", dnsAddr, err)
		}
		session.DNSAddr = dnsAddr
	}

	return session, nil
}
