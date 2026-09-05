package relaytest

import (
	"context"
	"strings"
	"testing"
)

func TestSessionOptions(t *testing.T) {
	sc := sessionConfig{
		enableSOCKS: true,
		enableDNS:   false,
		overrides:   make(map[string]int),
	}

	optDNS := WithDNS()
	optDNS(&sc)
	if !sc.enableDNS {
		t.Fatalf("expected enableDNS=true after WithDNS()")
	}

	optNoSocks := WithoutSOCKS()
	optNoSocks(&sc)
	if sc.enableSOCKS {
		t.Fatalf("expected enableSOCKS=false after WithoutSOCKS()")
	}

	optOverrides := WithOverrides(map[string]int{"test-port": 12345})
	optOverrides(&sc)
	if sc.overrides["test-port"] != 12345 {
		t.Fatalf("expected overrides[test-port]=12345, got %d", sc.overrides["test-port"])
	}
}

func TestTestSessionCloseIdempotent(t *testing.T) {
	var closedCount int
	session := &TestSession{
		Alias: "test-alias",
		cleanupFunc: func() {
			closedCount++
		},
	}

	session.Close()
	session.Close()
	session.Close()

	if closedCount != 1 {
		t.Fatalf("expected cleanupFunc to be called exactly once, got %d", closedCount)
	}

	// Nil session should not panic
	var nilSession *TestSession
	nilSession.Close()
}

func TestTestSessionResolveDNSWithoutListener(t *testing.T) {
	session := &TestSession{
		Alias: "test-alias",
	}

	_, _, err := session.ResolveDNS("example.com", 1, 1)
	if err == nil || !strings.Contains(err.Error(), "DNS listener is not enabled") {
		t.Fatalf("expected error mentioning DNS listener not enabled, got %v", err)
	}
}

func TestStartTestSessionNilConfig(t *testing.T) {
	_, err := StartTestSession(context.Background(), nil, "test")
	if err == nil {
		t.Fatalf("expected error when cfg is nil")
	}
}
