package ipv6rotate

import (
	"testing"
	"xray-proxya/internal/config"
)

func TestValidateRejectsIncompleteRotation(t *testing.T) {
	if err := Validate(config.IPv6Config{}); err == nil {
		t.Fatal("incomplete rotation was accepted")
	}
}

func TestSocketPathUsesConfigDirectory(t *testing.T) {
	t.Setenv("XRAY_PROXYA_CONFIG_DIR", t.TempDir())
	if got := SocketPath("default"); got == "" {
		t.Fatal("empty socket path")
	}
}
