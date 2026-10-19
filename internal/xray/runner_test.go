package xray

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestXrayDownloadURLIsPinned(t *testing.T) {
	url := xrayDownloadURL("64")
	if !strings.Contains(url, "/releases/download/"+PinnedXrayVersion+"/") {
		t.Fatalf("download URL is not pinned: %s", url)
	}
	if strings.Contains(url, "/releases/latest/") {
		t.Fatalf("download URL still uses latest release: %s", url)
	}
}

func TestExtractSHA256SupportsOfficialSHA2Format(t *testing.T) {
	const expected = "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"

	actual, err := extractSHA256("SHA2-256= " + expected + "\n")
	if err != nil {
		t.Fatalf("extractSHA256 returned an error: %v", err)
	}
	if actual != expected {
		t.Fatalf("extractSHA256 returned %q, want %q", actual, expected)
	}
}

func TestValidateRuntimeNilConfig(t *testing.T) {
	err := ValidateRuntime(nil)
	if err == nil {
		t.Fatalf("expected error when validating nil config")
	}
}

func TestGetFreePortReturnsValidPort(t *testing.T) {
	port, err := GetFreePort()
	if err != nil {
		t.Fatalf("GetFreePort failed: %v", err)
	}
	if port <= 0 || port > 65535 {
		t.Fatalf("invalid port returned: %d", port)
	}
}

func TestStartXrayTempWithOutput(t *testing.T) {
	var stderr bytes.Buffer
	cmd, cleanup, err := StartXrayTempWithOutput([]byte("{}"), &stderr)
	if err != nil {
		t.Fatalf("StartXrayTempWithOutput failed: %v", err)
	}
	defer cleanup()

	if cmd.Stderr != &stderr {
		t.Errorf("expected cmd.Stderr to be assigned, got %v", cmd.Stderr)
	}
}

func TestGenerateX25519Clamped(t *testing.T) {
	for i := 0; i < 20; i++ {
		privB64, pubB64, err := GenerateX25519()
		if err != nil {
			t.Fatalf("GenerateX25519 failed: %v", err)
		}
		priv, err := base64.RawURLEncoding.DecodeString(privB64)
		if err != nil {
			t.Fatalf("failed to decode priv: %v", err)
		}
		if len(priv) != 32 {
			t.Fatalf("expected 32 bytes, got %d", len(priv))
		}
		// Verify RFC 7748 Curve25519 clamping
		if priv[0]&7 != 0 {
			t.Errorf("byte 0 lowest 3 bits not cleared: %d", priv[0])
		}
		if priv[31]&128 != 0 {
			t.Errorf("byte 31 highest bit not cleared: %d", priv[31])
		}
		if priv[31]&64 == 0 {
			t.Errorf("byte 31 second highest bit not set: %d", priv[31])
		}

		pub, err := base64.RawURLEncoding.DecodeString(pubB64)
		if err != nil {
			t.Fatalf("failed to decode pub: %v", err)
		}
		var expectedPub [32]byte
		var privArr [32]byte
		copy(privArr[:], priv)
		curve25519.ScalarBaseMult(&expectedPub, &privArr)
		if !bytes.Equal(pub, expectedPub[:]) {
			t.Errorf("pub key mismatch")
		}
	}
}
