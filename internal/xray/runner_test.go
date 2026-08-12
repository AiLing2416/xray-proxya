package xray

import (
	"strings"
	"testing"
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
