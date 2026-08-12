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
