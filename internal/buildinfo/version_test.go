package buildinfo

import (
	"strings"
	"testing"
)

func TestGetVersion(t *testing.T) {
	v := GetVersion()
	if IsSlim {
		if !strings.HasSuffix(v, "-slim") {
			t.Errorf("expected -slim suffix in slim build, got %q", v)
		}
		if Profile != "slim" {
			t.Errorf("expected Profile 'slim', got %q", Profile)
		}
	} else {
		if strings.HasSuffix(v, "-slim") {
			t.Errorf("unexpected -slim suffix in full build, got %q", v)
		}
		if Profile != "full" {
			t.Errorf("expected Profile 'full', got %q", Profile)
		}
	}
}
