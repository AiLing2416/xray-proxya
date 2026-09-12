package gateway

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"xray-proxya/internal/config"
)

func TestFilterTestEndpoints_ExcludesBypassDNS(t *testing.T) {
	cfg := &config.UserConfig{
		Gateway: config.GatewayConfig{
			BypassDNS: []string{"1.1.1.1", "invalid"},
		},
	}
	want := []string{"https://1.0.0.1/cdn-cgi/trace"}
	got, err := FilterTestEndpoints(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FilterTestEndpoints() = %v, want %v", got, want)
	}
}

func TestFilterTestEndpoints_AllBypassedErrors(t *testing.T) {
	cfg := &config.UserConfig{
		Gateway: config.GatewayConfig{
			BypassDNS: []string{"1.1.1.1", "1.0.0.1"},
		},
	}
	got, err := FilterTestEndpoints(cfg)
	if err == nil {
		t.Fatalf("expected error when all endpoints are bypassed, got %v", got)
	}
	if !strings.Contains(err.Error(), "all trace endpoints are bypassed") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestParseTraceExitIP(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "valid trace response",
			body: "fl=123f45\nh=1.1.1.1\nip=198.51.100.25\nts=1700000000\nvisit_scheme=https\n",
			want: "198.51.100.25",
		},
		{
			name: "leading and trailing whitespace",
			body: "  fl=123f45\n  ip=203.0.113.88  \n  ts=1700000000\n",
			want: "203.0.113.88",
		},
		{
			name: "missing ip field",
			body: "fl=123f45\nh=1.1.1.1\nts=1700000000\n",
			want: "",
		},
		{
			name: "empty body",
			body: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseTraceExitIP(tt.body)
			if got != tt.want {
				t.Errorf("ParseTraceExitIP() = %q, want %q", got, tt.want)
			}
			// Verify alias works identically
			gotAlias := ParseCloudflareTraceIP(tt.body)
			if gotAlias != tt.want {
				t.Errorf("ParseCloudflareTraceIP() = %q, want %q", gotAlias, tt.want)
			}
		})
	}
}

func TestRunLocalProxyTest_DisabledFails(t *testing.T) {
	cfg := &config.UserConfig{
		Gateway: config.GatewayConfig{
			State: "disabled",
		},
	}
	_, err := RunLocalProxyTest(cfg)
	if err == nil {
		t.Fatal("expected error for disabled gateway, got nil")
	}
	if !strings.Contains(err.Error(), "gateway state is disabled") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestRunSimulatedLANTest_DisabledOrNonRootFails(t *testing.T) {
	// If non-root, it should fail with root privileges error
	if os.Geteuid() != 0 {
		cfg := &config.UserConfig{
			Gateway: config.GatewayConfig{
				State:      "proxy",
				LANEnabled: true,
			},
		}
		_, err := RunSimulatedLANTest(cfg)
		if err == nil {
			t.Fatal("expected error for non-root, got nil")
		}
		if !strings.Contains(err.Error(), "requires root privileges") {
			t.Fatalf("unexpected error message: %v", err)
		}
	} else {
		cfg := &config.UserConfig{
			Gateway: config.GatewayConfig{
				State:      "disabled",
				LANEnabled: false,
			},
		}
		_, err := RunSimulatedLANTest(cfg)
		if err == nil {
			t.Fatal("expected error for disabled gateway, got nil")
		}
	}
}
