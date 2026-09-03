package relaysub

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"xray-proxya/internal/config"
)

func TestSanitizeRemark(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    " 🇭🇰 [BGP] / 香港 01 (倍率: 0.5x) ",
			expected: "🇭🇰-BGP-香港-01-倍率-0.5x",
		},
		{
			input:    "%E6%97%A5%E6%9C%AC-Tokyo%2F01",
			expected: "日本-Tokyo-01",
		},
		{
			input:    "US-West-01",
			expected: "US-West-01",
		},
		{
			input:    "###---///",
			expected: "",
		},
		{
			input:    "SG | Fast & Secure *Premium*",
			expected: "SG-Fast-Secure-Premium",
		},
	}

	for _, tt := range tests {
		got := SanitizeRemark(tt.input)
		if got != tt.expected {
			t.Errorf("SanitizeRemark(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestParseSubscriptionAndDeduplication(t *testing.T) {
	link1 := "vless://c8abfd6a-bba7-4db9-b43e-82c2beb76049@1.1.1.1:443?security=none#HK-01"
	link2 := "vless://c8abfd6a-bba7-4db9-b43e-82c2beb76049@2.2.2.2:443?security=none#HK-01" // Duplicate remark
	link3 := "trojan://password@3.3.3.3:443#Trojan-Ignored"                                    // Should be skipped
	link4 := "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@4.4.4.4:8388#US-01"

	combined := strings.Join([]string{link1, link2, link3, link4}, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(combined))

	nodes, skipped, err := ParseSubscription("myair", []byte(encoded))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if skipped != 1 {
		t.Errorf("expected 1 skipped item (trojan), got %d", skipped)
	}

	if len(nodes) != 3 {
		t.Fatalf("expected 3 valid nodes, got %d", len(nodes))
	}

	if nodes[0].Alias != "myair/HK-01" {
		t.Errorf("expected first node alias 'myair/HK-01', got %q", nodes[0].Alias)
	}
	if nodes[1].Alias != "myair/HK-01-2" {
		t.Errorf("expected duplicate node alias 'myair/HK-01-2', got %q", nodes[1].Alias)
	}
	if nodes[2].Alias != "myair/US-01" {
		t.Errorf("expected third node alias 'myair/US-01', got %q", nodes[2].Alias)
	}
}

func TestComputeDiff(t *testing.T) {
	currentOutbounds := []config.CustomOutbound{
		{Alias: "manual-vps", Enabled: true, Config: map[string]interface{}{"port": 1111}},
		{Alias: "air/HK-01", Enabled: true, Config: map[string]interface{}{"port": 2222}},
		{Alias: "air/Old-Node", Enabled: true, Config: map[string]interface{}{"port": 3333}},
	}

	newNodes := []ParsedNode{
		{
			Alias:  "air/HK-01",
			Config: map[string]interface{}{"port": 2222}, // Unchanged
		},
		{
			Alias:  "air/New-Node",
			Config: map[string]interface{}{"port": 4444}, // Added
		},
	}

	diff := ComputeDiff("air", currentOutbounds, newNodes)

	if len(diff.Unchanged) != 1 || diff.Unchanged[0].Alias != "air/HK-01" {
		t.Errorf("expected 1 unchanged node (air/HK-01)")
	}
	if len(diff.Added) != 1 || diff.Added[0].Alias != "air/New-Node" {
		t.Errorf("expected 1 added node (air/New-Node)")
	}
	if len(diff.Removed) != 1 || diff.Removed[0].Alias != "air/Old-Node" {
		t.Errorf("expected 1 removed node (air/Old-Node)")
	}

	// Verify merged outbounds contains manual-vps + HK-01 + New-Node
	if len(diff.MergedOutbounds) != 3 {
		t.Fatalf("expected 3 merged outbounds, got %d", len(diff.MergedOutbounds))
	}
	if diff.MergedOutbounds[0].Alias != "manual-vps" {
		t.Errorf("expected manual-vps preserved, got %q", diff.MergedOutbounds[0].Alias)
	}
}

func TestFetchSubscription(t *testing.T) {
	expectedUA := "v2rayN/6.23"
	payload := base64.StdEncoding.EncodeToString([]byte("vless://uuid@1.2.3.4:443?security=none#node-1"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != expectedUA {
			http.Error(w, fmt.Sprintf("invalid UA: %s", r.Header.Get("User-Agent")), http.StatusBadRequest)
			return
		}
		w.Write([]byte(payload))
	}))
	defer srv.Close()

	body, err := FetchSubscription(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchSubscription failed: %v", err)
	}

	if string(body) != payload {
		t.Fatalf("expected payload %q, got %q", payload, string(body))
	}
}
