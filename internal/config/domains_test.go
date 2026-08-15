package config

import (
	"testing"
)

func TestNormalizeVendor(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"aws", VendorAWS},
		{"Amazon", VendorAWS},
		{"gcp", VendorGCP},
		{"google", VendorGCP},
		{"azure", VendorAzure},
		{"Microsoft", VendorAzure},
		{"cloudflare", VendorCloudflare},
		{"cf", VendorCloudflare},
		{"oracle", VendorOracle},
		{"oci", VendorOracle},
		{"generic", VendorGeneric},
		{"unknown", "unknown"},
	}

	for _, c := range cases {
		if got := NormalizeVendor(c.input); got != c.expected {
			t.Errorf("NormalizeVendor(%q) = %q; want %q", c.input, got, c.expected)
		}
	}
}

func TestGetCloudVendorDomains(t *testing.T) {
	awsDomains := GetCloudVendorDomains(VendorAWS)
	if len(awsDomains) == 0 {
		t.Fatalf("expected AWS domains, got empty")
	}

	// Check exclusion of redirect domains
	for _, d := range GetAllRealityDomains() {
		if d == "www.apple.com" || d == "www.nvidia.com" || d == "www.intel.com" || d == "www.icloud.com" {
			t.Errorf("forbidden redirect domain %s found in pool", d)
		}
	}
}

func TestGetRandomRealityDomain(t *testing.T) {
	d := GetRandomRealityDomain()
	if d == "" {
		t.Fatalf("expected random domain, got empty")
	}
}
