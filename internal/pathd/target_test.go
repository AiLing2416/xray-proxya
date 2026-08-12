package pathd

import (
	"net"
	"testing"
)

func TestValidateProbeTarget(t *testing.T) {
	for _, value := range []string{"13.193.197.192", "103.179.45.197", "2606:4700:4700::1111"} {
		if err := ValidateProbeTarget(net.ParseIP(value)); err != nil {
			t.Fatalf("%s rejected: %v", value, err)
		}
	}
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.168.1.1", "192.175.48.1", "198.18.0.1", "192.0.2.1", "::1", "100::1", "3fff::1", "fc00::1", "fe80::1", "2001:db8::1"} {
		if err := ValidateProbeTarget(net.ParseIP(value)); err == nil {
			t.Fatalf("%s accepted", value)
		}
	}
	for _, value := range []string{"192.0.0.9", "192.0.0.10", "192.31.196.1", "2001:1::1", "2001:3::1"} {
		if err := ValidateProbeTarget(net.ParseIP(value)); err != nil {
			t.Fatalf("%s rejected: %v", value, err)
		}
	}
}
