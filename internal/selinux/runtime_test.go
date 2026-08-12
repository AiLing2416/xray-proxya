package selinux

import "testing"

func TestIsEnforcingValue(t *testing.T) {
	for _, value := range []string{"1", "1\n", " 1\n"} {
		if !isEnforcingValue([]byte(value)) {
			t.Fatalf("%q was not recognized as enforcing", value)
		}
	}
	for _, value := range []string{"0", "Enforcing", "", "2"} {
		if isEnforcingValue([]byte(value)) {
			t.Fatalf("%q was incorrectly recognized as enforcing", value)
		}
	}
}
