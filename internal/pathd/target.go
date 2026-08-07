package pathd

import (
	"fmt"
	"net"
)

// ValidateProbeTarget permits only globally routable addresses. It is checked
// on both ends of PathLink so a compromised gateway cannot probe remote-local
// networks, metadata endpoints, or reserved address space.
func ValidateProbeTarget(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("invalid IP target")
	}
	if v4 := ip.To4(); v4 != nil {
		if !isPublicIPv4(v4) {
			return fmt.Errorf("target %s is not a public IPv4 address", v4)
		}
		return nil
	}
	v6 := ip.To16()
	if v6 == nil || !isPublicIPv6(v6) {
		return fmt.Errorf("target %s is not a public IPv6 address", ip)
	}
	return nil
}

func IsPublicTarget(ip net.IP) bool { return ValidateProbeTarget(ip) == nil }

func isPublicIPv4(ip net.IP) bool {
	v := ip.To4()
	if v == nil || v[0] == 0 || v[0] >= 224 || v[0] == 10 || v[0] == 127 {
		return false
	}
	if v[0] == 100 && v[1]&0xc0 == 0x40 {
		return false
	} // CGNAT
	if v[0] == 169 && v[1] == 254 {
		return false
	}
	if v[0] == 172 && v[1] >= 16 && v[1] <= 31 {
		return false
	}
	if v[0] == 192 && (v[1] == 0 || v[1] == 168 || (v[1] == 0 && v[2] == 2)) {
		return false
	}
	if v[0] == 198 && (v[1] == 18 || v[1] == 19 || v[1] == 51) {
		return false
	}
	return !(v[0] == 203 && v[1] == 0 && v[2] == 113)
}

func isPublicIPv6(ip net.IP) bool {
	v := ip.To16()
	if v == nil || ip.To4() != nil || v[0]&0xe0 != 0x20 {
		return false
	}
	// RFC 3849 documentation prefix must not be a probe target.
	return !(v[0] == 0x20 && v[1] == 0x01 && v[2] == 0x0d && v[3] == 0xb8)
}
