package utils

import (
	"crypto/rand"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// GenerateRandomIPv6 picks a random IP from the given subnet (CIDR)
func GenerateRandomIPv6(subnet string) (string, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}

	ones, bits := ipNet.Mask.Size()
	if bits != 128 {
		return "", fmt.Errorf("not an IPv6 subnet: %s", subnet)
	}

	// Start with the prefix
	newIP := make([]byte, 16)
	copy(newIP, ipNet.IP)

	// Generate random bytes for the host part
	randomBytes := make([]byte, 16)
	_, err = rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Apply mask
	for i := 0; i < 16; i++ {
		// Calculate how many bits of this byte are in the host part
		byteStartBit := i * 8
		if byteStartBit >= ones {
			// Entire byte is host part
			newIP[i] = randomBytes[i]
		} else if byteStartBit+8 > ones {
			// Part of the byte is prefix, part is host
			mask := byte(0xFF >> (ones - byteStartBit))
			newIP[i] = (newIP[i] & ^mask) | (randomBytes[i] & mask)
		}
		// else: byte is entirely prefix, keep as is
	}

	return net.IP(newIP).String(), nil
}

// SetupIPv6Addr adds an IPv6 address to an interface using 'ip' command
func SetupIPv6Addr(ip string, iface string) error {
	// Check if already exists to avoid error
	if checkAddrExists(ip, iface) {
		return nil
	}
	// Use sudo as this requires root
	cmd := exec.Command("sudo", "ip", "-6", "addr", "add", ip+"/128", "dev", iface)
	return cmd.Run()
}

func checkAddrExists(ip, iface string) bool {
	out, err := exec.Command("ip", "-6", "addr", "show", "dev", iface).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), ip)
}

// AutoDetectIPv6Subnet tries to find the first public IPv6 subnet and its interface
func AutoDetectIPv6Subnet() (subnet string, iface string, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			if ip.To4() == nil && isPublicIP(ip) {
				// Found a public IPv6
				ones, _ := ipNet.Mask.Size()
				// Return the subnet in CIDR format
				return fmt.Sprintf("%s/%d", ipNet.IP.Mask(ipNet.Mask).String(), ones), i.Name, nil
			}
		}
	}
	return "", "", fmt.Errorf("no public IPv6 subnet found")
}

// TestIPv6Reachability checks if we can bind to an IP and reach a target
func TestIPv6Reachability(ip string) bool {
	// A simple way is to use ping6 (requires root usually, or CAP_NET_RAW)
	// Or try to establish a TCP connection to a known IPv6 target from this source IP
	// target: Google Public DNS (IPv6)
	target := "[2001:4860:4860::8888]:53"
	d := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)},
		Timeout:   2 * 1000 * 1000 * 1000, // 2s
	}
	conn, err := d.Dial("tcp6", target)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
