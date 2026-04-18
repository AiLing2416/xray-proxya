package utils

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// --- Port & Basic Network ---

func IsPortFree(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil { return false }
	ln.Close()
	return true
}

func GetFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil { return 0, err }
	l, err := net.ListenTCP("tcp", addr)
	if err != nil { return 0, err }
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil { return "127.0.0.1" }
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil { return ipnet.IP.String() }
		}
	}
	return "127.0.0.1"
}

func GetPublicIPv4() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://api.ipify.org")
	if err != nil { return "" }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(body))
}

func GetPublicIPv6() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://api64.ipify.org")
	if err != nil { return "" }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	ip := strings.TrimSpace(string(body))
	if strings.Contains(ip, ":") { return ip }
	return ""
}

func GetSmartIP(v6 bool) string {
	if v6 {
		if ip := GetPublicIPv6(); ip != "" { return ip }
	} else {
		if ip := GetPublicIPv4(); ip != "" { return ip }
	}
	return GetLocalIP()
}

// --- IPv6 Advanced (Block & NDP) ---

func GenerateRandomIPv6(subnet string) (string, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil { return "", err }

	ones, bits := ipNet.Mask.Size()
	if bits != 128 { return "", fmt.Errorf("not an IPv6 subnet: %s", subnet) }

	newIP := make([]byte, 16)
	copy(newIP, ipNet.IP)

	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)

	for i := 0; i < 16; i++ {
		byteStartBit := i * 8
		if byteStartBit >= ones {
			newIP[i] = randomBytes[i]
		} else if byteStartBit+8 > ones {
			mask := byte(0xFF >> (ones - byteStartBit))
			newIP[i] = (newIP[i] & ^mask) | (randomBytes[i] & mask)
		}
	}
	return net.IP(newIP).String(), nil
}

func SetupIPv6Addr(ip string, iface string) error {
	out, _ := exec.Command("ip", "-6", "addr", "show", "dev", iface).Output()
	if strings.Contains(string(out), ip) { return nil }
	
	exec.Command("sudo", "sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.accept_ra=2", iface)).Run()
	return exec.Command("sudo", "ip", "-6", "addr", "add", ip+"/128", "dev", iface).Run()
}

func RemoveIPv6Addr(ip string, iface string) error {
	// Best effort to remove old IP
	return exec.Command("sudo", "ip", "-6", "addr", "del", ip+"/128", "dev", iface).Run()
}

func SetupNDPProxy(ip, iface string) error {
	exec.Command("sudo", "sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.proxy_ndp=1", iface)).Run()
	return exec.Command("sudo", "ip", "-6", "neigh", "add", "proxy", ip, "dev", iface).Run()
}

func AutoDetectIPv6Subnet() (string, string, error) {
	ifaces, err := net.Interfaces(); if err != nil { return "", "", err }
	for _, i := range ifaces {
		addrs, err := i.Addrs(); if err != nil { continue }
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet); if !ok { continue }
			if ipNet.IP.To4() == nil && IsPublicIP(ipNet.IP) {
				ones, _ := ipNet.Mask.Size()
				return fmt.Sprintf("%s/%d", ipNet.IP.Mask(ipNet.Mask).String(), ones), i.Name, nil
			}
		}
	}
	return "", "", fmt.Errorf("no public ipv6 subnet found")
}

func TestIPv6Reachability(ip string) bool {
	target := "[2001:4860:4860::8888]:53"
	d := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)},
		Timeout:   2 * time.Second,
	}
	conn, err := d.Dial("tcp6", target)
	if err != nil { return false }
	conn.Close()
	return true
}

// --- Helpers ---

func IsPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() { return false }
	return true
}

func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit { return fmt.Sprintf("%d B", b) }
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
