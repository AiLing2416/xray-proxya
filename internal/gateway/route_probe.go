package gateway

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"xray-proxya/internal/config"
)

// GatewayTraceEndpoints defines default Cloudflare trace endpoints for route observation.
var GatewayTraceEndpoints = []string{
	"https://1.1.1.1/cdn-cgi/trace",
	"https://1.0.0.1/cdn-cgi/trace",
}

// FilterTestEndpoints filters out any trace endpoints whose IP/host is bypassed in Gateway config.
func FilterTestEndpoints(cfg *config.UserConfig) ([]string, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}
	bypassed := make(map[string]struct{}, len(cfg.Gateway.BypassDNS))
	for _, ip := range cfg.Gateway.BypassDNS {
		bypassed[strings.TrimSpace(ip)] = struct{}{}
	}
	var res []string
	for _, ep := range GatewayTraceEndpoints {
		host := ep
		if strings.HasPrefix(host, "https://") {
			host = strings.TrimPrefix(host, "https://")
		}
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}
		if _, ok := bypassed[host]; !ok {
			res = append(res, ep)
		}
	}
	if len(res) == 0 {
		return nil, errors.New("all trace endpoints are bypassed by bypass-dns configuration")
	}
	return res, nil
}

// ParseTraceExitIP scans the response body line-by-line and extracts the value of the `ip=` field.
func ParseTraceExitIP(body string) string {
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "ip=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "ip="))
		}
	}
	return ""
}

// ParseCloudflareTraceIP is an alias for ParseTraceExitIP for backwards compatibility.
func ParseCloudflareTraceIP(body string) string {
	return ParseTraceExitIP(body)
}

// RunLocalProxyTest sends a real HTTP request through the gateway to discover the observed public IP.
func RunLocalProxyTest(cfg *config.UserConfig) (string, error) {
	if cfg == nil || cfg.Gateway.State == "disabled" {
		return "", errors.New("gateway state is disabled")
	}

	endpoints, err := FilterTestEndpoints(cfg)
	if err != nil {
		return "", err
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	var lastErr error
	for _, ep := range endpoints {
		req, err := http.NewRequest("GET", ep, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "curl/7.88.1")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		ip := ParseTraceExitIP(string(body))
		if ip != "" {
			return ip, nil
		}
		lastErr = fmt.Errorf("no ip field in response from %s", ep)
	}

	// Fallback to external curl binary if http.Client encounters local routing/socket quirks
	if lastErr != nil {
		for _, ep := range endpoints {
			out, err := exec.Command("curl", "-sk", "-m", "5", ep).CombinedOutput()
			if err == nil {
				ip := ParseTraceExitIP(string(out))
				if ip != "" {
					return ip, nil
				}
			}
		}
		return "", lastErr
	}
	return "", errors.New("trace failed: no endpoints responded")
}

// RunSimulatedLANTest creates a dedicated network namespace to simulate a LAN client sending
// traffic through the gateway, then captures and verifies the exit IP.
func RunSimulatedLANTest(cfg *config.UserConfig) (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("simulated LAN test requires root privileges for netns operations")
	}
	if cfg == nil || cfg.Gateway.State == "disabled" || !cfg.Gateway.LANEnabled {
		return "", errors.New("LAN gateway is disabled")
	}
	if cfg.Gateway.State != "proxy" {
		return "", fmt.Errorf("simulated LAN test is only supported in proxy state (active state is %q)", cfg.Gateway.State)
	}

	endpoints, err := FilterTestEndpoints(cfg)
	if err != nil {
		return "", err
	}

	const (
		nsName      = "ns-proxya-test"
		vethGateway = "veth-tg"
		vethClient  = "veth-tc"
	)

	// Clean up any stale interfaces/namespaces from a previous aborted run
	_ = exec.Command("ip", "netns", "del", nsName).Run()
	_ = exec.Command("ip", "link", "del", vethGateway).Run()

	// Ensure full cleanup on return
	defer func() {
		_ = exec.Command("ip", "netns", "del", nsName).Run()
		_ = exec.Command("ip", "link", "del", vethGateway).Run()
		_ = ApplyFirewall(cfg)
	}()

	// 1. Create network namespace
	if out, err := exec.Command("ip", "netns", "add", nsName).CombinedOutput(); err != nil {
		return "", fmt.Errorf("create netns %s: %w (output: %s)", nsName, err, strings.TrimSpace(string(out)))
	}

	// 2. Create veth pair
	if out, err := exec.Command("ip", "link", "add", vethGateway, "type", "veth", "peer", "name", vethClient).CombinedOutput(); err != nil {
		return "", fmt.Errorf("create veth pair: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	// 3. Move client end to netns
	if out, err := exec.Command("ip", "link", "set", vethClient, "netns", nsName).CombinedOutput(); err != nil {
		return "", fmt.Errorf("move %s to netns: %w (output: %s)", vethClient, err, strings.TrimSpace(string(out)))
	}

	// 4. Configure gateway side
	if out, err := exec.Command("ip", "addr", "add", "192.168.250.1/24", "dev", vethGateway).CombinedOutput(); err != nil {
		return "", fmt.Errorf("assign ip to %s: %w (output: %s)", vethGateway, err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("ip", "link", "set", vethGateway, "up").CombinedOutput(); err != nil {
		return "", fmt.Errorf("bring up %s: %w (output: %s)", vethGateway, err, strings.TrimSpace(string(out)))
	}

	// Disable rp_filter and send_redirects on gateway side
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/"+vethGateway+"/rp_filter", []byte("0\n"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/"+vethGateway+"/send_redirects", []byte("0\n"), 0644)
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf."+vethGateway+".rp_filter=0").Run()
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf."+vethGateway+".send_redirects=0").Run()

	// 5. Configure namespace side
	if out, err := exec.Command("ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		return "", fmt.Errorf("bring up lo in netns: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("ip", "netns", "exec", nsName, "ip", "addr", "add", "192.168.250.2/24", "dev", vethClient).CombinedOutput(); err != nil {
		return "", fmt.Errorf("assign ip to %s in netns: %w (output: %s)", vethClient, err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("ip", "netns", "exec", nsName, "ip", "link", "set", vethClient, "up").CombinedOutput(); err != nil {
		return "", fmt.Errorf("bring up %s in netns: %w (output: %s)", vethClient, err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("ip", "netns", "exec", nsName, "ip", "route", "add", "default", "via", "192.168.250.1").CombinedOutput(); err != nil {
		return "", fmt.Errorf("add default route in netns: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	// 6. Insert temporary nftables rule to mark traffic arriving from vethGateway
	nftCmd := exec.Command("nft", "insert", "rule", "inet", tableName, "prerouting", "iifname", vethGateway, "meta", "l4proto", "{ tcp, udp }", "meta", "mark", "set", tunMark)
	if out, err := nftCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("insert temporary nftables rule: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	// 7. Execute curl within namespace sandbox to observe public IP
	var lastErr error
	for _, ep := range endpoints {
		out, err := exec.Command("ip", "netns", "exec", nsName, "curl", "-sk", "-m", "5", ep).CombinedOutput()
		if err != nil {
			lastErr = fmt.Errorf("netns curl %s failed: %w (output: %s)", ep, err, strings.TrimSpace(string(out)))
			continue
		}
		ip := ParseTraceExitIP(string(out))
		if ip != "" {
			return ip, nil
		}
		lastErr = fmt.Errorf("no ip field in netns curl response from %s: %s", ep, strings.TrimSpace(string(out)))
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", errors.New("simulated LAN test failed: no endpoints responded")
}
