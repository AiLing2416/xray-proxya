package doctor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"xray-proxya/internal/config"
)

// CheckKernel inspects kernel module availability and sysctl parameters.
func CheckKernel(ctx context.Context, role config.AppRole) []CheckResult {
	var results []CheckResult

	// Load present kernel modules (from /proc/modules and builtin)
	loadedModules, builtinModules := readKernelModuleSets()

	isModuleAvailable := func(name string) (bool, string) {
		if loadedModules[name] {
			return true, "loaded"
		}
		if builtinModules[name] {
			return true, "builtin"
		}
		// Test if module exists on disk via modprobe dry-run
		if err := exec.Command("modprobe", "-n", name).Run(); err == nil {
			return true, "available"
		}
		return false, "missing"
	}

	// 1. Check Gateway Modules (tun, nf_tables, nft_tproxy, nft_nat, nft_masq, nf_conntrack)
	gwModStart := time.Now()
	gwModules := []string{"tun", "nf_tables", "nft_tproxy", "nft_nat", "nft_masq", "nf_conntrack"}

	if role == config.RoleServer {
		results = append(results, CheckResult{
			Category:   "Kernel Capabilities",
			Name:       "Gateway Network Modules",
			Status:     StatusSkip,
			Detail:     "Gateway modules (tun, nft_tproxy, nft_nat, etc.) not required for Server role",
			DurationMs: time.Since(gwModStart).Milliseconds(),
		})
	} else if role == config.RoleGateway {
		var missing []string
		var loadedDesc []string
		for _, mod := range gwModules {
			ok, status := isModuleAvailable(mod)
			if !ok {
				missing = append(missing, mod)
			} else {
				loadedDesc = append(loadedDesc, fmt.Sprintf("%s (%s)", mod, status))
			}
		}

		if len(missing) == 0 {
			results = append(results, CheckResult{
				Category:   "Kernel Capabilities",
				Name:       "Gateway Network Modules",
				Status:     StatusPass,
				Detail:     "All required gateway modules available (tun, nftables, tproxy, nat, conntrack)",
				DurationMs: time.Since(gwModStart).Milliseconds(),
			})
		} else {
			results = append(results, CheckResult{
				Category:    "Kernel Capabilities",
				Name:        "Gateway Network Modules",
				Status:      StatusFail,
				Detail:      fmt.Sprintf("Missing required gateway modules: %s", strings.Join(missing, ", ")),
				Remediation: "Install kernel-modules extra package or load with 'modprobe <module>'",
				DurationMs:  time.Since(gwModStart).Milliseconds(),
			})
		}
	} else {
		// Generic host without specific role
		var missing []string
		for _, mod := range gwModules {
			if ok, _ := isModuleAvailable(mod); !ok {
				missing = append(missing, mod)
			}
		}
		if len(missing) == 0 {
			results = append(results, CheckResult{
				Category:   "Kernel Capabilities",
				Name:       "Gateway Network Modules",
				Status:     StatusPass,
				Detail:     "All gateway modules available (tun, nftables, tproxy, nat, conntrack)",
				DurationMs: time.Since(gwModStart).Milliseconds(),
			})
		} else {
			results = append(results, CheckResult{
				Category:    "Kernel Capabilities",
				Name:        "Gateway Network Modules",
				Status:      StatusWarn,
				Detail:      fmt.Sprintf("Optional modules missing: %s (only required if running as Gateway)", strings.Join(missing, ", ")),
				Remediation: "Load missing modules if planning to use Gateway mode",
				DurationMs:  time.Since(gwModStart).Milliseconds(),
			})
		}
	}

	// 2. Check BBR Congestion Control
	bbrStart := time.Now()
	ok, status := isModuleAvailable("tcp_bbr")
	if ok {
		if status == "loaded" || status == "builtin" {
			results = append(results, CheckResult{
				Category:   "Kernel Capabilities",
				Name:       "TCP BBR Congestion",
				Status:     StatusPass,
				Detail:     fmt.Sprintf("tcp_bbr is %s and ready", status),
				DurationMs: time.Since(bbrStart).Milliseconds(),
			})
		} else {
			results = append(results, CheckResult{
				Category:    "Kernel Capabilities",
				Name:        "TCP BBR Congestion",
				Status:      StatusWarn,
				Detail:      "tcp_bbr module is available but not loaded into active congestion algorithms",
				Remediation: "Run 'xray-proxya tune use bbr' to activate BBR congestion control",
				DurationMs:  time.Since(bbrStart).Milliseconds(),
			})
		}
	} else {
		results = append(results, CheckResult{
			Category:    "Kernel Capabilities",
			Name:        "TCP BBR Congestion",
			Status:      StatusWarn,
			Detail:      "tcp_bbr module not found in kernel",
			Remediation: "Upgrade kernel or install kernel-modules-extra for BBR acceleration",
			DurationMs:  time.Since(bbrStart).Milliseconds(),
		})
	}

	// 3. Check IP Forwarding (net.ipv4.ip_forward)
	ipfStart := time.Now()
	if role == config.RoleServer {
		results = append(results, CheckResult{
			Category:   "Kernel & Limits",
			Name:       "IPv4 Forwarding",
			Status:     StatusSkip,
			Detail:     "IP forwarding not required for Server role (Socket proxy architecture)",
			DurationMs: time.Since(ipfStart).Milliseconds(),
		})
	} else {
		val := readSysctlString("/proc/sys/net/ipv4/ip_forward")
		if val == "1" {
			results = append(results, CheckResult{
				Category:   "Kernel & Limits",
				Name:       "IPv4 Forwarding",
				Status:     StatusPass,
				Detail:     "net.ipv4.ip_forward = 1",
				DurationMs: time.Since(ipfStart).Milliseconds(),
			})
		} else if role == config.RoleGateway {
			results = append(results, CheckResult{
				Category:    "Kernel & Limits",
				Name:        "IPv4 Forwarding",
				Status:      StatusFail,
				Detail:      "net.ipv4.ip_forward = 0 (Gateway cannot route LAN client traffic)",
				Remediation: "Enable forwarding with 'sysctl -w net.ipv4.ip_forward=1'",
				DurationMs:  time.Since(ipfStart).Milliseconds(),
			})
		} else {
			results = append(results, CheckResult{
				Category:   "Kernel & Limits",
				Name:       "IPv4 Forwarding",
				Status:     StatusSkip,
				Detail:     "net.ipv4.ip_forward = 0 (only required if operating as Gateway)",
				DurationMs: time.Since(ipfStart).Milliseconds(),
			})
		}
	}

	// 4. Check File Descriptors Limit (nofile)
	nofileStart := time.Now()
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err == nil {
		if rlimit.Cur >= 4096 {
			results = append(results, CheckResult{
				Category:   "Kernel & Limits",
				Name:       "File Descriptors (nofile)",
				Status:     StatusPass,
				Detail:     fmt.Sprintf("Limit: %d (Max: %d)", rlimit.Cur, rlimit.Max),
				DurationMs: time.Since(nofileStart).Milliseconds(),
			})
		} else {
			results = append(results, CheckResult{
				Category:    "Kernel & Limits",
				Name:        "File Descriptors (nofile)",
				Status:      StatusWarn,
				Detail:      fmt.Sprintf("Current limit is low: %d (recommended: >= 4096)", rlimit.Cur),
				Remediation: "Increase file limit via 'ulimit -n 65535' or /etc/security/limits.conf",
				DurationMs:  time.Since(nofileStart).Milliseconds(),
			})
		}
	}

	return results
}

func readKernelModuleSets() (map[string]bool, map[string]bool) {
	loaded := make(map[string]bool)
	builtin := make(map[string]bool)

	// Read loaded modules from /proc/modules
	if file, err := os.Open("/proc/modules"); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) > 0 {
				modName := strings.ReplaceAll(fields[0], "-", "_")
				loaded[modName] = true
				loaded[fields[0]] = true
			}
		}
		file.Close()
	}

	// Read builtin modules
	var release string
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err == nil {
		var buf []byte
		for _, b := range uname.Release {
			if b == 0 {
				break
			}
			buf = append(buf, byte(b))
		}
		release = string(buf)
	}

	builtinPaths := []string{
		fmt.Sprintf("/lib/modules/%s/modules.builtin", release),
		"/lib/modules/modules.builtin",
	}

	for _, path := range builtinPaths {
		if file, err := os.Open(path); err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasSuffix(line, ".ko") {
					parts := strings.Split(line, "/")
					base := strings.TrimSuffix(parts[len(parts)-1], ".ko")
					base = strings.ReplaceAll(base, "-", "_")
					builtin[base] = true
				}
			}
			file.Close()
			break
		}
	}

	return loaded, builtin
}

func readSysctlString(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
