package doctor

import (
	"context"
	"fmt"
	"strings"
	"syscall"
	"time"

	"xray-proxya/internal/config"
	"xray-proxya/internal/tune"
)

// CheckKernel inspects kernel module availability and sysctl parameters.
func CheckKernel(ctx context.Context, role config.AppRole) []CheckResult {
	var results []CheckResult

	// Inspect present kernel modules using unified module registry
	moduleRegistry := tune.NewModuleRegistry()

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
			info := moduleRegistry.Inspect(mod)
			if !info.Present {
				missing = append(missing, mod)
			} else {
				loadedDesc = append(loadedDesc, fmt.Sprintf("%s (%s)", mod, info.Status))
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
			if info := moduleRegistry.Inspect(mod); !info.Present {
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
	bbrInfo := moduleRegistry.Inspect("tcp_bbr")
	if bbrInfo.Present {
		if bbrInfo.Status == tune.ModuleStatusLoaded || bbrInfo.Status == tune.ModuleStatusBuiltin {
			results = append(results, CheckResult{
				Category:   "Kernel Capabilities",
				Name:       "TCP BBR Congestion",
				Status:     StatusPass,
				Detail:     fmt.Sprintf("tcp_bbr is %s and ready", bbrInfo.Status),
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
		val, _ := tune.ReadSysctl("net.ipv4.ip_forward")
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
