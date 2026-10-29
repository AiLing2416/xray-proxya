package doctor

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"xray-proxya/internal/config"
)

type portBinding struct {
	Port        int
	Description string
	Protocol    string
}

// CheckPortConflicts inspects whether the ports defined in the user config
// are available or owned by active xray-proxya/xray processes rather than third-party apps.
func CheckPortConflicts(ctx context.Context, cfg *config.UserConfig) []CheckResult {
	start := time.Now()
	var results []CheckResult

	if cfg == nil {
		results = append(results, CheckResult{
			Category:   "Port Bindings",
			Name:       "Configured Ports",
			Status:     StatusPass,
			Detail:     "No active configuration loaded; skipped port binding checks",
			DurationMs: time.Since(start).Milliseconds(),
		})
		return results
	}

	// Collect configured ports to verify
	var bindings []portBinding
	seen := make(map[string]bool)

	addPortWithProto := func(p int, desc, proto string) {
		if proto == "" {
			proto = "tcp"
		}
		key := fmt.Sprintf("%s:%d", proto, p)
		if p > 0 && p <= 65535 && !seen[key] {
			seen[key] = true
			bindings = append(bindings, portBinding{Port: p, Description: desc, Protocol: proto})
		}
	}
	addPort := func(p int, desc string) {
		addPortWithProto(p, desc, "tcp")
	}

	if cfg.APIInbound > 0 {
		addPort(cfg.APIInbound, "API Port")
	}
	if cfg.TestInbound > 0 {
		addPort(cfg.TestInbound, "Test Inbound Port")
	}
	for _, m := range cfg.Presets {
		if m.Enabled && m.Port > 0 {
			if m.Mode == config.ModeHysteria2 {
				addPortWithProto(m.Port, fmt.Sprintf("Preset UDP Port (%s)", m.Mode), "udp")
			} else {
				addPort(m.Port, fmt.Sprintf("Preset Port (%s)", m.Mode))
			}
		}
	}
	if cfg.SkinPort > 0 {
		hasActiveSkin := false
		for _, m := range cfg.Presets {
			if m.Enabled && m.Skin != "" {
				hasActiveSkin = true
				break
			}
		}
		if hasActiveSkin {
			addPort(cfg.SkinPort, "Web Camouflage Skin Port")
		}
	}
	if cfg.SubPort > 0 {
		addPort(cfg.SubPort, "Subscription Port")
	}
	if cfg.GuestSubPort > 0 {
		addPort(cfg.GuestSubPort, "Guest Subscription Port")
	}
	if cfg.AdminSub.Port > 0 {
		addPort(cfg.AdminSub.Port, "Admin Subscription Port")
	}
	for _, out := range cfg.CustomOutbounds {
		if out.Enabled {
			if out.InternalProxyPort > 0 {
				addPort(out.InternalProxyPort, fmt.Sprintf("Relay Port (%s)", out.Alias))
			}
			if out.InternalHttpPort > 0 {
				addPort(out.InternalHttpPort, fmt.Sprintf("Relay HTTP Port (%s)", out.Alias))
			}
		}
	}

	if len(bindings) == 0 {
		results = append(results, CheckResult{
			Category:   "Port Bindings",
			Name:       "Configured Ports",
			Status:     StatusPass,
			Detail:     "No active listen ports defined in configuration",
			DurationMs: time.Since(start).Milliseconds(),
		})
		return results
	}

	for _, b := range bindings {
		itemStart := time.Now()
		if b.Protocol == "udp" {
			conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", b.Port))
			if err == nil {
				conn.Close()
				results = append(results, CheckResult{
					Category:   "Port Bindings",
					Name:       fmt.Sprintf("%s (%d)", b.Description, b.Port),
					Status:     StatusPass,
					Detail:     "Port is available",
					DurationMs: time.Since(itemStart).Milliseconds(),
				})
				continue
			}

			// Port is in use, identify the owning process
			owner, pid, isOurProcess := identifyUDPPortOwner(b.Port)
			if isOurProcess {
				results = append(results, CheckResult{
					Category:   "Port Bindings",
					Name:       fmt.Sprintf("%s (%d)", b.Description, b.Port),
					Status:     StatusPass,
					Detail:     fmt.Sprintf("Active (owned by %s, PID: %d)", owner, pid),
					DurationMs: time.Since(itemStart).Milliseconds(),
				})
			} else if pid > 0 {
				results = append(results, CheckResult{
					Category:    "Port Bindings",
					Name:        fmt.Sprintf("%s (%d)", b.Description, b.Port),
					Status:      StatusFail,
					Detail:      fmt.Sprintf("Port occupied by external process: %s (PID: %d)", owner, pid),
					Remediation: fmt.Sprintf("Stop or reconfigure %s to release port %d", owner, b.Port),
					DurationMs:  time.Since(itemStart).Milliseconds(),
				})
			} else {
				results = append(results, CheckResult{
					Category:    "Port Bindings",
					Name:        fmt.Sprintf("%s (%d)", b.Description, b.Port),
					Status:      StatusFail,
					Detail:      fmt.Sprintf("Port is in use by another process: %v", err),
					Remediation: fmt.Sprintf("Ensure no conflicting daemon is listening on port %d", b.Port),
					DurationMs:  time.Since(itemStart).Milliseconds(),
				})
			}
			continue
		}

		// Test listening on TCP
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", b.Port))
		if err == nil {
			// Port is free
			ln.Close()
			results = append(results, CheckResult{
				Category:   "Port Bindings",
				Name:       fmt.Sprintf("%s (%d)", b.Description, b.Port),
				Status:     StatusPass,
				Detail:     "Port is available",
				DurationMs: time.Since(itemStart).Milliseconds(),
			})
			continue
		}

		// Port is in use, identify the owning process
		owner, pid, isOurProcess := identifyPortOwner(b.Port)
		if isOurProcess {
			results = append(results, CheckResult{
				Category:   "Port Bindings",
				Name:       fmt.Sprintf("%s (%d)", b.Description, b.Port),
				Status:     StatusPass,
				Detail:     fmt.Sprintf("Active (owned by %s, PID: %d)", owner, pid),
				DurationMs: time.Since(itemStart).Milliseconds(),
			})
		} else if pid > 0 {
			results = append(results, CheckResult{
				Category:    "Port Bindings",
				Name:        fmt.Sprintf("%s (%d)", b.Description, b.Port),
				Status:      StatusFail,
				Detail:      fmt.Sprintf("Port occupied by external process: %s (PID: %d)", owner, pid),
				Remediation: fmt.Sprintf("Stop or reconfigure %s to release port %d", owner, b.Port),
				DurationMs:  time.Since(itemStart).Milliseconds(),
			})
		} else {
			results = append(results, CheckResult{
				Category:    "Port Bindings",
				Name:        fmt.Sprintf("%s (%d)", b.Description, b.Port),
				Status:      StatusFail,
				Detail:      fmt.Sprintf("Port is in use by another process: %v", err),
				Remediation: fmt.Sprintf("Ensure no conflicting daemon is listening on port %d", b.Port),
				DurationMs:  time.Since(itemStart).Milliseconds(),
			})
		}
	}

	return results
}

func findProcessByInodes(inodes []uint64) (string, int, bool) {
	if len(inodes) == 0 {
		return "unknown", 0, false
	}

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return "unknown", 0, false
	}

	inodeSet := make(map[string]bool)
	for _, inode := range inodes {
		inodeSet[fmt.Sprintf("socket:[%d]", inode)] = true
	}

	for _, entry := range procEntries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if inodeSet[link] {
				// Found the process
				commBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
				comm := strings.TrimSpace(string(commBytes))
				if comm == "" {
					comm = "unknown"
				}

				exeLink, _ := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
				isOur := isXrayProxyaProcess(comm, exeLink)
				return comm, pid, isOur
			}
		}
	}

	return "unknown", 0, false
}

// identifyPortOwner attempts to find the process name and PID listening on the given TCP port.
func identifyPortOwner(port int) (string, int, bool) {
	return findProcessByInodes(findTCPPortInodes(port))
}

// identifyUDPPortOwner attempts to find the process name and PID listening on the given UDP port.
func identifyUDPPortOwner(port int) (string, int, bool) {
	return findProcessByInodes(findUDPPortInodes(port))
}

func findUDPPortInodes(targetPort int) []uint64 {
	var inodes []uint64
	for _, procFile := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		file, err := os.Open(procFile)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		// Skip header line
		if scanner.Scan() {
			for scanner.Scan() {
				fields := strings.Fields(scanner.Text())
				if len(fields) < 10 {
					continue
				}
				// Local address field e.g. 0100007F:0050 (127.0.0.1:80)
				localAddr := fields[1]
				parts := strings.Split(localAddr, ":")
				if len(parts) != 2 {
					continue
				}
				portHex := parts[1]
				portNum, err := strconv.ParseInt(portHex, 16, 64)
				if err != nil {
					continue
				}
				// Match any non-zero inode on int(portNum) == targetPort
				if int(portNum) == targetPort {
					inode, err := strconv.ParseUint(fields[9], 10, 64)
					if err == nil && inode > 0 {
						inodes = append(inodes, inode)
					}
				}
			}
		}
		file.Close()
	}
	return inodes
}

func isXrayProxyaProcess(comm, exe string) bool {
	lowerComm := strings.ToLower(comm)
	lowerExe := strings.ToLower(exe)

	if lowerComm == "xray" || lowerComm == "xray-proxya" || lowerComm == "pathd" {
		return true
	}
	if strings.Contains(lowerExe, "xray-proxya") || strings.Contains(lowerExe, "xray") || strings.Contains(lowerExe, "pathd") {
		return true
	}
	return false
}

func findTCPPortInodes(targetPort int) []uint64 {
	var inodes []uint64
	for _, procFile := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		file, err := os.Open(procFile)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		// Skip header line
		if scanner.Scan() {
			for scanner.Scan() {
				fields := strings.Fields(scanner.Text())
				if len(fields) < 10 {
					continue
				}
				// Local address field e.g. 0100007F:0050 (127.0.0.1:80)
				localAddr := fields[1]
				parts := strings.Split(localAddr, ":")
				if len(parts) != 2 {
					continue
				}
				portHex := parts[1]
				portNum, err := strconv.ParseInt(portHex, 16, 64)
				if err != nil {
					continue
				}
				// State 0A represents TCP_LISTEN
				state := fields[3]
				if int(portNum) == targetPort && state == "0A" {
					inode, err := strconv.ParseUint(fields[9], 10, 64)
					if err == nil && inode > 0 {
						inodes = append(inodes, inode)
					}
				}
			}
		}
		file.Close()
	}
	_ = hex.EncodeToString
	return inodes
}
