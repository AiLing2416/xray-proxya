package xray

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// GetXrayStatus checks if xray is running and returns (isActive, pid).
func GetXrayStatus() (bool, int) {
	home, _ := os.UserHomeDir()
	configDir := filepath.Join(home, ".config", "xray-proxya")
	configPath := filepath.Join(configDir, "xray_config.json")
	pidPath := filepath.Join(configDir, "xray.pid")

	// Strategy 1: /proc traversal (Best for multi-user/restricted shells)
	files, err := os.ReadDir("/proc")
	if err == nil {
		for _, f := range files {
			if !f.IsDir() { continue }
			pid, err := strconv.Atoi(f.Name())
			if err != nil { continue }
			cmdlinePath := filepath.Join("/proc", f.Name(), "cmdline")
			data, err := os.ReadFile(cmdlinePath)
			if err != nil { continue }
			cmdline := string(data)
			if strings.Contains(cmdline, "xray") && strings.Contains(cmdline, "run") && strings.Contains(cmdline, configPath) {
				return true, pid
			}
		}
	}

	// Strategy 2: PID file fallback (For environments without /proc or hidepid)
	if data, err := os.ReadFile(pidPath); err == nil {
		pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
		if pid > 0 {
			// Double check if process exists (kill -0)
			cmd := exec.Command("kill", "-0", strconv.Itoa(pid))
			if err := cmd.Run(); err == nil {
				return true, pid
			}
		}
	}

	return false, 0
}

func StopXray() error {
	active, pid := GetXrayStatus()
	if active && pid > 0 {
		process, err := os.FindProcess(pid)
		if err == nil {
			return process.Kill()
		}
	}
	return nil
}

// GetXrayUptime returns how long the pid has been running.
func GetXrayUptime(pid int) string {
	cmd := exec.Command("ps", "-p", fmt.Sprintf("%d", pid), "-o", "etimes=")
	out, err := cmd.Output()
	if err != nil { return "Unknown" }
	seconds, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	mins := (seconds % 3600) / 60
	
	if days > 0 { return fmt.Sprintf("%dd %dh %dm", days, hours, mins) }
	if hours > 0 { return fmt.Sprintf("%dh %dm", hours, mins) }
	return fmt.Sprintf("%dm", mins)
}

// GetXrayStats queries the stats from Xray API and categorizes into Direct and Relay.
func GetXrayStats(apiPort int) (direct int64, relay int64, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	server := fmt.Sprintf("127.0.0.1:%d", apiPort)
	cmd := exec.CommandContext(ctx, GetXrayBinaryPath(), "api", "statsquery", "--server="+server)
	out, err := cmd.CombinedOutput()
	if err != nil { return 0, 0, err }

	re := regexp.MustCompile(`"name":\s*"outbound>>>([^>]+)>>>traffic>>>([^"]+)",\s*"value":\s*(\d+)`)
	matches := re.FindAllStringSubmatch(string(out), -1)
	for _, m := range matches {
		tag := m[1]
		val, _ := strconv.ParseInt(m[3], 10, 64)
		if tag == "direct" {
			direct += val
		} else if strings.HasPrefix(tag, "outbound-") {
			relay += val
		}
	}
	return direct, relay, nil
}

func GetXrayBinaryPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "bin", "xray")
}

func GetFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// ValidateConfig spawns a temporary xray process with -test.
func ValidateConfig(configJSON []byte) error {
	tmpFile, err := os.CreateTemp("", "xray-check-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write(configJSON); err != nil {
		return err
	}
	tmpFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, GetXrayBinaryPath(), "run", "-test", "-c", tmpFile.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("config validation failed: %v\nOutput: %s", err, string(output))
	}
	return nil
}

// StartXray starts the xray process.
func StartXray(configPath string) (*exec.Cmd, error) {
	cmd := exec.Command(GetXrayBinaryPath(), "run", "-c", configPath)
	logFile, err := os.OpenFile(filepath.Join(filepath.Dir(configPath), "xray.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// StartXrayTemp starts a temp xray with given config data and returns cleanup func.
func StartXrayTemp(configJSON []byte) (*exec.Cmd, func(), error) {
	// First, validate
	if err := ValidateConfig(configJSON); err != nil {
		return nil, nil, err
	}

	tmpFile, err := os.CreateTemp("", "xray-temp-*.json")
	if err != nil {
		return nil, nil, err
	}
	if _, err := tmpFile.Write(configJSON); err != nil {
		os.Remove(tmpFile.Name())
		return nil, nil, err
	}
	tmpFile.Close()

	cmd := exec.Command(GetXrayBinaryPath(), "run", "-c", tmpFile.Name())
	
	// Capture output to a temporary log file for debugging
	logFile, err := os.CreateTemp("", "xray-log-*.log")
	if err == nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}

	if err := cmd.Start(); err != nil {
		os.Remove(tmpFile.Name())
		if logFile != nil { os.Remove(logFile.Name()) }
		return nil, nil, err
	}

	cleanup := func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		os.Remove(tmpFile.Name())
		if logFile != nil {
			logFile.Close()
			os.Remove(logFile.Name())
		}
	}

	// Wait a bit and check if it's still running
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(1500 * time.Millisecond):
		// Still running, assume success
		return cmd, cleanup, nil
	case err := <-done:
		// Exited early
		logContent, _ := os.ReadFile(logFile.Name())
		cleanup()
		return nil, nil, fmt.Errorf("xray exited early: %v\nOutput: %s", err, string(logContent))
	}
}

// GenerateX25519 generates Reality keys.
func GenerateX25519() (privateKey string, publicKey string, err error) {
	cmd := exec.Command(GetXrayBinaryPath(), "x25519")
	output, err := cmd.CombinedOutput()
	if err != nil { return "", "", err }
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "PrivateKey:") {
			parts := strings.Split(line, ":"); if len(parts) > 1 { privateKey = strings.TrimSpace(parts[1]) }
		} else if strings.Contains(line, "PublicKey") {
			parts := strings.Split(line, ":"); if len(parts) > 1 { publicKey = strings.TrimSpace(parts[1]) }
		}
	}
	if privateKey == "" || publicKey == "" { return "", "", fmt.Errorf("failed to parse x25519 output") }
	return privateKey, publicKey, nil
}

// GenerateMLKEM generates ML-KEM-768 keys.
func GenerateMLKEM() (encryptionKey string, decryptionKey string, err error) {
	cmd := exec.Command(GetXrayBinaryPath(), "vlessenc")
	output, err := cmd.CombinedOutput()
	if err != nil { return "", "", err }
	reEnc := regexp.MustCompile(`"encryption":\s*"([^"]+)"`)
	reDec := regexp.MustCompile(`"decryption":\s*"([^"]+)"`)
	encMatches := reEnc.FindAllStringSubmatch(string(output), -1)
	decMatches := reDec.FindAllStringSubmatch(string(output), -1)
	if len(encMatches) > 1 && len(decMatches) > 1 {
		encryptionKey, decryptionKey = encMatches[1][1], decMatches[1][1]
	} else if len(encMatches) > 0 && len(decMatches) > 0 {
		encryptionKey, decryptionKey = encMatches[0][1], decMatches[0][1]
	}
	if encryptionKey == "" || decryptionKey == "" { return "", "", fmt.Errorf("failed to parse vlessenc output") }
	return encryptionKey, decryptionKey, nil
}

// GetRandomPath returns a random XHTTP/WS path.
func GetRandomPath() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "/" + hex.EncodeToString(b)
}

// GetRandomShortID returns a random 8-char hex string.
func GetRandomShortID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// RestartXrayService restarts Xray either via systemd or by starting it manually in background.
func RestartXrayService() error {
	fmt.Println("🔄 Restarting Xray service...")
	if IsServiceActive() {
		fmt.Println("🛰️ Systemd service detected, restarting via systemctl...")
		return exec.Command("sudo", "systemctl", "restart", "xray-proxya").Run()
	}

	// Manual fallback
	StopXray()
	time.Sleep(500 * time.Millisecond)
	
	cmd := exec.Command(GetXrayProxyaPath(), "run")
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("manual restart failed: %v", err)
	}
	
	// Save PID for manual management
	home, _ := os.UserHomeDir()
	pidPath := filepath.Join(home, ".config", "xray-proxya", "xray.pid")
	os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0600)
	
	fmt.Printf("✅ Xray started in background (PID: %d)\n", cmd.Process.Pid)
	return nil
}

func IsServiceActive() bool {
	err := exec.Command("sudo", "systemctl", "is-active", "--quiet", "xray-proxya").Run()
	return err == nil
}

func GetXrayProxyaPath() string {
	path, _ := os.Executable()
	if _, err := os.Stat(path); err != nil {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".local", "bin", "xray-proxya")
	}
	return path
}
