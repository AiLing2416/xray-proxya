package xray

import (
	"archive/zip"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"xray-proxya/internal/config"

	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
)

// --- Process Management (PID & /proc) ---

func GetXrayStatus() (bool, int) {
	pidPath := filepath.Join(config.GetConfigDir(), "xray.pid")
	data, err := os.ReadFile(pidPath)
	if err != nil { return false, 0 }

	var pid int
	fmt.Sscanf(string(data), "%d", &pid)
	if pid <= 0 { return false, 0 }

	// Check if process exists
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
		return false, 0
	}

	// Verify identity: Check if /proc/[pid]/exe points to our xray binary
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err == nil {
		// On some systems it might be a symlink to the actual binary, but this is a good enough check
		if !strings.Contains(exePath, "xray") {
			return false, 0
		}
	}

	process, err := os.FindProcess(pid)
	if err == nil {
		if err := process.Signal(syscall.Signal(0)); err == nil { return true, pid }
	}
	return false, 0
}

func GetXrayUptime(pid int) string {
	// For uptime, we look at the process start time in /proc
	info, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	if err != nil { return "N/A" }
	
	duration := time.Since(info.ModTime())
	if duration < 0 { duration = 0 }
	h, m := int(duration.Hours()), int(duration.Minutes())%60
	return fmt.Sprintf("%dh %dm", h, m)
}

func StopXray() {
	active, pid := GetXrayStatus()
	if active {
		// Try graceful first, then kill
		process, _ := os.FindProcess(pid)
		process.Signal(syscall.SIGTERM)
		
		time.Sleep(500 * time.Millisecond)
		if active, _ := GetXrayStatus(); active {
			syscall.Kill(-pid, syscall.SIGKILL) // Kill process group
			process.Kill()
		}
	}
	
	if os.Geteuid() == 0 {
		// Only cleanup specific interfaces we manage
		exec.Command("ip", "link", "delete", "proxya-tun").Run()
		exec.Command("ip", "link", "delete", "lan-tun").Run()
	}
	
	pidPath := filepath.Join(config.GetConfigDir(), "xray.pid")
	os.Remove(pidPath)
}

func GetXrayAssetPath() string {
	home, _ := os.UserHomeDir()
	if os.Geteuid() == 0 { home = "/root" }
	return filepath.Join(home, ".local", "share", "xray-proxya", "bin")
}

func StartXrayBackground() error {
	path, err := os.Executable()
	if err != nil || path == "" { path = os.Args[0] }
	absPath, _ := filepath.Abs(path)

	logPath := filepath.Join(config.GetConfigDir(), "xray.log")
	os.MkdirAll(filepath.Dir(logPath), 0700)
	
	cmd := exec.Command(absPath, "run")
	// Standardized asset location
	assetPath := GetXrayAssetPath()
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+assetPath)
	
	// Open for appending with 0600
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil { return err }
	
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return err
	}
	logFile.Close()

	// Wait a bit to see if it crashes immediately
	time.Sleep(1 * time.Second)
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return fmt.Errorf("xray exited immediately. Check logs at %s", logPath)
	}

	pidStr := fmt.Sprintf("%d", cmd.Process.Pid)
	pidPath := filepath.Join(config.GetConfigDir(), "xray.pid")
	os.WriteFile(pidPath, []byte(pidStr), 0600)

	fmt.Printf("✅ Xray started in background (PID: %s)\n", pidStr)
	return nil
}

func RestartXrayService() error {
	fmt.Println("🔄 Restarting Xray service...")
	isRoot := os.Geteuid() == 0
	
	if isRoot {
		if _, err := exec.LookPath("systemctl"); err == nil {
			// Check system mode
			if exec.Command("systemctl", "list-unit-files", "xray-proxya.service").Run() == nil {
				return exec.Command("systemctl", "restart", "xray-proxya").Run()
			}
		}
		if _, err := exec.LookPath("rc-service"); err == nil {
			if exec.Command("rc-service", "xray-proxya", "status").Run() == nil {
				return exec.Command("rc-service", "xray-proxya", "restart").Run()
			}
		}
	}

	// Rootless or no service found: Use nohup fallback
	StopXray()
	return StartXrayBackground()
}

func StartService() error {
	isRoot := os.Geteuid() == 0
	if isRoot {
		if _, err := exec.LookPath("systemctl"); err == nil {
			if exec.Command("systemctl", "list-unit-files", "xray-proxya.service").Run() == nil {
				return exec.Command("systemctl", "start", "xray-proxya").Run()
			}
		}
		if _, err := exec.LookPath("rc-service"); err == nil {
			return exec.Command("rc-service", "xray-proxya", "start").Run()
		}
	}
	active, pid := GetXrayStatus()
	if active {
		fmt.Printf("ℹ️ Xray is already running (PID: %d).\n", pid)
		return nil
	}
	return StartXrayBackground()
}

func StopService() {
	isRoot := os.Geteuid() == 0
	if isRoot {
		if _, err := exec.LookPath("systemctl"); err == nil {
			if exec.Command("systemctl", "list-unit-files", "xray-proxya.service").Run() == nil {
				exec.Command("systemctl", "stop", "xray-proxya").Run()
				return
			}
		}
		if _, err := exec.LookPath("rc-service"); err == nil {
			exec.Command("rc-service", "xray-proxya", "stop").Run()
			return
		}
	}
	StopXray()
}

// --- Xray Execution Core ---

func StartXrayRaw(configPath string) error {
	bin := GetXrayBinaryPath()
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		fmt.Println("⬇️ Xray core missing, downloading...")
		if err := DownloadXray(); err != nil { return err }
	}
	cmd := exec.Command(bin, "run", "-c", configPath)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(bin))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func StartXray(configPath string) (*exec.Cmd, error) {
	bin := GetXrayBinaryPath()
	cmd := exec.Command(bin, "run", "-c", configPath)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(bin))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil { return nil, err }
	return cmd, nil
}

func StartXrayTemp(jsonData []byte) (*exec.Cmd, func(), error) {
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("xray-check-%d.json", time.Now().Unix()))
	os.WriteFile(tmpFile, jsonData, 0644)
	
	bin := GetXrayBinaryPath()
	cmd := exec.Command(bin, "run", "-c", tmpFile)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(bin))

	if err := cmd.Start(); err != nil {
		os.Remove(tmpFile)
		return nil, nil, err
	}
	return cmd, func() { cmd.Process.Kill(); os.Remove(tmpFile) }, nil
}

func ValidateConfig(jsonData []byte) error {
	tmpFile := filepath.Join(os.TempDir(), "xray-test.json")
	os.WriteFile(tmpFile, jsonData, 0644)
	defer os.Remove(tmpFile)
	
	bin := GetXrayBinaryPath()
	cmd := exec.Command(bin, "run", "-test", "-c", tmpFile)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(bin))
	out, err := cmd.CombinedOutput()
	if err != nil { return fmt.Errorf("%v: %s", err, string(out)) }
	return nil
}

// --- Utils & Metrics ---

func GetXrayStats(apiPort int) (map[string]int64, error) {
	bin := GetXrayBinaryPath()
	cmd := exec.Command(bin, "api", "statsquery", "--server=127.0.0.1:"+fmt.Sprint(apiPort), "--pattern=", "--reset=false")
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(bin))
	out, err := cmd.Output()
	if err != nil { 
		fmt.Printf("DEBUG: API Command Failed: %v\n", err)
		return nil, err 
	}
	fmt.Printf("DEBUG: Raw API Output: %s\n", string(out))

	// Use map[string]interface{} for dynamic parsing because 'stat' can be missing or different types
	var raw map[string]interface{}
	if err := json.Unmarshal(out, &raw); err != nil { return nil, err }

	stats := make(map[string]int64)
	statVal, ok := raw["stat"]
	if !ok || statVal == nil { return stats, nil }

	// Xray standard return is an array of stats
	if list, ok := statVal.([]interface{}); ok {
		for _, item := range list {
			if m, ok := item.(map[string]interface{}); ok {
				name, _ := m["name"].(string)
				// Value is returned as a string or number depending on version/protobuf mapping
				var value int64
				switch v := m["value"].(type) {
				case float64: value = int64(v)
				case string: fmt.Sscanf(v, "%d", &value)
				}
				if name != "" { stats[name] = value }
			}
		}
	} else if m, ok := statVal.(map[string]interface{}); ok {
		// Single object case
		name, _ := m["name"].(string)
		var value int64
		switch v := m["value"].(type) {
		case float64: value = int64(v)
		case string: fmt.Sscanf(v, "%d", &value)
		}
		if name != "" { stats[name] = value }
	}

	return stats, nil
}

func RemoveUserAPI(apiPort int, inboundTag, email string) error {
	bin := GetXrayBinaryPath()
	cmd := exec.Command(bin, "api", "rmu", "--server=127.0.0.1:"+fmt.Sprint(apiPort), "-tag="+inboundTag, email)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(bin))
	out, err := cmd.CombinedOutput()
	if err != nil { return fmt.Errorf("%v: %s", err, string(out)) }
	return nil
}

func GetFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil { return 0, err }
	l, err := net.ListenTCP("tcp", addr)
	if err != nil { return 0, err }
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func GetXrayBinaryPath() string {
	home, _ := os.UserHomeDir()
	if os.Geteuid() == 0 && home == "" {
		home = "/root"
	}
	return filepath.Join(home, ".local", "share", "xray-proxya", "bin", "xray")
}

func GetXrayProxyaPath() string {
	path, err := os.Executable()
	if err != nil || path == "" { return os.Args[0] }
	return path
}

// --- Crypto & Random Helpers ---

func GenerateX25519() (string, string, error) {
	var priv [32]byte
	rand.Read(priv[:])
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	return base64.RawURLEncoding.EncodeToString(priv[:]), base64.RawURLEncoding.EncodeToString(pub[:]), nil
}

func GenerateMLKEM() (string, string, error) {
	bin := GetXrayBinaryPath()
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		if err := DownloadXray(); err != nil { return "", "", err }
	}
	out, err := exec.Command(bin, "vlessenc").Output()
	if err != nil { return "", "", err }
	lines := strings.Split(string(out), "\n")
	var encryption, decryption string
	var inKEM bool
	for _, line := range lines {
		if strings.Contains(line, "Authentication: ML-KEM-768") { inKEM = true }
		if inKEM {
			if strings.Contains(line, "\"decryption\":") {
				parts := strings.Split(line, "\"")
				if len(parts) >= 4 { decryption = parts[3] }
			} else if strings.Contains(line, "\"encryption\":") {
				parts := strings.Split(line, "\"")
				if len(parts) >= 4 { encryption = parts[3] }
			}
		}
		if encryption != "" && decryption != "" { break }
	}
	if encryption == "" || decryption == "" { return "", "", fmt.Errorf("failed to parse xray vlessenc output") }
	return encryption, decryption, nil
}

func GetRandomPath() string { return "/" + uuid.New().String()[:8] }
func GetRandomShortID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func DownloadXray() error {
	arch := "64"
	out, _ := exec.Command("uname", "-m").Output()
	if strings.Contains(string(out), "aarch64") || strings.Contains(string(out), "arm64") { arch = "arm64-v8a" }
	url := fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-%s.zip", arch)
	binPath := GetXrayBinaryPath()
	binDir := filepath.Dir(binPath)
	os.MkdirAll(binDir, 0755)

	resp, err := http.Get(url)
	if err != nil { return err }
	defer resp.Body.Close()

	tmpZip, err := os.CreateTemp("", "xray-*.zip")
	if err != nil { return err }
	defer os.Remove(tmpZip.Name())
	
	if _, err := io.Copy(tmpZip, resp.Body); err != nil { return err }
	tmpZip.Close()

	r, err := zip.OpenReader(tmpZip.Name())
	if err != nil { return err }
	defer r.Close()

	for _, f := range r.File {
		if f.Name == "xray" || strings.HasSuffix(f.Name, ".dat") {
			rc, err := f.Open()
			if err != nil { return err }
			defer rc.Close()

			targetPath := filepath.Join(binDir, f.Name)
			if f.Name == "xray" {
				targetPath = binPath
			}
			
			outFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
			if err != nil { return err }
			
			if _, err := io.Copy(outFile, rc); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
		}
	}
	return nil
}
