package xray

import (
	"archive/zip"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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

	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil { return true, pid }
	
	process, err := os.FindProcess(pid)
	if err == nil {
		if err := process.Signal(syscall.Signal(0)); err == nil { return true, pid }
	}
	return false, 0
}

func GetXrayUptime(pid int) string {
	info, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		pidPath := filepath.Join(config.GetConfigDir(), "xray.pid")
		info, err = os.Stat(pidPath)
	}
	if err != nil { return "N/A" }
	
	duration := time.Since(info.ModTime())
	if duration < 0 { duration = 0 }
	h, m := int(duration.Hours()), int(duration.Minutes())%60
	return fmt.Sprintf("%dh %dm", h, m)
}

func StopXray() {
	active, pid := GetXrayStatus()
	if active {
		// Kill the background 'run' manager group
		syscall.Kill(-pid, syscall.SIGKILL)
		process, _ := os.FindProcess(pid)
		process.Kill()
	}
	
	// CRITICAL FIX: Use sudo to ensure we can kill root processes and cleanup interfaces
	exec.Command("sudo", "pkill", "-9", "-x", "xray").Run()
	
	// Cleanup TUN interfaces if they exist
	exec.Command("sudo", "ip", "link", "delete", "proxya-tun").Run()
	exec.Command("sudo", "ip", "link", "delete", "lan-tun").Run()
	
	pidPath := filepath.Join(config.GetConfigDir(), "xray.pid")
	os.Remove(pidPath)
	time.Sleep(1 * time.Second)
}

func StartXrayBackground() error {
	path, err := os.Executable()
	if err != nil || path == "" { path = os.Args[0] }

	logPath := filepath.Join(config.GetConfigDir(), "xray.log")
	// Ensure log directory exists
	os.MkdirAll(filepath.Dir(logPath), 0755)
	
	cmdStr := fmt.Sprintf("nohup %s run > %s 2>&1 & echo $!", path, logPath)
	
	out, err := exec.Command("sh", "-c", cmdStr).Output()
	if err != nil { return err }

	pidStr := strings.TrimSpace(string(out))
	pidPath := filepath.Join(config.GetConfigDir(), "xray.pid")
	os.WriteFile(pidPath, []byte(pidStr), 0644)

	fmt.Printf("✅ Xray started in background (PID: %s)\n", pidStr)
	return nil
}

func RestartXrayService() error {
	fmt.Println("🔄 Restarting Xray service...")
	if _, err := exec.LookPath("systemctl"); err == nil {
		if exec.Command("systemctl", "is-active", "--quiet", "xray-proxya").Run() == nil {
			return exec.Command("systemctl", "restart", "xray-proxya").Run()
		}
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		if exec.Command("rc-service", "xray-proxya", "status").Run() == nil {
			return exec.Command("rc-service", "xray-proxya", "restart").Run()
		}
	}
	StopXray()
	return StartXrayBackground()
}

// --- Xray Execution Core ---

func StartXrayRaw(configPath string) error {
	bin := GetXrayBinaryPath()
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		fmt.Println("⬇️ Xray core missing, downloading...")
		if err := DownloadXray(); err != nil { return err }
	}
	cmd := exec.Command(bin, "run", "-c", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func StartXray(configPath string) (*exec.Cmd, error) {
	bin := GetXrayBinaryPath()
	cmd := exec.Command(bin, "run", "-c", configPath)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil { return nil, err }
	return cmd, nil
}

func StartXrayTemp(jsonData []byte) (*exec.Cmd, func(), error) {
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("xray-check-%d.json", time.Now().Unix()))
	os.WriteFile(tmpFile, jsonData, 0644)
	
	cmd := exec.Command(GetXrayBinaryPath(), "run", "-c", tmpFile)

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
	
	cmd := exec.Command(GetXrayBinaryPath(), "run", "-test", "-c", tmpFile)
	out, err := cmd.CombinedOutput()
	if err != nil { return fmt.Errorf("%v: %s", err, string(out)) }
	return nil
}

// --- Utils & Metrics ---

func GetXrayStats(pid int) (up, down int64, err error) { return 0, 0, nil }

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
	if os.Geteuid() == 0 { home = "/root" }
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
		if f.Name == "xray" {
			rc, err := f.Open()
			if err != nil { return err }
			defer rc.Close()

			outFile, err := os.OpenFile(binPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
			if err != nil { return err }
			defer outFile.Close()

			if _, err := io.Copy(outFile, rc); err != nil { return err }
			return nil
		}
	}
	return fmt.Errorf("xray binary not found in zip package")
}
