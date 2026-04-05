package xray

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
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
		syscall.Kill(-pid, syscall.SIGKILL)
		process, _ := os.FindProcess(pid)
		process.Kill()
		exec.Command("pkill", "-9", "xray").Run()
	}
	pidPath := filepath.Join(config.GetConfigDir(), "xray.pid")
	os.Remove(pidPath)
	time.Sleep(200 * time.Millisecond)
}

func RestartXrayService() error {
	fmt.Println("🔄 Restarting Xray service...")
	
	if _, err := exec.LookPath("systemctl"); err == nil {
		if exec.Command("systemctl", "is-active", "--quiet", "xray-proxya").Run() == nil {
			fmt.Println("🛰️ Systemd service detected, restarting...")
			return exec.Command("systemctl", "restart", "xray-proxya").Run()
		}
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		if exec.Command("rc-service", "xray-proxya", "status").Run() == nil {
			fmt.Println("🛰️ OpenRC service detected, restarting...")
			return exec.Command("rc-service", "xray-proxya", "restart").Run()
		}
	}

	StopXray()
	time.Sleep(500 * time.Millisecond)

	path, _ := os.Executable()
	// Use shell to background and write PID to avoid child capture
	cmdStr := fmt.Sprintf("nohup %s run > /dev/null 2>&1 & echo $!", path)
	out, err := exec.Command("sh", "-c", cmdStr).Output()
	if err != nil { return err }

	pidStr := strings.TrimSpace(string(out))
	pidPath := filepath.Join(config.GetConfigDir(), "xray.pid")
	os.WriteFile(pidPath, []byte(pidStr), 0644)

	fmt.Printf("✅ Xray started in background (Shell Mode, PID: %s)\n", pidStr)
	return nil
}

// --- Xray Execution Core ---

func StartXrayRaw(configPath string) error {
	bin := GetXrayBinaryPath()
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		fmt.Println("⬇️ Xray core missing at expected path, downloading...")
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
	return exec.Command(GetXrayBinaryPath(), "test", "-c", tmpFile).Run()
}

// --- Utils & Metrics ---

func GetXrayStats(pid int) (up, down int64, err error) {
	return 0, 0, nil
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
	// Root: /root/.local/share/xray-proxya/bin/xray
	// User: /home/user/.local/share/xray-proxya/bin/xray
	home, _ := os.UserHomeDir()
	if os.Geteuid() == 0 { home = "/root" }
	return filepath.Join(home, ".local", "share", "xray-proxya", "bin", "xray")
}

func GetXrayProxyaPath() string {
	path, _ := os.Executable()
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
	return GenerateX25519()
}

func GetRandomPath() string { return "/" + uuid.New().String()[:8] }
func GetRandomShortID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func DownloadXray() error {
	arch := "64"
	if strings.Contains(exec.Command("uname", "-m").String(), "aarch64") { arch = "arm64-v8a" }
	url := fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-%s.zip", arch)
	
	binPath := GetXrayBinaryPath()
	binDir := filepath.Dir(binPath)
	os.MkdirAll(binDir, 0755)

	zipFile := "/tmp/xray.zip"
	exec.Command("curl", "-Ls", url, "-o", zipFile).Run()
	exec.Command("unzip", "-o", zipFile, "xray", "-d", binDir).Run()
	os.Remove(zipFile)
	exec.Command("chmod", "+x", binPath).Run()
	return nil
}
