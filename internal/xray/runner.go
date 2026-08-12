package xray

import (
	"archive/zip"
	"crypto/rand"
	"crypto/sha256"
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
	"xray-proxya/internal/config"

	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
)

var restartHook func() error

// PinnedXrayVersion is deliberately fixed for reproducible installs. Update
// this value only after the release has passed the project's gateway and
// protocol regression tests.
const PinnedXrayVersion = "v26.3.27"

// RegisterRestartHook installs the post-restart runtime synchronizer used by
// consumers that own kernel state associated with the Xray process. The hook
// runs only after the new process has been started successfully.
func RegisterRestartHook(hook func() error) {
	restartHook = hook
}

func GetXrayAssetPath() string {
	return filepath.Join(config.GetHomeDir(), ".local", "share", "xray-proxya", "bin")
}

func RestartXrayService() error {
	return config.WithLifecycleLock(func() error {
		if err := restartXrayService(); err != nil {
			return err
		}
		if restartHook != nil {
			if err := restartHook(); err != nil {
				return fmt.Errorf("restore runtime state after Xray restart: %w", err)
			}
		}
		return nil
	})
}

// RestartXrayServiceWithoutHook is used by gateway transitions that are
// deliberately changing the TUN state themselves. All ordinary restarts must
// use RestartXrayService so the registered runtime synchronizer runs.
func RestartXrayServiceWithoutHook() error {
	return restartXrayService()
}

func restartXrayService() error {
	return ManageSystemdUnit("restart", MainServiceUnit)
}

// --- Xray Execution Core ---

func StartXrayRaw(configPath string) error {
	bin := GetXrayBinaryPath()
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		fmt.Println("⬇️ Xray core missing, downloading...")
		if err := DownloadXray(); err != nil {
			return err
		}
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
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func StartXrayTemp(jsonData []byte) (*exec.Cmd, func(), error) {
	tmp, err := os.CreateTemp(os.TempDir(), "xray-check-*.json")
	if err != nil {
		return nil, nil, err
	}
	tmpFile := tmp.Name()
	if _, err := tmp.Write(jsonData); err != nil {
		tmp.Close()
		os.Remove(tmpFile)
		return nil, nil, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpFile)
		return nil, nil, err
	}

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
	tmp, err := os.CreateTemp(os.TempDir(), "xray-test-*.json")
	if err != nil {
		return err
	}
	tmpFile := tmp.Name()
	if _, err := tmp.Write(jsonData); err != nil {
		tmp.Close()
		os.Remove(tmpFile)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpFile)
		return err
	}
	defer os.Remove(tmpFile)

	bin := GetXrayBinaryPath()
	cmd := exec.Command(bin, "run", "-test", "-c", tmpFile)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(bin))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(out))
	}
	return nil
}

// --- Utils & Metrics ---

func GetXrayStats(apiPort int) (map[string]int64, error) {
	bin := GetXrayBinaryPath()
	cmd := exec.Command(bin, "api", "statsquery", "--server=127.0.0.1:"+fmt.Sprint(apiPort), "--pattern=", "--reset=false")
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(bin))
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Use map[string]interface{} for dynamic parsing because 'stat' can be missing or different types

	var raw map[string]interface{}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}

	stats := make(map[string]int64)
	statVal, ok := raw["stat"]
	if !ok || statVal == nil {
		return stats, nil
	}

	// Xray standard return is an array of stats
	if list, ok := statVal.([]interface{}); ok {
		for _, item := range list {
			if m, ok := item.(map[string]interface{}); ok {
				name, _ := m["name"].(string)
				// Value is returned as a string or number depending on version/protobuf mapping
				var value int64
				switch v := m["value"].(type) {
				case float64:
					value = int64(v)
				case string:
					fmt.Sscanf(v, "%d", &value)
				}
				if name != "" {
					stats[name] = value
				}
			}
		}
	} else if m, ok := statVal.(map[string]interface{}); ok {
		// Single object case
		name, _ := m["name"].(string)
		var value int64
		switch v := m["value"].(type) {
		case float64:
			value = int64(v)
		case string:
			fmt.Sscanf(v, "%d", &value)
		}
		if name != "" {
			stats[name] = value
		}
	}

	return stats, nil
}

func RemoveUserAPI(apiPort int, inboundTag, email string) error {
	bin := GetXrayBinaryPath()
	cmd := exec.Command(bin, "api", "rmu", "--server=127.0.0.1:"+fmt.Sprint(apiPort), "-tag="+inboundTag, email)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(bin))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(out))
	}
	return nil
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

func GetXrayBinaryPath() string {
	return filepath.Join(config.GetHomeDir(), ".local", "share", "xray-proxya", "bin", "xray")
}

func GetXrayProxyaPath() string {
	path, err := os.Executable()
	if err != nil || path == "" {
		return os.Args[0]
	}
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
		if err := DownloadXray(); err != nil {
			return "", "", err
		}
	}
	out, err := exec.Command(bin, "vlessenc").Output()
	if err != nil {
		return "", "", err
	}
	lines := strings.Split(string(out), "\n")
	var encryption, decryption string
	var inKEM bool
	for _, line := range lines {
		if strings.Contains(line, "Authentication: ML-KEM-768") {
			inKEM = true
		}
		if inKEM {
			if strings.Contains(line, "\"decryption\":") {
				parts := strings.Split(line, "\"")
				if len(parts) >= 4 {
					decryption = parts[3]
				}
			} else if strings.Contains(line, "\"encryption\":") {
				parts := strings.Split(line, "\"")
				if len(parts) >= 4 {
					encryption = parts[3]
				}
			}
		}
		if encryption != "" && decryption != "" {
			break
		}
	}
	if encryption == "" || decryption == "" {
		return "", "", fmt.Errorf("failed to parse xray vlessenc output")
	}
	return encryption, decryption, nil
}

func GetRandomPath() string { return "/" + uuid.New().String()[:8] }
func GetRandomShortID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func extractSHA256(content string) (string, error) {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		normalized := strings.ToLower(line)
		var hashPart string
		if idx := strings.Index(normalized, "sha2-256="); idx >= 0 {
			hashPart = line[idx+len("sha2-256="):]
		} else if idx := strings.Index(normalized, "sha256="); idx >= 0 {
			hashPart = line[idx+len("sha256="):]
		} else if idx := strings.Index(normalized, "sha-256="); idx >= 0 {
			hashPart = line[idx+len("sha-256="):]
		} else if idx := strings.Index(normalized, "sha256:"); idx >= 0 {
			hashPart = line[idx+len("sha256:"):]
		} else if idx := strings.Index(normalized, "256="); idx >= 0 {
			hashPart = line[idx+len("256="):]
		}

		if hashPart != "" {
			hashPart = strings.TrimSpace(hashPart)
			if len(hashPart) == 64 {
				if _, err := hex.DecodeString(hashPart); err == nil {
					return hashPart, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no valid SHA256 hash found in digest")
}

func DownloadXray() error {
	arch := "64"
	out, _ := exec.Command("uname", "-m").Output()
	if strings.Contains(string(out), "aarch64") || strings.Contains(string(out), "arm64") {
		arch = "arm64-v8a"
	}
	url := xrayDownloadURL(arch)
	binPath := GetXrayBinaryPath()
	binDir := filepath.Dir(binPath)
	os.MkdirAll(binDir, 0755)

	// 1. Download digest file first to verify the ZIP file
	respDgst, err := http.Get(url + ".dgst")
	if err != nil {
		return fmt.Errorf("failed to download xray digest: %w", err)
	}
	defer respDgst.Body.Close()
	if respDgst.StatusCode != http.StatusOK {
		return fmt.Errorf("xray digest download returned status %s", respDgst.Status)
	}
	dgstBytes, err := io.ReadAll(respDgst.Body)
	if err != nil {
		return fmt.Errorf("failed to read xray digest body: %w", err)
	}
	expectedHash, err := extractSHA256(string(dgstBytes))
	if err != nil {
		return fmt.Errorf("invalid xray digest format: %w", err)
	}

	// 2. Download the core zip file
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("xray download returned status %s", resp.Status)
	}

	tmpZip, err := os.CreateTemp("", "xray-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmpZip.Name())

	if _, err := io.Copy(tmpZip, resp.Body); err != nil {
		return err
	}
	tmpZip.Close()

	// 3. Compute SHA256 of the downloaded file
	zipBytes, err := os.ReadFile(tmpZip.Name())
	if err != nil {
		return fmt.Errorf("failed to read downloaded zip: %w", err)
	}
	hasher := sha256.New()
	hasher.Write(zipBytes)
	actualHash := hex.EncodeToString(hasher.Sum(nil))

	// 4. Verify integrity
	if actualHash != expectedHash {
		return fmt.Errorf("integrity check failed: xray zip SHA256 mismatch (got %s, expected %s)", actualHash, expectedHash)
	}

	// 5. Unpack
	r, err := zip.OpenReader(tmpZip.Name())
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		baseName := filepath.Base(f.Name)
		if baseName == "xray" || strings.HasSuffix(baseName, ".dat") {
			err := func() error {
				rc, err := f.Open()
				if err != nil {
					return err
				}
				defer rc.Close()

				targetPath := filepath.Join(binDir, baseName)
				outFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
				if err != nil {
					return err
				}
				defer outFile.Close()

				if _, err := io.Copy(outFile, rc); err != nil {
					return err
				}
				return nil
			}()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func xrayDownloadURL(arch string) string {
	return fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/download/%s/Xray-linux-%s.zip", PinnedXrayVersion, arch)
}
