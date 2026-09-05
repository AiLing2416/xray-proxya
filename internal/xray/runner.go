package xray

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/pkg/utils"

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

func createTempConfigFile(jsonData []byte) (string, error) {
	tmp, err := os.CreateTemp(os.TempDir(), "xray-check-*.json")
	if err != nil {
		return "", err
	}
	tmpFile := tmp.Name()
	if _, err := tmp.Write(jsonData); err != nil {
		tmp.Close()
		os.Remove(tmpFile)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpFile)
		return "", err
	}
	return tmpFile, nil
}

// StartXrayTemp starts a temporary Xray process using the provided JSON config data.
func StartXrayTemp(jsonData []byte) (*exec.Cmd, func(), error) {
	return StartXrayTempWithOutput(jsonData, nil)
}

// StartXrayTempWithOutput starts a temporary Xray process using the provided JSON config data
// and redirects stderr to the specified writer if provided.
func StartXrayTempWithOutput(jsonData []byte, stderr io.Writer) (*exec.Cmd, func(), error) {
	tmpFile, err := createTempConfigFile(jsonData)
	if err != nil {
		return nil, nil, err
	}

	bin := GetXrayBinaryPath()
	cmd := exec.Command(bin, "run", "-c", tmpFile)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(bin))
	if stderr != nil {
		cmd.Stderr = stderr
	}

	if err := cmd.Start(); err != nil {
		os.Remove(tmpFile)
		return nil, nil, err
	}

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
			_ = os.Remove(tmpFile)
		})
	}
	return cmd, cleanup, nil
}

// ValidateRuntime performs an isolated sandbox runtime test by starting a temporary
// Xray instance with randomized dynamic ports to ensure the generated config can bind and run.
func ValidateRuntime(cfg *config.UserConfig) error {
	if cfg == nil {
		return fmt.Errorf("nil config provided")
	}

	testSocksPort, err := utils.GetFreePort()
	if err != nil {
		return fmt.Errorf("failed to allocate test-socks port: %w", err)
	}
	apiPort, err := utils.GetFreePort()
	if err != nil {
		return fmt.Errorf("failed to allocate api port: %w", err)
	}

	overrides := map[string]int{
		"test-socks":           testSocksPort,
		"api":                  apiPort,
		"gateway-tun-disabled": 1,
	}

	for _, m := range cfg.Presets {
		if m.Enabled {
			p, err := utils.GetFreePort()
			if err != nil {
				return fmt.Errorf("failed to allocate preset port: %w", err)
			}
			overrides[string(m.Mode)] = p
		}
	}

	for _, co := range cfg.CustomOutbounds {
		if co.InternalProxyPort > 0 {
			p, err := utils.GetFreePort()
			if err != nil {
				return fmt.Errorf("failed to allocate outbound socks port: %w", err)
			}
			overrides["outbound-"+co.Alias] = p
			if co.InternalHttpPort > 0 {
				hp, err := utils.GetFreePort()
				if err != nil {
					return fmt.Errorf("failed to allocate outbound http port: %w", err)
				}
				overrides["outbound-http-"+co.Alias] = hp
			}
		}
	}

	testJSON, err := GenerateXrayJSON(cfg, overrides, "")
	if err != nil {
		return fmt.Errorf("generate runtime test json: %w", err)
	}

	var stderrBuf bytes.Buffer
	cmd, cleanup, err := StartXrayTempWithOutput(testJSON, &stderrBuf)
	if err != nil {
		return err
	}
	defer cleanup()

	// Give it a tiny bit of time to start and check if it is still running
	time.Sleep(100 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		out := strings.TrimSpace(stderrBuf.String())
		if out != "" {
			return fmt.Errorf("temporary xray instance exited prematurely: %s", out)
		}
		return fmt.Errorf("temporary xray instance exited prematurely")
	}
	return nil
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
	return utils.GetFreePort()
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
