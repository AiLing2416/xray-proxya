package xray

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"xray-proxya/internal/config"
)

const serviceUnitName = "xray-proxya"

type ServiceState struct {
	IsRoot        bool
	InitSystem    string
	ControlMode   string
	UnitInstalled bool
	Active        bool
	PID           int
	Uptime        string
	LogPath       string
	ConfigPath    string
	ServiceFile   string
	Status        string
	Hint          string
	XrayPath      string
	XrayPresent   bool
	XrayVersion   string
	GeoIPPath     string
	GeoIPPresent  bool
	GeoIPFeature  string
}

func GetServiceState() ServiceState {
	state := ServiceState{
		IsRoot:     os.Geteuid() == 0,
		InitSystem: "none",
		LogPath:    GetXrayLogPath(),
		ConfigPath: config.GetConfigPath(),
		Uptime:     "-",
		Status:     "stopped",
		XrayPath:   GetXrayBinaryPath(),
		GeoIPPath:  filepath.Join(GetXrayAssetPath(), "geoip.dat"),
	}

	if _, err := exec.LookPath("systemctl"); err == nil {
		state.InitSystem = "systemd"
		if path := findSystemdServiceFile(serviceUnitName + ".service"); path != "" {
			state.UnitInstalled = true
			state.ServiceFile = path
			state.ControlMode = "systemd"
		}
		if active, pid := getSystemdState(serviceUnitName); active {
			state.Active = true
			state.PID = pid
			state.Status = "running"
			state.ControlMode = "systemd"
		}
	}

	if state.InitSystem == "none" {
		if _, err := exec.LookPath("rc-service"); err == nil {
			state.InitSystem = "openrc"
		}
	}
	if state.InitSystem == "openrc" {
		if _, err := os.Stat(openRCServiceFile(serviceUnitName)); err == nil {
			state.UnitInstalled = true
			state.ServiceFile = openRCServiceFile(serviceUnitName)
			if state.ControlMode == "" {
				state.ControlMode = "openrc"
			}
		}
		if active, pid := getOpenRCState(serviceUnitName); active {
			state.Active = true
			state.PID = pid
			state.Status = "running"
			state.ControlMode = "openrc"
		}
	}

	if active, pid := GetXrayStatus(); active {
		if !state.Active {
			state.Active = true
			state.Status = "running"
		}
		if state.PID == 0 {
			state.PID = pid
		}
		if state.ControlMode == "" || !state.UnitInstalled {
			state.ControlMode = "nohup"
		}
	}

	if state.Active && state.PID > 0 {
		state.Uptime = GetXrayUptime(state.PID)
	}
	if state.ControlMode == "" {
		if state.UnitInstalled {
			state.ControlMode = state.InitSystem
		} else {
			state.ControlMode = "nohup"
		}
	}
	state.XrayPresent, state.XrayVersion = inspectXrayBinary(state.XrayPath)
	state.GeoIPPresent, state.GeoIPFeature = inspectGeoIPDat(state.GeoIPPath)
	state.Hint = buildServiceHint(state)
	return state
}

func ReadLogTail(lines int) (string, error) {
	data, err := os.ReadFile(GetXrayLogPath())
	if err != nil {
		return "", err
	}
	return tailLogContent(string(data), lines), nil
}

func findSystemdServiceFile(unit string) string {
	for _, path := range []string{
		filepath.Join("/etc/systemd/system", unit),
		filepath.Join("/lib/systemd/system", unit),
		filepath.Join("/usr/lib/systemd/system", unit),
	} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func openRCServiceFile(name string) string {
	return filepath.Join("/etc/init.d", name)
}

func getSystemdState(name string) (bool, int) {
	cmd := exec.Command("systemctl", "is-active", name)
	if err := cmd.Run(); err != nil {
		return false, 0
	}
	out, err := exec.Command("systemctl", "show", "-p", "MainPID", "--value", name).Output()
	if err != nil {
		return true, 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return true, pid
}

func getOpenRCState(name string) (bool, int) {
	if err := exec.Command("rc-service", name, "status").Run(); err != nil {
		return false, 0
	}
	active, pid := GetXrayStatus()
	if active {
		return true, pid
	}
	return true, 0
}

func buildServiceHint(state ServiceState) string {
	switch {
	case state.Active && state.ControlMode == "systemd":
		return "Managed by systemd."
	case state.Active && state.ControlMode == "openrc":
		return "Managed by OpenRC."
	case state.Active && state.ControlMode == "nohup":
		return "Running in rootless/nohup mode with xray.pid tracking."
	case state.IsRoot && state.UnitInstalled:
		return fmt.Sprintf("Managed unit installed via %s, currently stopped.", state.InitSystem)
	case state.IsRoot:
		return "No managed unit found. Start will fall back to nohup until a service is installed."
	default:
		return "Rootless mode uses nohup and xray.pid. Install/uninstall is unavailable."
	}
}

func tailLogContent(content string, lines int) string {
	if lines <= 0 || content == "" {
		return ""
	}
	hasTrailingNewline := strings.HasSuffix(content, "\n")
	parts := strings.Split(content, "\n")
	if hasTrailingNewline && len(parts) > 0 {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return ""
	}
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	out := strings.Join(parts, "\n")
	if hasTrailingNewline {
		out += "\n"
	}
	return out
}

func inspectXrayBinary(path string) (bool, string) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false, "missing"
	}
	cmd := exec.Command(path, "version")
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+GetXrayAssetPath())
	out, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed == "" {
			trimmed = err.Error()
		}
		return true, trimmed
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return true, "present"
	}
	return true, strings.TrimSpace(lines[0])
}

func inspectGeoIPDat(path string) (bool, string) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false, "missing"
	}
	f, err := os.Open(path)
	if err != nil {
		return true, "present but unreadable"
	}
	defer f.Close()

	head := make([]byte, 12)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF {
		return true, fmt.Sprintf("present, size=%d, read error", info.Size())
	}
	head = head[:n]
	return true, fmt.Sprintf("size=%d, head=%s", info.Size(), hex.EncodeToString(head))
}
