package tune

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var ErrUnsupported = errors.New("unsupported sysctl key")

func normalizeValue(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}

func procPathForKey(key string) string {
	return filepath.Join("/proc/sys", strings.ReplaceAll(key, ".", "/"))
}

func ReadSysctl(key string) (string, error) {
	data, err := os.ReadFile(procPathForKey(key))
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrUnsupported
		}
		return "", err
	}
	return normalizeValue(string(data)), nil
}

func WriteSysctl(key, value string) error {
	cmd := exec.Command("sysctl", "-w", fmt.Sprintf("%s=%s", key, value))
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := normalizeValue(string(out))
		if msg == "" {
			msg = err.Error()
		}
		if strings.Contains(msg, "No such file") || strings.Contains(msg, "cannot stat") {
			return ErrUnsupported
		}
		return errors.New(msg)
	}
	return nil
}

func AvailableCongestionControls() ([]string, error) {
	value, err := ReadSysctl("net.ipv4.tcp_available_congestion_control")
	if err != nil {
		return nil, err
	}
	if value == "" {
		return nil, nil
	}
	return strings.Fields(value), nil
}

func KernelVersion() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}
