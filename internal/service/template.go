package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"xray-proxya/internal/config"
	"xray-proxya/internal/pathd"
)

// PathdConfigPath returns the path to the pathd JSON configuration.
func PathdConfigPath() string {
	return filepath.Join(config.GetConfigDir(), "pathd.json")
}

// PathdBinaryPath returns the expected location of the pathd binary.
func PathdBinaryPath() string {
	return filepath.Join(config.GetHomeDir(), ".local", "share", "xray-proxya", "bin", "pathd")
}

// MainUnitCapabilities computes required Linux capabilities for the main service unit.
func MainUnitCapabilities(cfg *config.UserConfig) string {
	if cfg != nil && cfg.Role == config.RoleGateway {
		return "CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW"
	}
	return "CAP_NET_BIND_SERVICE"
}

// BuildSystemdServiceContent generates the systemd unit file content for the main proxy service.
func BuildSystemdServiceContent(binPath, workDir, assetDir, configDir, capabilities string, system, privateDevices bool) string {
	userLine := ""
	wantedBy := "default.target"
	capabilityLines := ""
	privateDevicesValue := "yes"
	if !privateDevices {
		privateDevicesValue = "no"
	}
	if system {
		userLine = "User=root\n"
		wantedBy = "multi-user.target"
		capabilityLines = fmt.Sprintf("CapabilityBoundingSet=%s\nAmbientCapabilities=%s\n", capabilities, capabilities)
	}
	return fmt.Sprintf(`[Unit]
Description=Xray-Proxya Service
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
%sExecStart=%s run
Restart=on-failure
RestartSec=2
WorkingDirectory=%s
Environment=XRAY_LOCATION_ASSET=%s
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
PrivateDevices=%s
ReadWritePaths=%s %s
%s

[Install]
WantedBy=%s
`, userLine, binPath, workDir, assetDir, privateDevicesValue, configDir, assetDir, capabilityLines, wantedBy)
}

// BuildSubServiceContent generates the systemd unit file content for the subscription service.
func BuildSubServiceContent(binPath, workDir, configDir, assetDir string, system bool) string {
	userLine := ""
	wantedBy := "default.target"
	capabilityLines := ""
	if system {
		userLine = "User=root\n"
		wantedBy = "multi-user.target"
		capabilityLines = "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n"
	}
	return fmt.Sprintf(`[Unit]
Description=Xray-Proxya Subscription Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
%sExecStartPre=%s sub validate
ExecStart=%s sub run
Restart=on-failure
RestartSec=2
WorkingDirectory=%s
Environment=XRAY_LOCATION_ASSET=%s
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=%s %s
%s

[Install]
WantedBy=%s
`, userLine, binPath, binPath, workDir, assetDir, configDir, assetDir, capabilityLines, wantedBy)
}

// BuildIPv6RotateServiceContent generates the systemd unit file content for the IPv6 rotation service.
func BuildIPv6RotateServiceContent(binPath, workDir, configDir, assetDir string) string {
	return fmt.Sprintf(`[Unit]
Description=Xray-Proxya IPv6 Rotation Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStartPre=%s ipv6-rotate validate
ExecStart=%s ipv6-rotate run
Restart=on-failure
RestartSec=2
WorkingDirectory=%s
Environment=XRAY_LOCATION_ASSET=%s
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=%s %s
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
`, binPath, binPath, workDir, assetDir, configDir, assetDir)
}

// BuildPathdServiceContent generates the systemd unit file content for the PathLink ICMP agent.
func BuildPathdServiceContent(binaryPath, configPath string) string {
	return fmt.Sprintf(`[Unit]
Description=Xray-Proxya PathLink Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# pathd needs only raw ICMP; it never changes routing, firewall, or files.
User=root
ExecStart=%s serve --config %s
Restart=on-failure
RestartSec=2
UMask=0077
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
`, binaryPath, configPath)
}

// WritePathdConfig writes out the pathd configuration file based on the user config.
func WritePathdConfig(cfg *config.UserConfig) error {
	if cfg == nil || cfg.Role != config.RoleServer {
		return fmt.Errorf("pathd configuration is available only on a Server")
	}
	if cfg.Path.Listen == "" {
		return fmt.Errorf("pathd listen address is not configured; run 'path set --listen <address>'")
	}
	if err := pathd.ValidateListenAddress(cfg.Path.Listen); err != nil {
		return err
	}
	if cfg.Path.IdleSeconds <= 0 {
		return fmt.Errorf("pathd idle timeout is invalid")
	}
	if cfg.Path.Token == "" {
		return fmt.Errorf("pathd token is not configured; run 'path set --token <token>'")
	}
	data, err := json.MarshalIndent(struct {
		Listen      string `json:"listen"`
		Token       string `json:"token"`
		IdleSeconds int    `json:"idle_seconds"`
	}{cfg.Path.Listen, cfg.Path.Token, cfg.Path.IdleSeconds}, "", "  ")
	if err != nil {
		return err
	}
	path := PathdConfigPath()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pathd.json-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
