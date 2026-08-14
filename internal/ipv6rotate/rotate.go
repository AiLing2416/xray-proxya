// Package ipv6rotate implements the privileged half of rotating subscription
// addresses.  The HTTP server has no CAP_NET_ADMIN; it asks this daemon for a
// new address over a private Unix socket instead.
package ipv6rotate

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"xray-proxya/internal/config"
	"xray-proxya/pkg/utils"
)

type request struct {
	Operation string `json:"operation"`
}
type response struct {
	Address string `json:"address,omitempty"`
	Error   string `json:"error,omitempty"`
}
type state struct {
	Addresses []string `json:"addresses"`
}

var mutex sync.Mutex

func SocketPath(instance string) string {
	return filepath.Join(config.GetConfigDir(), "ipv6-rotate", instance+".sock")
}
func statePath(instance string) string {
	return filepath.Join(config.GetConfigDir(), "ipv6-rotate", instance+".json")
}

func Validate(rotation config.IPv6Config) error {
	if strings.TrimSpace(rotation.Interface) == "" || strings.TrimSpace(rotation.Subnet) == "" {
		return fmt.Errorf("IPv6 rotation requires --interface and --subnet")
	}
	if _, _, err := net.ParseCIDR(rotation.Subnet); err != nil {
		return fmt.Errorf("invalid IPv6 subnet: %w", err)
	}
	iface, err := net.InterfaceByName(rotation.Interface)
	if err != nil || iface == nil {
		return fmt.Errorf("network interface %q is unavailable", rotation.Interface)
	}
	return nil
}

func Serve(instance string, rotation config.IPv6Config) error {
	if err := Validate(rotation); err != nil {
		return err
	}
	dir := filepath.Dir(SocketPath(instance))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	_ = os.Remove(SocketPath(instance))
	listener, err := net.Listen("unix", SocketPath(instance))
	if err != nil {
		return fmt.Errorf("listen on rotation socket: %w", err)
	}
	defer func() { listener.Close(); _ = os.Remove(SocketPath(instance)) }()
	if err := os.Chmod(SocketPath(instance), 0600); err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handle(conn, instance, rotation)
	}
}

func handle(conn net.Conn, instance string, rotation config.IPv6Config) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	var req request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(response{Error: "invalid request"})
		return
	}
	if req.Operation != "next" {
		_ = json.NewEncoder(conn).Encode(response{Error: "unsupported operation"})
		return
	}
	address, err := NextAddress(instance, rotation)
	if err != nil {
		_ = json.NewEncoder(conn).Encode(response{Error: err.Error()})
		return
	}
	_ = json.NewEncoder(conn).Encode(response{Address: address})
}

func Next(socket string) (string, error) {
	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		return "", fmt.Errorf("IPv6 rotation service unavailable: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := json.NewEncoder(conn).Encode(request{Operation: "next"}); err != nil {
		return "", err
	}
	var res response
	if err := json.NewDecoder(conn).Decode(&res); err != nil {
		return "", err
	}
	if res.Error != "" {
		return "", fmt.Errorf("%s", res.Error)
	}
	if res.Address == "" {
		return "", fmt.Errorf("rotation service returned no address")
	}
	return res.Address, nil
}

func NextAddress(instance string, rotation config.IPv6Config) (string, error) {
	mutex.Lock()
	defer mutex.Unlock()
	address, err := utils.GenerateRandomIPv6(rotation.Subnet)
	if err != nil {
		return "", err
	}
	current := state{}
	data, _ := os.ReadFile(statePath(instance))
	if len(data) > 0 {
		_ = json.Unmarshal(data, &current)
	}
	limit := rotation.MaxAddresses
	if limit <= 0 {
		limit = 6
	}
	for len(current.Addresses) >= limit {
		old := current.Addresses[0]
		current.Addresses = current.Addresses[1:]
		_ = utils.RemoveIPv6Addr(old, rotation.Interface)
		if rotation.EnableNDP {
			_ = utils.RemoveNDPProxy(old, rotation.Interface)
		}
	}
	if err := utils.SetupIPv6Addr(address, rotation.Interface); err != nil {
		return "", fmt.Errorf("assign IPv6 address: %w", err)
	}
	if rotation.EnableNDP {
		if err := utils.SetupNDPProxy(address, rotation.Interface); err != nil {
			_ = utils.RemoveIPv6Addr(address, rotation.Interface)
			return "", fmt.Errorf("configure NDP proxy: %w", err)
		}
	}
	current.Addresses = append(current.Addresses, address)
	encoded, err := json.Marshal(current)
	if err != nil {
		return "", err
	}
	temp, err := os.CreateTemp(filepath.Dir(statePath(instance)), ".state-")
	if err != nil {
		return "", err
	}
	name := temp.Name()
	defer os.Remove(name)
	if _, err := temp.Write(encoded); err != nil {
		temp.Close()
		return "", err
	}
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return "", err
	}
	if err := temp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(name, statePath(instance)); err != nil {
		return "", err
	}
	return address, nil
}
