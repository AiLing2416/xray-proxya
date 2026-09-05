package tune

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// ModuleStatus represents the detection status of a Linux kernel module.
type ModuleStatus string

const (
	ModuleStatusLoaded    ModuleStatus = "loaded"    // Loaded in memory (/proc/modules)
	ModuleStatusBuiltin   ModuleStatus = "builtin"   // Compiled directly into the kernel (modules.builtin)
	ModuleStatusAvailable ModuleStatus = "available" // Present on disk and loadable (modprobe -n)
	ModuleStatusMissing   ModuleStatus = "missing"   // Not found in memory, builtin, or modprobe
)

// ModuleInfo holds the status and presence of a kernel module.
type ModuleInfo struct {
	Name    string       `json:"name"`
	Status  ModuleStatus `json:"status"`
	Present bool         `json:"present"`
}

// NormalizeModuleName standardizes module names (replacing hyphens with underscores).
func NormalizeModuleName(name string) string {
	return strings.ReplaceAll(strings.TrimSpace(name), "-", "_")
}

// ModuleRegistry provides an interface for inspecting kernel modules.
type ModuleRegistry interface {
	Inspect(name string) ModuleInfo
	InspectAll(names []string) map[string]ModuleInfo
}

type linuxModuleRegistry struct {
	loadedModules  map[string]bool
	builtinModules map[string]bool
}

// NewModuleRegistry creates and initializes a module registry snapshot from /proc/modules and modules.builtin.
func NewModuleRegistry() ModuleRegistry {
	loaded, builtin := readKernelModuleSets()
	return &linuxModuleRegistry{
		loadedModules:  loaded,
		builtinModules: builtin,
	}
}

func (r *linuxModuleRegistry) Inspect(name string) ModuleInfo {
	norm := NormalizeModuleName(name)
	if r.loadedModules[norm] || r.loadedModules[name] {
		return ModuleInfo{Name: name, Status: ModuleStatusLoaded, Present: true}
	}
	if r.builtinModules[norm] || r.builtinModules[name] {
		return ModuleInfo{Name: name, Status: ModuleStatusBuiltin, Present: true}
	}
	if err := exec.Command("modprobe", "-n", name).Run(); err == nil {
		return ModuleInfo{Name: name, Status: ModuleStatusAvailable, Present: true}
	}
	return ModuleInfo{Name: name, Status: ModuleStatusMissing, Present: false}
}

func (r *linuxModuleRegistry) InspectAll(names []string) map[string]ModuleInfo {
	results := make(map[string]ModuleInfo, len(names))
	for _, name := range names {
		results[name] = r.Inspect(name)
	}
	return results
}

// InspectModule inspects a single module using a freshly sampled registry.
func InspectModule(name string) ModuleInfo {
	return NewModuleRegistry().Inspect(name)
}

// InspectModules inspects multiple modules using a single shared registry snapshot.
func InspectModules(names []string) map[string]ModuleInfo {
	return NewModuleRegistry().InspectAll(names)
}

func readKernelModuleSets() (map[string]bool, map[string]bool) {
	loaded := make(map[string]bool)
	builtin := make(map[string]bool)

	// Read loaded modules from /proc/modules
	if file, err := os.Open("/proc/modules"); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) > 0 {
				modName := NormalizeModuleName(fields[0])
				loaded[modName] = true
				loaded[fields[0]] = true
			}
		}
		file.Close()
	}

	// Read builtin modules from current kernel release
	var release string
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err == nil {
		var buf []byte
		for _, b := range uname.Release {
			if b == 0 {
				break
			}
			buf = append(buf, byte(b))
		}
		release = string(buf)
	}

	builtinPaths := []string{
		fmt.Sprintf("/lib/modules/%s/modules.builtin", release),
		"/lib/modules/modules.builtin",
	}

	for _, path := range builtinPaths {
		if file, err := os.Open(path); err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasSuffix(line, ".ko") {
					parts := strings.Split(line, "/")
					base := strings.TrimSuffix(parts[len(parts)-1], ".ko")
					base = NormalizeModuleName(base)
					builtin[base] = true
				}
			}
			file.Close()
			break
		}
	}

	return loaded, builtin
}
