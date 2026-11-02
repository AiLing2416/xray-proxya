package xray

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"xray-proxya/internal/config"
)

var (
	// DefaultSystemBinaryCandidates defines the standard public system paths probed for Xray core.
	DefaultSystemBinaryCandidates = []string{
		"/usr/bin/xray",
		"/usr/local/bin/xray",
	}

	// DefaultSystemAssetDirs defines the standard public system paths probed for dat assets.
	DefaultSystemAssetDirs = []string{
		"/usr/share/xray",
		"/usr/share/v2ray",
	}

	// Regex matching outputs such as "Xray 26.10.31 (Xray...", "Xray v26.10.31...", or "Xray core version 26.10.31..."
	xrayVerPrefixRegex = regexp.MustCompile(`(?i)(?:^|\s)xray(?:\s+core)?(?:\s+version)?\s+v?([0-9]+(?:\.[0-9]+)+(?:[-+][a-zA-Z0-9.-]+)?)`)

	// Regex matching standalone versions like "v26.10.31", "26.10.31", "1.8.24", "26.10.31-beta.1"
	standaloneVerRegex = regexp.MustCompile(`^v?([0-9]+(?:\.[0-9]+)+(?:[-+][a-zA-Z0-9.-]+)?)$`)
)

var (
	resolverMu       sync.RWMutex
	cachedXrayBinary string
	cachedXrayAsset  string
)

// ParseXrayVersion extracts and normalizes the Xray version string from either full command
// output or a raw version string. Returns a canonical version with a "v" prefix (e.g. "v26.10.31").
func ParseXrayVersion(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("empty version string")
	}

	// 1. Try matching Xray output format
	if matches := xrayVerPrefixRegex.FindStringSubmatch(trimmed); len(matches) >= 2 {
		return "v" + matches[1], nil
	}

	// 2. Try matching standalone version
	if matches := standaloneVerRegex.FindStringSubmatch(trimmed); len(matches) >= 2 {
		return "v" + matches[1], nil
	}

	return "", fmt.Errorf("unable to parse xray version from: %q", raw)
}

// parseVersionComponents splits a version into numeric components and an optional pre-release suffix.
func parseVersionComponents(v string) ([]int, string, error) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if v == "" {
		return nil, "", fmt.Errorf("empty version string")
	}

	var prerelease string
	if idx := strings.IndexAny(v, "-+"); idx >= 0 {
		prerelease = v[idx+1:]
		v = v[:idx]
	}

	parts := strings.Split(v, ".")
	if len(parts) == 0 {
		return nil, "", fmt.Errorf("invalid version format: %q", v)
	}

	var nums []int
	for _, p := range parts {
		if p == "" {
			return nil, "", fmt.Errorf("invalid version component in %q", v)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, "", fmt.Errorf("invalid version component %q in %q", p, v)
		}
		nums = append(nums, n)
	}
	return nums, prerelease, nil
}

// CompareVersions compares two Xray version strings (CalVer or SemVer).
// Returns:
//
//	 1 if v1 > v2
//	 0 if v1 == v2
//	-1 if v1 < v2
//	error if either version string cannot be parsed.
func CompareVersions(v1, v2 string) (int, error) {
	parsed1, err := ParseXrayVersion(v1)
	if err != nil {
		return 0, fmt.Errorf("failed to parse version %q: %w", v1, err)
	}
	parsed2, err := ParseXrayVersion(v2)
	if err != nil {
		return 0, fmt.Errorf("failed to parse version %q: %w", v2, err)
	}

	nums1, pre1, err := parseVersionComponents(parsed1)
	if err != nil {
		return 0, fmt.Errorf("failed to parse components of %q: %w", parsed1, err)
	}
	nums2, pre2, err := parseVersionComponents(parsed2)
	if err != nil {
		return 0, fmt.Errorf("failed to parse components of %q: %w", parsed2, err)
	}

	maxLen := len(nums1)
	if len(nums2) > maxLen {
		maxLen = len(nums2)
	}

	for i := 0; i < maxLen; i++ {
		n1, n2 := 0, 0
		if i < len(nums1) {
			n1 = nums1[i]
		}
		if i < len(nums2) {
			n2 = nums2[i]
		}
		if n1 > n2 {
			return 1, nil
		}
		if n1 < n2 {
			return -1, nil
		}
	}

	// Main numeric components are equal. Compare pre-release / build metadata.
	// In SemVer/CalVer, a release version is higher than a pre-release version.
	if pre1 == "" && pre2 != "" {
		return 1, nil
	}
	if pre1 != "" && pre2 == "" {
		return -1, nil
	}
	if pre1 != pre2 {
		if pre1 > pre2 {
			return 1, nil
		}
		return -1, nil
	}

	return 0, nil
}

// IsVersionAtLeast checks if candidate version meets or exceeds the floor version requirement.
func IsVersionAtLeast(version, floor string) (bool, error) {
	cmp, err := CompareVersions(version, floor)
	if err != nil {
		return false, err
	}
	return cmp >= 0, nil
}

// Resolver configures and executes binary and asset discovery.
type Resolver struct {
	Getenv          func(key string) string
	Stat            func(name string) (os.FileInfo, error)
	LookPath        func(file string) (string, error)
	ExecVersion     func(binPath string) (string, error)
	HomeDir         string
	Candidates      []string
	SystemAssetDirs []string
	PinnedVersion   string
}

// NewDefaultResolver constructs a Resolver configured with live OS hooks.
func NewDefaultResolver() *Resolver {
	return &Resolver{
		Getenv:          os.Getenv,
		Stat:            os.Stat,
		LookPath:        exec.LookPath,
		ExecVersion:     execVersionDefault,
		HomeDir:         config.GetHomeDir(),
		Candidates:      DefaultSystemBinaryCandidates,
		SystemAssetDirs: DefaultSystemAssetDirs,
		PinnedVersion:   PinnedXrayVersion,
	}
}

func execVersionDefault(binPath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, "version")
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(binPath))
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (r *Resolver) statFile(name string) (os.FileInfo, error) {
	if r.Stat != nil {
		return r.Stat(name)
	}
	return os.Stat(name)
}

func (r *Resolver) hasDatFiles(dir string) bool {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return false
	}
	for _, dat := range []string{"geoip.dat", "geosite.dat"} {
		p := filepath.Join(dir, dat)
		if info, err := r.statFile(p); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

func (r *Resolver) defaultPrivateAssetPath() string {
	home := r.HomeDir
	if home == "" {
		home = config.GetHomeDir()
	}
	return filepath.Join(home, ".local", "share", "xray-proxya", "bin")
}

func (r *Resolver) defaultPrivateBinaryPath() string {
	return filepath.Join(r.defaultPrivateAssetPath(), "xray")
}

// ResolveBinary probes candidate paths and returns the chosen Xray core binary path:
// 1. Prioritize user explicitly specified environment variable XRAY_BIN (if set and file exists).
// 2. Probe system public paths (/usr/bin/xray, /usr/local/bin/xray, and LookPath found xray).
//    Check if candidate version >= PinnedXrayVersion. If qualified, reuse system binary.
// 3. If no qualified system binary exists, check private directory.
// 4. If private directory does not exist either, fallback to default private binary path.
func (r *Resolver) ResolveBinary() string {
	// 1. User explicit environment variable XRAY_BIN (if set and file exists)
	if r.Getenv != nil {
		if envBin := strings.TrimSpace(r.Getenv("XRAY_BIN")); envBin != "" {
			if info, err := r.statFile(envBin); err == nil && !info.IsDir() {
				return envBin
			}
		}
	}

	// 2. Probe system public candidates
	privateBin := r.defaultPrivateBinaryPath()
	candidates := make([]string, 0, len(r.Candidates)+1)
	candidates = append(candidates, r.Candidates...)
	if r.LookPath != nil {
		if lp, err := r.LookPath("xray"); err == nil && strings.TrimSpace(lp) != "" {
			candidates = append(candidates, strings.TrimSpace(lp))
		}
	}

	seen := make(map[string]bool)
	cleanPrivate := filepath.Clean(privateBin)

	pinned := r.PinnedVersion
	if pinned == "" {
		pinned = PinnedXrayVersion
	}

	for _, cand := range candidates {
		cand = strings.TrimSpace(cand)
		if cand == "" {
			continue
		}
		cleanCand := filepath.Clean(cand)
		if seen[cleanCand] {
			continue
		}
		seen[cleanCand] = true

		// Skip private binary path during system candidate probe
		if cleanCand == cleanPrivate {
			continue
		}

		info, err := r.statFile(cleanCand)
		if err != nil || info.IsDir() {
			continue
		}

		// Ensure file has executable permissions
		if info.Mode()&0111 == 0 {
			continue
		}

		// Query version
		if r.ExecVersion == nil {
			continue
		}
		verOutput, err := r.ExecVersion(cleanCand)
		if err != nil {
			continue
		}
		candVer, err := ParseXrayVersion(verOutput)
		if err != nil {
			continue
		}

		ok, err := IsVersionAtLeast(candVer, pinned)
		if err == nil && ok {
			return cleanCand
		}
	}

	// 3. Check private directory
	if info, err := r.statFile(privateBin); err == nil && !info.IsDir() {
		return privateBin
	}

	// 4. Fallback to default private binary path
	return privateBin
}

// ResolveAsset resolves the asset directory for GeoIP / GeoSite dat files:
// 1. If XRAY_LOCATION_ASSET is set, prioritize it.
// 2. Otherwise check the directory of the current Xray binary; if dat files exist there, use it.
// 3. Otherwise check system public asset paths (/usr/share/xray or /usr/share/v2ray) for dat files.
// 4. Otherwise fallback to private directory.
func (r *Resolver) ResolveAsset(binPath string) string {
	// 1. Environment variable XRAY_LOCATION_ASSET
	if r.Getenv != nil {
		if envAsset := strings.TrimSpace(r.Getenv("XRAY_LOCATION_ASSET")); envAsset != "" {
			return envAsset
		}
	}

	// 2. Binary co-located directory
	if binPath != "" {
		binDir := filepath.Dir(binPath)
		if r.hasDatFiles(binDir) {
			return binDir
		}
	}

	// 3. System public asset paths
	for _, dir := range r.SystemAssetDirs {
		if r.hasDatFiles(dir) {
			return dir
		}
	}

	// 4. Fallback to private directory
	return r.defaultPrivateAssetPath()
}

// GetDefaultPrivateAssetPath returns the default private asset directory path.
func GetDefaultPrivateAssetPath() string {
	return filepath.Join(config.GetHomeDir(), ".local", "share", "xray-proxya", "bin")
}

// GetDefaultPrivateBinaryPath returns the default private Xray binary path.
func GetDefaultPrivateBinaryPath() string {
	return filepath.Join(GetDefaultPrivateAssetPath(), "xray")
}

// ResolveXrayBinaryPath resolves the binary path using live system settings without caching.
func ResolveXrayBinaryPath() string {
	return NewDefaultResolver().ResolveBinary()
}

// ResolveXrayAssetPath resolves the asset directory path using live system settings without caching.
func ResolveXrayAssetPath(binPath string) string {
	return NewDefaultResolver().ResolveAsset(binPath)
}

// GetXrayBinaryPath resolves and returns the active Xray core binary path.
// The resolved path is cached thread-safely across repeated invocations.
func GetXrayBinaryPath() string {
	resolverMu.RLock()
	cached := cachedXrayBinary
	resolverMu.RUnlock()
	if cached != "" {
		if _, err := os.Stat(cached); err == nil {
			return cached
		}
	}

	resolverMu.Lock()
	defer resolverMu.Unlock()
	if cachedXrayBinary != "" {
		if _, err := os.Stat(cachedXrayBinary); err == nil {
			return cachedXrayBinary
		}
	}

	cachedXrayBinary = ResolveXrayBinaryPath()
	return cachedXrayBinary
}

// GetXrayAssetPath resolves and returns the active directory containing geoip.dat and geosite.dat.
// The resolved path is cached thread-safely across repeated invocations.
func GetXrayAssetPath() string {
	resolverMu.RLock()
	cached := cachedXrayAsset
	resolverMu.RUnlock()
	if cached != "" {
		return cached
	}

	resolverMu.Lock()
	defer resolverMu.Unlock()
	if cachedXrayAsset != "" {
		return cachedXrayAsset
	}

	bin := cachedXrayBinary
	if bin == "" {
		cachedXrayBinary = ResolveXrayBinaryPath()
		bin = cachedXrayBinary
	}

	cachedXrayAsset = ResolveXrayAssetPath(bin)
	return cachedXrayAsset
}

// ResetResolverCache clears cached paths for binary and asset resolutions.
// Intended for testing or after downloading/updating the core.
func ResetResolverCache() {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	cachedXrayBinary = ""
	cachedXrayAsset = ""
}
