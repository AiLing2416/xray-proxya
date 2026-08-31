package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"xray-proxya/internal/xray"
)

var xrayVerRegex = regexp.MustCompile(`Xray\s+([0-9]+\.[0-9]+\.[0-9]+)`)

// CheckCore inspects the presence, permissions, version match of the Xray core
// binary, as well as the geoip.dat and geosite.dat asset files.
func CheckCore(ctx context.Context) []CheckResult {
	var results []CheckResult

	// 1. Check Xray binary existence and permissions
	binStart := time.Now()
	binPath := xray.GetXrayBinaryPath()
	binInfo, err := os.Stat(binPath)

	if os.IsNotExist(err) {
		results = append(results, CheckResult{
			Category:    "Core & Assets",
			Name:        "Xray Binary",
			Status:      StatusFail,
			Detail:      fmt.Sprintf("Binary not found at %s", binPath),
			Remediation: "Install Xray core via 'xray-proxya service run' or manual download",
			DurationMs:  time.Since(binStart).Milliseconds(),
		})
	} else if err != nil {
		results = append(results, CheckResult{
			Category:    "Core & Assets",
			Name:        "Xray Binary",
			Status:      StatusFail,
			Detail:      fmt.Sprintf("Failed to stat %s: %v", binPath, err),
			Remediation: "Check file permissions and path access",
			DurationMs:  time.Since(binStart).Milliseconds(),
		})
	} else if binInfo.Mode()&0111 == 0 {
		results = append(results, CheckResult{
			Category:    "Core & Assets",
			Name:        "Xray Binary",
			Status:      StatusFail,
			Detail:      fmt.Sprintf("Binary at %s is not executable", binPath),
			Remediation: fmt.Sprintf("Grant execute permission: chmod +x %s", binPath),
			DurationMs:  time.Since(binStart).Milliseconds(),
		})
	} else {
		// Binary exists and is executable, test execution and version
		cmd := exec.CommandContext(ctx, binPath, "version")
		cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(binPath))
		out, err := cmd.Output()
		if err != nil {
			results = append(results, CheckResult{
				Category:    "Core & Assets",
				Name:        "Xray Binary & Version",
				Status:      StatusFail,
				Detail:      fmt.Sprintf("Failed to execute '%s version': %v", binPath, err),
				Remediation: "Verify binary architecture compatibility or reinstall core",
				DurationMs:  time.Since(binStart).Milliseconds(),
			})
		} else {
			outStr := string(out)
			match := xrayVerRegex.FindStringSubmatch(outStr)
			var currentVer string
			if len(match) >= 2 {
				currentVer = match[1]
			} else {
				// Fallback: take the first line
				lines := strings.Split(strings.TrimSpace(outStr), "\n")
				if len(lines) > 0 {
					currentVer = lines[0]
				}
			}

			pinnedVer := strings.TrimPrefix(xray.PinnedXrayVersion, "v")
			cleanCurVer := strings.TrimPrefix(currentVer, "v")

			if cleanCurVer == pinnedVer {
				results = append(results, CheckResult{
					Category:   "Core & Assets",
					Name:       "Xray Binary & Version",
					Status:     StatusPass,
					Detail:     fmt.Sprintf("v%s (matches pinned %s)", cleanCurVer, xray.PinnedXrayVersion),
					DurationMs: time.Since(binStart).Milliseconds(),
				})
			} else {
				results = append(results, CheckResult{
					Category:    "Core & Assets",
					Name:        "Xray Binary & Version",
					Status:      StatusWarn,
					Detail:      fmt.Sprintf("v%s (pinned is %s)", cleanCurVer, xray.PinnedXrayVersion),
					Remediation: "Consider updating xray binary to the pinned release version",
					DurationMs:  time.Since(binStart).Milliseconds(),
				})
			}
		}
	}

	// 2. Check Geo asset files
	geoStart := time.Now()
	assetDir := filepath.Dir(binPath)
	geoIPPath := filepath.Join(assetDir, "geoip.dat")
	geoSitePath := filepath.Join(assetDir, "geosite.dat")

	hasIP := fileExists(geoIPPath)
	hasSite := fileExists(geoSitePath)

	if hasIP && hasSite {
		results = append(results, CheckResult{
			Category:   "Core & Assets",
			Name:       "Geo Data Files",
			Status:     StatusPass,
			Detail:     "geoip.dat and geosite.dat present",
			DurationMs: time.Since(geoStart).Milliseconds(),
		})
	} else if !hasIP && !hasSite {
		results = append(results, CheckResult{
			Category:    "Core & Assets",
			Name:        "Geo Data Files",
			Status:      StatusWarn,
			Detail:      "Missing geoip.dat and geosite.dat",
			Remediation: "Routing domain/IP rules may fail without geo asset files",
			DurationMs:  time.Since(geoStart).Milliseconds(),
		})
	} else if !hasIP {
		results = append(results, CheckResult{
			Category:    "Core & Assets",
			Name:        "Geo Data Files",
			Status:      StatusWarn,
			Detail:      "Missing geoip.dat",
			Remediation: "Download geoip.dat to " + assetDir,
			DurationMs:  time.Since(geoStart).Milliseconds(),
		})
	} else {
		results = append(results, CheckResult{
			Category:    "Core & Assets",
			Name:        "Geo Data Files",
			Status:      StatusWarn,
			Detail:      "Missing geosite.dat",
			Remediation: "Download geosite.dat to " + assetDir,
			DurationMs:  time.Since(geoStart).Milliseconds(),
		})
	}

	return results
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
