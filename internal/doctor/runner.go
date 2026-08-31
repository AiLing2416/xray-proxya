package doctor

import (
	"context"
	"sync"
	"time"

	"xray-proxya/internal/config"
)

// RunDiagnostics executes all health checks and produces a structured Report.
func RunDiagnostics(ctx context.Context, opts Options) *Report {
	if opts.Timeout <= 0 {
		opts.Timeout = 12 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	// Load user config if available to detect role and configured ports
	cfg, _ := config.LoadConfig()
	var role config.AppRole
	if cfg != nil {
		role = cfg.Role
	}
	if opts.RoleOverride != "" {
		role = config.AppRole(opts.RoleOverride)
	}

	report := &Report{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Role:      string(role),
	}
	if report.Role == "" {
		report.Role = "generic"
	}

	var results []CheckResult
	var mu sync.Mutex

	appendResults := func(res []CheckResult) {
		mu.Lock()
		results = append(results, res...)
		mu.Unlock()
	}

	appendSingle := func(res CheckResult) {
		mu.Lock()
		results = append(results, res)
		mu.Unlock()
	}

	var wg sync.WaitGroup

	// 1. Core & Geo assets (Fast local file check)
	wg.Add(1)
	go func() {
		defer wg.Done()
		appendResults(CheckCore(ctx))
	}()

	// 2. Port conflict detection (Fast local /proc & socket check)
	wg.Add(1)
	go func() {
		defer wg.Done()
		appendResults(CheckPortConflicts(ctx, cfg))
	}()

	// 3. Clock skew (Network NTP/HTTP probe)
	wg.Add(1)
	go func() {
		defer wg.Done()
		appendSingle(CheckClockSkew(ctx))
	}()

	// 4. Kernel modules & sysctl (Local kernel inspection)
	wg.Add(1)
	go func() {
		defer wg.Done()
		appendResults(CheckKernel(ctx, role))
	}()

	// 5. User session lingering (Local loginctl check)
	wg.Add(1)
	go func() {
		defer wg.Done()
		appendSingle(CheckUserLinger(ctx))
	}()

	// 6. Public UDP multi-protocol reachability (Network UDP probe, Server role)
	wg.Add(1)
	go func() {
		defer wg.Done()
		appendSingle(CheckUDPCapabilities(ctx, role))
	}()

	// 7. Modern web protocols & security (Network DoH/H2/H3/ECH probe, Server role)
	wg.Add(1)
	go func() {
		defer wg.Done()
		appendSingle(CheckModernProtocols(ctx, role))
	}()

	wg.Wait()

	report.Results = results
	calculateSummary(report)

	return report
}

func calculateSummary(report *Report) {
	for _, r := range report.Results {
		report.Summary.Total++
		switch r.Status {
		case StatusPass:
			report.Summary.Passed++
		case StatusWarn:
			report.Summary.Warning++
		case StatusFail:
			report.Summary.Failed++
		case StatusSkip:
			report.Summary.Skipped++
		}
	}
	report.Summary.Healthy = (report.Summary.Failed == 0)
}
