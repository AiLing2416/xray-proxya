package doctor

import "time"

// Status represents the health status of a check item.
type Status string

const (
	StatusPass Status = "PASS"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
	StatusSkip Status = "SKIP"
)

// CheckResult records the diagnostic outcome of a single inspection.
type CheckResult struct {
	Category    string `json:"category"`
	Name        string `json:"name"`
	Status      Status `json:"status"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
	DurationMs  int64  `json:"duration_ms"`
}

// Summary provides aggregated metrics across all diagnostic checks.
type Summary struct {
	Passed  int  `json:"passed"`
	Warning int  `json:"warning"`
	Failed  int  `json:"failed"`
	Skipped int  `json:"skipped"`
	Total   int  `json:"total"`
	Healthy bool `json:"healthy"`
}

// Report holds the complete diagnostic report ready for output or serialization.
type Report struct {
	Timestamp string        `json:"timestamp"`
	Role      string        `json:"role"`
	Summary   Summary       `json:"summary"`
	Results   []CheckResult `json:"results"`
}

// Options configures a diagnostic run.
type Options struct {
	RoleOverride string
	Verbose      bool
	Timeout      time.Duration
}
