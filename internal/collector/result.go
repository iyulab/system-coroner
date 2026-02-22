// Package collector implements parallel script execution for IoC collection.
package collector

import (
	"strings"
	"time"
)

// FailureKind classifies why a check failed to execute.
type FailureKind int

const (
	FailureNone        FailureKind = iota // no failure (ExitCode == 0)
	FailureTimeout                        // killed by timeout
	FailurePermission                     // access denied / permission denied
	FailureScriptError                    // script returned non-zero exit code
	FailureNotFound                       // interpreter or command not found
	FailureUnknown                        // unclassified error
)

// String returns a short human-readable label for the failure kind.
func (k FailureKind) String() string {
	switch k {
	case FailureNone:
		return "none"
	case FailureTimeout:
		return "timeout"
	case FailurePermission:
		return "permission_denied"
	case FailureScriptError:
		return "script_error"
	case FailureNotFound:
		return "not_found"
	default:
		return "unknown"
	}
}

// Result holds the output of a single check execution.
type Result struct {
	// CheckID is the unique identifier of the check.
	CheckID string
	// Stdout is the raw stdout output (expected JSON).
	Stdout []byte
	// Stderr is the raw stderr output (diagnostic messages).
	Stderr []byte
	// ExitCode is the process exit code (-1 if killed).
	ExitCode int
	// Duration is the actual execution time.
	Duration time.Duration
	// Error is non-nil if the check failed to execute.
	Error error
	// TimedOut is true if the check was killed due to timeout.
	TimedOut bool
	// FailureKind classifies the reason for failure.
	FailureKind FailureKind
	// CollectedAt is the UTC timestamp when collection started.
	CollectedAt time.Time
	// ChildPID is the PID of the spawned child process (0 if unavailable).
	ChildPID int
}

// maxStderrExcerpt is the maximum number of characters for the stderr excerpt.
const maxStderrExcerpt = 200

// permissionKeywords are patterns indicating a permission/elevation problem.
var permissionKeywords = []string{
	"access denied",
	"access is denied",
	"permission denied",
	"requires elevation",
	"run as administrator",
	"관리자",
}

// StderrExcerpt returns the first 200 characters of stderr (trimmed),
// with a hint appended when permission-related keywords are detected.
func (r *Result) StderrExcerpt() string {
	raw := strings.TrimSpace(string(r.Stderr))
	if raw == "" {
		return ""
	}

	excerpt := raw
	if len(excerpt) > maxStderrExcerpt {
		excerpt = excerpt[:maxStderrExcerpt] + "..."
	}

	lower := strings.ToLower(raw)
	for _, kw := range permissionKeywords {
		if strings.Contains(lower, kw) {
			excerpt += " [Hint: re-run with administrator privileges]"
			break
		}
	}

	return excerpt
}
