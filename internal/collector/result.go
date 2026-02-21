// Package collector implements parallel script execution for IoC collection.
package collector

import "time"

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
}
