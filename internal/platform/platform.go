// Package platform provides OS detection and intrusion detection check definitions.
package platform

import (
	"runtime"
	"time"
)

// Check defines a single intrusion detection check.
type Check struct {
	// ID is the unique identifier matching config.toml keys.
	ID string
	// Name is the human-readable display name.
	Name string
	// Description explains what attack technique this check detects.
	Description string
	// Script is the path within the embedded filesystem (e.g. "scripts/windows/c2_connections.ps1").
	Script string
	// Timeout is the maximum execution time before the process is killed.
	Timeout time.Duration
	// OutputFormat is the expected output format ("json").
	OutputFormat string
	// RequiresAdmin indicates if elevated privileges are needed.
	RequiresAdmin bool
}

// DetectOS returns the current operating system identifier.
func DetectOS() string {
	return runtime.GOOS
}

// GetChecks returns the intrusion detection checks for the current OS.
func GetChecks() []Check {
	switch DetectOS() {
	case "windows":
		return WindowsChecks()
	case "linux":
		return LinuxChecks()
	default:
		return nil
	}
}

// FilterChecks returns only checks whose IDs are in the allowed list.
// If allowed is nil or empty, all checks are returned.
func FilterChecks(checks []Check, allowed []string) []Check {
	if len(allowed) == 0 {
		return checks
	}
	set := make(map[string]bool, len(allowed))
	for _, id := range allowed {
		set[id] = true
	}
	var filtered []Check
	for _, c := range checks {
		if set[c.ID] {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

// FilterEnabled returns only checks that are enabled in the config.
// If enabledMap is nil, all checks are returned.
func FilterEnabled(checks []Check, enabledMap map[string]bool) []Check {
	if enabledMap == nil {
		return checks
	}
	var filtered []Check
	for _, c := range checks {
		enabled, exists := enabledMap[c.ID]
		if !exists || enabled {
			filtered = append(filtered, c)
		}
	}
	return filtered
}
