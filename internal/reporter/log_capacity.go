package reporter

import (
	"encoding/json"
	"fmt"
)

// LogCapacityWarning represents a warning about event log capacity issues
// that may affect evidence availability (RP-009).
type LogCapacityWarning struct {
	LogName     string  `json:"log_name"`
	FileSizeMB  float64 `json:"file_size_mb"`
	MaxSizeMB   float64 `json:"max_size_mb"`
	FillPercent float64 `json:"fill_percent"`
	LogMode     string  `json:"log_mode"`      // Circular, AutoBackup, Retain
	RecordCount int     `json:"record_count"`
	Warning     string  `json:"warning"`
	Severity    string  `json:"severity"`       // high, medium
}

// DetectLogCapacityWarnings analyzes raw check data for log capacity issues.
// It examines the log_tampering check's log_sizes array to find logs that are
// near capacity in circular (overwrite) mode, indicating potential evidence loss.
func DetectLogCapacityWarnings(rawCheckData map[string]string) []LogCapacityWarning {
	logData, ok := rawCheckData["log_tampering"]
	if !ok || logData == "" {
		return nil
	}

	var parsed struct {
		LogSizes []struct {
			Name        string  `json:"name"`
			FileSizeMB  float64 `json:"file_size_mb"`
			MaxSizeMB   float64 `json:"max_size_mb"`
			FillPercent float64 `json:"fill_percent"`
			LogMode     string  `json:"log_mode"`
			RecordCount int     `json:"record_count"`
			IsEnabled   bool    `json:"is_enabled"`
		} `json:"log_sizes"`
	}
	if err := json.Unmarshal([]byte(logData), &parsed); err != nil {
		return nil
	}

	var warnings []LogCapacityWarning
	for _, ls := range parsed.LogSizes {
		if !ls.IsEnabled {
			warnings = append(warnings, LogCapacityWarning{
				LogName:  ls.Name,
				LogMode:  "disabled",
				Warning:  fmt.Sprintf("Event log '%s' is DISABLED — no events are being recorded.", ls.Name),
				Severity: "high",
			})
			continue
		}

		// Circular mode + high fill = evidence is being overwritten
		if ls.LogMode == "Circular" && ls.FillPercent >= 90 {
			warnings = append(warnings, LogCapacityWarning{
				LogName:     ls.Name,
				FileSizeMB:  ls.FileSizeMB,
				MaxSizeMB:   ls.MaxSizeMB,
				FillPercent: ls.FillPercent,
				LogMode:     ls.LogMode,
				RecordCount: ls.RecordCount,
				Warning: fmt.Sprintf(
					"'%s' log is %.0f%% full (%.1f/%.1f MB) in Circular mode — oldest events are being overwritten. Evidence from earlier attack stages may already be lost.",
					ls.Name, ls.FillPercent, ls.FileSizeMB, ls.MaxSizeMB,
				),
				Severity: "high",
			})
			continue
		}

		// Very small log relative to max size = recently cleared and refilling
		if ls.MaxSizeMB > 0 && ls.FillPercent < 5 && ls.RecordCount > 0 {
			warnings = append(warnings, LogCapacityWarning{
				LogName:     ls.Name,
				FileSizeMB:  ls.FileSizeMB,
				MaxSizeMB:   ls.MaxSizeMB,
				FillPercent: ls.FillPercent,
				LogMode:     ls.LogMode,
				RecordCount: ls.RecordCount,
				Warning: fmt.Sprintf(
					"'%s' log is only %.1f%% full (%.2f/%.1f MB, %d records) — this may indicate the log was recently cleared. Cross-reference with Event 1102/104 clear events.",
					ls.Name, ls.FillPercent, ls.FileSizeMB, ls.MaxSizeMB, ls.RecordCount,
				),
				Severity: "medium",
			})
		}
	}
	return warnings
}
