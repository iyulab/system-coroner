package reporter

import (
	"encoding/json"
	"testing"
)

func TestDetectLogCapacityWarnings_NoData(t *testing.T) {
	// No log_tampering key → nil
	got := DetectLogCapacityWarnings(map[string]string{})
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}

	// Empty string → nil
	got = DetectLogCapacityWarnings(map[string]string{"log_tampering": ""})
	if got != nil {
		t.Fatalf("expected nil for empty string, got %v", got)
	}

	// Invalid JSON → nil
	got = DetectLogCapacityWarnings(map[string]string{"log_tampering": "not-json"})
	if got != nil {
		t.Fatalf("expected nil for bad JSON, got %v", got)
	}
}

func TestDetectLogCapacityWarnings_DisabledLog(t *testing.T) {
	data := map[string]interface{}{
		"log_sizes": []map[string]interface{}{
			{
				"name":         "Security",
				"file_size_mb": 0.0,
				"max_size_mb":  20.0,
				"fill_percent": 0.0,
				"log_mode":     "Circular",
				"record_count": 0,
				"is_enabled":   false,
			},
		},
	}
	raw, _ := json.Marshal(data)

	warnings := DetectLogCapacityWarnings(map[string]string{"log_tampering": string(raw)})
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(warnings))
	}
	w := warnings[0]
	if w.Severity != "high" {
		t.Errorf("expected severity high, got %s", w.Severity)
	}
	if w.LogMode != "disabled" {
		t.Errorf("expected log_mode disabled, got %s", w.LogMode)
	}
	if w.LogName != "Security" {
		t.Errorf("expected log_name Security, got %s", w.LogName)
	}
}

func TestDetectLogCapacityWarnings_CircularFull(t *testing.T) {
	data := map[string]interface{}{
		"log_sizes": []map[string]interface{}{
			{
				"name":         "Security",
				"file_size_mb": 19.5,
				"max_size_mb":  20.0,
				"fill_percent": 97.5,
				"log_mode":     "Circular",
				"record_count": 50000,
				"is_enabled":   true,
			},
		},
	}
	raw, _ := json.Marshal(data)

	warnings := DetectLogCapacityWarnings(map[string]string{"log_tampering": string(raw)})
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(warnings))
	}
	w := warnings[0]
	if w.Severity != "high" {
		t.Errorf("expected severity high, got %s", w.Severity)
	}
	if w.LogMode != "Circular" {
		t.Errorf("expected Circular, got %s", w.LogMode)
	}
	if w.FillPercent != 97.5 {
		t.Errorf("expected fill_percent 97.5, got %f", w.FillPercent)
	}
}

func TestDetectLogCapacityWarnings_RecentlyCleared(t *testing.T) {
	data := map[string]interface{}{
		"log_sizes": []map[string]interface{}{
			{
				"name":         "System",
				"file_size_mb": 0.5,
				"max_size_mb":  20.0,
				"fill_percent": 2.5,
				"log_mode":     "Circular",
				"record_count": 100,
				"is_enabled":   true,
			},
		},
	}
	raw, _ := json.Marshal(data)

	warnings := DetectLogCapacityWarnings(map[string]string{"log_tampering": string(raw)})
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(warnings))
	}
	w := warnings[0]
	if w.Severity != "medium" {
		t.Errorf("expected severity medium, got %s", w.Severity)
	}
	if w.FillPercent != 2.5 {
		t.Errorf("expected fill_percent 2.5, got %f", w.FillPercent)
	}
}

func TestDetectLogCapacityWarnings_HealthyLog(t *testing.T) {
	data := map[string]interface{}{
		"log_sizes": []map[string]interface{}{
			{
				"name":         "Application",
				"file_size_mb": 10.0,
				"max_size_mb":  20.0,
				"fill_percent": 50.0,
				"log_mode":     "Circular",
				"record_count": 25000,
				"is_enabled":   true,
			},
		},
	}
	raw, _ := json.Marshal(data)

	warnings := DetectLogCapacityWarnings(map[string]string{"log_tampering": string(raw)})
	if len(warnings) != 0 {
		t.Fatalf("expected 0 warnings for healthy log, got %d", len(warnings))
	}
}

func TestDetectLogCapacityWarnings_MultipleConditions(t *testing.T) {
	data := map[string]interface{}{
		"log_sizes": []map[string]interface{}{
			{
				"name":         "Security",
				"file_size_mb": 19.8,
				"max_size_mb":  20.0,
				"fill_percent": 99.0,
				"log_mode":     "Circular",
				"record_count": 60000,
				"is_enabled":   true,
			},
			{
				"name":         "Application",
				"file_size_mb": 10.0,
				"max_size_mb":  20.0,
				"fill_percent": 50.0,
				"log_mode":     "Circular",
				"record_count": 25000,
				"is_enabled":   true,
			},
			{
				"name":         "PowerShell",
				"file_size_mb": 0.0,
				"max_size_mb":  15.0,
				"fill_percent": 0.0,
				"log_mode":     "Circular",
				"record_count": 0,
				"is_enabled":   false,
			},
			{
				"name":         "System",
				"file_size_mb": 0.3,
				"max_size_mb":  20.0,
				"fill_percent": 1.5,
				"log_mode":     "Circular",
				"record_count": 50,
				"is_enabled":   true,
			},
		},
	}
	raw, _ := json.Marshal(data)

	warnings := DetectLogCapacityWarnings(map[string]string{"log_tampering": string(raw)})
	// Security (circular full) + PowerShell (disabled) + System (recently cleared) = 3
	if len(warnings) != 3 {
		t.Fatalf("expected 3 warnings, got %d", len(warnings))
	}

	// Verify ordering matches input order
	if warnings[0].LogName != "Security" || warnings[0].Severity != "high" {
		t.Errorf("warning[0]: expected Security/high, got %s/%s", warnings[0].LogName, warnings[0].Severity)
	}
	if warnings[1].LogName != "PowerShell" || warnings[1].Severity != "high" {
		t.Errorf("warning[1]: expected PowerShell/high, got %s/%s", warnings[1].LogName, warnings[1].Severity)
	}
	if warnings[2].LogName != "System" || warnings[2].Severity != "medium" {
		t.Errorf("warning[2]: expected System/medium, got %s/%s", warnings[2].LogName, warnings[2].Severity)
	}
}

func TestDetectLogCapacityWarnings_RetainMode(t *testing.T) {
	// Retain mode at 95% fill should NOT trigger (only Circular triggers)
	data := map[string]interface{}{
		"log_sizes": []map[string]interface{}{
			{
				"name":         "Security",
				"file_size_mb": 19.0,
				"max_size_mb":  20.0,
				"fill_percent": 95.0,
				"log_mode":     "Retain",
				"record_count": 50000,
				"is_enabled":   true,
			},
		},
	}
	raw, _ := json.Marshal(data)

	warnings := DetectLogCapacityWarnings(map[string]string{"log_tampering": string(raw)})
	if len(warnings) != 0 {
		t.Fatalf("Retain mode should not trigger circular-full warning, got %d", len(warnings))
	}
}
