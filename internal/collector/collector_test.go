package collector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"
	"time"

	"github.com/iyulab/system-coroner/internal/platform"
)

// makeScript returns platform-appropriate script content for a given JSON output.
func makeScript(jsonOut string) ([]byte, string) {
	if runtime.GOOS == "windows" {
		return []byte(fmt.Sprintf(`Write-Output '%s'`, jsonOut)), "scripts/test.ps1"
	}
	return []byte(fmt.Sprintf(`echo '%s'`, jsonOut)), "scripts/test.sh"
}

func TestCollect_EvidenceFirst(t *testing.T) {
	timeout := 5 * time.Second
	if runtime.GOOS == "windows" {
		timeout = 30 * time.Second
	}

	jsonOut := `{"check":"test_check","items":[]}`
	script, scriptPath := makeScript(jsonOut)

	fakeFS := fstest.MapFS{
		scriptPath: &fstest.MapFile{Data: script},
	}
	check := platform.Check{
		ID:      "test_check",
		Name:    "Integration Test Check",
		Script:  scriptPath,
		Timeout: timeout,
	}

	dir := t.TempDir()
	writer, err := NewWriter(dir)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	coll := New(fakeFS, writer, false)

	results := coll.Collect(context.Background(), []platform.Check{check})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]

	if r.CheckID != "test_check" {
		t.Errorf("CheckID = %q, want %q", r.CheckID, "test_check")
	}
	if r.FailureKind != FailureNone {
		t.Errorf("FailureKind = %v, want FailureNone; stderr: %s; err: %v", r.FailureKind, r.Stderr, r.Error)
	}

	// Evidence-first: file must exist on disk immediately after collection
	jsonFile := filepath.Join(dir, "test_check.json")
	if _, err := os.Stat(jsonFile); err != nil {
		t.Errorf("evidence file not saved: %v", err)
	}

	// Hash must be recorded
	hashes := writer.Hashes()
	if len(hashes) == 0 {
		t.Error("expected at least one file hash recorded")
	}
}

func TestCollect_ScriptNotInFS(t *testing.T) {
	// embed.FS mock: empty — no scripts available
	fakeFS := fstest.MapFS{}
	check := platform.Check{
		ID:      "missing_check",
		Name:    "Missing Script",
		Script:  "scripts/does_not_exist.sh",
		Timeout: 5 * time.Second,
	}

	dir := t.TempDir()
	writer, _ := NewWriter(dir)
	coll := New(fakeFS, writer, false)

	results := coll.Collect(context.Background(), []platform.Check{check})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Error == nil {
		t.Error("expected non-nil error for missing script")
	}
	if r.FailureKind != FailureUnknown {
		t.Errorf("FailureKind = %v, want FailureUnknown", r.FailureKind)
	}
	// No evidence file should be saved (no stdout)
	if _, err := os.Stat(filepath.Join(dir, "missing_check.json")); err == nil {
		t.Error("evidence file should not exist for missing script")
	}
}

func TestCollect_Parallel(t *testing.T) {
	timeout := 5 * time.Second
	if runtime.GOOS == "windows" {
		timeout = 30 * time.Second
	}

	const numChecks = 2
	fakeFS := fstest.MapFS{}
	checks := make([]platform.Check, numChecks)

	for i := 0; i < numChecks; i++ {
		jsonOut := fmt.Sprintf(`{"id":%d}`, i)
		var script []byte
		var path string
		if runtime.GOOS == "windows" {
			script = []byte(fmt.Sprintf(`Write-Output '%s'`, jsonOut))
			path = fmt.Sprintf("scripts/check_%d.ps1", i)
		} else {
			script = []byte(fmt.Sprintf(`echo '%s'`, jsonOut))
			path = fmt.Sprintf("scripts/check_%d.sh", i)
		}
		fakeFS[path] = &fstest.MapFile{Data: script}
		checks[i] = platform.Check{
			ID:      fmt.Sprintf("check_%d", i),
			Name:    fmt.Sprintf("Check %d", i),
			Script:  path,
			Timeout: timeout,
		}
	}

	dir := t.TempDir()
	writer, _ := NewWriter(dir)
	coll := New(fakeFS, writer, false)

	results := coll.Collect(context.Background(), checks)

	if len(results) != numChecks {
		t.Fatalf("expected %d results, got %d", numChecks, len(results))
	}

	successCount := 0
	for _, r := range results {
		if r.FailureKind == FailureNone {
			successCount++
		}
	}
	if successCount != numChecks {
		t.Errorf("expected %d successes, got %d", numChecks, successCount)
	}

	// All checks must have at least one evidence file (stdout JSON).
	// stderr logs (.log) may also be saved; check for >= numChecks.
	hashes := writer.Hashes()
	if len(hashes) < numChecks {
		t.Errorf("expected at least %d files saved, got %d", numChecks, len(hashes))
	}
}

func TestCollect_ContextCancellation(t *testing.T) {
	var script []byte
	var scriptPath string
	if runtime.GOOS == "windows" {
		script = []byte(`Start-Sleep -Seconds 30`)
		scriptPath = "scripts/slow.ps1"
	} else {
		script = []byte(`sleep 30`)
		scriptPath = "scripts/slow.sh"
	}

	fakeFS := fstest.MapFS{
		scriptPath: &fstest.MapFile{Data: script},
	}
	check := platform.Check{
		ID:      "slow_check",
		Script:  scriptPath,
		Timeout: 60 * time.Second,
	}

	dir := t.TempDir()
	writer, _ := NewWriter(dir)
	coll := New(fakeFS, writer, false)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()

	results := coll.Collect(ctx, []platform.Check{check})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Error == nil {
		t.Error("expected error for cancelled context")
	}
}
