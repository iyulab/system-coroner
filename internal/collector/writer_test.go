package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewWriter_CreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "output")
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if w.OutputDir() != dir {
		t.Errorf("OutputDir() = %q, want %q", w.OutputDir(), dir)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("should be a directory")
	}
}

func TestWriter_SaveResult(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}

	result := Result{
		CheckID: "c2_connections",
		Stdout:  []byte(`{"check":"c2_connections","items":[]}`),
		Stderr:  []byte("verbose: scanning connections...\n"),
	}

	if err := w.SaveResult(result); err != nil {
		t.Fatalf("SaveResult: %v", err)
	}

	// Verify JSON file
	jsonPath := filepath.Join(dir, "c2_connections.json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read json: %v", err)
	}
	if string(data) != `{"check":"c2_connections","items":[]}` {
		t.Errorf("json content = %q", data)
	}

	// Verify log file
	logPath := filepath.Join(dir, "c2_connections.log")
	data, err = os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if string(data) != "verbose: scanning connections...\n" {
		t.Errorf("log content = %q", data)
	}
}

func TestWriter_SaveResult_NoStderr(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewWriter(dir)

	result := Result{
		CheckID: "test_check",
		Stdout:  []byte(`{}`),
	}

	if err := w.SaveResult(result); err != nil {
		t.Fatalf("SaveResult: %v", err)
	}

	// JSON should exist
	if _, err := os.Stat(filepath.Join(dir, "test_check.json")); err != nil {
		t.Error("json file should exist")
	}
	// Log should NOT exist
	if _, err := os.Stat(filepath.Join(dir, "test_check.log")); err == nil {
		t.Error("log file should not exist when stderr is empty")
	}
}

func TestWriter_SaveMeta(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewWriter(dir)

	meta := CollectionMeta{
		Hostname:    "WEB-01",
		OS:          "windows",
		StartedAt:   time.Now().UTC(),
		CompletedAt: time.Now().UTC(),
		Duration:    "5s",
		TotalChecks: 2,
		Succeeded:   1,
		Failed:      1,
		Checks: []CheckMeta{
			{ID: "c2", Duration: "2s", ExitCode: 0, HasOutput: true},
			{ID: "log", Duration: "3s", ExitCode: 1, Error: "access denied"},
		},
	}

	if err := w.SaveMeta(meta); err != nil {
		t.Fatalf("SaveMeta: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "collection_meta.json"))
	if err != nil {
		t.Fatal(err)
	}

	var loaded CollectionMeta
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	if loaded.Hostname != "WEB-01" {
		t.Errorf("hostname = %q", loaded.Hostname)
	}
	if loaded.TotalChecks != 2 {
		t.Errorf("total_checks = %d", loaded.TotalChecks)
	}
}

func TestGenerateOutputDir(t *testing.T) {
	dir := GenerateOutputDir("output")
	if dir == "output" {
		t.Error("should include timestamp")
	}
	if !filepath.IsAbs(dir) && filepath.Dir(dir) != "output" {
		// Just check it starts with the base dir
		if filepath.Dir(dir) != "output" {
			t.Errorf("dir = %q, should be under 'output'", dir)
		}
	}
}

func TestWriter_SHA256Hash(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewWriter(dir)

	data := []byte(`{"check":"test","items":[]}`)
	result := Result{
		CheckID: "test_hash",
		Stdout:  data,
	}

	if err := w.SaveResult(result); err != nil {
		t.Fatalf("SaveResult: %v", err)
	}

	hashes := w.Hashes()
	if len(hashes) != 1 {
		t.Fatalf("expected 1 hash, got %d", len(hashes))
	}

	expected := sha256.Sum256(data)
	expectedHex := hex.EncodeToString(expected[:])
	if hashes[0].SHA256 != expectedHex {
		t.Errorf("hash = %s, want %s", hashes[0].SHA256, expectedHex)
	}
	if hashes[0].File != "test_hash.json" {
		t.Errorf("file = %s", hashes[0].File)
	}
	if hashes[0].Size != len(data) {
		t.Errorf("size = %d, want %d", hashes[0].Size, len(data))
	}
}

func TestWriter_SaveManifest(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewWriter(dir)

	// Save a result to populate hashes
	w.SaveResult(Result{
		CheckID: "c2",
		Stdout:  []byte(`{"test": true}`),
	})

	if err := w.SaveManifest("TEST-HOST"); err != nil {
		t.Fatalf("SaveManifest: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if manifest.Hostname != "TEST-HOST" {
		t.Errorf("hostname = %s", manifest.Hostname)
	}
	if len(manifest.Files) != 1 {
		t.Errorf("expected 1 file, got %d", len(manifest.Files))
	}
	if manifest.Files[0].File != "c2.json" {
		t.Errorf("file = %s", manifest.Files[0].File)
	}
	if manifest.Files[0].SHA256 == "" {
		t.Error("expected non-empty sha256")
	}
}

func TestBuildMeta_SHA256(t *testing.T) {
	data := []byte(`{"test": true}`)
	results := []Result{
		{CheckID: "check1", Stdout: data},
	}
	meta := BuildMeta("host", "windows", time.Now(), results)
	if len(meta.Checks) != 1 {
		t.Fatal("expected 1 check")
	}
	expected := sha256.Sum256(data)
	expectedHex := hex.EncodeToString(expected[:])
	if meta.Checks[0].SHA256 != expectedHex {
		t.Errorf("sha256 = %s, want %s", meta.Checks[0].SHA256, expectedHex)
	}
}

func TestBuildMeta(t *testing.T) {
	start := time.Now().UTC()
	results := []Result{
		{CheckID: "check1", ExitCode: 0, Duration: 2 * time.Second, Stdout: []byte("{}")},
		{CheckID: "check2", ExitCode: 1, Duration: 3 * time.Second, Error: fmt.Errorf("failed")},
		{CheckID: "check3", ExitCode: -1, Duration: 5 * time.Second, TimedOut: true, Error: fmt.Errorf("timeout")},
	}

	meta := BuildMeta("TEST-HOST", "windows", start, results)

	if meta.Hostname != "TEST-HOST" {
		t.Errorf("hostname = %q", meta.Hostname)
	}
	if meta.TotalChecks != 3 {
		t.Errorf("total = %d", meta.TotalChecks)
	}
	if meta.Succeeded != 1 {
		t.Errorf("succeeded = %d", meta.Succeeded)
	}
	if meta.Failed != 1 {
		t.Errorf("failed = %d", meta.Failed)
	}
	if meta.TimedOut != 1 {
		t.Errorf("timed_out = %d", meta.TimedOut)
	}
}

func TestBuildMeta_EmptyResults(t *testing.T) {
	start := time.Now().UTC()
	meta := BuildMeta("EMPTY-HOST", "linux", start, []Result{})

	if meta.TotalChecks != 0 {
		t.Errorf("total = %d, want 0", meta.TotalChecks)
	}
	if meta.Succeeded != 0 {
		t.Errorf("succeeded = %d", meta.Succeeded)
	}
	if meta.Failed != 0 {
		t.Errorf("failed = %d", meta.Failed)
	}
	if meta.Hostname != "EMPTY-HOST" {
		t.Errorf("hostname = %q", meta.Hostname)
	}
	if meta.OS != "linux" {
		t.Errorf("os = %q", meta.OS)
	}
}

func TestBuildMeta_AllFailed(t *testing.T) {
	start := time.Now().UTC()
	results := []Result{
		{CheckID: "a", ExitCode: 1, Error: fmt.Errorf("fail1")},
		{CheckID: "b", ExitCode: 1, Error: fmt.Errorf("fail2")},
	}
	meta := BuildMeta("FAIL-HOST", "windows", start, results)

	if meta.Succeeded != 0 {
		t.Errorf("succeeded = %d, want 0", meta.Succeeded)
	}
	if meta.Failed != 2 {
		t.Errorf("failed = %d, want 2", meta.Failed)
	}
}

func TestWriter_MultipleResults(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewWriter(dir)

	for i := 0; i < 5; i++ {
		r := Result{
			CheckID: fmt.Sprintf("check_%d", i),
			Stdout:  []byte(fmt.Sprintf(`{"id":%d}`, i)),
		}
		if err := w.SaveResult(r); err != nil {
			t.Fatalf("SaveResult check_%d: %v", i, err)
		}
	}

	hashes := w.Hashes()
	if len(hashes) != 5 {
		t.Errorf("expected 5 hashes, got %d", len(hashes))
	}

	// Verify each file exists
	for i := 0; i < 5; i++ {
		path := filepath.Join(dir, fmt.Sprintf("check_%d.json", i))
		if _, err := os.Stat(path); err != nil {
			t.Errorf("check_%d.json should exist", i)
		}
	}
}
