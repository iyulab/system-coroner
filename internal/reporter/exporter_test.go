package reporter

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportEvidence_CreatesZip(t *testing.T) {
	// Setup: create a fake output directory with files
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "2026-02-21T10-00-00")
	os.MkdirAll(outputDir, 0755)

	// Write some evidence files
	os.WriteFile(filepath.Join(outputDir, "c2_connections.json"), []byte(`{"check":"c2_connections"}`), 0644)
	os.WriteFile(filepath.Join(outputDir, "persistence.json"), []byte(`{"check":"persistence"}`), 0644)
	os.WriteFile(filepath.Join(outputDir, "report.html"), []byte(`<html>report</html>`), 0644)
	os.WriteFile(filepath.Join(outputDir, "manifest.json"), []byte(`{"files":[]}`), 0644)

	// Export
	zipPath, err := ExportEvidence(outputDir, "test-host", "linux", "test-0.1.0")
	if err != nil {
		t.Fatalf("ExportEvidence error: %v", err)
	}

	// Verify ZIP exists
	if _, err := os.Stat(zipPath); os.IsNotExist(err) {
		t.Fatalf("ZIP file not created: %s", zipPath)
	}

	// Verify ZIP path is outputDir + .zip
	expectedPath := outputDir + ".zip"
	if zipPath != expectedPath {
		t.Errorf("zip path = %q, want %q", zipPath, expectedPath)
	}

	// Open and inspect ZIP
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer r.Close()

	names := make(map[string]bool)
	for _, f := range r.File {
		// Strip directory prefix
		name := filepath.Base(f.Name)
		names[name] = true
	}

	// Should contain original files + package_info.json
	for _, expected := range []string{"c2_connections.json", "persistence.json", "report.html", "manifest.json", "package_info.json"} {
		if !names[expected] {
			t.Errorf("ZIP missing file: %s (has: %v)", expected, names)
		}
	}
}

func TestExportEvidence_PackageInfo(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "2026-02-21T10-00-00")
	os.MkdirAll(outputDir, 0755)

	os.WriteFile(filepath.Join(outputDir, "test.json"), []byte(`{"data":"test"}`), 0644)

	zipPath, err := ExportEvidence(outputDir, "forensic-host", "windows", "v0.5.0")
	if err != nil {
		t.Fatalf("ExportEvidence error: %v", err)
	}

	// Read package_info.json from ZIP
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer r.Close()

	var pkgInfo EvidencePackage
	for _, f := range r.File {
		if strings.HasSuffix(f.Name, "package_info.json") {
			rc, _ := f.Open()
			defer rc.Close()
			json.NewDecoder(rc).Decode(&pkgInfo)
			break
		}
	}

	if pkgInfo.Hostname != "forensic-host" {
		t.Errorf("hostname = %q, want %q", pkgInfo.Hostname, "forensic-host")
	}
	if pkgInfo.OS != "windows" {
		t.Errorf("os = %q, want %q", pkgInfo.OS, "windows")
	}
	if pkgInfo.ToolVersion != "v0.5.0" {
		t.Errorf("tool_version = %q, want %q", pkgInfo.ToolVersion, "v0.5.0")
	}
	if len(pkgInfo.Files) != 1 {
		t.Errorf("files count = %d, want 1", len(pkgInfo.Files))
	}
	if len(pkgInfo.Files) > 0 && pkgInfo.Files[0].SHA256 == "" {
		t.Error("file hash should not be empty")
	}
}

func TestExportEvidence_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "empty")
	os.MkdirAll(outputDir, 0755)

	zipPath, err := ExportEvidence(outputDir, "host", "linux", "v0.1.0")
	if err != nil {
		t.Fatalf("ExportEvidence error: %v", err)
	}

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer r.Close()

	// Should have only package_info.json
	if len(r.File) != 1 {
		t.Errorf("expected 1 file (package_info), got %d", len(r.File))
	}
}
