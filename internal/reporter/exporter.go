package reporter

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// EvidencePackage represents the metadata for a forensic evidence package.
type EvidencePackage struct {
	Version     string        `json:"version"`
	Hostname    string        `json:"hostname"`
	OS          string        `json:"os"`
	CreatedAt   time.Time     `json:"created_at"`
	ToolVersion string        `json:"tool_version"`
	Files       []PackageFile `json:"files"`
}

// PackageFile records a file included in the evidence package.
type PackageFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ExportEvidence creates a ZIP archive of the output directory for forensic handoff.
// The archive includes all JSON evidence files, logs, manifest, and report.
// Returns the path to the created ZIP file.
func ExportEvidence(outputDir, hostname, osName, toolVersion string) (string, error) {
	zipPath := outputDir + ".zip"

	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", fmt.Errorf("create zip: %w", err)
	}
	defer zipFile.Close()

	w := zip.NewWriter(zipFile)
	defer w.Close()

	var files []PackageFile
	dirBase := filepath.Base(outputDir)

	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return "", fmt.Errorf("read output dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filePath := filepath.Join(outputDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Read file content
		content, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		// Add to ZIP with directory prefix
		archivePath := dirBase + "/" + entry.Name()
		zf, err := w.Create(archivePath)
		if err != nil {
			return "", fmt.Errorf("zip create %s: %w", entry.Name(), err)
		}
		if _, err := zf.Write(content); err != nil {
			return "", fmt.Errorf("zip write %s: %w", entry.Name(), err)
		}

		// Record hash
		h := sha256.Sum256(content)
		files = append(files, PackageFile{
			Name:   entry.Name(),
			SHA256: hex.EncodeToString(h[:]),
			Size:   info.Size(),
		})
	}

	// Add package metadata as package_info.json
	pkg := EvidencePackage{
		Version:     "1.0",
		Hostname:    hostname,
		OS:          osName,
		CreatedAt:   time.Now().UTC(),
		ToolVersion: toolVersion,
		Files:       files,
	}
	pkgJSON, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal package info: %w", err)
	}

	zf, err := w.Create(dirBase + "/package_info.json")
	if err != nil {
		return "", fmt.Errorf("zip create package_info: %w", err)
	}
	if _, err := zf.Write(pkgJSON); err != nil {
		return "", fmt.Errorf("zip write package_info: %w", err)
	}

	// Flush the writer before computing archive hash
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("close zip writer: %w", err)
	}
	if err := zipFile.Close(); err != nil {
		return "", fmt.Errorf("close zip file: %w", err)
	}

	return zipPath, nil
}
