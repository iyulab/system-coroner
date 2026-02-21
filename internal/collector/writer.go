package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Writer handles saving IoC collection results to disk.
// Evidence-first principle: raw data is saved before any LLM analysis.
// Thread-safe: multiple goroutines may call SaveResult concurrently.
type Writer struct {
	outputDir string
	mu        sync.Mutex
	hashes    []FileHash // accumulated hashes for manifest
}

// FileHash records the SHA-256 hash of a saved evidence file.
type FileHash struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

// NewWriter creates a Writer for the given output directory.
func NewWriter(outputDir string) (*Writer, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}
	return &Writer{outputDir: outputDir}, nil
}

// OutputDir returns the output directory path.
func (w *Writer) OutputDir() string {
	return w.outputDir
}

// SaveResult writes a collection result to disk immediately.
// Stdout goes to {checkID}.json, stderr goes to {checkID}.log.
// SHA-256 hashes are recorded for the manifest.
func (w *Writer) SaveResult(result Result) error {
	// Always save stdout (JSON output) if present
	if len(result.Stdout) > 0 {
		filename := result.CheckID + ".json"
		path := filepath.Join(w.outputDir, filename)
		if err := os.WriteFile(path, result.Stdout, 0644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		w.mu.Lock()
		w.hashes = append(w.hashes, FileHash{
			File:   filename,
			SHA256: sha256Hex(result.Stdout),
			Size:   len(result.Stdout),
		})
		w.mu.Unlock()
	}

	// Save stderr (diagnostic output) if present
	if len(result.Stderr) > 0 {
		filename := result.CheckID + ".log"
		path := filepath.Join(w.outputDir, filename)
		if err := os.WriteFile(path, result.Stderr, 0644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		w.mu.Lock()
		w.hashes = append(w.hashes, FileHash{
			File:   filename,
			SHA256: sha256Hex(result.Stderr),
			Size:   len(result.Stderr),
		})
		w.mu.Unlock()
	}

	return nil
}

// sha256Hex computes the SHA-256 hex digest of data.
func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// CollectionMeta holds metadata about the collection run.
type CollectionMeta struct {
	Hostname    string      `json:"hostname"`
	OS          string      `json:"os"`
	StartedAt   time.Time   `json:"started_at"`
	CompletedAt time.Time   `json:"completed_at"`
	Duration    string      `json:"duration"`
	Checks      []CheckMeta `json:"checks"`
	TotalChecks int         `json:"total_checks"`
	Succeeded   int         `json:"succeeded"`
	Failed      int         `json:"failed"`
	TimedOut    int         `json:"timed_out"`
}

// CheckMeta holds metadata about a single check execution.
type CheckMeta struct {
	ID          string `json:"id"`
	Duration    string `json:"duration"`
	ExitCode    int    `json:"exit_code"`
	TimedOut    bool   `json:"timed_out,omitempty"`
	Error       string `json:"error,omitempty"`
	FailureKind string `json:"failure_kind,omitempty"` // none | timeout | permission_denied | script_error | not_found | unknown
	HasOutput   bool   `json:"has_output"`
	SHA256      string `json:"sha256,omitempty"`
}

// Manifest records all evidence file hashes for integrity verification.
type Manifest struct {
	GeneratedAt time.Time  `json:"generated_at"`
	Hostname    string     `json:"hostname"`
	Files       []FileHash `json:"files"`
}

// SaveMeta writes the collection metadata to collection_meta.json.
func (w *Writer) SaveMeta(meta CollectionMeta) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}
	path := filepath.Join(w.outputDir, "collection_meta.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write meta: %w", err)
	}
	return nil
}

// SaveManifest writes the hash manifest to manifest.json.
func (w *Writer) SaveManifest(hostname string) error {
	w.mu.Lock()
	files := make([]FileHash, len(w.hashes))
	copy(files, w.hashes)
	w.mu.Unlock()

	manifest := Manifest{
		GeneratedAt: time.Now().UTC(),
		Hostname:    hostname,
		Files:       files,
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	path := filepath.Join(w.outputDir, "manifest.json")
	return os.WriteFile(path, data, 0644)
}

// Hashes returns the accumulated file hashes.
func (w *Writer) Hashes() []FileHash {
	w.mu.Lock()
	defer w.mu.Unlock()
	cp := make([]FileHash, len(w.hashes))
	copy(cp, w.hashes)
	return cp
}

// GenerateOutputDir creates a timestamped output directory under baseDir.
func GenerateOutputDir(baseDir string) string {
	ts := time.Now().Format("2006-01-02T15-04-05")
	return filepath.Join(baseDir, ts)
}
