package collector

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/iyulab/system-coroner/internal/platform"
)

const verboseIDWidth = 30 // column width for check ID in verbose log

// Collector runs intrusion detection checks in parallel and saves results.
type Collector struct {
	scripts fs.FS
	writer  *Writer
	verbose bool
}

// New creates a Collector with an FS containing scripts and a result writer.
// In production, scripts is an embed.FS; in tests, any fs.FS can be used.
func New(scripts fs.FS, writer *Writer, verbose bool) *Collector {
	return &Collector{
		scripts: scripts,
		writer:  writer,
		verbose: verbose,
	}
}

// Collect runs all checks in parallel and returns the results.
// Failed checks are recorded but do not stop other checks.
func (c *Collector) Collect(ctx context.Context, checks []platform.Check) []Result {
	results := make([]Result, len(checks))
	var wg sync.WaitGroup

	for i, check := range checks {
		wg.Add(1)
		go func(idx int, chk platform.Check) {
			defer wg.Done()

			if c.verbose {
				fmt.Fprintf(os.Stderr, "[collector] start: %-*s  %s\n", verboseIDWidth, chk.ID, chk.Name)
			}

			// Read script content from embedded FS
			scriptContent, err := fs.ReadFile(c.scripts, chk.Script)
			if err != nil {
				results[idx] = Result{
					CheckID:     chk.ID,
					Error:       fmt.Errorf("read script %s: %w", chk.Script, err),
					ExitCode:    -1,
					FailureKind: FailureUnknown,
					CollectedAt: time.Now().UTC(),
				}
				if c.verbose {
					fmt.Fprintf(os.Stderr, "[collector] done:  %-*s  0s  unknown\n", verboseIDWidth, chk.ID)
				}
				return
			}

			result := RunCheck(ctx, chk, scriptContent)
			results[idx] = result

			// Evidence-first: save result to disk immediately
			if saveErr := c.writer.SaveResult(result); saveErr != nil {
				fmt.Fprintf(os.Stderr, "[collector] warning: failed to save %s: %v\n", chk.ID, saveErr)
			}

			if c.verbose {
				status := result.FailureKind.String()
				fmt.Fprintf(os.Stderr, "[collector] done:  %-*s  %s  %s\n",
					verboseIDWidth, chk.ID, result.Duration.Round(time.Millisecond), status)
			}
		}(i, check)
	}

	wg.Wait()
	return results
}

// BuildMeta creates a CollectionMeta from the results.
func BuildMeta(hostname, osName string, startedAt time.Time, results []Result) CollectionMeta {
	now := time.Now().UTC()
	meta := CollectionMeta{
		Hostname:    hostname,
		OS:          osName,
		StartedAt:   startedAt,
		CompletedAt: now,
		Duration:    now.Sub(startedAt).String(),
		TotalChecks: len(results),
	}

	for _, r := range results {
		cm := CheckMeta{
			ID:          r.CheckID,
			Duration:    r.Duration.String(),
			ExitCode:    r.ExitCode,
			TimedOut:    r.TimedOut,
			FailureKind: r.FailureKind.String(),
			HasOutput:   len(r.Stdout) > 0,
			SHA256:      sha256Hex(r.Stdout),
		}
		if r.Error != nil {
			cm.Error = r.Error.Error()
			if r.TimedOut {
				meta.TimedOut++
			} else {
				meta.Failed++
			}
		} else {
			meta.Succeeded++
		}
		meta.Checks = append(meta.Checks, cm)
	}

	return meta
}
