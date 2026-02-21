package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ProgressFunc is called when each per-check LLM analysis completes.
// done is the number of checks completed so far; total is the total count.
type ProgressFunc func(checkID string, done, total int, elapsed time.Duration, err error)

// Analyzer orchestrates the two-phase LLM analysis pipeline.
type Analyzer struct {
	provider   Provider
	hostname   string
	osName     string
	verbose    bool
	onProgress ProgressFunc
}

// New creates an Analyzer with the given LLM provider.
func New(provider Provider, hostname, osName string, verbose bool) *Analyzer {
	return &Analyzer{
		provider: provider,
		hostname: hostname,
		osName:   osName,
		verbose:  verbose,
	}
}

// SetProgress sets a callback invoked after each per-check analysis completes.
func (a *Analyzer) SetProgress(fn ProgressFunc) {
	a.onProgress = fn
}

// AnalyzeAll runs Phase 1 (per-check) and Phase 2 (synthesis) analysis.
func (a *Analyzer) AnalyzeAll(ctx context.Context, checkData map[string]string) (*AnalysisResult, error) {
	result := &AnalysisResult{}

	// Phase 1: Per-check analysis (parallel)
	findings, rawFindings := a.analyzeChecks(ctx, checkData)
	result.Findings = findings
	result.RawFindings = rawFindings

	if len(findings) == 0 {
		if a.verbose {
			fmt.Fprintf(os.Stderr, "[analyzer] no findings parsed, skipping synthesis\n")
		}
		return result, nil
	}

	// Phase 2: Cross-analysis synthesis
	if a.onProgress != nil {
		fmt.Fprintf(os.Stderr, "  [synthesis]                    running...\r")
	}
	synthStart := time.Now()
	verdict, err := a.synthesize(ctx, findings)
	synthElapsed := time.Since(synthStart)

	if a.onProgress != nil {
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [synthesis]                    ✗  %s\n", synthElapsed.Round(time.Millisecond))
		} else {
			fmt.Fprintf(os.Stderr, "  [synthesis]                    ✓  %s\n", synthElapsed.Round(time.Millisecond))
		}
	}
	if err != nil {
		if a.verbose {
			fmt.Fprintf(os.Stderr, "[analyzer] synthesis failed: %v\n", err)
		}
		// Continue without synthesis — findings are still valuable
	} else {
		result.Verdict = verdict
	}

	return result, nil
}

// AnalyzeCheck runs Phase 1 analysis for a single check.
func (a *Analyzer) AnalyzeCheck(ctx context.Context, checkID, data string) (Finding, error) {
	pre := Preprocess(checkID, a.osName, data)
	if a.verbose && (pre.FilteredIPs > 0 || pre.TruncatedFields > 0) {
		fmt.Fprintf(os.Stderr, "[analyzer] %s: preprocess filtered=%d ips, truncated=%d fields\n",
			checkID, pre.FilteredIPs, pre.TruncatedFields)
	}

	prompt := BuildCheckPrompt(checkID, a.hostname, a.osName, pre.Data)
	systemPrompt := GetSystemPrompt(a.osName)

	if a.verbose {
		fmt.Fprintf(os.Stderr, "[analyzer] analyzing: %s\n", checkID)
	}

	// Set structured output schema if provider supports it
	if fs, ok := a.provider.(FormatSetter); ok {
		fs.SetFormat(FindingSchema)
	}

	raw, err := a.callWithRetry(ctx, systemPrompt, prompt)
	if err != nil {
		return Finding{}, fmt.Errorf("analyze %s: %w", checkID, err)
	}

	finding, err := ParseFinding(checkID, raw)
	if err != nil {
		return Finding{}, fmt.Errorf("parse %s: %w (raw: %s)", checkID, err, truncate(raw, 200))
	}

	return finding, nil
}

// analyzeChecks runs per-check analysis in parallel.
func (a *Analyzer) analyzeChecks(ctx context.Context, checkData map[string]string) ([]Finding, []RawFinding) {
	type result struct {
		finding    Finding
		rawFinding *RawFinding
	}

	results := make([]result, 0, len(checkData))
	var mu sync.Mutex
	var wg sync.WaitGroup
	total := len(checkData)
	var doneCount atomic.Int32

	for checkID, data := range checkData {
		wg.Add(1)
		go func(id, d string) {
			defer wg.Done()

			start := time.Now()
			finding, err := a.AnalyzeCheck(ctx, id, d)
			elapsed := time.Since(start)

			done := int(doneCount.Add(1))
			if a.onProgress != nil {
				a.onProgress(id, done, total, elapsed, err)
			}

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				if a.verbose {
					fmt.Fprintf(os.Stderr, "[analyzer] %s failed: %v\n", id, err)
				}
				// Preserve raw output on failure
				raw := RawFinding{
					CheckID:    id,
					ParseError: err.Error(),
				}
				results = append(results, result{rawFinding: &raw})
			} else {
				results = append(results, result{finding: finding})
			}
		}(checkID, data)
	}

	wg.Wait()

	var findings []Finding
	var rawFindings []RawFinding
	for _, r := range results {
		if r.rawFinding != nil {
			rawFindings = append(rawFindings, *r.rawFinding)
		} else {
			findings = append(findings, r.finding)
		}
	}
	return findings, rawFindings
}

// synthesize runs Phase 2 cross-analysis.
func (a *Analyzer) synthesize(ctx context.Context, findings []Finding) (*Verdict, error) {
	findingsJSON, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal findings: %w", err)
	}

	prompt := BuildSynthesisPrompt(a.hostname, a.osName, len(findings), string(findingsJSON))

	if a.verbose {
		fmt.Fprintf(os.Stderr, "[analyzer] running synthesis with %d findings\n", len(findings))
	}

	// Set structured output schema if provider supports it
	if fs, ok := a.provider.(FormatSetter); ok {
		fs.SetFormat(VerdictSchema)
	}

	systemPrompt := GetSystemPrompt(a.osName)
	raw, err := a.callWithRetry(ctx, systemPrompt, prompt)
	if err != nil {
		return nil, fmt.Errorf("synthesis: %w", err)
	}

	verdict, err := ParseVerdict(raw)
	if err != nil {
		return nil, fmt.Errorf("parse synthesis: %w", err)
	}

	return &verdict, nil
}

// callWithRetry calls the LLM provider with one retry on failure.
func (a *Analyzer) callWithRetry(ctx context.Context, system, user string) (string, error) {
	raw, err := a.provider.Analyze(ctx, system, user)
	if err != nil {
		if a.verbose {
			fmt.Fprintf(os.Stderr, "[analyzer] first attempt failed, retrying: %v\n", err)
		}
		// One retry
		raw, err = a.provider.Analyze(ctx, system, user)
		if err != nil {
			return "", err
		}
	}
	return raw, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
