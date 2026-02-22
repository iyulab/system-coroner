// Package orchestrator coordinates the Collect → Analyze → Report pipeline.
package orchestrator

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iyulab/system-coroner/internal/analyzer"
	"github.com/iyulab/system-coroner/internal/browser"
	"github.com/iyulab/system-coroner/internal/collector"
	"github.com/iyulab/system-coroner/internal/config"
	"github.com/iyulab/system-coroner/internal/platform"
	"github.com/iyulab/system-coroner/internal/reporter"
	"github.com/iyulab/system-coroner/internal/server"
	"github.com/iyulab/system-coroner/internal/sigma"
	"github.com/iyulab/system-coroner/scripts"
)

// Options holds CLI flags for the orchestrator.
type Options struct {
	CollectOnly bool
	Only        []string
	Fixture     string
	SkipCollect bool
	Verbose     bool
	Version     string
	Serve       bool // start interactive server after analysis
	ServePort   int  // server port (default 8742)
}

// Orchestrator runs the three-stage pipeline.
type Orchestrator struct {
	cfg      *config.Config
	opts     Options
	checks   []platform.Check
	provider analyzer.Provider // optional: injected for testing
}

// New creates an Orchestrator with validated config and platform checks.
func New(cfg *config.Config, opts Options) *Orchestrator {
	checks := platform.GetChecks()
	checks = platform.FilterEnabled(checks, cfg.Checks)
	checks = platform.FilterChecks(checks, opts.Only)

	return &Orchestrator{
		cfg:    cfg,
		opts:   opts,
		checks: checks,
	}
}

// SetProvider overrides the LLM provider (used in tests).
func (o *Orchestrator) SetProvider(p analyzer.Provider) {
	o.provider = p
}

// registerKnownGoodPaths registers operator-declared and auto-detected paths as known-good.
// Auto-detected: the directory containing the coroner binary and the configured output base dir.
// Operator-declared: any paths listed in config.Baseline.KnownPaths.
func registerKnownGoodPaths(cfg *config.Config) {
	// Auto: coroner's own binary directory (e.g. D:\tool where coroner.exe lives)
	if exePath, err := os.Executable(); err == nil {
		if abs, err := filepath.Abs(filepath.Dir(exePath)); err == nil {
			analyzer.AddKnownGoodPath(abs)
		}
	}
	// Auto: configured output directory (e.g. D:\tool\output or ./output)
	if cfg.Output.Dir != "" {
		if abs, err := filepath.Abs(cfg.Output.Dir); err == nil {
			analyzer.AddKnownGoodPath(abs)
		}
	}
	// Operator-declared paths from [baseline] known_paths
	for _, p := range cfg.Baseline.KnownPaths {
		if abs, err := filepath.Abs(p); err == nil {
			analyzer.AddKnownGoodPath(abs)
		}
	}
}

// registerHostIPs collects all local network interface addresses and registers them
// as known-good IPs in the analyzer preprocessor. This prevents the host's own
// external IP from being flagged as a C2 connection (FP-001).
func registerHostIPs() {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	for _, addr := range addrs {
		var ipStr string
		switch v := addr.(type) {
		case *net.IPNet:
			ipStr = v.IP.String()
		case *net.IPAddr:
			ipStr = v.IP.String()
		}
		if ipStr != "" && ipStr != "0.0.0.0" && ipStr != "::" {
			analyzer.AddKnownGoodIP(ipStr)
		}
	}
}

// Run executes the full pipeline.
func (o *Orchestrator) Run(ctx context.Context) error {
	if len(o.checks) == 0 {
		return fmt.Errorf("no checks available for platform %q", platform.DetectOS())
	}

	hostname, _ := os.Hostname()
	osName := platform.DetectOS()
	startTime := time.Now()

	// FP-001: Register host's own IPs as known-good to prevent self-IP false positives
	registerHostIPs()

	// FP-003: Register known-good paths to prevent coroner's own footprint from being
	// flagged as attack staging. Auto-detect the binary directory and output base dir,
	// then merge with any operator-declared paths from config [baseline].
	registerKnownGoodPaths(o.cfg)

	// FP-006: Register coroner's own PID so spawned child processes can be identified.
	analyzer.AddSelfPID(os.Getpid())

	// Generate output directory
	outputDir := collector.GenerateOutputDir(o.cfg.Output.Dir)
	if o.opts.Verbose {
		fmt.Fprintf(os.Stderr, "[orchestrator] output: %s\n", outputDir)
	}

	// --- Stage 1: Collect ---
	var results []collector.Result
	var collectionDuration time.Duration
	var evidenceHashes []collector.FileHash

	if o.opts.SkipCollect && o.opts.Fixture != "" {
		// Load from fixture directory
		if o.opts.Verbose {
			fmt.Fprintf(os.Stderr, "[orchestrator] loading fixtures from: %s\n", o.opts.Fixture)
		}
		loaded, err := loadFixtures(o.opts.Fixture, o.checks)
		if err != nil {
			return fmt.Errorf("load fixtures: %w", err)
		}
		results = loaded
		collectionDuration = time.Since(startTime)
	} else {
		// Run collection
		fmt.Fprintf(os.Stderr, "[*] Collecting IoC data (%d checks)...\n", len(o.checks))
		collectStart := time.Now()

		writer, err := collector.NewWriter(outputDir)
		if err != nil {
			return fmt.Errorf("create writer: %w", err)
		}

		scriptFS := scripts.WindowsScripts
		if osName == "linux" {
			scriptFS = scripts.LinuxScripts
		}
		coll := collector.New(scriptFS, writer, o.opts.Verbose)
		results = coll.Collect(ctx, o.checks)
		collectionDuration = time.Since(collectStart)

		// Save collection metadata
		meta := collector.BuildMeta(hostname, osName, collectStart, results)
		if err := writer.SaveMeta(meta); err != nil {
			fmt.Fprintf(os.Stderr, "[orchestrator] warning: %v\n", err)
		}

		// Save evidence hash manifest
		if err := writer.SaveManifest(hostname); err != nil {
			fmt.Fprintf(os.Stderr, "[orchestrator] warning: manifest: %v\n", err)
		}
		evidenceHashes = writer.Hashes()

		fmt.Fprintf(os.Stderr, "[*] Collection complete (%s)\n", collectionDuration)

		succeeded := 0
		for _, r := range results {
			if r.Error == nil {
				succeeded++
			}
		}
		fmt.Fprintf(os.Stderr, "[*] %d/%d checks succeeded\n", succeeded, len(results))

		// FP-006: Register child PIDs from collection for self-process filtering
		for _, r := range results {
			if r.ChildPID > 0 {
				analyzer.AddSelfPID(r.ChildPID)
			}
		}
	}

	if o.opts.CollectOnly {
		fmt.Printf("Collection results saved to: %s\n", outputDir)
		return nil
	}

	// --- Stage 1.5: Sigma Rules Matching ---
	var sigmaMatches []sigma.SigmaMatch
	sigmaEngine, sigmaErr := sigma.NewDefault()
	if sigmaErr != nil {
		fmt.Fprintf(os.Stderr, "[orchestrator] warning: sigma engine init: %v\n", sigmaErr)
	} else {
		sigmaMatches = sigmaEngine.MatchAll(ctx, results)
		if len(sigmaMatches) > 0 {
			fmt.Fprintf(os.Stderr, "[*] Sigma: %d rule match(es) detected\n", len(sigmaMatches))
		}
	}

	// --- Stage 2: Analyze ---
	fmt.Fprintf(os.Stderr, "[*] Analyzing with LLM (%s/%s)...\n", o.cfg.LLM.Provider, o.cfg.LLM.Model)
	analyzeStart := time.Now()

	provider := o.provider
	if provider == nil {
		var err error
		provider, err = analyzer.NewProvider(
			o.cfg.LLM.Provider,
			o.cfg.LLM.APIKey,
			o.cfg.LLM.Model,
			o.cfg.LLM.Endpoint,
			o.cfg.LLM.Timeout,
		)
		if err != nil {
			return fmt.Errorf("create provider: %w", err)
		}
	}

	// Build check data map from results (used for LLM analysis and raw viewer)
	checkData := make(map[string]string)
	for _, r := range results {
		if len(r.Stdout) > 0 {
			checkData[r.CheckID] = string(r.Stdout)
		}
	}
	rawCheckData := checkData // same data — LLM preprocessing happens inside analyzer

	a := analyzer.New(provider, hostname, osName, o.opts.Verbose)
	if !o.opts.Verbose {
		a.SetProgress(func(checkID string, done, total int, elapsed time.Duration, err error) {
			status := "✓"
			if err != nil {
				status = "✗"
			}
			width := len(fmt.Sprintf("%d", total))
			fmt.Fprintf(os.Stderr, "  [%*d/%d] %-22s %s  %s\n",
				width, done, total,
				checkID, status, elapsed.Round(time.Millisecond))
		})
	}
	analysisResult, err := a.AnalyzeAll(ctx, checkData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[orchestrator] analysis error: %v\n", err)
		// Continue with partial results — never abort
	}

	analysisDuration := time.Since(analyzeStart)
	fmt.Fprintf(os.Stderr, "[*] Analysis complete (%s)\n", analysisDuration)

	// --- Stage 3: Report ---
	fmt.Fprintf(os.Stderr, "[*] Generating report...\n")

	// Convert evidence hashes for the report
	var reportHashes []reporter.EvidenceHash
	for _, h := range evidenceHashes {
		reportHashes = append(reportHashes, reporter.EvidenceHash{
			File:   h.File,
			SHA256: h.SHA256,
			Size:   h.Size,
		})
	}

	// Build collection failures list (script execution errors)
	checkNameMap := make(map[string]string, len(o.checks))
	for _, c := range o.checks {
		checkNameMap[c.ID] = c.Name
	}
	var collectionFailures []reporter.CollectionFailure
	for _, r := range results {
		if r.Error != nil {
			collectionFailures = append(collectionFailures, reporter.CollectionFailure{
				CheckID:       r.CheckID,
				CheckName:     checkNameMap[r.CheckID],
				Error:         r.Error.Error(),
				FailureKind:   r.FailureKind.String(),
				StderrExcerpt: r.StderrExcerpt(),
			})
		}
	}

	agg := &reporter.Aggregator{}
	isolation := agg.ShouldIsolate(analysisResult.Findings, collectionFailures)
	confidenceSummary := reporter.SummarizeConfidence(analysisResult.Findings)
	iocs := reporter.CollectAllIoCs(analysisResult.Findings)

	// GAP-001: Compute combined gap analysis for compound failure scenarios
	failedCheckIDs := make([]string, 0, len(collectionFailures))
	for _, f := range collectionFailures {
		failedCheckIDs = append(failedCheckIDs, f.CheckID)
	}

	// ANA-005: Separate findings by type for distinct report sections
	intrusionFindings := reporter.FilterIntrusionFindings(analysisResult.Findings)
	hardeningFindings := reporter.FilterExposureFindings(analysisResult.Findings)

	reportData := reporter.ReportData{
		Hostname:            hostname,
		OS:                  osName,
		GeneratedAt:         time.Now().UTC(),
		Version:             o.opts.Version,
		Isolation:           isolation,
		ConfidenceSummary:   confidenceSummary,
		TotalChecks:         len(o.checks),
		Findings:            intrusionFindings,
		RawFindings:         analysisResult.RawFindings,
		HardeningFindings:   hardeningFindings,
		Verdict:             analysisResult.Verdict,
		IoCs:                iocs,
		EvidenceHashes:      reportHashes,
		CollectionFailures:  collectionFailures,
		EvidenceGaps:        reporter.AnalyzeEvidenceGaps(collectionFailures),
		CombinedGaps:        reporter.DescribeCombinedGaps(failedCheckIDs),
		LogCapacityWarnings: reporter.DetectLogCapacityWarnings(rawCheckData),
		RawCheckData:        rawCheckData,
		SigmaMatches:        sigmaMatches,
		CollectionDuration:  collectionDuration.String(),
		AnalysisDuration:    analysisDuration.String(),
	}

	rep, err := reporter.New()
	if err != nil {
		return fmt.Errorf("create reporter: %w", err)
	}

	// Ensure output dir exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	reportPath, err := rep.Generate(reportData, outputDir)
	if err != nil {
		return fmt.Errorf("generate report: %w", err)
	}

	totalDuration := time.Since(startTime)
	fmt.Fprintf(os.Stderr, "[*] Report generated: %s\n", reportPath)

	// --- Evidence Package Export ---
	fmt.Fprintf(os.Stderr, "[*] Creating evidence package...\n")
	zipPath, zipErr := reporter.ExportEvidence(outputDir, hostname, osName, o.opts.Version)
	if zipErr != nil {
		fmt.Fprintf(os.Stderr, "[orchestrator] warning: evidence export: %v\n", zipErr)
	} else {
		fmt.Fprintf(os.Stderr, "[*] Evidence package: %s\n", zipPath)
	}

	fmt.Fprintf(os.Stderr, "[*] Total time: %s\n", totalDuration)

	// Print final summary
	fmt.Printf("\n=== system-coroner Report ===\n")
	fmt.Printf("Hostname: %s\n", hostname)
	fmt.Printf("Checks: %d | Findings: %d\n", len(o.checks), len(analysisResult.Findings))
	if isolation.Isolate {
		fmt.Printf("ISOLATION: %s — %s\n", isolation.Urgency, isolation.Reason)
	}
	fmt.Printf("Report: %s\n", reportPath)
	if zipErr == nil {
		fmt.Printf("Evidence: %s\n", zipPath)
	}

	// --- Serve Mode ---
	if o.opts.Serve {
		reEvalFn := func(reqCtx context.Context, analystContext string) (*reporter.ReportData, error) {
			reAnalyzer := analyzer.New(provider, hostname, osName, o.opts.Verbose)
			reAnalyzer.SetAnalystContext(analystContext)

			newResult, err := reAnalyzer.AnalyzeAll(reqCtx, checkData)
			if err != nil {
				return nil, err
			}

			newAgg := &reporter.Aggregator{}
			newIsolation := newAgg.ShouldIsolate(newResult.Findings, collectionFailures)
			newConfidence := reporter.SummarizeConfidence(newResult.Findings)
			newIoCs := reporter.CollectAllIoCs(newResult.Findings)

			newData := reportData
			newData.Findings = newResult.Findings
			newData.RawFindings = newResult.RawFindings
			newData.Verdict = newResult.Verdict
			newData.Isolation = newIsolation
			newData.ConfidenceSummary = newConfidence
			newData.IoCs = newIoCs
			newData.AnalystContext = analystContext
			return &newData, nil
		}

		htmlBytes, err := os.ReadFile(reportPath)
		if err != nil {
			return fmt.Errorf("read report: %w", err)
		}

		renderFn := func(data *reporter.ReportData) (string, error) {
			newRep, err := reporter.New()
			if err != nil {
				return "", err
			}
			return newRep.GenerateString(*data)
		}

		port := o.opts.ServePort
		if port == 0 {
			port = 8742
		}

		srv := server.New(nil, string(htmlBytes), reEvalFn)
		srv.SetRenderFunc(renderFn)

		addr, err := srv.Start(ctx, port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[*] Warning: serve mode failed: %v\n", err)
		} else {
			url := "http://" + addr
			fmt.Fprintf(os.Stderr, "[*] Interactive mode: %s\n", url)
			fmt.Printf("Interactive: %s\n", url)
			browser.Open(url)

			fmt.Fprintf(os.Stderr, "[*] Press Ctrl+C to stop server\n")
			<-ctx.Done()
			srv.Stop()
		}
	}

	return nil
}

// loadFixtures reads fixture JSON files and creates fake Results.
func loadFixtures(fixtureDir string, checks []platform.Check) ([]collector.Result, error) {
	// Validate fixture directory exists
	info, err := os.Stat(fixtureDir)
	if err != nil {
		return nil, fmt.Errorf("fixture directory not found: %s", fixtureDir)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("fixture path is not a directory: %s", fixtureDir)
	}

	absBase, err := filepath.Abs(fixtureDir)
	if err != nil {
		return nil, fmt.Errorf("resolve fixture path: %w", err)
	}

	var results []collector.Result
	for _, check := range checks {
		// Use filepath.Join for OS-safe path construction
		path := filepath.Join(fixtureDir, check.ID+".json")

		// Prevent path traversal: resolved path must stay within fixtureDir
		absPath, err := filepath.Abs(path)
		if err != nil || !strings.HasPrefix(absPath, absBase) {
			results = append(results, collector.Result{
				CheckID: check.ID,
				Error:   fmt.Errorf("invalid fixture path for %s", check.ID),
			})
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			// Not all fixtures may exist
			results = append(results, collector.Result{
				CheckID: check.ID,
				Error:   fmt.Errorf("fixture not found: %s", path),
			})
			continue
		}
		results = append(results, collector.Result{
			CheckID:     check.ID,
			Stdout:      data,
			ExitCode:    0,
			CollectedAt: time.Now().UTC(),
		})
	}
	return results, nil
}
