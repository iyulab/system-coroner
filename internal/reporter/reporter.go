package reporter

import (
	"embed"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iyulab/system-coroner/internal/analyzer"
	"github.com/iyulab/system-coroner/internal/sigma"
)

//go:embed templates/*.tmpl
var templates embed.FS

// CollectionFailure records a check that failed during script execution.
type CollectionFailure struct {
	CheckID     string `json:"check_id"`
	CheckName   string `json:"check_name"`
	Error       string `json:"error"`
	FailureKind string `json:"failure_kind"` // timeout | permission_denied | script_error | not_found | unknown
}

// ReportData is the complete data model passed to the HTML template.
type ReportData struct {
	// Header
	Hostname    string    `json:"hostname"`
	OS          string    `json:"os"`
	GeneratedAt time.Time `json:"generated_at"`
	Version     string    `json:"version"`

	// Isolation decision
	Isolation IsolationRecommendation `json:"isolation"`

	// Summary
	ConfidenceSummary ConfidenceSummary `json:"confidence_summary"`
	TotalChecks       int               `json:"total_checks"`

	// Findings
	Findings    []analyzer.Finding    `json:"findings"`
	RawFindings []analyzer.RawFinding `json:"raw_findings,omitempty"`

	// Verdict (cross-analysis)
	Verdict *analyzer.Verdict `json:"verdict,omitempty"`

	// IoC list
	IoCs []analyzer.IoCEntry `json:"iocs"`

	// Evidence integrity
	EvidenceHashes []EvidenceHash `json:"evidence_hashes,omitempty"`

	// Collection failures (script execution errors)
	CollectionFailures []CollectionFailure `json:"collection_failures,omitempty"`

	// Evidence gap analysis (RP-007): forensic impact of each collection failure
	EvidenceGaps []EvidenceGap `json:"evidence_gaps,omitempty"`

	// Log capacity warnings (RP-009): event log capacity and evidence loss risk
	LogCapacityWarnings []LogCapacityWarning `json:"log_capacity_warnings,omitempty"`

	// RawCheckData holds the raw collected JSON for each check (keyed by check ID).
	// Used by the raw evidence JSON viewer (UI-007).
	RawCheckData map[string]string `json:"raw_check_data,omitempty"`

	// Sigma rule matches (pre-LLM deterministic detections)
	SigmaMatches []sigma.SigmaMatch `json:"sigma_matches,omitempty"`

	// Collection metadata
	CollectionDuration string `json:"collection_duration"`
	AnalysisDuration   string `json:"analysis_duration"`

	// Analyst context (for interactive re-evaluation)
	AnalystContext string `json:"analyst_context,omitempty"`
}

// EvidenceHash holds file-level integrity information for the report.
type EvidenceHash struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

// Reporter generates HTML reports from analysis results.
type Reporter struct {
	tmpl *template.Template
}

// New creates a Reporter with the embedded HTML template.
func New() (*Reporter, error) {
	funcMap := template.FuncMap{
		"bannerClass": func(iso IsolationRecommendation) string {
			if iso.Banner == "red" && iso.Urgency == "immediate" {
				return "banner-critical"
			}
			switch iso.Banner {
			case "red":
				return "banner-red"
			case "yellow":
				return "banner-yellow"
			default:
				return "banner-green"
			}
		},
		"confidenceClass": func(confidence string) string {
			switch confidence {
			case "confirmed":
				return "confidence-confirmed"
			case "high":
				return "confidence-high"
			case "medium":
				return "confidence-medium"
			case "low":
				return "confidence-low"
			default:
				return "confidence-info"
			}
		},
		"riskClass": func(risk string) string {
			switch risk {
			case "critical":
				return "risk-critical"
			case "high":
				return "risk-high"
			case "medium":
				return "risk-medium"
			default:
				return "risk-low"
			}
		},
		"killChainClass": func(phase string) string {
			p := strings.ToLower(phase)
			switch {
			case strings.Contains(p, "initial"), strings.Contains(p, "recon"), strings.Contains(p, "resource"):
				return "kc-initial"
			case strings.Contains(p, "execut"), strings.Contains(p, "persist"), strings.Contains(p, "privilege"):
				return "kc-execution"
			case strings.Contains(p, "defense"), strings.Contains(p, "credential"), strings.Contains(p, "discovery"):
				return "kc-evasion"
			case strings.Contains(p, "lateral"), strings.Contains(p, "collect"), strings.Contains(p, "command"):
				return "kc-lateral"
			case strings.Contains(p, "exfil"), strings.Contains(p, "impact"):
				return "kc-impact"
			default:
				return "kc-default"
			}
		},
		"failureKindClass": func(kind string) string {
			switch kind {
			case "timeout":
				return "fk-timeout"
			case "permission_denied":
				return "fk-permission"
			case "script_error":
				return "fk-script"
			case "not_found":
				return "fk-notfound"
			default:
				return "fk-unknown"
			}
		},
		"sigmaLevelClass": func(level string) string {
			switch strings.ToLower(level) {
			case "critical":
				return "sigma-critical"
			case "high":
				return "sigma-high"
			case "medium":
				return "sigma-medium"
			case "low":
				return "sigma-low"
			default:
				return "sigma-info"
			}
		},
	}

	tmpl, err := template.New("report.html.tmpl").Funcs(funcMap).ParseFS(templates, "templates/report.html.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}

	return &Reporter{tmpl: tmpl}, nil
}

// GenerateString renders the HTML template to a string (used by serve mode).
func (r *Reporter) GenerateString(data ReportData) (string, error) {
	var buf strings.Builder
	if err := r.tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render report: %w", err)
	}
	return buf.String(), nil
}

// Generate renders the HTML report and writes it to the output directory.
func (r *Reporter) Generate(data ReportData, outputDir string) (string, error) {
	reportPath := filepath.Join(outputDir, "report.html")
	f, err := os.Create(reportPath)
	if err != nil {
		return "", fmt.Errorf("create report: %w", err)
	}
	defer f.Close()

	if err := r.tmpl.Execute(f, data); err != nil {
		return "", fmt.Errorf("render report: %w", err)
	}

	return reportPath, nil
}
