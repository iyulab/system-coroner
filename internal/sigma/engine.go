// Package sigma evaluates Sigma detection rules against collected check results.
package sigma

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"path/filepath"

	sigmalib "github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"

	"github.com/iyulab/system-coroner/internal/collector"
)

//go:embed rules
var embeddedRules embed.FS

// Engine evaluates Sigma rules against collected check results.
type Engine struct {
	rules []evaluator.RuleEvaluator
}

// NewDefault creates an Engine loaded with the built-in embedded Sigma rules.
func NewDefault() (*Engine, error) {
	sub, err := fs.Sub(embeddedRules, "rules")
	if err != nil {
		return nil, err
	}
	return New(sub)
}

// New creates an Engine by loading Sigma rules from the given FS.
// All .yml/.yaml files are parsed as Sigma rules.
func New(rulesFS fs.FS) (*Engine, error) {
	var rules []evaluator.RuleEvaluator

	err := fs.WalkDir(rulesFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := filepath.Ext(path)
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		data, err := fs.ReadFile(rulesFS, path)
		if err != nil {
			return err
		}
		rule, err := sigmalib.ParseRule(data)
		if err != nil {
			return err
		}
		rules = append(rules, *evaluator.ForRule(rule))
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &Engine{rules: rules}, nil
}

// MatchAll evaluates all rules against each collected result and returns matches.
// Rules are scoped by logsource.category (must match result.CheckID).
func (e *Engine) MatchAll(ctx context.Context, results []collector.Result) []SigmaMatch {
	var matches []SigmaMatch
	for _, result := range results {
		if len(result.Stdout) == 0 {
			continue
		}
		matches = append(matches, e.matchResult(ctx, result)...)
	}
	return matches
}

// matchResult evaluates rules against a single check result.
func (e *Engine) matchResult(ctx context.Context, result collector.Result) []SigmaMatch {
	var data map[string]interface{}
	if err := json.Unmarshal(result.Stdout, &data); err != nil {
		return nil
	}

	events := extractEvents(data)
	if len(events) == 0 {
		return nil
	}

	var matches []SigmaMatch
	for _, ev := range e.rules {
		// Scope rule to the matching check via logsource.category
		cat := ev.Rule.Logsource.Category
		if cat != "" && cat != result.CheckID {
			continue
		}

		for _, event := range events {
			res, err := ev.Matches(ctx, event)
			if err != nil || !res.Match {
				continue
			}
			matches = append(matches, SigmaMatch{
				CheckID:   result.CheckID,
				RuleTitle: ev.Rule.Title,
				RuleID:    ev.Rule.ID,
				Level:     ev.Rule.Level,
				Event:     event,
			})
			break // one match per rule per check result is sufficient
		}
	}
	return matches
}

// extractEvents returns a list of flat event maps from collected result JSON.
// Array elements that are objects become individual events.
// Top-level objects (non-array) are included as-is.
func extractEvents(data map[string]interface{}) []map[string]interface{} {
	var events []map[string]interface{}
	for _, v := range data {
		switch typed := v.(type) {
		case []interface{}:
			for _, item := range typed {
				if m, ok := item.(map[string]interface{}); ok {
					events = append(events, m)
				}
			}
		case map[string]interface{}:
			events = append(events, typed)
		}
	}
	return events
}
