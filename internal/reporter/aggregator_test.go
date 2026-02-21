package reporter

import (
	"testing"

	"github.com/iyulab/system-coroner/internal/analyzer"
)

func TestShouldIsolate_Confirmed(t *testing.T) {
	agg := &Aggregator{}
	findings := []analyzer.Finding{
		{Check: "test", IntrusionConfidence: "confirmed", Title: "Confirmed intrusion"},
	}
	result := agg.ShouldIsolate(findings)
	if !result.Isolate {
		t.Error("expected Isolate=true for confirmed finding")
	}
	if result.Urgency != "immediate" {
		t.Errorf("expected urgency=immediate, got %s", result.Urgency)
	}
	if result.Banner != "red" {
		t.Errorf("expected banner=red, got %s", result.Banner)
	}
}

func TestShouldIsolate_TwoHigh(t *testing.T) {
	agg := &Aggregator{}
	findings := []analyzer.Finding{
		{Check: "a", IntrusionConfidence: "high"},
		{Check: "b", IntrusionConfidence: "high"},
	}
	result := agg.ShouldIsolate(findings)
	if !result.Isolate {
		t.Error("expected Isolate=true for 2+ high findings")
	}
	if result.Urgency != "urgent" {
		t.Errorf("expected urgency=urgent, got %s", result.Urgency)
	}
}

func TestShouldIsolate_OneHigh(t *testing.T) {
	agg := &Aggregator{}
	findings := []analyzer.Finding{
		{Check: "a", IntrusionConfidence: "high"},
	}
	result := agg.ShouldIsolate(findings)
	if result.Isolate {
		t.Error("expected Isolate=false for single high finding")
	}
	if result.Urgency != "monitor" {
		t.Errorf("expected urgency=monitor, got %s", result.Urgency)
	}
	if result.Banner != "yellow" {
		t.Errorf("expected banner=yellow, got %s", result.Banner)
	}
}

func TestShouldIsolate_MediumOnly(t *testing.T) {
	agg := &Aggregator{}
	findings := []analyzer.Finding{
		{Check: "a", IntrusionConfidence: "medium"},
	}
	result := agg.ShouldIsolate(findings)
	if result.Isolate {
		t.Error("expected Isolate=false for medium finding")
	}
	if result.Banner != "yellow" {
		t.Errorf("expected banner=yellow, got %s", result.Banner)
	}
}

func TestShouldIsolate_Clean(t *testing.T) {
	agg := &Aggregator{}
	findings := []analyzer.Finding{}
	result := agg.ShouldIsolate(findings)
	if result.Isolate {
		t.Error("expected Isolate=false for no findings")
	}
	if result.Urgency != "none" {
		t.Errorf("expected urgency=none, got %s", result.Urgency)
	}
	if result.Banner != "green" {
		t.Errorf("expected banner=green, got %s", result.Banner)
	}
}

func TestSummarizeConfidence(t *testing.T) {
	findings := []analyzer.Finding{
		{IntrusionConfidence: "confirmed"},
		{IntrusionConfidence: "high"},
		{IntrusionConfidence: "high"},
		{IntrusionConfidence: "medium"},
		{IntrusionConfidence: "low"},
		{IntrusionConfidence: "informational"},
		{IntrusionConfidence: "clean"},
	}
	s := SummarizeConfidence(findings)
	if s.Confirmed != 1 {
		t.Errorf("expected Confirmed=1, got %d", s.Confirmed)
	}
	if s.High != 2 {
		t.Errorf("expected High=2, got %d", s.High)
	}
	if s.Medium != 1 {
		t.Errorf("expected Medium=1, got %d", s.Medium)
	}
	if s.Low != 1 {
		t.Errorf("expected Low=1, got %d", s.Low)
	}
	if s.Informational != 1 {
		t.Errorf("expected Informational=1, got %d", s.Informational)
	}
	if s.Clean != 1 {
		t.Errorf("expected Clean=1, got %d", s.Clean)
	}
}

func TestCollectAllIoCs(t *testing.T) {
	findings := []analyzer.Finding{
		{
			Check: "c2",
			IoC: analyzer.IoC{
				IPs:     []string{"1.2.3.4"},
				Domains: []string{"evil.com"},
				Hashes:  []string{"abc123"},
			},
		},
		{
			Check: "persist",
			IoC: analyzer.IoC{
				Processes:    []string{"malware.exe"},
				RegistryKeys: []string{"HKLM\\Run\\bad"},
				UserAccounts: []string{"hacker"},
			},
		},
	}
	iocs := CollectAllIoCs(findings)
	if len(iocs) != 6 {
		t.Errorf("expected 6 IoCs, got %d", len(iocs))
	}

	typeCount := make(map[string]int)
	for _, ioc := range iocs {
		typeCount[ioc.Type]++
	}
	expected := map[string]int{
		"ip": 1, "domain": 1, "hash": 1,
		"process": 1, "registry_key": 1, "user_account": 1,
	}
	for typ, count := range expected {
		if typeCount[typ] != count {
			t.Errorf("expected %d %s IoCs, got %d", count, typ, typeCount[typ])
		}
	}
}

func TestCollectAllIoCs_Empty(t *testing.T) {
	iocs := CollectAllIoCs(nil)
	if len(iocs) != 0 {
		t.Errorf("expected 0 IoCs for nil findings, got %d", len(iocs))
	}
}
