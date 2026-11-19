package analysis

import (
	"bytes"
	"strings"
	"testing"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

func TestTrainBaselineCountsUnknownProvidersAndSignatures(t *testing.T) {
	events := []model.Event{
		{Provider: "Vendor-X", Host: "edge-1", EventID: "100", Level: "info"},
		{Provider: "Vendor-X", Host: "edge-1", EventID: "100", Level: "info"},
		{Provider: "Vendor-Y", Host: "db-1", EventID: "200", Level: "warning"},
	}
	baseline := TrainBaseline(events)
	if baseline.EventCount != 3 || baseline.ProviderCounts["vendor-x"] != 2 || baseline.ProviderCounts["vendor-y"] != 1 {
		t.Fatalf("unexpected baseline counts: %#v", baseline)
	}
	if baseline.HostCounts["edge-1"] != 2 {
		t.Fatalf("expected host count, got %#v", baseline.HostCounts)
	}
}

func TestAnalyzeWithBaselineDetectsUnseenSource(t *testing.T) {
	training := make([]model.Event, 30)
	for i := range training {
		training[i] = model.Event{Provider: "known-router", EventID: "link-up", Message: "interface link state changed"}
	}
	baseline := TrainBaseline(training)
	report, err := AnalyzeWithBaseline([]model.Event{{Provider: "unknown-appliance", EventID: "9001", Message: "policy changed"}}, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(report, "learning.unseen-log-source") {
		t.Fatalf("expected unseen source finding, got %#v", report.Findings)
	}
}

func TestAnalyzeWithBaselineDetectsNewPatternForKnownSource(t *testing.T) {
	training := make([]model.Event, 30)
	for i := range training {
		training[i] = model.Event{Provider: "known-router", EventID: "link-up"}
	}
	baseline := TrainBaseline(training)
	report, err := AnalyzeWithBaseline([]model.Event{{Provider: "known-router", EventID: "admin-login-failed"}}, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(report, "learning.unseen-event-pattern") {
		t.Fatalf("expected unseen event pattern, got %#v", report.Findings)
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	baseline := TrainBaseline([]model.Event{{Provider: "switch", EventID: "port-up"}})
	var buf bytes.Buffer
	if err := SaveBaseline(&buf, baseline); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadBaseline(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.EventCount != 1 || loaded.ProviderCounts["switch"] != 1 {
		t.Fatalf("unexpected loaded baseline: %#v", loaded)
	}
}

func TestLoadBaselineRejectsInvalidSchema(t *testing.T) {
	_, err := LoadBaseline(strings.NewReader(`{"schema_version":99,"event_count":1,"provider_counts":{},"provider_signature_counts":{}}`))
	if err == nil {
		t.Fatal("expected unsupported schema error")
	}
}
