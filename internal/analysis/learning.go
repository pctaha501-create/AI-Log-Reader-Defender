package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

const baselineSchemaVersion = 1

var (
	baselineIPPattern = regexp.MustCompile(`(?i)\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	baselineNumberPattern = regexp.MustCompile(`\b[0-9]+\b`)
	baselineHexPattern = regexp.MustCompile(`(?i)\b[0-9a-f]{12,}\b`)
)

// Baseline is a local, vendor-neutral profile learned from previously observed
// events. It stores counts and fingerprints, never complete log messages.
type Baseline struct {
	SchemaVersion          int            `json:"schema_version"`
	TrainedAt              time.Time      `json:"trained_at"`
	EventCount             int            `json:"event_count"`
	ProviderCounts         map[string]int `json:"provider_counts"`
	ProviderSignatureCount map[string]int `json:"provider_signature_counts"`
	HostCounts             map[string]int `json:"host_counts"`
	HostSignatureCount     map[string]int `json:"host_signature_counts"`
}

// TrainBaseline learns normal source and event-frequency profiles from a
// trusted historical log sample. Use a representative, known-good period.
func TrainBaseline(events []model.Event) Baseline {
	b := Baseline{
		SchemaVersion:          baselineSchemaVersion,
		TrainedAt:              time.Now().UTC(),
		EventCount:             len(events),
		ProviderCounts:         make(map[string]int),
		ProviderSignatureCount: make(map[string]int),
		HostCounts:              make(map[string]int),
		HostSignatureCount:      make(map[string]int),
	}
	for _, event := range events {
		provider := eventProvider(event)
		signature := eventSignature(event)
		b.ProviderCounts[provider]++
		b.ProviderSignatureCount[provider+"|"+signature]++
		if host := normalizeKey(event.Host); host != "" {
			b.HostCounts[host]++
			b.HostSignatureCount[host+"|"+signature]++
		}
	}
	return b
}

// AnalyzeWithBaseline runs the normal explainable detections and adds
// conservative novelty findings learned from a local baseline.
func AnalyzeWithBaseline(events []model.Event, baseline Baseline) (model.Report, error) {
	if err := baseline.Validate(); err != nil {
		return model.Report{}, err
	}
	report := Analyze(events)
	providers := make(map[string][]int)
	newPatterns := make(map[string][]int)
	for i, event := range events {
		provider := eventProvider(event)
		signature := eventSignature(event)
		if baseline.ProviderCounts[provider] == 0 {
			providers[provider] = append(providers[provider], i)
			continue
		}
		key := provider + "|" + signature
		if baseline.ProviderSignatureCount[key] == 0 && baseline.ProviderCounts[provider] >= 25 {
			newPatterns[key] = append(newPatterns[key], i)
		}
	}

	providerNames := make([]string, 0, len(providers))
	for name := range providers {
		providerNames = append(providerNames, name)
	}
	sort.Strings(providerNames)
	for _, name := range providerNames {
		indexes := providers[name]
		report.Findings = append(report.Findings, finding(
			"learning.unseen-log-source", "low", "Previously unseen log source",
			fmt.Sprintf("The source %q was not present in the trained baseline. This may be a newly added device, software component, or logging configuration; novelty alone is not evidence of an attack.", name),
			indexes, []string{fmt.Sprintf("provider=%q; baseline_events=%d; observed_events=%d", name, baseline.EventCount, len(indexes))},
		))
	}

	patternKeys := make([]string, 0, len(newPatterns))
	for key := range newPatterns {
		patternKeys = append(patternKeys, key)
	}
	sort.Strings(patternKeys)
	for _, key := range patternKeys {
		indexes := newPatterns[key]
		report.Findings = append(report.Findings, finding(
			"learning.unseen-event-pattern", "low", "New event pattern for a known source",
			"A known log source emitted an event fingerprint that was not observed during baseline training. Review the raw events and surrounding activity; software updates and configuration changes can also introduce new patterns.",
			indexes, []string{fmt.Sprintf("provider_signature=%s; baseline_provider_events=%d; observed_events=%d", key, baseline.ProviderCounts[strings.SplitN(key, "|", 2)[0]], len(indexes))},
		))
	}

	sort.SliceStable(report.Findings, func(i, j int) bool {
		if severityRank(report.Findings[i].Severity) != severityRank(report.Findings[j].Severity) {
			return severityRank(report.Findings[i].Severity) > severityRank(report.Findings[j].Severity)
		}
		if report.Findings[i].RuleID != report.Findings[j].RuleID {
			return report.Findings[i].RuleID < report.Findings[j].RuleID
		}
		return report.Findings[i].ID < report.Findings[j].ID
	})
	report.AIAnalysis += fmt.Sprintf("\nBehavioral baseline: compared %d events with a local profile trained on %d events; %d unseen source groups and %d unseen event patterns were observed. Novelty findings are triage signals, not proof of compromise.", len(events), baseline.EventCount, len(providers), len(newPatterns))
	return report, nil
}

func (b Baseline) Validate() error {
	if b.SchemaVersion != baselineSchemaVersion {
		return fmt.Errorf("unsupported baseline schema version %d", b.SchemaVersion)
	}
	if b.EventCount < 1 {
		return fmt.Errorf("baseline contains no training events")
	}
	if b.ProviderCounts == nil || b.ProviderSignatureCount == nil {
		return fmt.Errorf("baseline is missing provider statistics")
	}
	return nil
}

func SaveBaseline(w io.Writer, baseline Baseline) error {
	if err := baseline.Validate(); err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(baseline); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	return nil
}

func LoadBaseline(r io.Reader) (Baseline, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var baseline Baseline
	if err := dec.Decode(&baseline); err != nil {
		return Baseline{}, fmt.Errorf("read baseline: %w", err)
	}
	if err := baseline.Validate(); err != nil {
		return Baseline{}, err
	}
	return baseline, nil
}

func eventProvider(event model.Event) string {
	if provider := normalizeKey(event.Provider); provider != "" {
		return provider
	}
	if source := normalizeKey(event.Source); source != "" {
		return source
	}
	return "unknown"
}

func normalizeKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func eventSignature(event model.Event) string {
	identity := strings.Join([]string{
		eventProvider(event),
		normalizeKey(event.Source),
		normalizeKey(event.EventID),
		normalizeKey(event.Level),
	}, "|")
	if strings.TrimSpace(event.EventID) == "" {
		message := strings.ToLower(strings.TrimSpace(event.Message))
		message = baselineIPPattern.ReplaceAllString(message, "<ip>")
		message = baselineHexPattern.ReplaceAllString(message, "<hex>")
		message = baselineNumberPattern.ReplaceAllString(message, "<n>")
		fields := strings.Fields(message)
		if len(fields) > 12 {
			fields = fields[:12]
		}
		identity += "|" + strings.Join(fields, " ")
	}
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:12])
}
