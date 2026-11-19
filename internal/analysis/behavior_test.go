package analysis

import (
	"strings"
	"testing"
	"time"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

func TestOfflineIntelligenceDetectsEncodedPowerShell(t *testing.T) {
	events := []model.Event{{Provider: "Microsoft-Windows-PowerShell", Message: "powershell.exe -EncodedCommand SQBFAFgA"}}
	report := Analyze(events)
	if !hasRule(report, "behavior.encoded-powershell") {
		t.Fatal("expected encoded PowerShell behavior finding")
	}
	if !strings.Contains(report.AIAnalysis, "Built-in offline intelligence summary") {
		t.Fatal("expected automatic offline analysis summary")
	}
	if !strings.Contains(report.AIAnalysis, "no external model") {
		t.Fatal("summary should disclose offline engine method")
	}
}

func TestOfflineIntelligenceDetectsDefenderTampering(t *testing.T) {
	events := []model.Event{{Message: "powershell Set-MpPreference -DisableRealtimeMonitoring $true"}}
	if !hasRule(Analyze(events), "behavior.defender-protection-tampering") {
		t.Fatal("expected Defender tampering finding")
	}
}

func TestOfflineIntelligenceDetectsEventVolumeSpike(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	events := make([]model.Event, 0, 52)
	for i := 0; i < 3; i++ {
		events = append(events, model.Event{Timestamp: base.Add(time.Duration(i) * 10 * time.Minute), Host: "router-1", Provider: "syslog", Source: "firewall"})
	}
	for i := 0; i < 49; i++ {
		events = append(events, model.Event{Timestamp: base.Add(10*time.Minute + time.Duration(i)*time.Second), Host: "router-1", Provider: "syslog", Source: "firewall"})
	}
	if !hasRule(Analyze(events), "behavior.event-volume-spike") {
		t.Fatal("expected event-volume anomaly finding")
	}
}

func TestOfflineIntelligenceNoFindingForOrdinaryText(t *testing.T) {
	report := Analyze([]model.Event{{Message: "user logged in successfully"}})
	for _, f := range report.Findings {
		if strings.HasPrefix(f.RuleID, "behavior.") {
			t.Fatalf("unexpected behavior finding: %s", f.RuleID)
		}
	}
	if !strings.Contains(report.AIAnalysis, "does not prove the system is safe") {
		t.Fatal("expected cautious no-indicator summary")
	}
}
