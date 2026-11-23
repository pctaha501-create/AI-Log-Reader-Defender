package analysis

import (
	"testing"
	"time"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

func TestAdvancedCorrelationDetectsIdentityCompromiseChain(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	events := []model.Event{
		{Timestamp: base, Host: "dc-01", SourceIP: "192.0.2.44", User: "operator", EventID: "4625", Message: "failed login"},
		{Timestamp: base.Add(2 * time.Minute), Host: "dc-01", User: "operator", EventID: "4720", Message: "user account created"},
		{Timestamp: base.Add(4 * time.Minute), Host: "dc-01", User: "operator", EventID: "4728", Message: "added to administrators"},
		{Timestamp: base.Add(6 * time.Minute), Host: "dc-01", User: "operator", EventID: "1102", Message: "audit log was cleared"},
	}
	findings := analyzeAdvancedCorrelation(events)
	if len(findings) != 1 {
		t.Fatalf("expected one identity chain finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].RuleID != "correlation.identity-compromise-chain" || findings[0].Severity != "critical" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if len(findings[0].EventIndexes) != 4 {
		t.Fatalf("expected all four event indexes, got %v", findings[0].EventIndexes)
	}
}

func TestAdvancedCorrelationDoesNotClaimAuditClearWhenStageMissing(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	events := []model.Event{
		{Timestamp: base, Host: "home-pc", User: "sample-user", SourceIP: "203.0.113.10", EventID: "4625", Message: "An account failed to log on"},
		{Timestamp: base.Add(5 * time.Minute), Host: "home-pc", User: "new-user", EventID: "4720", Message: "A user account was created"},
		{Timestamp: base.Add(6 * time.Minute), Host: "home-pc", User: "new-user", EventID: "4732", Message: "A member was added to a security-enabled local group"},
	}
	findings := analyzeAdvancedCorrelation(events)
	for _, finding := range findings {
		if finding.RuleID == "correlation.identity-compromise-chain" {
			t.Fatalf("must not claim audit-log clearing when no clear event exists: %#v", finding)
		}
	}
}

func TestAdvancedCorrelationDetectsDefenseEvasionAndImpact(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	events := []model.Event{
		{Timestamp: base, Host: "fileserver", User: "admin", Message: "Set-MpPreference DisableRealtimeMonitoring"},
		{Timestamp: base.Add(time.Minute), Host: "fileserver", User: "admin", Message: "vssadmin delete shadows"},
		{Timestamp: base.Add(2 * time.Minute), Host: "fileserver", User: "admin", EventID: "1102", Message: "security log was cleared"},
	}
	findings := analyzeAdvancedCorrelation(events)
	if len(findings) != 1 || findings[0].RuleID != "correlation.defense-evasion-before-impact" {
		t.Fatalf("expected defense-evasion chain, got %#v", findings)
	}
}

func TestAdvancedCorrelationRejectsUnrelatedOrOutOfWindowEvents(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	unrelated := []model.Event{
		{Timestamp: base, Host: "host-a", User: "alice", EventID: "4625", Message: "failed login"},
		{Timestamp: base.Add(time.Minute), Host: "host-b", User: "alice", EventID: "4720", Message: "user account created"},
		{Timestamp: base.Add(2 * time.Minute), Host: "host-c", User: "alice", EventID: "4728", Message: "added to administrators"},
		{Timestamp: base.Add(3 * time.Minute), Host: "host-d", User: "alice", EventID: "1102", Message: "audit log was cleared"},
	}
	if got := analyzeAdvancedCorrelation(unrelated); len(got) != 0 {
		t.Fatalf("unrelated hosts must not correlate: %#v", got)
	}
	outOfWindow := []model.Event{
		{Timestamp: base, Host: "host-a", User: "alice", EventID: "4625", Message: "failed login"},
		{Timestamp: base.Add(3 * time.Hour), Host: "host-a", User: "alice", EventID: "4720", Message: "user account created"},
		{Timestamp: base.Add(4 * time.Hour), Host: "host-a", User: "alice", EventID: "4728", Message: "added to administrators"},
		{Timestamp: base.Add(5 * time.Hour), Host: "host-a", User: "alice", EventID: "1102", Message: "audit log was cleared"},
	}
	if got := analyzeAdvancedCorrelation(outOfWindow); len(got) != 0 {
		t.Fatalf("events outside the correlation window must not correlate: %#v", got)
	}
}

func TestAdvancedCorrelationSkipsEventsWithoutIdentity(t *testing.T) {
	events := []model.Event{
		{EventID: "4720", Message: "user account created"},
		{EventID: "4728", Message: "added to administrators"},
		{EventID: "1102", Message: "audit log was cleared"},
	}
	if got := analyzeAdvancedCorrelation(events); len(got) != 0 {
		t.Fatalf("events without a shared identity must not correlate: %#v", got)
	}
}

func TestAdvancedCorrelationRejectsDifferentAccountsOnSameHost(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	events := []model.Event{
		{Timestamp: base, Host: "dc-01", User: "alice", EventID: "4625", Message: "failed login"},
		{Timestamp: base.Add(time.Minute), Host: "dc-01", User: "bob", EventID: "4720", Message: "user account created"},
		{Timestamp: base.Add(2 * time.Minute), Host: "dc-01", User: "bob", EventID: "4728", Message: "added to administrators"},
		{Timestamp: base.Add(3 * time.Minute), Host: "dc-01", User: "bob", EventID: "1102", Message: "audit log was cleared"},
	}
	if got := analyzeAdvancedCorrelation(events); len(got) != 0 {
		t.Fatalf("events for different accounts on one host must not form an identity chain: %#v", got)
	}
}

func TestAdvancedCorrelationRequiresTimestampsForTimeBoundedChain(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	events := []model.Event{
		{Host: "dc-01", User: "alice", EventID: "4625", Message: "failed login"},
		{Timestamp: base.Add(time.Minute), Host: "dc-01", User: "alice", EventID: "4720", Message: "user account created"},
		{Timestamp: base.Add(2 * time.Minute), Host: "dc-01", User: "alice", EventID: "4728", Message: "added to administrators"},
		{Timestamp: base.Add(3 * time.Minute), Host: "dc-01", User: "alice", EventID: "1102", Message: "audit log was cleared"},
	}
	if got := analyzeAdvancedCorrelation(events); len(got) != 0 {
		t.Fatalf("a time-bounded chain must not include an event with an unknown timestamp: %#v", got)
	}
}
