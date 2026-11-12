package analysis

import (
	"fmt"
	"testing"
	"time"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

func TestFirewallDetectsWindowsBlockedTraffic(t *testing.T) {
	events := []model.Event{{EventID:"5157", Source:"Security", Provider:"Microsoft-Windows-Security-Auditing", Message:"The Windows Filtering Platform has blocked a connection.", SourceIP:"198.51.100.8", Timestamp:time.Now().UTC()}}
	report := Analyze(events)
	if len(report.Findings) != 0 {
		t.Fatalf("single blocked connection should not trigger a scan finding: %#v", report.Findings)
	}
}

func TestFirewallDetectsPortScanFromUFW(t *testing.T) {
	now := time.Now().UTC()
	events := make([]model.Event, 0, 10)
	for i := 0; i < 10; i++ {
		events = append(events, model.Event{Source:"syslog", Provider:"kernel", Message:fmt.Sprintf("[UFW BLOCK] IN=eth0 SRC=203.0.113.9 DST=192.0.2.10 PROTO=TCP DPT=%d", 20+i), Timestamp:now.Add(time.Duration(i)*10*time.Second)})
	}
	report := Analyze(events)
	found := false
	for _, f := range report.Findings { if f.RuleID == "firewall.port-scan-suspected" { found = true } }
	if !found { t.Fatalf("expected suspected port scan finding, got %#v", report.Findings) }
}

func TestFirewallDetectsDisabledProtection(t *testing.T) {
	report := Analyze([]model.Event{{Source:"Windows Firewall", Message:"Windows Defender Firewall service stopped"}})
	for _, f := range report.Findings { if f.RuleID == "firewall.protection-disabled" && f.Severity == "critical" { return } }
	t.Fatalf("expected critical firewall-disabled finding: %#v", report.Findings)
}
