package analysis

import (
 "testing"
 "github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)
func TestRepeatedFailuresDetection(t *testing.T) {
 events := make([]model.Event, 5); for i := range events { events[i] = model.Event{EventID:"4625", SourceIP:"198.51.100.20", Message:"An account failed to log on"} }
 r := Analyze(events); found := false; for _, f := range r.Findings { if f.RuleID == "authentication.repeated-failures" { found = true } }; if !found { t.Fatal("expected repeated failures finding") }
}
func TestAccountCreationPrivilegeCorrelation(t *testing.T) {
 events := []model.Event{{EventID:"4720", Message:"A user account was created"}, {EventID:"4732", Message:"Member added to the Administrators group"}}
 r := Analyze(events); found := false; for _, f := range r.Findings { if f.RuleID == "correlation.account-created-then-privileged" { found = true } }; if !found { t.Fatal("expected correlation finding") }
}
func TestPublicIP(t *testing.T) { if !IsPublicIP("8.8.8.8") || IsPublicIP("192.168.1.1") || IsPublicIP("127.0.0.1") { t.Fatal("public IP classification failed") } }
