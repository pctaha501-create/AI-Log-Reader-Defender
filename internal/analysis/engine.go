package analysis

import (
 "crypto/sha256"
 "fmt"
 "net"
 "strings"
 "time"

 "github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)
func Analyze(events []model.Event) model.Report {
 r := model.Report{GeneratedAt: time.Now().UTC(), EventCount: len(events), Findings: []model.Finding{}}
 failed := map[string][]int{}
 for i, e := range events {
  msg := strings.ToLower(e.Message)
  if isFailedLogin(e, msg) { key := e.SourceIP; if key == "" { key = e.User }; if key == "" { key = "unknown" }; failed[key] = append(failed[key], i) }
  if containsAny(msg, "malware detected", "trojan detected", "virus detected", "ransomware detected", "quarantined threat") {
   r.Findings = append(r.Findings, finding("endpoint.malware-indicator", "high", "Malware-related event", "An explicit malware or quarantine indicator was observed. Validate the originating security product and event details.", []int{i}, []string{clip(e.Message)}))
  }
  if containsAny(msg, "audit log was cleared", "event log was cleared", "log was cleared") || e.EventID == "1102" {
   r.Findings = append(r.Findings, finding("windows.audit-log-cleared", "high", "Security audit log cleared", "An audit-log-clearing event may be maintenance or defense evasion; investigate the actor and surrounding events.", []int{i}, []string{clip(e.Message)}))
  }
  if containsAny(msg, "new user account", "user account created", "account was created") || e.EventID == "4720" {
   r.Findings = append(r.Findings, finding("identity.account-created", "medium", "User account creation", "A new-account event was observed. Confirm that the account creation was authorized.", []int{i}, []string{clip(e.Message)}))
  }
  if containsAny(msg, "added to administrators", "added to the administrators group", "privilege assigned", "privilege escalation") || e.EventID == "4728" || e.EventID == "4732" {
   r.Findings = append(r.Findings, finding("identity.privilege-change", "high", "Privileged group or privilege change", "A privileged membership change was observed. Verify the initiating account and change request.", []int{i}, []string{clip(e.Message)}))
  }
 }
 for key, indexes := range failed { if len(indexes) >= 5 { ev := events[indexes[0]]; r.Findings = append(r.Findings, finding("authentication.repeated-failures", "medium", "Repeated authentication failures", fmt.Sprintf("At least %d failed-login events share source key %q in this input batch. This is a triage signal, not proof of brute force.", len(indexes), key), indexes, []string{fmt.Sprintf("first observed user=%q source_ip=%q", ev.User, ev.SourceIP)})) } }
 r.Findings = append(r.Findings, correlate(events)...)
 return r
}
func isFailedLogin(e model.Event, msg string) bool { return e.EventID == "4625" || containsAny(msg, "failed to log on", "login failed", "authentication failure", "failed password") }
func containsAny(s string, needles ...string) bool { for _, n := range needles { if strings.Contains(s, n) { return true } }; return false }
func clip(s string) string { s = strings.TrimSpace(s); if len(s) > 240 { return s[:240] }; return s }
func finding(rule, severity, title, desc string, indexes []int, evidence []string) model.Finding {
 seed := fmt.Sprintf("%s|%v|%s", rule, indexes, desc); sum := sha256.Sum256([]byte(seed))
 return model.Finding{ID: fmt.Sprintf("%x", sum[:8]), RuleID: rule, Severity: severity, Title: title, Description: desc, EventIndexes: indexes, Evidence: evidence}
}
// Correlate a newly created account followed by a privileged-group change in this batch.
func correlate(events []model.Event) []model.Finding {
 var created, elevated []int
 for i, e := range events {
  m := strings.ToLower(e.Message)
  if e.EventID == "4720" || containsAny(m, "user account created", "new user account") { created = append(created, i) }
  if e.EventID == "4728" || e.EventID == "4732" || containsAny(m, "added to administrators", "added to the administrators group") { elevated = append(elevated, i) }
 }
 for _, a := range created { for _, b := range elevated { if b > a && b-a <= 100 {
  return []model.Finding{finding("correlation.account-created-then-privileged", "high", "Account creation followed by privilege change", "A user-account creation was followed by a privileged-group change within the same batch. Confirm both actions and identify the actor.", []int{a,b}, []string{fmt.Sprintf("event indexes %d then %d", a,b)})}
 } } }
 return nil
}
func IsPublicIP(value string) bool { ip := net.ParseIP(value); return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() }
