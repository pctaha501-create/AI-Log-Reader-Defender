package analysis

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

const failureThreshold = 5
const failureWindow = 10 * time.Minute

type failureEvent struct {
	index int
	at    time.Time
}

type Options struct {
	FailureThreshold int
	FailureWindow    time.Duration
}

// Analyze evaluates normalized events with deterministic, explainable rules.
func Analyze(events []model.Event) model.Report {
	return AnalyzeWithOptions(events, Options{})
}

func AnalyzeWithOptions(events []model.Event, opts Options) model.Report {
	if opts.FailureThreshold < 1 {
		opts.FailureThreshold = failureThreshold
	}
	if opts.FailureWindow <= 0 {
		opts.FailureWindow = failureWindow
	}
	r := model.Report{GeneratedAt: time.Now().UTC(), EventCount: len(events), Findings: []model.Finding{}}
	failed := map[string][]failureEvent{}
	for i, e := range events {
		msg, id := strings.ToLower(strings.TrimSpace(e.Message)), strings.TrimSpace(e.EventID)
		if isFailedLogin(e, msg) {
			key := strings.TrimSpace(e.SourceIP)
			if key == "" {
				key = strings.TrimSpace(e.User)
			}
			if key == "" {
				key = "unknown"
			}
			failed[key] = append(failed[key], failureEvent{i, e.Timestamp})
		}
		switch {
		case containsAny(msg, "malware detected", "trojan detected", "virus detected", "ransomware detected", "quarantined threat", "malicious file detected"):
			r.Findings = append(r.Findings, finding("endpoint.malware-indicator", "high", "Malware-related event", "An explicit malware or quarantine indicator was observed. Validate the originating security product, detection name, file path, and remediation status.", []int{i}, []string{clip(e.Message)}))
		case id == "1102" || id == "104" || containsAny(msg, "audit log was cleared", "security log was cleared", "event log was cleared", "log was cleared"):
			r.Findings = append(r.Findings, finding("audit.log-cleared", "high", "Event log cleared", "A log-clearing event may be routine maintenance or an attempt to hinder investigation. Verify the actor, reason, and surrounding activity.", []int{i}, []string{eventEvidence(e)}))
		case id == "4720" || containsAny(msg, "new user account", "user account created", "account was created"):
			r.Findings = append(r.Findings, finding("identity.account-created", "medium", "User account creation", "A new-account event was observed. Confirm that the account, creator, and timing were authorized.", []int{i}, []string{eventEvidence(e)}))
		case id == "4728" || id == "4732" || id == "4756" || containsAny(msg, "added to administrators", "added to the administrators group", "added to privileged group", "privilege escalation"):
			r.Findings = append(r.Findings, finding("identity.privilege-change", "high", "Privileged membership change", "A privileged group membership or privilege-change indicator was observed. Verify the initiating account and approved change.", []int{i}, []string{eventEvidence(e)}))
		case id == "4726" || id == "4733" || id == "4757" || containsAny(msg, "user account deleted", "account was deleted", "removed from administrators"):
			r.Findings = append(r.Findings, finding("identity.account-or-membership-removed", "low", "Account or membership removed", "An account deletion or group-membership removal indicator was observed. Confirm it matches an authorized administrative action.", []int{i}, []string{eventEvidence(e)}))
		}
	}
	keys := make([]string, 0, len(failed))
	for k := range failed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		items := failed[key]
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].at.IsZero() {
				return false
			}
			if items[j].at.IsZero() {
				return true
			}
			return items[i].at.Before(items[j].at)
		})
		indexes := largestWindow(items, opts.FailureWindow)
		if len(indexes) >= opts.FailureThreshold {
			r.Findings = append(r.Findings, finding("authentication.repeated-failures", "medium", "Repeated authentication failures", fmt.Sprintf("%d failed-login events for source key %q occurred within a %s window. This is a triage signal, not proof of brute force.", len(indexes), key, opts.FailureWindow), indexes, []string{fmt.Sprintf("source_key=%q; first_event_index=%d; last_event_index=%d", key, indexes[0], indexes[len(indexes)-1])}))
		}
	}
	r.Findings = append(r.Findings, correlate(events)...)
	r.Findings = append(r.Findings, analyzeNetwork(events)...)
	r.Findings = append(r.Findings, analyzeBehavior(events)...)
	r.Findings = append(r.Findings, analyzeVendorAdapters(events)...)
	r.Findings = append(r.Findings, analyzeGenericSecurity(events)...)
	sort.SliceStable(r.Findings, func(i, j int) bool {
		if severityRank(r.Findings[i].Severity) != severityRank(r.Findings[j].Severity) {
			return severityRank(r.Findings[i].Severity) > severityRank(r.Findings[j].Severity)
		}
		if r.Findings[i].RuleID != r.Findings[j].RuleID {
			return r.Findings[i].RuleID < r.Findings[j].RuleID
		}
		return r.Findings[i].ID < r.Findings[j].ID
	})
	r.AIAnalysis = buildOfflineAnalysis(events, r.Findings)
	return r
}

func largestWindow(items []failureEvent, w time.Duration) []int {
	best := []int{}
	for left := 0; left < len(items); left++ {
		right := left
		for right < len(items) {
			if !items[left].at.IsZero() && !items[right].at.IsZero() && items[right].at.Sub(items[left].at) > w {
				break
			}
			right++
		}
		if right-left > len(best) {
			best = make([]int, 0, right-left)
			for _, v := range items[left:right] {
				best = append(best, v.index)
			}
		}
	}
	return best
}

func isFailedLogin(e model.Event, m string) bool {
	id := strings.TrimSpace(e.EventID)
	return id == "4625" || id == "4771" || id == "4776" || containsAny(m, "failed to log on", "login failed", "authentication failure", "failed password", "invalid password")
}

func containsAny(s string, n ...string) bool {
	for _, v := range n {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 240 {
		return s[:240] + "…"
	}
	return s
}

func eventEvidence(e model.Event) string {
	p := []string{}
	if e.EventID != "" {
		p = append(p, "event_id="+e.EventID)
	}
	if e.Provider != "" {
		p = append(p, "provider="+e.Provider)
	}
	if e.User != "" {
		p = append(p, "user="+e.User)
	}
	if e.SourceIP != "" {
		p = append(p, "source_ip="+e.SourceIP)
	}
	if e.Message != "" {
		p = append(p, "message="+clip(e.Message))
	}
	if len(p) == 0 {
		return "event contained no normalized evidence fields"
	}
	return strings.Join(p, "; ")
}

func finding(rule, sev, title, desc string, idx []int, evidence []string) model.Finding {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%v|%s", rule, idx, desc)))
	return model.Finding{ID: fmt.Sprintf("%x", sum[:8]), RuleID: rule, Severity: sev, Title: title, Description: desc, EventIndexes: idx, Evidence: evidence}
}

func correlate(events []model.Event) []model.Finding {
	created, elevated := []int{}, []int{}
	for i, e := range events {
		m := strings.ToLower(e.Message)
		if e.EventID == "4720" || containsAny(m, "user account created", "new user account") {
			created = append(created, i)
		}
		if e.EventID == "4728" || e.EventID == "4732" || e.EventID == "4756" || containsAny(m, "added to administrators", "added to the administrators group") {
			elevated = append(elevated, i)
		}
	}
	for _, a := range created {
		for _, b := range elevated {
			if b > a && b-a <= 100 {
				return []model.Finding{finding("correlation.account-created-then-privileged", "high", "Account creation followed by privilege change", "A user-account creation was followed by a privileged-group change within 100 events in this input. Confirm both actions and identify the actor.", []int{a, b}, []string{fmt.Sprintf("event indexes %d then %d", a, b)})}
			}
		}
	}
	return nil
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// IsPublicIP reports globally routable unicast addresses, excluding private,
// loopback, link-local, unspecified, and multicast addresses.
func IsPublicIP(v string) bool {
	ip := net.ParseIP(strings.TrimSpace(v))
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}
