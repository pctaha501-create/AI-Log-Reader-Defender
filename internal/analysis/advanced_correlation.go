package analysis

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

const advancedCorrelationWindow = 2 * time.Hour

type stagedEvent struct {
	index int
	at    time.Time
	stage int
}

func analyzeAdvancedCorrelation(events []model.Event) []model.Finding {
	byKey := make(map[string][]stagedEvent)
	for i, event := range events {
		stage := classifyAttackStage(event)
		if stage == 0 {
			continue
		}
		for _, key := range correlationKeys(event) {
			byKey[key] = append(byKey[key], stagedEvent{index: i, at: event.Timestamp, stage: stage})
		}
	}

	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	seen := make(map[string]bool)
	findings := make([]model.Finding, 0)
	for _, key := range keys {
		items := byKey[key]
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].at.IsZero() || items[j].at.IsZero() {
				return items[i].index < items[j].index
			}
			if items[i].at.Equal(items[j].at) {
				return items[i].index < items[j].index
			}
			return items[i].at.Before(items[j].at)
		})

		identity := collectOrderedStages(items, []int{1, 2, 3, 4})
		if len(identity) >= 3 {
			emitCorrelation(&findings, seen,
				"correlation.identity-compromise-chain", "critical",
				"Multi-stage identity compromise pattern",
				"Related events show an ordered chain of authentication failures, account creation, privilege assignment and audit-log clearing. This combination warrants urgent investigation; correlation is based on shared event identity and does not prove a successful compromise.",
				key, identity)
		}

		impact := collectOrderedStages(items, []int{5, 6, 4})
		if len(impact) >= 3 {
			emitCorrelation(&findings, seen,
				"correlation.defense-evasion-before-impact", "critical",
				"Defense evasion followed by backup destruction",
				"Related events indicate security protection was weakened, backup or recovery data was targeted, and audit logging was cleared. Verify each action and preserve original evidence immediately.",
				key, impact)
		}
	}
	return findings
}

// Stage identifiers: 1 authentication failure, 2 account creation,
// 3 privilege grant, 4 audit clearing, 5 protection disabled, 6 backup destruction.
func classifyAttackStage(event model.Event) int {
	text := strings.ToLower(event.Message + " " + rawEventText(event.Raw))
	id := strings.TrimSpace(event.EventID)
	switch {
	case id == "1102" || id == "104" || containsAny(text, "audit log was cleared", "security log was cleared", "event log was cleared", "logs were cleared"):
		return 4
	case containsAny(text, "delete shadows", "vssadmin delete", "wbadmin delete", "remove-backup", "backup repository deleted", "backup retention disabled", "immutable backup disabled", "recovery catalog deleted"):
		return 6
	case containsAny(text, "set-mppreference", "disablerealtimemonitoring", "firewall disabled", "firewall was disabled", "endpoint protection disabled", "security monitoring disabled", "auditd stopped", "logging service stopped"):
		return 5
	case id == "4728" || id == "4732" || id == "4756" || containsAny(text, "added to administrators", "added to the administrators group", "added to privileged group", "privilege escalation", "administrator privileges granted"):
		return 3
	case id == "4720" || containsAny(text, "new user account", "user account created", "account was created", "created user account"):
		return 2
	case isFailedLogin(event, text):
		return 1
	default:
		return 0
	}
}

func rawEventText(raw map[string]any) string {
	if len(raw) == 0 {
		return ""
	}
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		b.WriteByte(' ')
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(fmt.Sprint(raw[key]))
	}
	return b.String()
}

func correlationKeys(event model.Event) []string {
	values := []struct{ kind, value string }{
		{"host", event.Host},
		{"user", event.User},
		{"ip", event.SourceIP},
	}
	keys := make([]string, 0, len(values))
	for _, item := range values {
		value := strings.ToLower(strings.TrimSpace(item.value))
		if value != "" && value != "unknown" && value != "-" {
			keys = append(keys, item.kind+":"+value)
		}
	}
	return keys
}

func collectOrderedStages(items []stagedEvent, wanted []int) []int {
	selected := make([]int, 0, len(wanted))
	position := 0
	var firstTime time.Time
	for _, item := range items {
		if item.stage != wanted[position] {
			continue
		}
		if len(selected) == 0 {
			firstTime = item.at
		} else if !firstTime.IsZero() && !item.at.IsZero() && item.at.Sub(firstTime) > advancedCorrelationWindow {
			selected = selected[:0]
			position = 0
			if item.stage != wanted[0] {
				continue
			}
			firstTime = item.at
		}
		selected = append(selected, item.index)
		position++
		if position == len(wanted) {
			return selected
		}
	}
	return selected
}

func emitCorrelation(out *[]model.Finding, seen map[string]bool, rule, severity, title, description, key string, indexes []int) {
	if len(indexes) < 3 {
		return
	}
	ordered := append([]int(nil), indexes...)
	sort.Ints(ordered)
	f := finding(rule, severity, title, description,
		ordered, []string{fmt.Sprintf("correlation_key=%s; ordered_event_indexes=%v; window=%s", key, indexes, advancedCorrelationWindow)})
	if seen[f.ID] {
		return
	}
	seen[f.ID] = true
	*out = append(*out, f)
}
