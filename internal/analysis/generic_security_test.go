package analysis

import (
	"testing"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

func hasGenericRule(findings []model.Finding, rule string) bool {
	for _, item := range findings {
		if item.RuleID == rule {
			return true
		}
	}
	return false
}

func TestGenericSecurityRulesAreVendorNeutral(t *testing.T) {
	tests := []struct {
		name string
		event model.Event
		rule string
	}{
		{
			name: "backup destruction",
			event: model.Event{Source: "unknown appliance", Message: "vssadmin delete shadows /all"},
			rule: "generic.backup-destruction-indicator",
		},
		{
			name: "MFA disabled",
			event: model.Event{Provider: "IdentityService-X", Raw: map[string]any{"operation": "MFA disabled for tenant"}},
			rule: "generic.identity-strong-auth-disabled",
		},
		{
			name: "public storage exposure",
			event: model.Event{Source: "CloudAudit-Unknown", Message: "public access enabled for object storage bucket"},
			rule: "generic.cloud-public-exposure",
		},
		{
			name: "privileged container",
			event: model.Event{Provider: "ContainerPlatform-Z", Raw: map[string]any{"container": "api", "securityContext.privileged": true}},
			rule: "generic.container-privileged-execution",
		},
		{
			name: "industrial safety override",
			event: model.Event{Source: "PlantController", Message: "Emergency stop interlock bypassed by operator"},
			rule: "generic.industrial-safety-override",
		},
		{
			name: "PLC program change",
			event: model.Event{Provider: "IndustrialVendorUnknown", Message: "PLC control program downloaded"},
			rule: "generic.industrial-control-program-change",
		},
		{
			name: "SQL injection indicator",
			event: model.Event{Source: "UnknownWAF", Message: "request query contains UNION SELECT username from accounts"},
			rule: "generic.web-injection-attempt",
		},
		{
			name: "audit collection disabled",
			event: model.Event{Source: "UnknownLinux", Message: "security audit disabled"},
			rule: "generic.audit-collection-disabled",
		},
		{
			name: "scheduled task persistence",
			event: model.Event{Source: "UnknownEndpoint", Message: "new scheduled task created"},
			rule: "generic.persistence-mechanism-created",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := analyzeGenericSecurity([]model.Event{test.event})
			if !hasGenericRule(findings, test.rule) {
				t.Fatalf("expected vendor-neutral rule %q; got %#v", test.rule, findings)
			}
			for _, item := range findings {
				if item.RuleID == test.rule {
					if len(item.EventIndexes) != 1 || item.EventIndexes[0] != 0 {
						t.Fatalf("finding lost source event index: %#v", item)
					}
					if len(item.Evidence) == 0 || item.Evidence[0] == "" {
						t.Fatalf("finding has no evidence: %#v", item)
					}
				}
			}
		})
	}
}

func TestGenericSecurityRulesIgnoreUnrelatedEvents(t *testing.T) {
	events := []model.Event{
		{Source: "unknown", Message: "user signed in successfully"},
		{Source: "unknown", Message: "routine backup completed"},
		{Source: "unknown", Message: "container restarted after update"},
		{Source: "unknown", Message: "PLC status read"},
		{Source: "unknown", Message: "GET /index.html 200"},
	}
	if findings := analyzeGenericSecurity(events); len(findings) != 0 {
		t.Fatalf("unrelated events must not trigger generic security findings: %#v", findings)
	}
}
