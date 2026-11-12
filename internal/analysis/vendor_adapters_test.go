package analysis

import (
	"testing"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

func hasVendorRule(events []model.Event, rule string) bool {
	for _, f := range analyzeVendorAdapters(events) { if f.RuleID == rule { return true } }
	return false
}

func TestVendorAdaptersFortiGateTrafficDeny(t *testing.T) {
	e := model.Event{Provider:"FortiGate", Message:"forward traffic denied", Raw:map[string]any{"device_vendor":"Fortinet","device_product":"FortiGate","type":"traffic","subtype":"forward","action":"deny","srcip":"198.51.100.24","dstip":"192.0.2.10","dstport":"445","policyid":"17"}}
	if !hasVendorRule([]model.Event{e}, "fortigate.traffic-denied") { t.Fatal("expected FortiGate deny adapter") }
}

func TestVendorAdaptersMikroTikDrop(t *testing.T) {
	e := model.Event{Source:"syslog", Provider:"MikroTik RouterOS", Message:"firewall,info forward: in:ether1 out:bridge, src-mac 00:11:22:33:44:55, proto TCP (SYN), 198.51.100.8:53122->192.0.2.20:22, len 60"}
	if !hasVendorRule([]model.Event{e}, "mikrotik.firewall-drop") { t.Fatal("expected MikroTik firewall adapter") }
}

func TestVendorAdaptersCiscoASAACL(t *testing.T) {
	e := model.Event{Provider:"Cisco ASA", Message:"%ASA-6-106023: Deny tcp src outside:198.51.100.5/51422 dst inside:192.0.2.12/22 by access-group OUTSIDE_IN"}
	if !hasVendorRule([]model.Event{e}, "cisco.acl-deny") { t.Fatal("expected Cisco ASA ACL adapter") }
}

func TestVendorAdaptersDefenderEvents(t *testing.T) {
	for _, tc := range []struct{id, rule string}{{"1116","defender.threat-detected"},{"1117","defender.remediation-action"},{"5001","defender.protection-disabled"},{"5007","defender.configuration-changed"}} {
		if !hasVendorRule([]model.Event{{Provider:"Microsoft-Windows-Windows Defender", EventID:tc.id, Message:"Defender operational event"}}, tc.rule) { t.Errorf("event %s: expected %s", tc.id, tc.rule) }
	}
}

func TestVendorAdaptersLinuxAudit(t *testing.T) {
	e := model.Event{Source:"audit", Provider:"auditd", Message:"type=USER_AUTH msg=audit(1790000000.123:42): pid=1234 uid=0 auid=1000 acct=\"admin\" exe=\"/usr/sbin/sshd\" addr=198.51.100.7 res=failed", Raw:map[string]any{"type":"USER_AUTH","acct":"admin","exe":"/usr/sbin/sshd","addr":"198.51.100.7","res":"failed"}}
	if !hasVendorRule([]model.Event{e}, "linux-audit.authentication-failure") { t.Fatal("expected Linux audit auth adapter") }
}

func TestVendorAdapterDoesNotTreatFingerprintAsFinding(t *testing.T) {
	e := model.Event{Provider:"FortiGate", Message:"normal status update", Raw:map[string]any{"device_vendor":"Fortinet","device_product":"FortiGate"}}
	if got := analyzeVendorAdapters([]model.Event{e}); len(got) != 0 { t.Fatalf("unexpected findings: %#v", got) }
}
