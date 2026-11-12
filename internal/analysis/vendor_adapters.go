package analysis

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

// analyzeVendorAdapters contains product-family-specific detections. The rules
// deliberately require recognizable vendor fields or message signatures; a
// vendor fingerprint alone never creates a security finding.
func analyzeVendorAdapters(events []model.Event) []model.Finding {
	var out []model.Finding
	for i, e := range events {
		raw := lowerRaw(e.Raw)
		text := strings.ToLower(e.Message + " " + rawText(raw))
		switch detectAdapterFamily(e, raw, text) {
		case "fortigate":
			out = append(out, analyzeFortiGate(i, e, raw, text)...)
		case "mikrotik":
			out = append(out, analyzeMikroTik(i, e, raw, text)...)
		case "cisco":
			out = append(out, analyzeCisco(i, e, raw, text)...)
		case "windows-defender":
			out = append(out, analyzeDefender(i, e, raw, text)...)
		case "linux-audit":
			out = append(out, analyzeLinuxAudit(i, e, raw, text)...)
		}
	}
	return out
}

func lowerRaw(in map[string]any) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if v != nil {
			out[strings.ToLower(k)] = strings.TrimSpace(fmt.Sprint(v))
		}
	}
	return out
}

func rawText(raw map[string]string) string {
	keys := make([]string, 0, len(raw))
	for k := range raw { keys = append(keys, k) }
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys { b.WriteString(k); b.WriteByte('='); b.WriteString(raw[k]); b.WriteByte(' ') }
	return b.String()
}

func rawValue(raw map[string]string, keys ...string) string {
	for _, k := range keys { if v := strings.TrimSpace(raw[strings.ToLower(k)]); v != "" { return v } }
	return ""
}

func detectAdapterFamily(e model.Event, raw map[string]string, text string) string {
	vendor := strings.ToLower(e.Provider + " " + rawValue(raw, "device_vendor", "vendor", "observer_vendor"))
	product := strings.ToLower(rawValue(raw, "device_product", "product", "product_name"))
	source := strings.ToLower(e.Source)
	switch {
	case strings.Contains(vendor+" "+product+" "+source, "fortigate") || strings.Contains(vendor+" "+product+" "+source, "fortios") || rawValue(raw, "devid", "vd") != "" && rawValue(raw, "logid") != "":
		return "fortigate"
	case strings.Contains(vendor+" "+product+" "+source, "mikrotik") || strings.Contains(text, "routeros") || strings.Contains(text, "mikrotik"):
		return "mikrotik"
	case strings.Contains(vendor+" "+product+" "+source, "cisco") || strings.Contains(text, "%asa-") || strings.Contains(text, "%sec-6-ipaccesslog"):
		return "cisco"
	case strings.Contains(vendor+" "+product+" "+source, "windows defender") || strings.Contains(vendor, "microsoft-windows-windows defender") || strings.Contains(source, "defender"):
		return "windows-defender"
	case strings.Contains(source, "audit") || strings.Contains(e.Provider, "audit") || strings.Contains(text, "type= user_auth") || strings.Contains(text, "type=user_auth") || strings.Contains(text, "type=syscall") || strings.Contains(text, "type=execve"):
		return "linux-audit"
	}
	return ""
}

func analyzeFortiGate(i int, e model.Event, r map[string]string, text string) []model.Finding {
	var out []model.Finding
	subtype := strings.ToLower(rawValue(r, "subtype"))
	eventType := strings.ToLower(rawValue(r, "type"))
	action := strings.ToLower(rawValue(r, "action", "act"))
	logid := rawValue(r, "logid")
	if action == "" {
		if strings.Contains(text, "action=deny") || strings.Contains(text, "action=blocked") { action = "deny" }
	}
	if (eventType == "traffic" || subtype == "forward" || strings.HasPrefix(logid, "00000000")) && containsAny(action, "deny", "blocked", "drop", "dropped", "reject") {
		src, dst := rawValue(r, "srcip", "src_ip"), rawValue(r, "dstip", "dst_ip")
		port := rawValue(r, "dstport", "dst_port")
		out = append(out, finding("fortigate.traffic-denied", "low", "FortiGate denied traffic",
			fmt.Sprintf("FortiGate recorded a denied traffic event (source %s, destination %s, destination port %s). Check policy ID, interface, service, and whether the deny is expected.", valueOr(src, "unknown"), valueOr(dst, "unknown"), valueOr(port, "unknown")),
			[]int{i}, []string{eventEvidence(e), "family=FortiGate; subtype="+subtype+"; action="+action+"; policyid="+rawValue(r, "policyid")}))
	}
	if strings.Contains(text, "admin login") || strings.Contains(text, "administrator login") || strings.Contains(logid, "010003") {
		if containsAny(text, "failed", "failure", "invalid", "incorrect") || containsAny(strings.ToLower(rawValue(r, "status")), "failed", "failure") {
			out = append(out, finding("fortigate.admin-login-failed", "medium", "FortiGate administrator login failed",
				"A FortiGate administrative authentication failure was recorded. Review the administrator name, source IP, trusted-host policy, and adjacent successful logins.",
				[]int{i}, []string{eventEvidence(e), "family=FortiGate; user="+rawValue(r, "user", "user_name")+"; srcip="+rawValue(r, "srcip")}))
		}
	}
	if strings.Contains(text, "system configuration changed") || strings.Contains(logid, "010004") || strings.Contains(text, "cfg save") {
		out = append(out, finding("fortigate.configuration-change", "medium", "FortiGate configuration change",
			"A FortiGate configuration-change indicator was found. Verify the administrator, changed object, configuration revision, and change ticket.",
			[]int{i}, []string{eventEvidence(e), "family=FortiGate; user="+rawValue(r, "user", "user_name")}))
	}
	return out
}

func analyzeMikroTik(i int, e model.Event, r map[string]string, text string) []model.Finding {
	var out []model.Finding
	isFirewall := strings.Contains(text, "firewall") || strings.Contains(text, "filter") || strings.Contains(text, "routeros")
	if !isFirewall { return out }
	if containsAny(text, "drop", "dropped", "reject") {
		src := rawValue(r, "src-address", "src_address", "src", "source_ip")
		dst := rawValue(r, "dst-address", "dst_address", "dst", "destination_ip")
		if src == "" {
			if m := mikrotikAddress.FindStringSubmatch(text); len(m) > 1 { src = m[1] }
		}
		out = append(out, finding("mikrotik.firewall-drop", "low", "MikroTik firewall dropped traffic",
			fmt.Sprintf("A RouterOS firewall drop/reject record was found (source %s, destination %s). Check chain, in/out interface, protocol, and rule order.", valueOr(src, "unknown"), valueOr(dst, "unknown")),
			[]int{i}, []string{eventEvidence(e), "family=MikroTik RouterOS; chain="+rawValue(r, "chain")+"; action=drop"}))
	}
	if containsAny(text, "login failure", "login failed", "authentication failed", "invalid user", "user password") {
		out = append(out, finding("mikrotik.login-failure", "medium", "MikroTik login failure",
			"A RouterOS authentication failure indicator was found. Correlate source address, account, service (SSH/Winbox/API), and repeated attempts.",
			[]int{i}, []string{eventEvidence(e), "family=MikroTik RouterOS; src="+rawValue(r, "src-address", "src")}))
	}
	if containsAny(text, "system,critical", "router rebooted", "rebooted without proper shutdown", "power failure") {
		out = append(out, finding("mikrotik.unexpected-reboot", "medium", "MikroTik unexpected reboot or power event",
			"RouterOS logged a reboot or abnormal shutdown indicator. Confirm power stability and whether an administrator initiated the restart.",
			[]int{i}, []string{eventEvidence(e), "family=MikroTik RouterOS"}))
	}
	return out
}

var mikrotikAddress = regexp.MustCompile(`(?i)(?:src-address=|\b)([0-9]{1,3}(?:\.[0-9]{1,3}){3}):[0-9]{1,5}`)

func analyzeCisco(i int, e model.Event, r map[string]string, text string) []model.Finding {
	var out []model.Finding
	if strings.Contains(text, "%asa-") || strings.Contains(text, "denied") && (strings.Contains(text, "access-group") || strings.Contains(text, "ipaccesslog")) {
		if containsAny(text, "deny", "denied", "drop") {
			out = append(out, finding("cisco.acl-deny", "low", "Cisco ACL denied traffic",
				"A Cisco ASA/IOS access-control denial was recorded. Review ACL name, interface direction, source/destination, ports, and expected policy.",
				[]int{i}, []string{eventEvidence(e), "family=Cisco ASA/IOS; acl="+rawValue(r, "acl", "access_group")}))
		}
	}
	if strings.Contains(text, "%asa-") && containsAny(text, "failed", "fail", "authentication rejected", "login denied") {
		out = append(out, finding("cisco.asa-auth-failure", "medium", "Cisco ASA authentication failure",
			"A Cisco ASA authentication failure indicator was found. Verify management-plane exposure, source address, account, and AAA server response.",
			[]int{i}, []string{eventEvidence(e), "family=Cisco ASA"}))
	}
	if containsAny(text, "configuration changed", "configured from", "write memory", "startup-config", "running-config") && (strings.Contains(text, "cisco") || strings.Contains(e.Provider, "SYS")) {
		out = append(out, finding("cisco.configuration-change", "medium", "Cisco device configuration activity",
			"A Cisco configuration-change or configuration-write indicator was observed. Confirm the operator, terminal/source, command authorization, and approved change window.",
			[]int{i}, []string{eventEvidence(e), "family=Cisco IOS/ASA"}))
	}
	return out
}

func analyzeDefender(i int, e model.Event, r map[string]string, text string) []model.Finding {
	id := strings.TrimSpace(e.EventID)
	var out []model.Finding
	switch id {
	case "1116":
		out = append(out, finding("defender.threat-detected", "high", "Microsoft Defender detected a threat",
			"Windows Defender event 1116 reports a threat detection. Review threat name, affected resource, detection origin, user, and the corresponding remediation event 1117.",
			[]int{i}, []string{eventEvidence(e), "family=Microsoft Defender; threat="+rawValue(r, "threat name", "threatname", "name")+"; path="+rawValue(r, "path", "resources")}))
	case "1117":
		out = append(out, finding("defender.remediation-action", "info", "Microsoft Defender remediation action",
			"Windows Defender event 1117 records an action taken on a threat. Confirm the action result and correlate it with event 1116; this event alone does not prove successful remediation.",
			[]int{i}, []string{eventEvidence(e), "family=Microsoft Defender; action="+rawValue(r, "action name", "actionname", "action")}))
	case "5001", "5010", "5012":
		out = append(out, finding("defender.protection-disabled", "critical", "Microsoft Defender protection component disabled",
			"A Defender operational event indicates that a protection component was disabled. Verify policy, tamper protection, actor, and whether protection was restored.",
			[]int{i}, []string{eventEvidence(e), "family=Microsoft Defender; event_id="+id}))
	case "5007":
		out = append(out, finding("defender.configuration-changed", "medium", "Microsoft Defender configuration changed",
			"Defender event 5007 indicates a configuration change. Inspect the old/new value, policy source, initiating process, and whether the change weakened protection.",
			[]int{i}, []string{eventEvidence(e), "family=Microsoft Defender; old="+rawValue(r, "old value", "oldvalue")+"; new="+rawValue(r, "new value", "newvalue")}))
	}
	if containsAny(text, "real-time protection disabled", "realtime monitoring disabled", "behavior monitoring disabled", "cloud-delivered protection disabled") && id != "5001" && id != "5010" && id != "5012" {
		out = append(out, finding("defender.protection-disabled-text", "critical", "Microsoft Defender protection appears disabled",
			"A Defender message explicitly indicates a protection feature was disabled. Confirm the exact feature, policy source, and current protection state.",
			[]int{i}, []string{eventEvidence(e), "family=Microsoft Defender"}))
	}
	return out
}

func analyzeLinuxAudit(i int, e model.Event, r map[string]string, text string) []model.Finding {
	var out []model.Finding
	typ := strings.ToUpper(rawValue(r, "type"))
	if typ == "" {
		if strings.Contains(text, "type=user_auth") { typ = "USER_AUTH" }
		if strings.Contains(text, "type=execve") { typ = "EXECVE" }
		if strings.Contains(text, "type=syscall") { typ = "SYSCALL" }
	}
	result := strings.ToLower(rawValue(r, "res", "result"))
	if typ == "USER_AUTH" || typ == "USER_LOGIN" || strings.Contains(text, "type=user_auth") || strings.Contains(text, "type=user_login") {
		if result == "failed" || containsAny(text, "res=failed", "authentication failure", "failed password") {
			out = append(out, finding("linux-audit.authentication-failure", "medium", "Linux audit recorded failed authentication",
				"Linux audit USER_AUTH/USER_LOGIN data reports a failed authentication. Correlate acct, addr, terminal, executable, PAM service, and repeated attempts.",
				[]int{i}, []string{eventEvidence(e), "family=Linux Audit; acct="+rawValue(r, "acct")+"; addr="+rawValue(r, "addr")+"; exe="+rawValue(r, "exe")}))
		}
	}
	if typ == "SYSCALL" || typ == "EXECVE" || strings.Contains(text, "type=syscall") || strings.Contains(text, "type=execve") {
		syscall := strings.ToLower(rawValue(r, "syscall"))
		exe := strings.ToLower(rawValue(r, "exe", "comm"))
		if containsAny(syscall, "mount", "init_module", "finit_module", "delete_module", "ptrace", "setuid", "setresuid") || containsAny(exe, "useradd", "usermod", "passwd", "visudo", "iptables", "nft") {
			out = append(out, finding("linux-audit.sensitive-system-operation", "medium", "Linux audit recorded a sensitive system operation",
				"Linux audit recorded a privileged or security-sensitive syscall/utility. Review auid, uid, euid, ses, success, executable, arguments, and parent process before classifying it as malicious.",
				[]int{i}, []string{eventEvidence(e), "family=Linux Audit; type="+typ+"; syscall="+syscall+"; exe="+exe+"; auid="+rawValue(r, "auid")+"; uid="+rawValue(r, "uid")+"; success="+rawValue(r, "success")}))
		}
	}
	if typ == "CONFIG_CHANGE" || containsAny(text, "auditd configuration changed", "audit rules changed", "audit configuration changed") {
		out = append(out, finding("linux-audit.audit-configuration-change", "medium", "Linux audit configuration changed",
			"Linux audit reports a configuration or rule change. Verify the actor, key, operation, and whether required audit coverage remains enabled.",
			[]int{i}, []string{eventEvidence(e), "family=Linux Audit; key="+rawValue(r, "key")+"; op="+rawValue(r, "op")}))
	}
	if containsAny(text, "audit daemon is suspending", "auditd: audit daemon is suspending", "audit backlog limit exceeded", "audit rate limit exceeded") {
		out = append(out, finding("linux-audit.audit-collection-degraded", "high", "Linux audit collection may be degraded",
			"An audit daemon suspension, backlog overflow, or rate-limit event was found. Investigate lost-event risk and restore reliable audit collection.",
			[]int{i}, []string{eventEvidence(e), "family=Linux Audit"}))
	}
	return out
}

func valueOr(s, fallback string) string { if strings.TrimSpace(s) == "" { return fallback }; return s }
