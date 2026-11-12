package analysis

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

const behaviorWindow = 5 * time.Minute

type behaviorBucket struct {
	key string
	at time.Time
	count int
	indexes []int
}

// analyzeBehavior adds offline, explainable behavior detections. It uses only
// the supplied events; it does not call a server or load an external model.
func analyzeBehavior(events []model.Event) []model.Finding {
	findings := make([]model.Finding, 0)
	for i, event := range events {
		text := strings.ToLower(event.Message + " " + rawCommand(event.Raw))
		switch {
		case containsAny(text,
			"powershell", "pwsh") && containsAny(text, "-encodedcommand", " -enc ", " -enc=", "frombase64string"):
			findings = append(findings, finding(
				"behavior.encoded-powershell", "high", "Encoded PowerShell execution",
				"A PowerShell-related event contains an encoded-command or Base64 execution indicator. Encoded commands can be legitimate administration, but are also commonly used to conceal scripts. Decode and inspect the command before taking action.",
				[]int{i}, []string{eventEvidence(event)},
			))
		case containsAny(text, "powershell", "pwsh") && containsAny(text,
			"downloadstring", "downloadfile", "invoke-webrequest", "net.webclient", "start-bitstransfer", " iwr ", " iex "):
			findings = append(findings, finding(
				"behavior.powershell-download-execution", "high", "PowerShell download or execution pattern",
				"A PowerShell-related event contains a web-download or dynamic-execution indicator. Verify the destination, script content, signer, parent process, and user.",
				[]int{i}, []string{eventEvidence(event)},
			))
		case containsAny(text, "set-mppreference") && containsAny(text, "disablerealtimemonitoring", "disablebehaviormonitoring", "disablescriptscanning", "disableioavprotection"):
			findings = append(findings, finding(
				"behavior.defender-protection-tampering", "critical", "Attempt to weaken endpoint protection",
				"A command-like event appears to change Microsoft Defender protection settings. Verify whether this was an authorized security-policy change.",
				[]int{i}, []string{eventEvidence(event)},
			))
		case containsAny(text, "certutil") && containsAny(text, "-urlcache", "-decode", "-decodehex"):
			findings = append(findings, finding(
				"behavior.certutil-transfer-or-decode", "medium", "Certutil transfer or decoding activity",
				"Certutil was used with a transfer or decoding option. This can be administrative but is also a known living-off-the-land technique; inspect the file path and network destination.",
				[]int{i}, []string{eventEvidence(event)},
			))
		case containsAny(text, "mshta") && containsAny(text, "http://", "https://", "javascript:", "vbscript:"):
			findings = append(findings, finding(
				"behavior.mshta-remote-content", "high", "MSHTA launched remote or script content",
				"MSHTA appears to reference remote content or an inline script. Validate the process tree, URL, and file reputation.",
				[]int{i}, []string{eventEvidence(event)},
			))
		case containsAny(text, "regsvr32") && containsAny(text, "http://", "https://", "/i:"):
			findings = append(findings, finding(
				"behavior.regsvr32-suspicious-registration", "high", "Regsvr32 suspicious registration pattern",
				"Regsvr32 appears to use a scriptlet or remote registration pattern. Inspect the command line, target file, and parent process.",
				[]int{i}, []string{eventEvidence(event)},
			))
		case containsAny(text, "bitsadmin") && containsAny(text, "/transfer", "/download"):
			findings = append(findings, finding(
				"behavior.bitsadmin-transfer", "medium", "BITS transfer command observed",
				"BITSAdmin was used for a transfer operation. Confirm the job owner, remote URL, and destination path.",
				[]int{i}, []string{eventEvidence(event)},
			))
		case containsAny(text, "rundll32") && containsAny(text, "javascript:", "url.dll", "http://", "https://"):
			findings = append(findings, finding(
				"behavior.rundll32-script-or-remote", "high", "Rundll32 script or remote-content pattern",
				"Rundll32 appears to invoke script-like or remote content. Verify the exact command, module path, and parent process.",
				[]int{i}, []string{eventEvidence(event)},
			))
		}
	}
	findings = append(findings, detectEventBursts(events)...)
	return findings
}

func rawCommand(raw map[string]any) string {
	var values []string
	for _, key := range []string{"command_line", "process_command_line", "process", "image", "executable", "parent_process", "script_block", "script", "cmdline"} {
		if value := strings.TrimSpace(fmt.Sprint(raw[key])); value != "" && value != "<nil>" {
			values = append(values, value)
		}
	}
	return strings.Join(values, " ")
}

func detectEventBursts(events []model.Event) []model.Finding {
	groups := make(map[string]map[int64][]int)
	for i, event := range events {
		if event.Timestamp.IsZero() { continue }
		source := strings.TrimSpace(event.Host + "|" + event.Provider + "|" + event.Source)
		if source == "||" { source = "unknown" }
		bucket := event.Timestamp.UTC().Unix() / int64(behaviorWindow.Seconds())
		if groups[source] == nil { groups[source] = make(map[int64][]int) }
		groups[source][bucket] = append(groups[source][bucket], i)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups { keys = append(keys, key) }
	sort.Strings(keys)
	findings := make([]model.Finding, 0)
	for _, key := range keys {
		buckets := groups[key]
		if len(buckets) < 3 { continue }
		var total, peak int
		var peakBucket int64
		for bucket, indexes := range buckets {
			total += len(indexes)
			if len(indexes) > peak { peak = len(indexes); peakBucket = bucket }
		}
		if total < 40 { continue }
		average := float64(total-peak) / float64(len(buckets)-1)
		if peak < 25 || float64(peak) < average*4 || float64(peak) < average+15 { continue }
		indexes := buckets[peakBucket]
		findings = append(findings, finding(
			"behavior.event-volume-spike", "medium", "Unusual event-volume spike",
			fmt.Sprintf("One five-minute interval contained %d events for source group %q, compared with an average of %.1f events in the other %d observed intervals. This may indicate an attack burst, noisy device, or logging/configuration change.", peak, key, average, len(buckets)-1),
			indexes, []string{fmt.Sprintf("source_group=%q; peak_events=%d; other_interval_average=%.1f", key, peak, average)},
		))
	}
	return findings
}

func buildOfflineAnalysis(events []model.Event, findings []model.Finding) string {
	counts := map[string]int{"critical":0, "high":0, "medium":0, "low":0}
	for _, item := range findings { counts[item.Severity]++ }
	var b strings.Builder
	b.WriteString("Built-in offline intelligence summary\n")
	b.WriteString("Method: explainable security rules + event-pattern and volume-anomaly analysis; no external model or network service.\n")
	fmt.Fprintf(&b, "Events examined: %d. Findings: %d (critical %d, high %d, medium %d, low %d).\n",
		len(events), len(findings), counts["critical"], counts["high"], counts["medium"], counts["low"])
	if len(findings) == 0 {
		b.WriteString("No indicators matched the current detection set. This does not prove the system is safe; coverage depends on enabled logging and available event fields.")
		return b.String()
	}
	b.WriteString("Priority observations:\n")
	limit := len(findings)
	if limit > 8 { limit = 8 }
	for i := 0; i < limit; i++ {
		f := findings[i]
		fmt.Fprintf(&b, "- [%s] %s: %s", strings.ToUpper(f.Severity), f.Title, f.Description)
		if len(f.EventIndexes) > 0 { fmt.Fprintf(&b, " (event indexes: %v)", f.EventIndexes) }
		b.WriteByte('\n')
	}
	b.WriteString("Recommended workflow: preserve the original logs; validate the cited event indexes and raw evidence; check the affected account, host, process tree, network destination, and change authorization; then contain or remediate only through your approved security procedure. Findings are triage signals and can include false positives.")
	return b.String()
}
