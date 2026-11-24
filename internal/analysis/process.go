package analysis

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

const processNetworkWindow = 2 * time.Minute

type processRecord struct {
	index int
	at time.Time
	host string
	pid string
	parentPID string
	image string
	parentImage string
	command string
}

func analyzeProcesses(events []model.Event) []model.Finding {
	records := make([]processRecord, 0)
	for i, event := range events {
		if !isProcessCreation(event) { continue }
		r := processRecord{
			index: i, at: event.Timestamp, host: strings.ToLower(strings.TrimSpace(event.Host)),
			pid: processField(event, "processid", "process_id", "newprocessid", "pid"),
			parentPID: processField(event, "parentprocessid", "parent_process_id", "creatorprocessid", "ppid"),
			image: processField(event, "newprocessname", "image", "processname", "process_path", "executable", "process"),
			parentImage: processField(event, "parentprocessname", "parentimage", "creatorprocessname", "parent_process"),
			command: processField(event, "commandline", "processcommandline", "process_command_line", "cmdline"),
		}
		if r.image != "" && r.parentImage != "" { records = append(records, r) }
	}

	findings := make([]model.Finding, 0)
	for _, r := range records {
		parent, child := processBaseName(r.parentImage), processBaseName(r.image)
		if !suspiciousParentChild(parent, child) { continue }
		indexes := []int{r.index}
		evidence := []string{fmt.Sprintf("parent=%s; child=%s; pid=%s; parent_pid=%s; command=%s", r.parentImage, r.image, r.pid, r.parentPID, clip(r.command))}
		for j, event := range events {
			if j == r.index || r.pid == "" || !sameProcessHost(r.host, event.Host) || event.Timestamp.IsZero() || r.at.IsZero() { continue }
			if event.Timestamp.Before(r.at) || event.Timestamp.Sub(r.at) > processNetworkWindow { continue }
			if !isProcessNetworkEvent(event) || canonicalPID(processField(event, "processid", "process_id", "pid", "application_process_id")) != canonicalPID(r.pid) { continue }
			indexes = append(indexes, j)
			evidence = append(evidence, "related network event: "+eventEvidence(event))
		}
		description := fmt.Sprintf("%s launched %s. This parent-child relationship is commonly abused for script or proxy execution; verify the user, command line, executable path, signature, and process ancestry.", r.parentImage, r.image)
		if len(indexes) > 1 { description += " A network connection event with the same process ID and host was also observed within two minutes; this is correlated evidence, not proof that the connection was malicious." }
		findings = append(findings, finding("process.suspicious-parent-child", "high", "Suspicious parent-child process execution", description, indexes, evidence))
	}
	return findings
}

func isProcessCreation(e model.Event) bool {
	id := strings.TrimSpace(e.EventID)
	if id == "1" || id == "4688" || strings.EqualFold(id, "EXECVE") || strings.EqualFold(id, "SYSCALL") { return true }
	s := strings.ToLower(e.Source + " " + e.Provider + " " + e.Message)
	return containsAny(s, "process creation", "process started", "audit execve")
}

func processField(e model.Event, names ...string) string {
	keys := make([]string, 0, len(e.Raw))
	for key := range e.Raw { keys = append(keys, key) }
	sort.Strings(keys)
	for _, name := range names {
		wanted := normalizeProcessKey(name)
		for _, key := range keys {
			value := e.Raw[key]
			if value == nil || normalizeProcessKey(key) != wanted { continue }
			v := strings.TrimSpace(fmt.Sprint(value))
			if v != "" && v != "<nil>" { return v }
		}
	}
	return ""
}

func normalizeProcessKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) { if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' { b.WriteRune(r) } }
	return b.String()
}

func processBaseName(path string) string {
	path = strings.Trim(strings.TrimSpace(path), "\"")
	name := strings.ToLower(filepath.Base(strings.ReplaceAll(path, "\\", "/")))
	return strings.TrimSuffix(name, ".exe")
}

func suspiciousParentChild(parent, child string) bool {
	office := map[string]bool{"winword": true, "excel": true, "powerpnt": true, "outlook": true, "onenote": true, "visio": true}
	browsers := map[string]bool{"chrome": true, "msedge": true, "firefox": true, "brave": true, "opera": true}
	scriptChildren := map[string]bool{"powershell": true, "pwsh": true, "cmd": true, "wscript": true, "cscript": true, "mshta": true}
	lolbinChildren := map[string]bool{"rundll32": true, "regsvr32": true, "mshta": true, "certutil": true, "bitsadmin": true}
	if office[parent] && scriptChildren[child] { return true }
	if browsers[parent] && (child == "powershell" || child == "pwsh" || child == "wscript" || child == "mshta") { return true }
	return (parent == "powershell" || parent == "pwsh" || parent == "cmd" || parent == "wscript" || parent == "cscript") && lolbinChildren[child]
}

func isProcessNetworkEvent(e model.Event) bool {
	id := strings.TrimSpace(e.EventID)
	if id == "5156" || id == "3" { return true }
	s := strings.ToLower(e.Source + " " + e.Provider + " " + e.Message)
	return containsAny(s, "network connection", "firewall allowed", "connection permitted")
}

func sameProcessHost(a, b string) bool {
	b = strings.ToLower(strings.TrimSpace(b))
	if a == "" || b == "" || a == "unknown" || b == "unknown" || a == "-" || b == "-" { return false }
	return a == b
}

func canonicalPID(pid string) string {
	pid = strings.TrimSpace(strings.ToLower(pid))
	if pid == "" { return "" }
	base, value := 10, pid
	if strings.HasPrefix(value, "0x") { base, value = 16, value[2:] }
	if n, err := strconv.ParseUint(value, base, 64); err == nil { return strconv.FormatUint(n, 10) }
	return pid
}
