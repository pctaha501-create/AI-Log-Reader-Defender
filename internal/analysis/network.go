package analysis

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

const firewallWindow = 5 * time.Minute
const firewallScanThreshold = 10

var networkKV = regexp.MustCompile("(?:^|\\s)(SRC|DST|SPT|DPT|PROTO|src_ip|dst_ip|src_port|dst_port|source_ip|destination_ip|source_port|destination_port)=([^\\s]+)")

type firewallEvent struct {
	index int
	at time.Time
	port string
}

func analyzeNetwork(events []model.Event) []model.Finding {
	findings := make([]model.Finding, 0)
	blocked := make(map[string][]firewallEvent)
	for i, e := range events {
		msg := strings.ToLower(e.Message)
		id := strings.TrimSpace(e.EventID)
		isFirewall := firewallEventSource(e)
		if !isFirewall {
			continue
		}
		switch {
		case id == "5025" || containsAny(msg, "firewall service stopped", "firewall disabled", "firewall has been disabled", "firewall is turned off", "firewall stopped"):
			findings = append(findings, finding("firewall.protection-disabled", "critical", "Firewall protection stopped or disabled", "A firewall service or protection-disable indicator was found. Verify the administrator, device state, and whether protection was intentionally disabled.", []int{i}, []string{eventEvidence(e)}))
		case id == "4946" || id == "4947" || id == "4948" || id == "4950" || containsAny(msg, "firewall rule added", "firewall rule modified", "firewall rule deleted", "firewall policy changed", "firewall configuration changed"):
			findings = append(findings, finding("firewall.policy-change", "medium", "Firewall policy or rule changed", "A firewall rule or policy change was observed. Review the rule name, direction, profile, ports, remote addresses, and initiating account.", []int{i}, []string{eventEvidence(e)}))
		}
		if firewallAction(e) != "blocked" {
			continue
		}
		src := networkField(e, "source_ip", "src", "src_ip", "srcip")
		if src == "" {
			src = strings.TrimSpace(e.SourceIP)
		}
		if src == "" {
			continue
		}
		port := networkField(e, "destination_port", "dst_port", "dpt", "dport")
		if port == "" {
			port = "-"
		}
		blocked[src] = append(blocked[src], firewallEvent{i, e.Timestamp, port})
	}
	sources := make([]string, 0, len(blocked))
	for src := range blocked {
		sources = append(sources, src)
	}
	sort.Strings(sources)
	for _, src := range sources {
		items := blocked[src]
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].at.IsZero() { return false }
			if items[j].at.IsZero() { return true }
			return items[i].at.Before(items[j].at)
		})
		best := []int{}
		bestPorts := map[string]bool{}
		for left := 0; left < len(items); left++ {
			if items[left].at.IsZero() { continue }
			right := left
			ports := make(map[string]bool)
			for right < len(items) && !items[right].at.IsZero() && items[right].at.Sub(items[left].at) <= firewallWindow {
				ports[items[right].port] = true
				right++
			}
			if right-left > len(best) {
				best = best[:0]
				bestPorts = ports
				for _, item := range items[left:right] { best = append(best, item.index) }
			}
		}
		if len(best) >= firewallScanThreshold && len(bestPorts) >= 5 {
			findings = append(findings, finding("firewall.port-scan-suspected", "high", "Possible port scan blocked by firewall", fmt.Sprintf("%d blocked connection attempts from %s targeted %d distinct destination ports within five minutes.", len(best), src, len(bestPorts)), best, []string{fmt.Sprintf("source_ip=%s; distinct_destination_ports=%d", src, len(bestPorts))}))
		} else if len(best) >= 20 {
			findings = append(findings, finding("firewall.repeated-blocks", "medium", "Repeated firewall blocks from one source", fmt.Sprintf("%d blocked connection attempts from %s were recorded within five minutes. This may be scanning, misconfiguration, or normal noisy traffic.", len(best), src), best, []string{fmt.Sprintf("source_ip=%s", src)}))
		}
	}
	return findings
}

func firewallEventSource(e model.Event) bool {
	id := strings.TrimSpace(e.EventID)
	if id == "5152" || id == "5156" || id == "5157" || id == "4946" || id == "4947" || id == "4948" || id == "4950" || id == "5024" || id == "5025" {
		return true
	}
	s := strings.ToLower(e.Source + " " + e.Provider + " " + e.Message)
	return containsAny(s, "firewall", "ufw", "iptables", "nftables", "pf packet filter", "firewalld", "security group")
}

func firewallAction(e model.Event) string {
	id := strings.TrimSpace(e.EventID)
	if id == "5152" || id == "5157" { return "blocked" }
	if id == "5156" { return "allowed" }
	msg := strings.ToLower(e.Message)
	action := strings.ToLower(networkField(e, "action", "act", "disposition"))
	if containsAny(action, "block", "deny", "drop", "reject") || containsAny(msg, "ufw block", "blocked", "denied", "dropped", "drop packet", "reject packet", "action=deny", "action=block") {
		return "blocked"
	}
	if containsAny(action, "allow", "accept", "permit") || containsAny(msg, "allowed", "accepted", "permit packet") {
		return "allowed"
	}
	return ""
}

func networkField(e model.Event, keys ...string) string {
	for _, key := range keys {
		if v, ok := e.Raw[key]; ok && v != nil {
			s := strings.TrimSpace(fmt.Sprint(v))
			if s != "" { return s }
		}
	}
	for _, m := range networkKV.FindAllStringSubmatch(e.Message, -1) {
		k, v := strings.ToLower(m[1]), strings.TrimSpace(m[2])
		for _, key := range keys {
			if k == strings.ToLower(key) { return v }
		}
	}
	// CEF and LEEF extension keys are case-insensitive.
	for rawKey, v := range e.Raw {
		for _, key := range keys {
			if strings.EqualFold(rawKey, key) && v != nil {
				s := strings.TrimSpace(fmt.Sprint(v))
				if s != "" { return s }
			}
		}
	}
	return ""
}

func parsePort(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
