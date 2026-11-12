package ingest

import (
	"strings"
	"testing"
)

func TestAutoDetectAndPreserveUnknownText(t *testing.T) {
	tests := []struct{name, input, source string}{
		{"syslog", "<34>Nov 12 10:20:30 edge kernel: IN=eth0 SRC=198.51.100.1 DST=192.0.2.1 PROTO=TCP DPT=443", "syslog"},
		{"cef", "CEF:0|Acme|Firewall|1|deny|Blocked|8|src=198.51.100.2 dst=192.0.2.2 dpt=22 act=blocked", "cef"},
		{"leef", "LEEF:2.0|Acme|Router|1|DROP|0x09|src=198.51.100.3\tdst=192.0.2.3\tdpt=53", "leef"},
		{"generic", "vendor_event=unclassified src=198.51.100.4 dst=192.0.2.4 action=deny", "generic-text"},
	}
	for _, tc := range tests { t.Run(tc.name, func(t *testing.T) {
		events, err := Read(strings.NewReader(tc.input), "auto")
		if err != nil { t.Fatal(err) }
		if len(events) != 1 { t.Fatalf("events=%d", len(events)) }
		if events[0].Raw["source"] != tc.source { t.Fatalf("source=%v", events[0].Raw["source"]) }
		if events[0].Raw["raw_line"] == nil && tc.source == "generic-text" { t.Fatal("raw line was lost") }
	}) }
}

func TestAutoDetectCSV(t *testing.T) {
	input := "timestamp,host,action,src,dst,dpt\n2026-11-12T10:00:00Z,edge,deny,198.51.100.5,192.0.2.5,443\n"
	events, err := Read(strings.NewReader(input), "auto")
	if err != nil { t.Fatal(err) }
	if len(events) != 1 || events[0].Raw["action"] != "deny" { t.Fatalf("unexpected CSV event: %#v", events) }
	if events[0].Raw["destination_port"] != "443" { t.Fatalf("network aliases missing: %#v", events[0].Raw) }
}
