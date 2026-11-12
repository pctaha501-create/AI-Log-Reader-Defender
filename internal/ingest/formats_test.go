package ingest

import (
	"strings"
	"testing"
)

func TestReadSyslogUFWFields(t *testing.T) {
	input := "<34>Nov 12 10:20:30 router kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.8 DST=192.0.2.1 PROTO=TCP DPT=443"
	events, err := Read(strings.NewReader(input), "syslog")
	if err != nil { t.Fatal(err) }
	if len(events) != 1 { t.Fatalf("got %d events", len(events)) }
	e := events[0]
	if e.SourceIP != "203.0.113.8" { t.Fatalf("source IP = %q", e.SourceIP) }
	if e.Raw["destination_ip"] != "192.0.2.1" || e.Raw["destination_port"] != "443" { t.Fatalf("network fields missing: %#v", e.Raw) }
	if e.Provider != "kernel" { t.Fatalf("provider = %q", e.Provider) }
	if e.Timestamp.IsZero() { t.Fatal("RFC3164 timestamp was not parsed") }
}

func TestReadRFC5424Syslog(t *testing.T) {
	input := "<134>1 2026-11-12T10:20:30Z fw01 firewalld 123 DENIED [meta sequenceId=\"7\"] IN=wan SRC=198.51.100.7 DST=192.0.2.4 DPT=22"
	events, err := Read(strings.NewReader(input), "syslog")
	if err != nil { t.Fatal(err) }
	if len(events) != 1 || events[0].Host != "fw01" { t.Fatalf("unexpected events: %#v", events) }
	if events[0].Timestamp.IsZero() || events[0].EventID != "DENIED" { t.Fatalf("RFC5424 header not parsed: %#v", events[0]) }
}

func TestReadCEF(t *testing.T) {
	input := "CEF:0|Acme|Firewall|1.0|deny-7|Blocked connection|8|src=198.51.100.4 dst=192.0.2.5 spt=5555 dpt=443 proto=TCP act=blocked"
	events, err := Read(strings.NewReader(input), "cef")
	if err != nil { t.Fatal(err) }
	if len(events) != 1 || events[0].SourceIP != "198.51.100.4" { t.Fatalf("unexpected CEF event: %#v", events) }
	if events[0].Raw["destination_port"] != "443" { t.Fatalf("destination port missing: %#v", events[0].Raw) }
}

func TestReadLEEF(t *testing.T) {
	input := "LEEF:2.0|Acme|Router|1.0|DROP|0x09|devTime=2026-11-12T10:20:30Z\tsrc=198.51.100.9\tdst=192.0.2.9\tdpt=53\tproto=UDP\tact=deny"
	events, err := Read(strings.NewReader(input), "leef")
	if err != nil { t.Fatal(err) }
	if len(events) != 1 || events[0].SourceIP != "198.51.100.9" { t.Fatalf("unexpected LEEF event: %#v", events[0]) }
	if events[0].Raw["destination_port"] != "53" { t.Fatalf("destination port missing: %#v", events[0].Raw) }
}
