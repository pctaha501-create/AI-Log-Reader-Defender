package ingest

import (
	"strings"
	"testing"
)

func TestAutoDetectStructuredJSONDocuments(t *testing.T) {
	cases := []struct {
		name, input string
		count int
	}{
		{"array", `[{"EventID":4625,"Computer":"edge-01","Message":"failed password","IpAddress":"198.51.100.9"},{"event_id":1102,"message":"audit log was cleared"}]`, 2},
		{"wrapped records", `{"events":[{"eventCode":"AUTH_FAIL","username":"alice","sourceIp":"203.0.113.4"}]}`, 1},
		{"nested event", `{"event":{"system":{"eventID":4625,"computer":"host-a"},"message":"login failed"}}`, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events, err := Read(strings.NewReader(tc.input), "auto")
			if err != nil { t.Fatal(err) }
			if len(events) != tc.count { t.Fatalf("got %d events, want %d", len(events), tc.count) }
		})
	}
	events, err := Read(strings.NewReader(cases[0].input), "auto")
	if err != nil { t.Fatal(err) }
	if events[0].EventID != "4625" || events[0].Host != "edge-01" || events[0].Message != "failed password" {
		t.Fatalf("structured aliases not normalized: %#v", events[0])
	}
	if events[0].Raw["raw_record"] == nil { t.Fatal("original JSON record was not preserved") }
}

func TestAutoDetectStructuredJSONECSAndOpenTelemetry(t *testing.T) {
	input := `{"@timestamp":"2026-11-23T10:00:00Z","event":{"id":"4625","severity":8,"provider":"authd","original":"authentication failed"},"host":{"name":"edge-02"},"user":{"name":"alice"},"source":{"ip":"203.0.113.9"},"destination":{"ip":"198.51.100.7"},"log":{"level":"warning"}}`
	events, err := Read(strings.NewReader(input), "auto")
	if err != nil { t.Fatal(err) }
	if len(events) != 1 { t.Fatalf("got %d events, want 1", len(events)) }
	got := events[0]
	if got.EventID != "4625" || got.Host != "edge-02" || got.User != "alice" || got.Provider != "authd" || got.Message != "authentication failed" {
		t.Fatalf("ECS aliases not normalized: %#v", got)
	}
	if got.Raw["source.ip"] != "203.0.113.9" || got.Raw["destination.ip"] != "198.51.100.7" {
		t.Fatalf("network evidence not preserved: %#v", got.Raw)
	}
}

func TestAutoDetectStructuredXMLWindowsEvents(t *testing.T) {
	input := `<?xml version="1.0"?><Events><Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2026-11-23T10:00:00Z"/><Computer>host-a</Computer></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">198.51.100.8</Data></EventData></Event><Event><System><EventID>1102</EventID><Computer>host-a</Computer></System><RenderingInfo><Message>The audit log was cleared</Message></RenderingInfo></Event></Events>`
	events, err := Read(strings.NewReader(input), "auto")
	if err != nil { t.Fatal(err) }
	if len(events) != 2 { t.Fatalf("got %d events, want 2", len(events)) }
	if events[0].EventID != "4625" || events[0].Host != "host-a" || events[0].User != "alice" || events[0].Provider != "Microsoft-Windows-Security-Auditing" {
		t.Fatalf("XML system fields missing: %#v", events[0])
	}
	if events[0].Raw["targetusername"] != "alice" { t.Fatalf("XML named event data missing: %#v", events[0].Raw) }
	if events[1].Message != "The audit log was cleared" { t.Fatalf("XML rendered message missing: %#v", events[1]) }
}

func TestAutoDetectDelimitedTabularLogs(t *testing.T) {
	input := "timestamp\tevent_id\thost\tmessage\n2026-11-23T10:00:00Z\tLOGIN_FAIL\tnode-1\tinvalid password\n"
	events, err := Read(strings.NewReader(input), "auto")
	if err != nil { t.Fatal(err) }
	if len(events) != 1 || events[0].EventID != "LOGIN_FAIL" || events[0].Host != "node-1" {
		t.Fatalf("unexpected TSV event: %#v", events)
	}
}
