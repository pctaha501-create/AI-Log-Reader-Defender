package ingest

import (
	"strings"
	"testing"
	"time"
)

func TestReadJSONLNormalizesAndPreservesRaw(t *testing.T) {
	input := `{"timestamp":"2026-11-11T10:00:00Z","event_id":4625,"message":"failed to log on","custom":"kept"}` + "\n"

	events, err := ReadJSONL(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].EventID != "4625" || events[0].Message != "failed to log on" {
		t.Fatalf("unexpected event: %+v", events[0])
	}
	if events[0].Raw["custom"] != "kept" {
		t.Fatal("unknown raw field was not preserved")
	}
}

func TestReadJSONLAcceptsUTF8BOM(t *testing.T) {
	input := "\uFEFF" + `{"timestamp":"2026-11-12T10:00:00Z","event_id":"4625","message":"failed to log on"}` + "\n"

	events, err := ReadJSONL(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].EventID != "4625" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestReadJSONLRejectsMalformedLine(t *testing.T) {
	if _, err := ReadJSONL(strings.NewReader("not-json\n")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestJournaldMicrosecondTimestamp(t *testing.T) {
	input := `{"__REALTIME_TIMESTAMP":1794408948000000,"MESSAGE":"test"}` + "\n"

	events, err := ReadJSONL(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}

	want := time.UnixMicro(1794408948000000).UTC()
	if !events[0].Timestamp.Equal(want) {
		t.Fatalf("got %v, want %v", events[0].Timestamp, want)
	}
}
