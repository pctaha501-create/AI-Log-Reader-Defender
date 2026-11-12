package ingest

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

// readAuto detects common wire/log encodings from the first meaningful line.
// Unknown formats are retained as generic events rather than discarded.
func readAuto(r io.Reader) ([]model.Event, error) {
	br := bufio.NewReader(r)
	var prefix strings.Builder
	var first string
	for {
		line, err := br.ReadString('\n')
		prefix.WriteString(line)
		if strings.TrimSpace(line) != "" {
			first = strings.TrimSpace(strings.TrimPrefix(line, "\uFEFF"))
			break
		}
		if err != nil {
			if err == io.EOF && prefix.Len() == 0 { return nil, nil }
			if err == io.EOF { break }
			return nil, err
		}
	}
	combined := io.MultiReader(strings.NewReader(prefix.String()), br)
	switch {
	case strings.HasPrefix(first, "{"):
		return ReadJSONL(combined)
	case strings.HasPrefix(first, "CEF:"):
		return readCEF(combined)
	case strings.HasPrefix(first, "LEEF:"):
		return readLEEF(combined)
	case strings.HasPrefix(first, "<") && len(first) > 2 && first[1] >= '0' && first[1] <= '9':
		return readSyslog(combined)
	case strings.Contains(first, ",") && looksLikeCSVHeader(first):
		return readCSV(combined)
	default:
		return readGeneric(combined)
	}
}

func looksLikeCSVHeader(line string) bool {
	l := strings.ToLower(line)
	for _, hint := range []string{"timestamp", "time", "date", "message", "event", "src", "source", "host", "severity", "action"} {
		if strings.Contains(l, hint) { return true }
	}
	return false
}

func readCSV(r io.Reader) ([]model.Event, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil { return nil, fmt.Errorf("CSV header: %w", err) }
	for i := range header { header[i] = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(header[i], "\uFEFF"))) }
	var events []model.Event
	for line := 2; ; line++ {
		row, err := cr.Read()
		if err == io.EOF { break }
		if err != nil { return nil, fmt.Errorf("CSV line %d: %w", line, err) }
		raw := map[string]any{"source":"csv"}
		fields := make(map[string]string)
		for i, value := range row {
			if i < len(header) && header[i] != "" { raw[header[i]] = strings.TrimSpace(value); fields[header[i]] = strings.TrimSpace(value) }
			raw[fmt.Sprintf("column_%d", i+1)] = value
		}
		mapNetworkAliases(raw, fields)
		raw["raw_csv_fields"] = row
		events = append(events, normalize(raw))
	}
	return events, nil
}

func readGeneric(r io.Reader) ([]model.Event, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 8*1024*1024)
	var events []model.Event
	for line := 1; s.Scan(); line++ {
		text := strings.TrimSpace(strings.TrimPrefix(s.Text(), "\uFEFF"))
		if text == "" { continue }
		fields := parseKeyValues(text)
		raw := map[string]any{"source":"generic-text", "message":text, "raw_line":text, "line_number":line}
		for key, value := range fields { raw[key] = value }
		mapNetworkAliases(raw, fields)
		events = append(events, normalize(raw))
	}
	if err := s.Err(); err != nil { return nil, fmt.Errorf("read generic text: %w", err) }
	return events, nil
}
