package ingest

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

const maxAutoInputBytes = 64 << 20

// readAuto detects common wire/log encodings. Structured documents are decoded
// before line-oriented fallbacks; unknown text is always retained verbatim.
func readAuto(r io.Reader) ([]model.Event, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxAutoInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxAutoInputBytes {
		return nil, fmt.Errorf("automatic input exceeds %d MiB limit", maxAutoInputBytes>>20)
	}
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	if len(trimmed) == 0 {
		return nil, nil
	}
	first := string(trimmed)
	switch {
	case strings.HasPrefix(first, "[") || strings.HasPrefix(first, "{"):
		if events, ok, err := readStructuredJSON(trimmed); ok || err != nil {
			return events, err
		}
		if strings.HasPrefix(first, "{") {
			return ReadJSONL(bytes.NewReader(data))
		}
	case strings.HasPrefix(first, "<"):
		if events, ok, err := readStructuredXML(trimmed); ok || err != nil {
			return events, err
		}
	case strings.HasPrefix(first, "CEF:"):
		return readCEF(bytes.NewReader(data))
	case strings.HasPrefix(first, "LEEF:"):
		return readLEEF(bytes.NewReader(data))
	case len(first) > 2 && first[0] == '<' && first[1] >= '0' && first[1] <= '9':
		return readSyslog(bytes.NewReader(data))
	case strings.Contains(first, ",") && looksLikeCSVHeader(strings.SplitN(first, "\n", 2)[0]):
		return readCSV(bytes.NewReader(data))
	case strings.Contains(first, "\t") && looksLikeCSVHeader(strings.SplitN(first, "\n", 2)[0]):
		return readDelimited(bytes.NewReader(data), '\t')
	case strings.Contains(first, ";") && looksLikeCSVHeader(strings.SplitN(first, "\n", 2)[0]):
		return readDelimited(bytes.NewReader(data), ';')
	}
	return readGeneric(bytes.NewReader(data))
}

func looksLikeCSVHeader(line string) bool {
	l := strings.ToLower(line)
	for _, hint := range []string{"timestamp", "time", "date", "message", "event", "src", "source", "host", "severity", "action", "eventid", "computer", "provider"} {
		if strings.Contains(l, hint) {
			return true
		}
	}
	return false
}

func readCSV(r io.Reader) ([]model.Event, error) {
	return readDelimited(r, ',')
}

func readDelimited(r io.Reader, delimiter rune) ([]model.Event, error) {
	cr := csv.NewReader(r)
	cr.Comma = delimiter
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("delimited header: %w", err)
	}
	for i := range header {
		header[i] = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(header[i], "\uFEFF")))
	}
	var events []model.Event
	for line := 2; ; line++ {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("delimited line %d: %w", line, err)
		}
		raw := map[string]any{"source": "delimited"}
		fields := make(map[string]string)
		for i, value := range row {
			if i < len(header) && header[i] != "" {
				raw[header[i]] = strings.TrimSpace(value)
				fields[header[i]] = strings.TrimSpace(value)
			}
			raw[fmt.Sprintf("column_%d", i+1)] = value
		}
		mapNetworkAliases(raw, fields)
		raw["raw_delimited_fields"] = row
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
		if text == "" {
			continue
		}
		fields := parseKeyValues(text)
		raw := map[string]any{"source": "generic-text", "message": text, "raw_line": text, "line_number": line}
		for key, value := range fields {
			raw[key] = value
		}
		mapNetworkAliases(raw, fields)
		events = append(events, normalize(raw))
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read generic text: %w", err)
	}
	return events, nil
}
