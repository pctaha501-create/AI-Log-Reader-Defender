package ingest

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

var (
	rfc5424 = regexp.MustCompile("^<(\\d{1,3})>(\\d+) (\\S+) (\\S+) (\\S+) (\\S+) (\\S+) (.*)$")
	rfc3164 = regexp.MustCompile("^<(\\d{1,3})>([A-Z][a-z]{2}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+(\\S+)\\s+([^:]+):\\s?(.*)$")
	kvPair = regexp.MustCompile("(?:^|\\s)([A-Za-z][A-Za-z0-9_.-]*)=(?:\"([^\"]*)\"|(\\S+))")
)

// Read parses a supported line-oriented format into normalized events.
// Supported formats: jsonl, syslog (RFC 3164/5424), cef, and leef.
func Read(r io.Reader, format string) ([]model.Event, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "jsonl":
		return ReadJSONL(r)
	case "syslog", "rfc3164", "rfc5424":
		return readSyslog(r)
	case "cef":
		return readCEF(r)
	case "leef":
		return readLEEF(r)
	default:
		return nil, fmt.Errorf("unsupported input format %q (use jsonl, syslog, cef, or leef)", format)
	}
}

func readSyslog(r io.Reader) ([]model.Event, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 8*1024*1024)
	events := make([]model.Event, 0)
	for line := 1; s.Scan(); line++ {
		text := strings.TrimSpace(strings.TrimPrefix(s.Text(), "\uFEFF"))
		if text == "" {
			continue
		}
		e, err := parseSyslogLine(text)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		events = append(events, e)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read syslog: %w", err)
	}
	return events, nil
}

func parseSyslogLine(line string) (model.Event, error) {
	raw := map[string]any{"raw_line": line, "source": "syslog"}
	if m := rfc5424.FindStringSubmatch(line); m != nil {
		pri, _ := strconv.Atoi(m[1])
		ts := m[3]
		host, app, procID, msgID := m[4], m[5], m[6], m[7]
		sd, message := splitStructuredData(m[8])
		raw["timestamp"], raw["host"], raw["provider"] = ts, host, app
		raw["process_id"], raw["event_id"], raw["structured_data"] = procID, msgID, sd
		raw["message"], raw["priority"], raw["facility"] = message, pri, pri/8
		raw["level"] = syslogLevel(pri)
		addNetworkFields(raw, message)
		return normalize(raw), nil
	}
	if m := rfc3164.FindStringSubmatch(line); m != nil {
		pri, _ := strconv.Atoi(m[1])
		ts, err := time.ParseInLocation("Jan 2 15:04:05", strings.Join(strings.Fields(m[2]), " "), time.Local)
		if err == nil {
			now := time.Now()
			ts = time.Date(now.Year(), ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), 0, time.Local)
			if ts.After(now.Add(24 * time.Hour)) {
				ts = ts.AddDate(-1, 0, 0)
			}
		}
		tag := strings.TrimSpace(m[4])
		app := tag
		if i := strings.IndexByte(tag, '['); i >= 0 {
			app = tag[:i]
			raw["process_id"] = strings.TrimSuffix(strings.TrimPrefix(tag[i:], "["), "]")
		}
		raw["timestamp"], raw["host"], raw["provider"] = ts.UTC(), m[3], app
		raw["message"], raw["priority"], raw["facility"] = m[5], pri, pri/8
		raw["level"], raw["event_id"] = syslogLevel(pri), "syslog"
		addNetworkFields(raw, m[5])
		return normalize(raw), nil
	}
	// Some appliances emit plain syslog payloads without an RFC priority/header.
	raw["message"] = line
	raw["provider"] = "unknown"
	addNetworkFields(raw, line)
	return normalize(raw), nil
}

func splitStructuredData(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-", ""
	}
	if strings.HasPrefix(s, "- ") {
		return "-", strings.TrimSpace(s[2:])
	}
	if strings.HasPrefix(s, "[") {
		escaped := false
		for i, r := range s {
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			if r == ']' && i+1 < len(s) && s[i+1] == ' ' {
				return s[:i+1], strings.TrimSpace(s[i+2:])
			}
		}
	}
	return "-", s
}

func syslogLevel(pri int) string {
	switch pri % 8 {
	case 0, 1, 2:
		return "critical"
	case 3:
		return "error"
	case 4:
		return "warning"
	case 5:
		return "notice"
	case 6:
		return "info"
	default:
		return "debug"
	}
}

func readCEF(r io.Reader) ([]model.Event, error) {
	return readSecurityLines(r, "cef", func(line string) (model.Event, error) {
		parts := splitEscaped(line, '|', 8)
		if len(parts) < 8 || !strings.HasPrefix(parts[0], "CEF:") {
			return model.Event{}, fmt.Errorf("expected CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension")
		}
		raw := map[string]any{
			"source": "cef", "provider": parts[1] + "/" + parts[2],
			"device_version": parts[3], "event_id": parts[4],
			"message": parts[5], "level": cefSeverity(parts[6]),
			"device_vendor": parts[1], "device_product": parts[2],
			"raw_line": line,
		}
		ext := parseKeyValues(parts[7])
		for k, v := range ext {
			raw[k] = v
		}
		mapNetworkAliases(raw, ext)
		if rt := ext["rt"]; rt != "" {
			raw["timestamp"] = rt
		}
		if host := ext["dvchost"]; host != "" {
			raw["host"] = host
		}
		if user := ext["suser"]; user != "" {
			raw["user"] = user
		}
		return normalize(raw), nil
	})
}

func readLEEF(r io.Reader) ([]model.Event, error) {
	return readSecurityLines(r, "leef", func(line string) (model.Event, error) {
		parts := splitEscaped(line, '|', 7)
		if len(parts) < 7 || !strings.HasPrefix(parts[0], "LEEF:") {
			return model.Event{}, fmt.Errorf("expected LEEF:Version|Vendor|Product|Version|EventID|Delimiter|Extension")
		}
		delimiter := parts[5]
		switch delimiter {
		case "0x09", "\\t", "":
			delimiter = "\t"
		}
		ext := make(map[string]string)
		for _, field := range strings.Split(parts[6], delimiter) {
			field = strings.TrimSpace(field)
			if i := strings.IndexByte(field, '='); i > 0 {
				ext[strings.ToLower(strings.TrimSpace(field[:i]))] = strings.TrimSpace(field[i+1:])
			}
		}
		raw := map[string]any{
			"source": "leef", "provider": parts[1] + "/" + parts[2],
			"event_id": parts[4], "message": ext["eventname"],
			"device_version": parts[3], "device_vendor": parts[1],
			"device_product": parts[2], "raw_line": line,
		}
		for k, v := range ext {
			raw[k] = v
		}
		mapNetworkAliases(raw, ext)
		if v := ext["devtime"]; v != "" {
			raw["timestamp"] = v
		}
		if v := ext["devtimeformat"]; v != "" {
			raw["timestamp_format"] = v
		}
		if v := ext["devname"]; v != "" {
			raw["host"] = v
		}
		if v := ext["usrname"]; v != "" {
			raw["user"] = v
		}
		if v := ext["sev"]; v != "" {
			raw["level"] = cefSeverity(v)
		}
		return normalize(raw), nil
	})
}

func readSecurityLines(r io.Reader, format string, parse func(string) (model.Event, error)) ([]model.Event, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 8*1024*1024)
	events := make([]model.Event, 0)
	for line := 1; s.Scan(); line++ {
		text := strings.TrimSpace(strings.TrimPrefix(s.Text(), "\uFEFF"))
		if text == "" {
			continue
		}
		e, err := parse(text)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", format, line, err)
		}
		events = append(events, e)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", format, err)
	}
	return events, nil
}

func splitEscaped(s string, sep byte, limit int) []string {
	parts := make([]string, 0, limit)
	var b strings.Builder
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			switch c {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteByte(c)
			}
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == sep && (limit <= 0 || len(parts) < limit-1) {
			parts = append(parts, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	if escaped {
		b.WriteByte('\\')
	}
	parts = append(parts, b.String())
	return parts
}

func parseKeyValues(s string) map[string]string {
	out := make(map[string]string)
	for _, m := range kvPair.FindAllStringSubmatch(s, -1) {
		v := m[2]
		if v == "" {
			v = m[3]
		}
		out[strings.ToLower(m[1])] = v
	}
	return out
}

func addNetworkFields(raw map[string]any, message string) {
	fields := parseKeyValues(message)
	mapNetworkAliases(raw, fields)
}

func mapNetworkAliases(raw map[string]any, fields map[string]string) {
	aliases := map[string][]string{
		"source_ip": {"src", "srcip", "src_ip", "sourceip", "source_ip"},
		"destination_ip": {"dst", "dstip", "dst_ip", "destinationip", "destination_ip"},
		"source_port": {"spt", "srcport", "src_port", "sourceport", "source_port"},
		"destination_port": {"dpt", "dstport", "dst_port", "destinationport", "destination_port", "dport"},
		"protocol": {"proto", "protocol"},
		"action": {"act", "action", "disposition"},
	}
	for target, keys := range aliases {
		for _, key := range keys {
			if v := fields[key]; v != "" {
				raw[target] = v
				break
			}
		}
	}
}

func cefSeverity(s string) string {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return strings.ToLower(s)
	}
	switch {
	case n >= 9:
		return "critical"
	case n >= 7:
		return "high"
	case n >= 4:
		return "medium"
	case n >= 1:
		return "low"
	default:
		return "info"
	}
}
