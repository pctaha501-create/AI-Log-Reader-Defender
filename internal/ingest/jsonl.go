package ingest

import (
 "bufio"
 "encoding/json"
 "fmt"
 "io"
 "strings"
 "time"

 "github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)
func ReadJSONL(r io.Reader) ([]model.Event, error) {
 s := bufio.NewScanner(r); s.Buffer(make([]byte, 64*1024), 8*1024*1024)
 var events []model.Event
 for line := 1; s.Scan(); line++ {
  b := append([]byte(nil), s.Bytes()...); if len(strings.TrimSpace(string(b))) == 0 { continue }
  var raw map[string]any
  if err := json.Unmarshal(b, &raw); err != nil { return nil, fmt.Errorf("line %d: %w", line, err) }
  events = append(events, normalize(raw))
 }
 if err := s.Err(); err != nil { return nil, err }; return events, nil
}
func normalize(raw map[string]any) model.Event {
 e := model.Event{Raw: raw}
 e.Timestamp = parseTime(first(raw, "timestamp", "time", "@timestamp", "ts", "__REALTIME_TIMESTAMP"))
 e.Source = str(first(raw, "source", "channel", "log_name"))
 e.Host = str(first(raw, "host", "hostname", "computer", "_HOSTNAME"))
 e.EventID = str(first(raw, "event_id", "eventid", "id"))
 e.Level = strings.ToLower(str(first(raw, "level", "severity", "priority")))
 e.Provider = str(first(raw, "provider", "source_name", "process", "SYSLOG_IDENTIFIER"))
 e.Message = str(first(raw, "message", "msg", "description", "MESSAGE", "eventMessage"))
 e.User = str(first(raw, "user", "username", "account", "_UID"))
 e.SourceIP = str(first(raw, "source_ip", "src_ip", "remote_addr", "ip"))
 return e
}
func first(m map[string]any, keys ...string) any { for _, k := range keys { if v, ok := m[k]; ok && v != nil { return v } }; return nil }
func str(v any) string { if v == nil { return "" }; return fmt.Sprint(v) }
func parseTime(v any) time.Time {
 if v == nil { return time.Time{} }
 if n, ok := v.(float64); ok {
  // journald exports __REALTIME_TIMESTAMP as microseconds since Unix epoch.
  if n > 1e14 { return time.UnixMicro(int64(n)).UTC() }
  if n > 1e9 { return time.Unix(int64(n), int64((n-float64(int64(n)))*1e9)).UTC() }
 }
 s := str(v)
 for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} { if t, err := time.Parse(layout, s); err == nil { return t.UTC() } }
 return time.Time{}
}
