//go:build darwin

package collector

import (
 "bytes"
 "encoding/json"
 "fmt"
 "io"
 "os/exec"
 "time"
)
func Platform() string { return "macos" }
func Collect(w io.Writer, since time.Duration) (int, error) {
 cmd := exec.Command("log", "show", "--style", "json", "--last", sinceArg(since))
 out, err := cmd.Output(); if err != nil { return 0, fmt.Errorf("collect with macOS Unified Logging: %w", err) }
 dec := json.NewDecoder(bytes.NewReader(out)); tok, err := dec.Token(); if err != nil { return 0, err }
 if d, ok := tok.(json.Delim); !ok || d != '[' { return 0, fmt.Errorf("unexpected macOS log JSON format") }
 var records []Record
 for dec.More() { var m map[string]any; if err := dec.Decode(&m); err != nil { return 0, err }; records = append(records, Record{"timestamp":m["timestamp"], "source":"macos-unified-log", "provider":m["process"], "message":m["eventMessage"], "level":m["messageType"], "raw_log":m}) }
 if _, err := dec.Token(); err != nil { return 0, err }; return writeRecords(w, records)
}
