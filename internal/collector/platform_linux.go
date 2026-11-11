//go:build linux

package collector

import (
 "bufio"
 "bytes"
 "encoding/json"
 "fmt"
 "io"
 "os/exec"
 "time"
)
func Platform() string { return "linux" }
func Collect(w io.Writer, since time.Duration) (int, error) {
 cmd := exec.Command("journalctl", "--since", sinceArg(since), "--output=json", "--no-pager")
 out, err := cmd.Output(); if err != nil { return 0, fmt.Errorf("collect with journalctl: %w", err) }
 s := bufio.NewScanner(bytes.NewReader(out)); s.Buffer(make([]byte, 64*1024), 8*1024*1024); var records []Record
 for s.Scan() { var m map[string]any; if err := json.Unmarshal(s.Bytes(), &m); err != nil { continue }; records = append(records, Record{"timestamp":m["__REALTIME_TIMESTAMP"], "source":"journald", "host":m["_HOSTNAME"], "provider":m["SYSLOG_IDENTIFIER"], "message":m["MESSAGE"], "level":m["PRIORITY"], "raw_journal":m}) }
 if err := s.Err(); err != nil { return 0, err }; return writeRecords(w, records)
}
