//go:build linux

package collector

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

func Platform() string { return "linux" }

func Collect(w io.Writer, since time.Duration) (int, error) {
	var records []Record
	cmd := exec.Command("journalctl", "--since", sinceArg(since), "--output=json", "--no-pager")
	out, journalErr := cmd.Output()
	if journalErr == nil {
		s := bufio.NewScanner(bytes.NewReader(out))
		s.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for s.Scan() {
			var m map[string]any
			if err := json.Unmarshal(s.Bytes(), &m); err != nil { continue }
			records = append(records, Record{
				"timestamp": m["__REALTIME_TIMESTAMP"], "source":"journald",
				"host":m["_HOSTNAME"], "provider":m["SYSLOG_IDENTIFIER"],
				"message":m["MESSAGE"], "level":m["PRIORITY"], "user":m["_UID"],
				"raw_journal":m,
			})
		}
		if err := s.Err(); err != nil { return 0, fmt.Errorf("scan journal output: %w", err) }
	}

	// File-based logs are included only when their modification time falls within
	// the requested lookback. Their individual timestamps remain in the raw line.
	paths := []string{
		"/var/log/auth.log", "/var/log/secure", "/var/log/syslog",
		"/var/log/messages", "/var/log/kern.log", "/var/log/ufw.log",
		"/var/log/audit/audit.log",
	}
	host, _ := os.Hostname()
	cutoff := time.Now().Add(-since)
	const maxLinesPerFile = 20000
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil { continue }
		info, statErr := f.Stat()
		if statErr != nil || info.ModTime().Before(cutoff) { _ = f.Close(); continue }
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 64*1024), 8*1024*1024)
		lines := make([]string, 0, maxLinesPerFile)
		next := 0
		for s.Scan() {
			line := s.Text()
			if line == "" { continue }
			if len(lines) < maxLinesPerFile { lines = append(lines, line) } else {
				lines[next] = line
				next = (next + 1) % maxLinesPerFile
			}
		}
		scanErr := s.Err()
		_ = f.Close()
		if scanErr != nil { continue }
		if len(lines) == maxLinesPerFile && next > 0 {
			lines = append(lines[next:], lines[:next]...)
		}
		for _, line := range lines {
			records = append(records, Record{"source":path, "host":host, "message":line, "raw_line":line, "platform":"linux"})
		}
	}
	if journalErr != nil && len(records) == 0 {
		return 0, fmt.Errorf("journalctl unavailable and no recent readable standard log files found: %w", journalErr)
	}
	return writeRecords(w, records)
}
