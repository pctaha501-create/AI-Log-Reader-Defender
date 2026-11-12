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

	// Read common distro firewall, authentication, audit and system log files.
	// Missing or unreadable files are normal on many distributions.
	paths := []string{
		"/var/log/auth.log", "/var/log/secure", "/var/log/syslog",
		"/var/log/messages", "/var/log/kern.log", "/var/log/ufw.log",
		"/var/log/audit/audit.log",
	}
	host, _ := os.Hostname()
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil { continue }
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for lineCount := 0; s.Scan() && lineCount < 20000; lineCount++ {
			line := s.Text()
			if line == "" { continue }
			records = append(records, Record{"source":path, "host":host, "message":line, "raw_line":line, "platform":"linux"})
		}
		_ = s.Err()
		_ = f.Close()
	}
	if journalErr != nil && len(records) == 0 {
		return 0, fmt.Errorf("journalctl unavailable and no readable standard log files found: %w", journalErr)
	}
	return writeRecords(w, records)
}

func sinceArg(d time.Duration) string { return d.Round(time.Second).String() }
