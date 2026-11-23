//go:build linux

package collector

import (
	"testing"
	"time"
)

func TestLinuxCollectorHasBoundedJournalQuery(t *testing.T) {
	if maxJournalRecords < 1 || maxJournalRecords > 100000 {
		t.Fatalf("unsafe journal record limit: %d", maxJournalRecords)
	}
	if journalCommandTimeout <= 0 || journalCommandTimeout > time.Minute {
		t.Fatalf("unexpected journal timeout: %s", journalCommandTimeout)
	}
}

func TestLinuxCollectorCoversCommonSecurityAndServiceLogs(t *testing.T) {
	required := []string{"/var/log/auth.log", "/var/log/secure", "/var/log/audit/audit.log", "/var/log/ufw.log", "/var/log/fail2ban.log", "/var/log/nginx/access.log"}
	seen := make(map[string]bool, len(linuxLogPaths))
	for _, path := range linuxLogPaths { seen[path] = true }
	for _, path := range required {
		if !seen[path] { t.Errorf("missing expected Linux log source %s", path) }
	}
}
