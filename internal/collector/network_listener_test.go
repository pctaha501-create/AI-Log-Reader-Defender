package collector

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
)

func TestSenderAllowlist(t *testing.T) {
	addr := &net.UDPAddr{IP:net.ParseIP("192.0.2.10"), Port:5514}
	if !senderAllowed(addr, nil) { t.Fatal("empty allowlist should preserve opt-in unrestricted behavior") }
	if !senderAllowed(addr, []string{"192.0.2.10"}) { t.Fatal("exact IP should be allowed") }
	if !senderAllowed(addr, []string{"192.0.2.0/24"}) { t.Fatal("matching CIDR should be allowed") }
	if senderAllowed(addr, []string{"198.51.100.0/24"}) { t.Fatal("unmatched sender should be denied") }
	if senderAllowed(addr, []string{"not-an-ip"}) { t.Fatal("invalid allowlist entry must not allow sender") }
}

func TestTCPFramerSupportsNewlineAndRFC6587(t *testing.T) {
 input := "<34>1 2026-11-23T10:00:00Z host app 1 ID1 - newline\n" +
  "51 <34>1 2026-11-23T10:00:01Z host app 1 ID2 - counted"
 f := newTCPFramer(bufio.NewReader(strings.NewReader(input)))
 first, ok, err := f.Next()
 if err != nil || !ok || first != "<34>1 2026-11-23T10:00:00Z host app 1 ID1 - newline" { t.Fatalf("newline frame = %q, %v, %v", first, ok, err) }
 second, ok, err := f.Next()
 if err != nil || !ok || second != "<34>1 2026-11-23T10:00:01Z host app 1 ID2 - counted" { t.Fatalf("octet frame = %q, %v, %v", second, ok, err) }
 if _, ok, err := f.Next(); ok || err != io.EOF { t.Fatalf("expected EOF, got ok=%v err=%v", ok, err) }
}

func TestTCPFramerRejectsOversizedOctetFrame(t *testing.T) {
 f := newTCPFramer(bufio.NewReader(strings.NewReader("1048577 ")))
 if _, _, err := f.Next(); err == nil { t.Fatal("expected oversized RFC 6587 frame to be rejected") }
}

func TestTCPFramerFlushesFinalUnterminatedLine(t *testing.T) {
 f := newTCPFramer(bufio.NewReader(strings.NewReader("CEF:0|Vendor|Product|1|ID|Event|5|src=192.0.2.1")))
 got, ok, err := f.Next()
 if err != nil || !ok || !strings.HasPrefix(got, "CEF:0|") { t.Fatalf("final line = %q, %v, %v", got, ok, err) }
}
