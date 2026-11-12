package collector

import (
	"net"
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
