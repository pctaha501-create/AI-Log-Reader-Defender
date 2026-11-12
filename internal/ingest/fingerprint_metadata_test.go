package ingest

import (
	"strings"
	"testing"
)

func TestExtractModelAndFirmwareFromMessage(t *testing.T) {
	events, err := ReadJSONL(strings.NewReader(`{"message":"edge firewall model: XR500 firmware: 1.2.3"}`))
	if err != nil { t.Fatal(err) }
	raw := events[0].Raw
	if got := str(raw["device_model"]); got != "XR500" { t.Fatalf("model=%q", got) }
	if got := str(raw["firmware_version"]); got != "1.2.3" { t.Fatalf("firmware=%q", got) }
}

func TestExpandedVendorHints(t *testing.T) {
	cases := []struct{ message, vendor, product string }{
		{"OPNsense firewall event", "OPNsense", "OPNsense"},
		{"Cisco Meraki appliance", "Cisco Meraki", ""},
		{"TP-Link Omada switch", "TP-Link", "Omada"},
		{"Netgate pfSense firewall", "Netgate", "pfSense"},
	}
	for _, tc := range cases {
		events, err := ReadJSONL(strings.NewReader(`{"message":` + quoteJSON(tc.message) + `} `))
		if err != nil { t.Fatal(err) }
		if got := str(events[0].Raw["device_vendor"]); got != tc.vendor { t.Fatalf("%q vendor=%q want %q", tc.message, got, tc.vendor) }
		if tc.product != "" { if got := str(events[0].Raw["device_product"]); got != tc.product { t.Fatalf("%q product=%q want %q", tc.message, got, tc.product) } }
	}
}

func quoteJSON(s string) string { b, _ := json.Marshal(s); return string(b) }
