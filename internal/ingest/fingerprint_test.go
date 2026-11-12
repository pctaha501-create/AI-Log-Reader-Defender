package ingest

import (
	"strings"
	"testing"
)

func TestVendorNeutralDeviceFingerprinting(t *testing.T) {
	cases := []struct {
		name, input, vendor, product, kind string
	}{
		{"fortinet firewall", `{"provider":"FortiGate","message":"action=deny src=198.51.100.2"}`, "Fortinet", "FortiGate", "firewall"},
		{"mikrotik router", `{"host":"routeros-edge","message":"firewall drop"}`, "MikroTik", "RouterOS", "firewall"},
		{"palo alto", `{"message":"PAN-OS traffic denied"}`, "Palo Alto Networks", "PAN-OS", "firewall"},
		{"unknown vendor preserved", `{"vendor":"Acme Networks","model":"XG-900","message":"custom event"}`, "Acme Networks", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events, err := ReadJSONL(strings.NewReader(tc.input))
			if err != nil { t.Fatal(err) }
			raw := events[0].Raw
			if got := str(raw["device_vendor"]); got != tc.vendor { t.Fatalf("vendor=%q want %q", got, tc.vendor) }
			if tc.product != "" && str(raw["device_product"]) != tc.product { t.Fatalf("product=%q want %q", raw["device_product"], tc.product) }
			if tc.kind != "" && str(raw["device_type"]) != tc.kind { t.Fatalf("type=%q want %q", raw["device_type"], tc.kind) }
			if tc.name == "unknown vendor preserved" && str(raw["device_model"]) != "XG-900" { t.Fatalf("model lost: %#v", raw) }
		})
	}
}

func TestExplicitVendorFieldsTakePrecedence(t *testing.T) {
	events, err := ReadJSONL(strings.NewReader(`{"vendor":"Acme","message":"Cisco firewall denied"}`))
	if err != nil { t.Fatal(err) }
	if got := str(events[0].Raw["device_vendor"]); got != "Acme" { t.Fatalf("explicit vendor overwritten: %q", got) }
}
