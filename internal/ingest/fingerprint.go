package ingest

import (
	"fmt"
	"regexp"
	"strings"
)

var firmwarePattern = regexp.MustCompile(`(?i)\\b(?:firmware|fw|version|software)[ :=/]+([vV]?[0-9][A-Za-z0-9._+-]*)`)
var modelPattern = regexp.MustCompile(`(?i)\\b(?:model|product)[ :=]+([A-Za-z0-9._-]+)`)

// inferDeviceMetadata enriches Raw without discarding vendor-specific fields.
// It uses explicit structured fields first, then conservative signature hints.
func inferDeviceMetadata(raw map[string]any) {
	vendor := firstNonEmpty(raw, "device_vendor", "vendor", "manufacturer", "manufacturer_name", "observer_vendor")
	product := firstNonEmpty(raw, "device_product", "product", "product_name", "observer_product")
	model := firstNonEmpty(raw, "device_model", "model", "model_name", "hardware_model")
	firmware := firstNonEmpty(raw, "firmware_version", "firmware", "fw_version", "software_version", "version")

	identity := strings.ToLower(strings.Join([]string{
		vendor, product, model, str(first(raw, "provider", "source_name", "process", "appname")),
		str(first(raw, "host", "hostname", "computer")), str(first(raw, "message", "msg", "description")),
		str(first(raw, "raw_line")),
	}, " "))
	if vendor == "" {
		vendor = detectVendor(identity)
	}
	if product == "" {
		product = detectProduct(identity)
	}
	if model == "" {
		if m := modelPattern.FindStringSubmatch(identity); len(m) > 1 {
			model = m[1]
		}
	}
	if firmware == "" {
		if m := firmwarePattern.FindStringSubmatch(identity); len(m) > 1 {
			firmware = m[1]
		}
	}
	deviceType := firstNonEmpty(raw, "device_type", "device_class", "observer_type")
	if deviceType == "" {
		deviceType = detectDeviceType(identity)
	}

	setIfMissing(raw, "device_vendor", vendor)
	setIfMissing(raw, "device_product", product)
	setIfMissing(raw, "device_model", model)
	setIfMissing(raw, "firmware_version", firmware)
	setIfMissing(raw, "device_type", deviceType)
	if vendor != "" || product != "" || model != "" || deviceType != "" {
		setIfMissing(raw, "device_identification", "structured-or-signature")
	} else {
		setIfMissing(raw, "device_identification", "unknown-preserved")
	}
}

func firstNonEmpty(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(str(m[key])); value != "" {
			return value
		}
	}
	return ""
}

func setIfMissing(m map[string]any, key, value string) {
	if strings.TrimSpace(str(m[key])) == "" && strings.TrimSpace(value) != "" {
		m[key] = value
	}
}

func detectVendor(identity string) string {
	// Broad hints only; unknown manufacturers remain intact in Raw.
	vendors := []struct{ needle, name string }{
		{"fortinet", "Fortinet"}, {"fortigate", "Fortinet"},
		{"palo alto", "Palo Alto Networks"}, {"pan-os", "Palo Alto Networks"},
		{"checkpoint", "Check Point"}, {"check point", "Check Point"},
		{"sonicwall", "SonicWall"}, {"watchguard", "WatchGuard"},
		{"sophos", "Sophos"}, {"juniper", "Juniper Networks"},
		{"mikrotik", "MikroTik"}, {"routeros", "MikroTik"},
		{"cisco", "Cisco"}, {"aruba", "HPE Aruba"},
		{"hewlett-packard", "HPE"}, {"hp ", "HPE"},
		{"ubiquiti", "Ubiquiti"}, {"unifi", "Ubiquiti"},
		{"tp-link", "TP-Link"}, {"tplink", "TP-Link"},
		{"huawei", "Huawei"}, {"zyxel", "Zyxel"},
		{"netgear", "NETGEAR"}, {"d-link", "D-Link"},
		{"dlink", "D-Link"}, {"f5 networks", "F5"},
		{"barracuda", "Barracuda"}, {"dell", "Dell"},
		{"lenovo", "Lenovo"}, {"microsoft", "Microsoft"},
		{"windows", "Microsoft"}, {"linux", "Linux"},
		{"apple", "Apple"},
	}
	for _, item := range vendors {
		if strings.Contains(identity, item.needle) {
			return item.name
		}
	}
	return ""
}

func detectProduct(identity string) string {
	switch {
	case strings.Contains(identity, "fortigate"):
		return "FortiGate"
	case strings.Contains(identity, "pan-os") || strings.Contains(identity, "palo alto"):
		return "PAN-OS"
	case strings.Contains(identity, "routeros"):
		return "RouterOS"
	case strings.Contains(identity, "unifi"):
		return "UniFi"
	case strings.Contains(identity, "windows filtering platform") || strings.Contains(identity, "microsoft-windows-security-auditing"):
		return "Windows Filtering Platform"
	case strings.Contains(identity, "suricata"):
		return "Suricata"
	case strings.Contains(identity, "zeek"):
		return "Zeek"
	case strings.Contains(identity, "snort"):
		return "Snort"
	}
	return ""
}

func detectDeviceType(identity string) string {
	switch {
	case strings.Contains(identity, "firewall") || strings.Contains(identity, "fortigate") || strings.Contains(identity, "pan-os") || strings.Contains(identity, "iptables") || strings.Contains(identity, "nftables") || strings.Contains(identity, "ufw"):
		return "firewall"
	case strings.Contains(identity, "switch") || strings.Contains(identity, "spanning-tree") || strings.Contains(identity, "stp "):
		return "network-switch"
	case strings.Contains(identity, "router") || strings.Contains(identity, "routing") || strings.Contains(identity, "ospf") || strings.Contains(identity, "bgp"):
		return "router"
	case strings.Contains(identity, "windows") || strings.Contains(identity, "linux") || strings.Contains(identity, "kernel") || strings.Contains(identity, "systemd"):
		return "computer"
	case strings.Contains(identity, "suricata") || strings.Contains(identity, "zeek") || strings.Contains(identity, "snort"):
		return "network-security-sensor"
	}
	return ""
}

// Keep fmt linked here for stable, human-readable diagnostics in future adapters.
var _ = fmt.Sprintf
