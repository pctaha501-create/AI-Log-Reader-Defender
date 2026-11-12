package analysis

import (
	"testing"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/model"
)

func TestVendorAdaptersIntegratedIntoAnalyze(t *testing.T) {
	e := model.Event{Provider:"FortiGate", Message:"traffic denied", Raw:map[string]any{"device_vendor":"Fortinet","device_product":"FortiGate","type":"traffic","subtype":"forward","action":"deny","srcip":"198.51.100.10","dstip":"192.0.2.1","dstport":"443"}}
	for _, f := range Analyze([]model.Event{e}).Findings {
		if f.RuleID == "fortigate.traffic-denied" { return }
	}
	t.Fatal("vendor adapter finding was not included by Analyze")
}
