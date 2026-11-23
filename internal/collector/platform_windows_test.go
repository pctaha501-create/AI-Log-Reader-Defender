//go:build windows

package collector

import "testing"

func TestWindowsCollectorCoversAdditionalSecurityChannels(t *testing.T) {
	required := []string{
		"Security", "Microsoft-Windows-Windows Defender/Operational",
		"Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-WMI-Activity/Operational",
		"Microsoft-Windows-TaskScheduler/Operational",
		"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
		"Microsoft-Windows-AppLocker/EXE and DLL", "Microsoft-Windows-CodeIntegrity/Operational",
	}
	seen := make(map[string]bool, len(windowsEventChannels))
	for _, channel := range windowsEventChannels { seen[channel] = true }
	for _, channel := range required {
		if !seen[channel] { t.Errorf("missing expected Windows event channel %s", channel) }
	}
	if windowsEventsPerChannel < 1000 || windowsEventsPerChannel > 10000 {
		t.Fatalf("unexpected per-channel query bound: %d", windowsEventsPerChannel)
	}
}
