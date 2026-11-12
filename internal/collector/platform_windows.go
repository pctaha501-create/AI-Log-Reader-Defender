//go:build windows

package collector

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

func Platform() string { return "windows" }

type windowsEvent struct {
	System struct {
		Provider struct { Name string `xml:"Name,attr"` } `xml:"Provider"`
		EventID string `xml:"EventID"`
		TimeCreated struct { SystemTime string `xml:"SystemTime,attr"` } `xml:"TimeCreated"`
		Channel string `xml:"Channel"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	EventData struct { Data []struct { Name string `xml:"Name,attr"`; Value string `xml:",chardata"` } `xml:"Data"` } `xml:"EventData"`
}

func Collect(w io.Writer, since time.Duration) (int, error) {
	channels := []string{
		"Security", "System", "Application",
		"Microsoft-Windows-Windows Defender/Operational",
		"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
		"Microsoft-Windows-PowerShell/Operational",
	}
	cutoff := time.Now().Add(-since)
	var records []Record
	var failures []string
	for _, channel := range channels {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		cmd := exec.CommandContext(ctx, "wevtutil.exe", "qe", channel, "/rd:true", "/c:2000", "/f:xml")
		out, err := cmd.Output()
		cancel()
		if err != nil { failures = append(failures, channel+": "+err.Error()); continue }
		decoder := xml.NewDecoder(strings.NewReader(string(out)))
		for {
			token, tokenErr := decoder.Token()
			if tokenErr == io.EOF { break }
			if tokenErr != nil { failures = append(failures, channel+" XML: "+tokenErr.Error()); break }
			start, ok := token.(xml.StartElement)
			if !ok || start.Name.Local != "Event" { continue }
			var ev windowsEvent
			if err := decoder.DecodeElement(&ev, &start); err != nil { failures = append(failures, channel+" event: "+err.Error()); continue }
			ts, _ := time.Parse(time.RFC3339Nano, ev.System.TimeCreated.SystemTime)
			if ts.IsZero() || ts.Before(cutoff) { continue }
			record := Record{
				"timestamp": ts.UTC(), "source": ev.System.Channel, "host": ev.System.Computer,
				"event_id": strings.TrimSpace(ev.System.EventID), "provider": ev.System.Provider.Name,
				"platform": "windows",
			}
			for _, item := range ev.EventData.Data {
				key := strings.TrimSpace(item.Name)
				if key == "" { key = fmt.Sprintf("data_%d", len(record)) }
				record[key] = strings.TrimSpace(item.Value)
			}
			records = append(records, record)
		}
	}
	if len(records) == 0 && len(failures) == len(channels) {
		return 0, fmt.Errorf("could not read any Windows event channel (run elevated if required): %s", strings.Join(failures, "; "))
	}
	n, err := writeRecords(w, records)
	if err != nil { return n, err }
	return n, nil
}
