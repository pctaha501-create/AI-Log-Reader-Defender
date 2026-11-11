package collector

import (
 "encoding/json"
 "fmt"
 "io"
 "time"
)
type Record map[string]any
func writeRecords(w io.Writer, records []Record) (int, error) {
 enc := json.NewEncoder(w); count := 0
 for _, record := range records { if err := enc.Encode(record); err != nil { return count, fmt.Errorf("write JSONL: %w", err) }; count++ }
 return count, nil
}
func sinceArg(d time.Duration) string { return d.Round(time.Second).String() }
