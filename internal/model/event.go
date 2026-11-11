package model

import "time"

type Event struct {
 Timestamp time.Time `json:"timestamp"`
 Source string `json:"source,omitempty"`
 Host string `json:"host,omitempty"`
 EventID string `json:"event_id,omitempty"`
 Level string `json:"level,omitempty"`
 Provider string `json:"provider,omitempty"`
 Message string `json:"message,omitempty"`
 User string `json:"user,omitempty"`
 SourceIP string `json:"source_ip,omitempty"`
 Raw map[string]any `json:"raw,omitempty"`
}
type Finding struct {
 ID string `json:"id"`
 RuleID string `json:"rule_id"`
 Severity string `json:"severity"`
 Title string `json:"title"`
 Description string `json:"description"`
 EventIndexes []int `json:"event_indexes"`
 Evidence []string `json:"evidence"`
}
type Report struct {
 GeneratedAt time.Time `json:"generated_at"`
 EventCount int `json:"event_count"`
 Findings []Finding `json:"findings"`
}
