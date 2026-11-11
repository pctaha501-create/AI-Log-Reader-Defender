package main

import (
 "encoding/json"
 "flag"
 "fmt"
 "os"
 "time"

 "github.com/pctaha501-create/AI-Log-Reader-Defender/internal/analysis"
 "github.com/pctaha501-create/AI-Log-Reader-Defender/internal/collector"
 "github.com/pctaha501-create/AI-Log-Reader-Defender/internal/ingest"
)

const version = "0.1.0"

func main() {
 if len(os.Args) < 2 { usage(); os.Exit(2) }
 switch os.Args[1] {
 case "version": fmt.Printf("AI Log Reader & Defender %s (%s)\n", version, collector.Platform())
 case "analyze": runAnalyze(os.Args[2:])
 case "collect": runCollect(os.Args[2:])
 default: usage(); os.Exit(2)
 }
}
func usage() {
 fmt.Fprintln(os.Stderr, "AI Log Reader & Defender")
 fmt.Fprintln(os.Stderr, "Usage: ald <version|analyze|collect>")
 fmt.Fprintln(os.Stderr, "  analyze --input events.jsonl [--json]")
 fmt.Fprintln(os.Stderr, "  collect --since 1h --out events.jsonl")
}
func runAnalyze(args []string) {
 fs := flag.NewFlagSet("analyze", flag.ExitOnError)
 input := fs.String("input", "", "JSONL input file (required)")
 asJSON := fs.Bool("json", false, "print machine-readable JSON")
 _ = fs.Parse(args)
 if *input == "" { fmt.Fprintln(os.Stderr, "--input is required"); os.Exit(2) }
 f, err := os.Open(*input); if err != nil { fatal(err) }; defer f.Close()
 events, err := ingest.ReadJSONL(f); if err != nil { fatal(err) }
 report := analysis.Analyze(events)
 if *asJSON { enc := json.NewEncoder(os.Stdout); enc.SetIndent("", "  "); if err := enc.Encode(report); err != nil { fatal(err) }; return }
 fmt.Printf("Analyzed %d events; %d findings\n", report.EventCount, len(report.Findings))
 for _, finding := range report.Findings {
  fmt.Printf("[%s] %s — %s\n  %s\n", finding.Severity, finding.RuleID, finding.Title, finding.Description)
  for _, evidence := range finding.Evidence { fmt.Printf("  evidence: %s\n", evidence) }
 }
}
func runCollect(args []string) {
 fs := flag.NewFlagSet("collect", flag.ExitOnError)
 since := fs.String("since", "1h", "look-back duration, for example 30m or 2h")
 out := fs.String("out", "events.jsonl", "output JSONL file")
 _ = fs.Parse(args)
 d, err := time.ParseDuration(*since); if err != nil || d <= 0 { fatal(fmt.Errorf("invalid --since duration: %q", *since)) }
 f, err := os.Create(*out); if err != nil { fatal(err) }; defer f.Close()
 count, err := collector.Collect(f, d); if err != nil { fatal(err) }
 fmt.Printf("Collected %d records from %s into %s\n", count, collector.Platform(), *out)
}
func fatal(err error) { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
