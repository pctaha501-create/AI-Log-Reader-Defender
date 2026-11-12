package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/analysis"
	localai "github.com/pctaha501-create/AI-Log-Reader-Defender/internal/ai"
	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/collector"
	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/ingest"
)

const version = "0.3.0"

func main() {
	if len(os.Args) < 2 { usage(); os.Exit(2) }
	switch os.Args[1] {
	case "version":
		fmt.Printf("AI Log Reader & Defender %s (%s)\n", version, collector.Platform())
	case "analyze":
		runAnalyze(os.Args[2:])
	case "collect":
		runCollect(os.Args[2:])
	case "listen":
		runListen(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}
func usage() {
	fmt.Fprintln(os.Stderr, "AI Log Reader & Defender")
	fmt.Fprintln(os.Stderr, "Usage: ald <version|analyze|collect|listen>")
	fmt.Fprintln(os.Stderr, "  analyze --input events.log [--format auto] [--ai ollama --model NAME] [--json]")
	fmt.Fprintln(os.Stderr, "  collect --since 1h --out events.jsonl")
	fmt.Fprintln(os.Stderr, "  listen --addr 0.0.0.0:5514 --protocol udp --format syslog --out network.jsonl")
}
func runAnalyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	input := fs.String("input", "", "input log file (required)")
	format := fs.String("format", "auto", "input format: auto, jsonl, syslog, cef, leef, csv, or text")
	asJSON := fs.Bool("json", false, "print machine-readable JSON")
	aiMode := fs.String("ai", "off", "optional local AI: off or ollama")
	ollamaURL := fs.String("ollama-url", "http://127.0.0.1:11434", "local Ollama URL (loopback only)")
	modelName := fs.String("model", "qwen3-coder:30b", "installed local Ollama model")
	_ = fs.Parse(args)
	if *input == "" { fmt.Fprintln(os.Stderr, "--input is required"); os.Exit(2) }
	f, err := os.Open(*input)
	if err != nil { fatal(err) }
	defer f.Close()
	events, err := ingest.Read(f, *format)
	if err != nil { fatal(err) }
	report := analysis.Analyze(events)
	if *aiMode == "ollama" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		answer, aiErr := localai.Analyze(ctx, *ollamaURL, *modelName, events, report)
		if aiErr != nil { fatal(aiErr) }
		report.AIAnalysis = answer
	} else if *aiMode != "off" {
		fatal(fmt.Errorf("unsupported --ai mode %q (use off or ollama)", *aiMode))
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil { fatal(err) }
		return
	}
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
	d, err := time.ParseDuration(*since)
	if err != nil || d <= 0 { fatal(fmt.Errorf("invalid --since duration: %q", *since)) }
	f, err := os.Create(*out)
	if err != nil { fatal(err) }
	defer f.Close()
	count, err := collector.Collect(f, d)
	if err != nil { fatal(err) }
	fmt.Printf("Collected %d records from %s into %s\n", count, collector.Platform(), *out)
}
func runListen(args []string) {
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	addr := fs.String("addr", "0.0.0.0:5514", "LAN address and port to listen on")
	protocol := fs.String("protocol", "udp", "transport: udp or tcp")
	format := fs.String("format", "syslog", "message format: syslog, cef, or leef")
	out := fs.String("out", "network-events.jsonl", "append received events to this JSONL file")
	_ = fs.Parse(args)
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil { fatal(err) }
	defer f.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Printf("Listening for %s/%s on %s; writing local events to %s (Ctrl+C to stop)\n", *protocol, *format, *addr, *out)
	if err := collector.ListenNetwork(ctx, f, *addr, *protocol, *format, os.Stderr); err != nil { fatal(err) }
}
func fatal(err error) { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
