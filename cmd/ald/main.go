package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/analysis"
	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/collector"
	"github.com/pctaha501-create/AI-Log-Reader-Defender/internal/ingest"
)

const version = "0.5.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Printf("AI Log Reader & Defender %s (%s)\n", version, collector.Platform())
	case "analyze":
		runAnalyze(os.Args[2:])
	case "train":
		runTrain(os.Args[2:])
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
	fmt.Fprintln(os.Stderr, "Usage: ald <version|analyze|train|collect|listen>")
	fmt.Fprintln(os.Stderr, "  analyze --input events.log [--format auto] [--baseline baseline.json] [--json]")
	fmt.Fprintln(os.Stderr, "  train --input trusted-events.log --output baseline.json [--format auto]")
	fmt.Fprintln(os.Stderr, "  collect --since 1h --out events.jsonl")
	fmt.Fprintln(os.Stderr, "  listen --addr 0.0.0.0:5514 --protocol udp --format syslog --allow 192.0.2.10,192.0.2.0/24 --out network.jsonl")
}

func runAnalyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	input := fs.String("input", "", "input log file (required)")
	format := fs.String("format", "auto", "input format: auto, jsonl, syslog, cef, leef, csv, or text")
	baselinePath := fs.String("baseline", "", "optional local behavioral baseline JSON")
	asJSON := fs.Bool("json", false, "print machine-readable JSON")
	_ = fs.Parse(args)
	if *input == "" {
		fmt.Fprintln(os.Stderr, "--input is required")
		os.Exit(2)
	}
	f, err := os.Open(*input)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	events, err := ingest.Read(f, *format)
	if err != nil {
		fatal(err)
	}
	var report = analysis.Analyze(events)
	if *baselinePath != "" {
		bf, err := os.Open(*baselinePath)
		if err != nil {
			fatal(err)
		}
		baseline, loadErr := analysis.LoadBaseline(bf)
		closeErr := bf.Close()
		if loadErr != nil {
			fatal(loadErr)
		}
		if closeErr != nil {
			fatal(closeErr)
		}
		report, err = analysis.AnalyzeWithBaseline(events, baseline)
		if err != nil {
			fatal(err)
		}
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fatal(err)
		}
		return
	}
	fmt.Printf("Analyzed %d events; %d findings\n", report.EventCount, len(report.Findings))
	if report.AIAnalysis != "" {
		fmt.Printf("\nOffline intelligence summary:\n%s\n", report.AIAnalysis)
	}
	for _, finding := range report.Findings {
		fmt.Printf("[%s] %s — %s\n  %s\n", finding.Severity, finding.RuleID, finding.Title, finding.Description)
		for _, evidence := range finding.Evidence {
			fmt.Printf("  evidence: %s\n", evidence)
		}
	}
}

func runTrain(args []string) {
	fs := flag.NewFlagSet("train", flag.ExitOnError)
	input := fs.String("input", "", "trusted historical log file (required)")
	output := fs.String("output", "baseline.json", "output baseline JSON file")
	format := fs.String("format", "auto", "input format: auto, jsonl, syslog, cef, leef, csv, or text")
	_ = fs.Parse(args)
	if *input == "" {
		fmt.Fprintln(os.Stderr, "--input is required")
		os.Exit(2)
	}
	in, err := os.Open(*input)
	if err != nil {
		fatal(err)
	}
	events, readErr := ingest.Read(in, *format)
	closeErr := in.Close()
	if readErr != nil {
		fatal(readErr)
	}
	if closeErr != nil {
		fatal(closeErr)
	}
	if len(events) == 0 {
		fatal(fmt.Errorf("no events found in training input"))
	}
	baseline := analysis.TrainBaseline(events)
	out, err := os.OpenFile(*output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		fatal(err)
	}
	saveErr := analysis.SaveBaseline(out, baseline)
	closeErr = out.Close()
	if saveErr != nil {
		fatal(saveErr)
	}
	if closeErr != nil {
		fatal(closeErr)
	}
	fmt.Printf("Learned a local behavioral baseline from %d events and %d log sources; saved to %s\n", baseline.EventCount, len(baseline.ProviderCounts), *output)
	fmt.Println("Train only with representative logs from a known-good environment. Baseline novelty is a triage signal, not proof of an attack.")
}

func runCollect(args []string) {
	fs := flag.NewFlagSet("collect", flag.ExitOnError)
	since := fs.String("since", "1h", "look-back duration, for example 30m or 2h")
	out := fs.String("out", "events.jsonl", "output JSONL file")
	_ = fs.Parse(args)
	d, err := time.ParseDuration(*since)
	if err != nil || d <= 0 {
		fatal(fmt.Errorf("invalid --since duration: %q", *since))
	}
	f, err := os.Create(*out)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	count, err := collector.Collect(f, d)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("Collected %d records from %s into %s\n", count, collector.Platform(), *out)
}

func runListen(args []string) {
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	addr := fs.String("addr", "0.0.0.0:5514", "LAN address and port to listen on")
	protocol := fs.String("protocol", "udp", "transport: udp or tcp")
	format := fs.String("format", "syslog", "message format: syslog, cef, or leef")
	out := fs.String("out", "network-events.jsonl", "append received events to this JSONL file")
	allow := fs.String("allow", "", "optional comma-separated sender IPs/CIDRs; unmatched senders are dropped")
	_ = fs.Parse(args)
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Printf("Listening for %s/%s on %s; writing local events to %s (Ctrl+C to stop)\n", *protocol, *format, *addr, *out)
	var senders []string
	if strings.TrimSpace(*allow) != "" {
		senders = strings.Split(*allow, ",")
	}
	if err := collector.ListenNetworkWithAllowlist(ctx, f, *addr, *protocol, *format, senders, os.Stderr); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
