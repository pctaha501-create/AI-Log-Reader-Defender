# AI Log Reader & Defender

Cross-platform, local-first security log intelligence for Windows, Linux and macOS.

**Milestone M0.1:** portable Go analysis core. This is not yet a trained AI model or a production endpoint-protection product.

## Build

Requires Go 1.23+.

```sh
go test ./...
go vet ./...
go build -o ald ./cmd/ald
```

Windows PowerShell: use ``go build -o ald.exe ./cmd/ald``.

## Commands

```sh
ald version
ald analyze --input events.jsonl
ald analyze --input events.jsonl --json
ald collect --since 1h --out events.jsonl
```

Input is JSON Lines (one JSON object per line). Preferred fields include timestamp, source, host, event_id, level, provider, message, user and source_ip. Unknown fields are preserved in the raw event map.

Native read-only collection uses wevtutil on Windows, journalctl on Linux and macOS Unified Logging via log show. Access and event availability vary by OS.

## Architecture and safety

- Shared Go core: normalization, deterministic detections and conservative batch correlation.
- Platform-specific collectors are isolated behind Go build tags.
- No Python, third-party Go modules, cloud calls or model downloads are required for M0.1.
- No destructive response actions, process termination, quarantine, firewall mutation, persistence or network listener.
- A rule match is a triage signal, not proof of compromise.
- No claim of model training, LLM reasoning, exhaustive log coverage or production readiness.

## Roadmap

1. Portable schema, JSONL ingestion, detections, correlation and CI for three OSes.
2. Improve native collectors and validate on real Windows/Linux/macOS hosts.
3. Durable local storage, rotation, health checks and UI.
4. Trainable anomaly/classification engine with labelled evaluation and precision/recall/F1.
5. Optional local LLM adapter after verifying an installed Ollama model.
6. Explicitly approved, auditable and reversible response workflows.

MIT License.
