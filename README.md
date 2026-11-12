# AI Log Reader & Defender

Cross-platform, local-first security log collection and analysis for **Windows 10/11 x64** and **Linux x64**. Written in Go. The core engine uses explainable rules; an optional local Ollama integration adds natural-language analysis without sending logs to a cloud service.

## What is included

- Automatic input detection for JSONL, Syslog RFC 3164/5424, CEF, LEEF, CSV with recognizable headers, generic key/value and plain text.
- Vendor/device fingerprinting as best-effort enrichment. Structured metadata takes priority; unknown brands and original fields are preserved.
- Network/firewall field normalization: source/destination IPs and ports, protocol and action.
- LAN Syslog receiver over UDP or newline-framed TCP for Syslog, CEF and LEEF.
- Windows collection from Security, System, Application, Defender Operational, Windows Firewall Advanced Security and PowerShell Operational channels, subject to local permissions.
- Linux collection from journald and common readable auth, system, kernel, UFW and audit log files.
- Explainable findings for repeated authentication failures, malware/quarantine indicators, event-log clearing, account and privilege changes, firewall policy changes, blocked traffic and suspected port scans.
- Optional offline LLM analysis using a locally installed Ollama model. It is opt-in and restricted to loopback endpoints.
- GitHub Actions quality checks, Windows/Linux x64 builds and smoke tests.

## Honest limitations

This is an initial security-triage release, not an antivirus replacement, EDR, SIEM or proof that a device is safe. The built-in detection engine is deterministic and explainable, not a pretrained classifier. Ollama is an optional locally hosted LLM; it is not bundled or trained by this project. Model quality depends on the model installed by the operator.

Brand detection is heuristic. No parser can guarantee compatibility with every proprietary or binary export. For closed formats, a documented adapter or representative sanitized samples are required. A basic unmanaged Ethernet hub/switch generally does not produce security logs. SNMP telemetry is not the same thing as Syslog and is not collected by this listener.

## Download

GitHub Actions builds the Windows and Linux binaries. Open the latest successful workflow run and download the matching artifact. Tagged releases publish binaries and SHA-256 checksums.

## Windows

PowerShell:

    .\ald-windows-amd64.exe version
    .\ald-windows-amd64.exe analyze --input .\firewall.log
    .\ald-windows-amd64.exe analyze --input .\events.jsonl --json
    .\ald-windows-amd64.exe collect --since 1h --out .\events.jsonl

Reading some Windows event channels may require an elevated terminal and appropriate local permissions.

## Linux

    chmod +x ./ald-linux-amd64
    ./ald-linux-amd64 version
    ./ald-linux-amd64 analyze --input ./firewall.log
    ./ald-linux-amd64 collect --since 1h --out ./events.jsonl

The collector uses journalctl and reads common files only when the current user has permission. File-based log availability varies by distribution.

## Optional local AI with Ollama

Install and start Ollama yourself, then make sure the requested model is already present locally. The default is `qwen3-coder:30b`; choose any compatible installed chat model:

    ald analyze --input firewall.log --ai ollama --model qwen3-coder:30b

The integration talks only to `http://127.0.0.1:11434` by default and rejects non-loopback endpoints. No API key, remote service or model download is performed by this program. AI output is advisory; verify findings against raw evidence. Logs are treated as untrusted data, not instructions.

## Receive logs from network devices

On a trusted LAN, configure a router, managed switch, VPN gateway, IDS/IPS or firewall to forward Syslog/CEF/LEEF to a machine running:

    ald listen --addr 0.0.0.0:5514 --protocol udp --format syslog --out network-events.jsonl

Use `--protocol tcp` for newline-framed TCP senders, or select `cef` / `leef` when appropriate. Restrict inbound traffic in the host firewall to known device IP addresses. Do not expose this listener to the public Internet. UDP can lose packets; TCP RFC 6587 octet-counting is not implemented yet.

## Supported input formats

| Format | Support |
|---|---|
| JSON Lines | Yes |
| Syslog RFC 3164 / RFC 5424 | Yes |
| CEF | Yes |
| LEEF | Yes |
| CSV with recognizable header | Yes |
| Generic key/value and plain text | Best-effort, raw line retained |
| Proprietary binary exports | Requires a format-specific adapter |
| SNMP polling/traps | Not a log format; separate collector needed |

## Detection notes

Rules look for common security indicators and correlations. They can produce false positives and miss attacks. Coverage depends on event IDs, source fields, permissions and device logging configuration. Always preserve raw logs and investigate the original event source.

## Privacy and safety

- No telemetry upload or cloud analysis.
- Local Ollama is optional and loopback-only.
- Collection is read-only; no automatic remediation, process termination, quarantine, firewall changes or configuration changes.
- The listener is opt-in and should be LAN-restricted.
- Logs can contain usernames, IPs, hostnames and other sensitive data. Protect exports and redact them before sharing.

## Development

Requires Go 1.23 or newer:

    gofmt -w .
    go test -race ./...
    go vet ./...
    go build ./cmd/ald

