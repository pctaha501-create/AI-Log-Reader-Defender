# AI Log Reader & Defender

Cross-platform, fully offline security log collection and analysis for **Windows 10/11 x64** and **Linux x64**. Written in Go. No Ollama, Python, API key, cloud account, network connection, or separately downloaded model is required.

## Built-in intelligence

The executable contains its own lightweight analysis engine. It combines explainable security rules, event correlation, suspicious command-pattern recognition, and statistical event-volume anomaly detection. Analysis runs automatically as part of every report; there is no AI setup step.

- Authentication failures, malware/quarantine indicators, event-log clearing, account and privilege changes.
- Firewall policy changes, disabled protection, blocked traffic and suspected port scans.
- Suspicious PowerShell encoded commands and download/execute patterns.
- Suspicious use of common Windows administration binaries such as Certutil, MSHTA, Regsvr32, BITSAdmin and Rundll32.
- Process lineage alerts for suspicious Office/browser-to-script-host execution, with optional same-host, same-PID, time-bounded correlation to Windows Filtering Platform or Sysmon network events.
- Unusual event-volume spikes across observed time buckets.
- A local summary with evidence references and suggested investigation steps.

This is an embedded, explainable rules-and-statistics engine, **not a large language model or a pretrained neural network**. It does not invent explanations from natural language. It is designed to be small, deterministic, private, and usable on ordinary computers without GPU acceleration. Findings are triage signals, not proof of compromise.

## Collection and supported formats

- Automatic detection: JSONL, Syslog RFC 3164/5424, CEF, LEEF, recognizable CSV, generic key/value and plain text.
- Vendor/device fingerprinting for a broad set of network and endpoint products. Unknown brands and fields are preserved; fingerprinting is heuristic, not exhaustive.
- Normalization of source/destination IPs and ports, protocol, action, host, provider, event ID, model and firmware when present.
- LAN receiver for UDP and newline-framed TCP Syslog/CEF/LEEF, with optional sender IP/CIDR allowlist, bounded TCP frames and connection cap.
- Windows event collection from Security, System, Application, Defender, Windows Firewall and PowerShell channels.
- Linux journald plus recent common authentication, system, kernel, UFW and audit log files when readable.
- GitHub Actions tests, static analysis, Windows/Linux x64 builds and smoke tests.

Proprietary or binary exports require a documented adapter or sanitized sample-based validation. An unmanaged Ethernet hub/switch usually produces no security logs. SNMP telemetry/traps are not Syslog and are not collected by this listener.

## Download

Open the latest successful GitHub Actions run and download the Windows or Linux artifact. Tagged releases publish binaries and SHA-256 checksums.

## Windows

    .\ald-windows-amd64.exe version
    .\ald-windows-amd64.exe analyze --input .\firewall.log
    .\ald-windows-amd64.exe analyze --input .\events.jsonl --json
    .\ald-windows-amd64.exe collect --since 1h --out .\events.jsonl

Some event channels require an elevated terminal or appropriate local permissions.

## Linux

    chmod +x ./ald-linux-amd64
    ./ald-linux-amd64 version
    ./ald-linux-amd64 analyze --input ./firewall.log
    ./ald-linux-amd64 collect --since 1h --out ./events.jsonl

The collector uses journalctl and recent common log files when readable. File-based collection uses file modification time as a coarse lookback filter; exact per-event timestamps remain in the original log lines.

## Receive network-device logs

Configure a router, managed switch, VPN gateway, IDS/IPS or firewall to forward Syslog/CEF/LEEF to a trusted LAN host:

    ald listen --addr 0.0.0.0:5514 --protocol udp --format syslog --allow 192.0.2.10,192.0.2.0/24 --out network-events.jsonl

Omit --allow only if the host firewall independently restricts the listener to trusted senders. Use --protocol tcp for newline-framed TCP. TCP supports newline-delimited framing and RFC 6587 octet-counted framing; each frame is bounded to 1 MiB. Never expose the listener to the public Internet; UDP delivery is not guaranteed.

## Supported formats

| Format | Support |
|---|---|
| JSON Lines, Syslog RFC 3164/5424, CEF, LEEF | Yes |
| CSV with recognizable header | Yes |
| Generic key/value and plain text | Best effort; raw line retained |
| Proprietary binary formats | Requires adapter |
| SNMP polling/traps | Separate telemetry collector required |

## Privacy and safety

- No telemetry upload or cloud analysis; analysis works without network access.
- No external AI runtime, model, or service.
- Collection is read-only; no automatic remediation or system configuration changes.
- Protect exported logs; they may contain usernames, IPs, hostnames and other sensitive data.
- Findings can be false positives or miss threats. Preserve and inspect original evidence.
- This is not a replacement for antivirus, EDR, SIEM, or professional incident response.

## Development

Requires Go 1.23 or newer:

    gofmt -w .
    go test -race ./...
    go vet ./...
    go build ./cmd/ald
