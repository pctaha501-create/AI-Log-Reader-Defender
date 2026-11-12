# AI Log Reader & Defender

Cross-platform, local-first security log collection and analysis for **Windows 10/11 x64** and **Linux x64**. Written in Go. The core engine uses explainable rules; optional local Ollama adds natural-language analysis without sending logs to a cloud service.

## Included capabilities

- Automatic detection: JSONL, Syslog RFC 3164/5424, CEF, LEEF, recognizable CSV, generic key/value and plain text.
- Vendor/device fingerprinting for a broad set of network and endpoint products. Unknown brands and fields are preserved; fingerprinting is heuristic, not exhaustive.
- Normalization of source/destination IPs and ports, protocol, action, host, provider, event ID, model and firmware when present.
- LAN receiver for UDP and newline-framed TCP Syslog/CEF/LEEF, with optional sender IP/CIDR allowlist, bounded TCP frames and connection cap.
- Windows event collection from Security, System, Application, Defender, Windows Firewall and PowerShell channels.
- Linux journald plus recent common authentication, system, kernel, UFW and audit log files when readable.
- Explainable detections for authentication failures, malware/quarantine indicators, event-log clearing, account/privilege changes, firewall policy changes, blocked traffic and suspected scans.
- Optional offline analysis with an already-installed local Ollama model.
- GitHub Actions tests, static analysis, Windows/Linux x64 builds and smoke tests.

## Limitations

This is an initial security-triage utility, not antivirus, EDR, SIEM or proof that a device is safe. Built-in rules are deterministic; there is no pretrained classifier. Ollama is optional and not bundled or trained by this project. Its output is advisory.

Standard formats provide broad multi-vendor compatibility, but proprietary or binary exports require a documented adapter or sanitized sample-based validation. An unmanaged Ethernet hub/switch usually produces no security logs. SNMP telemetry/traps are not Syslog and are not collected by this listener.

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

## Optional local AI (Ollama)

Start Ollama and make sure a compatible chat model is already installed:

    ald analyze --input firewall.log --ai ollama --model qwen3-coder:30b

The default endpoint is `http://127.0.0.1:11434`; non-loopback endpoints are rejected. No API key, cloud service or model download is used. AI output is advisory. Log contents are treated as untrusted evidence, not instructions.

## Receive network-device logs

Configure a router, managed switch, VPN gateway, IDS/IPS or firewall to forward Syslog/CEF/LEEF to a trusted LAN host:

    ald listen --addr 0.0.0.0:5514 --protocol udp --format syslog --allow 192.0.2.10,192.0.2.0/24 --out network-events.jsonl

Omit `--allow` only if the host firewall independently restricts the listener to trusted senders. Use `--protocol tcp` for newline-framed TCP. TCP RFC 6587 octet-counting is not implemented. Never expose the listener to the public Internet; UDP delivery is not guaranteed.

## Supported formats

| Format | Support |
|---|---|
| JSON Lines, Syslog RFC 3164/5424, CEF, LEEF | Yes |
| CSV with recognizable header | Yes |
| Generic key/value and plain text | Best effort; raw line retained |
| Proprietary binary formats | Requires adapter |
| SNMP polling/traps | Separate telemetry collector required |

## Privacy and safety

- No telemetry upload or cloud analysis.
- Ollama is opt-in and loopback-only.
- Collection is read-only; no remediation or system configuration changes.
- Protect exported logs; they may contain usernames, IPs, hostnames and other sensitive data.
- Findings can be false positives or miss threats. Preserve and inspect original evidence.

## Development

Requires Go 1.23 or newer:

    gofmt -w .
    go test -race ./...
    go vet ./...
    go build ./cmd/ald
