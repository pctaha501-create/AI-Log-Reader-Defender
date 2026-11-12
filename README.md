# AI Log Reader & Defender

Initial release track: Windows 10/11 x64 and Ubuntu/Linux x64. Local-first, read-only security-log triage utility written in Go. No Python runtime, third-party Go modules, cloud API, or downloaded model is required.

Status: this is a command-line utility using deterministic, explainable rules. It is not a trained AI model, antivirus replacement, EDR, SIEM, or proof that a device is safe. Findings require human review. A graphical interface and machine-learning classifier are not included in this initial release.

## Download without a development PC

GitHub Actions runs formatting checks, tests, static analysis, native builds, and smoke tests for Windows and Ubuntu/Linux. Open Actions, select the latest successful CI run, and download the Windows or Linux artifact. CI artifacts expire after 14 days. A version tag such as v0.2.0 publishes both binaries and SHA-256 checksums as a GitHub Release.

## Windows PowerShell

    .\ald-windows-amd64.exe version
    .\ald-windows-amd64.exe analyze --input .\testdata\sample-events.jsonl
    .\ald-windows-amd64.exe collect --since 1h --out .\events.jsonl
    .\ald-windows-amd64.exe analyze --input .\events.jsonl --json

Reading the Windows Security log may require an elevated terminal and suitable local permissions. Collection is read-only.

## Ubuntu/Linux

    chmod +x ./ald-linux-amd64
    ./ald-linux-amd64 version
    ./ald-linux-amd64 analyze --input ./testdata/sample-events.jsonl
    ./ald-linux-amd64 collect --since 1h --out ./events.jsonl
    ./ald-linux-amd64 analyze --input ./events.jsonl --json

Linux collection reads journald using journalctl. The current user must have permission to read the relevant entries. Do not run as root unless access policy requires it.

## Detection coverage

- Repeated authentication failures (Windows IDs 4625, 4771, 4776) grouped by source IP or user within a 10-minute window.
- Explicit malware, ransomware, and quarantine message indicators.
- Event-log clearing indicators (Windows 1102 and System 104).
- Account creation (Windows 4720).
- Privileged group membership changes (Windows 4728, 4732, 4756).
- Account deletion and group membership removal (Windows 4726, 4733, 4757).
- Basic same-batch correlation: account creation followed by privileged membership change within 100 events.

Coverage depends on available event fields and message text. This is not exhaustive threat detection. False positives and missed detections are possible.

## JSONL input

One JSON object per line. Common fields: timestamp, source, host, event_id, level, provider, message, user, source_ip. Unknown fields are retained in the raw map. UTF-8 BOM and blank lines are supported. See testdata/sample-events.jsonl.

## Privacy and safety

- No network listener, telemetry upload, cloud analysis, or automatic remediation.
- Collectors only read logs and write the requested output file.
- No process termination, file deletion, quarantine, firewall changes, or system configuration changes.
- Logs may contain usernames, hostnames, IP addresses, and sensitive data. Store exports securely and redact before sharing.
- A clean report does not prove the absence of compromise.

## Development

Requires Go 1.23 or newer:

    gofmt -w .
    go test ./...
    go vet ./...
    go build ./cmd/ald

## Roadmap

Expand and validate native event collection; add versioned rule packs and sanitized real-world fixtures; add local persistence and a graphical interface; develop an independently evaluated anomaly/classification model with precision, recall, and F1 metrics; optionally support a verified locally installed LLM.
