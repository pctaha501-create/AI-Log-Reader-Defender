# Broad log ingestion and collection

## Automatic input detection

Use `--format auto` (the default) to detect JSONL, RFC 3164/5424 Syslog, CEF, LEEF, CSV with recognizable headers, and generic key/value or plain-text logs. Unknown text is never silently dropped: the full original line is retained in `raw_line` and `message`, with any safely parsed key/value fields preserved. Use an explicit format when a source has ambiguous framing.

## Native collection

- Windows: Security, System, Application, Windows Defender Operational, Windows Firewall Advanced Security, and PowerShell Operational event channels are queried with `wevtutil`. Access to some channels may require an elevated terminal. EventData values are retained as original named fields.
- Linux: journald plus common files when readable: auth.log, secure, syslog, messages, kern.log, ufw.log, and audit.log. Distros vary; missing files are normal. For authoritative timestamps and complete retention, prefer journald JSON or direct file ingestion of the original log.

## Network and appliance coverage

Routers, managed switches, VPN gateways, IDS/IPS and firewalls from different manufacturers can forward standard Syslog, CEF or LEEF to the LAN listener. JSON/JSONL, CSV and generic key/value exports can be analyzed from files. Vendor fingerprinting is best-effort metadata enrichment; unknown vendors and fields remain intact. Proprietary binary exports require a documented adapter or sample-based validation.

A basic unmanaged Ethernet hub/switch generally does not produce security logs. SNMP polling/traps are telemetry, not a log format; they require a separate collector and are not claimed as supported by the log listener.

## Safety and limits

Keep the listener on a trusted LAN, restrict ingress with the host firewall to known device IPs, and do not expose it to the public Internet. UDP has no delivery guarantee. TCP input is newline-framed; RFC 6587 octet-counted syslog framing is not yet supported. Log collection is read-only. Rules provide explainable triage signals, not proof of compromise or a substitute for endpoint protection/SIEM validation.
