# Log formats and network telemetry

The ingestion layer accepts line-oriented JSONL, Syslog (RFC 3164 and RFC 5424), CEF, and LEEF.
The parsers preserve the original line and vendor extension fields in the normalized event's Raw map.
Common network fields such as source/destination IP, source/destination port, protocol, and action are normalized when present.

## Receive router and appliance logs over the LAN

The CLI can receive Syslog, CEF, or LEEF messages over UDP or line-delimited TCP and append normalized events to a local JSONL file:

    ald listen --addr 0.0.0.0:5514 --protocol udp --format syslog --out network-events.jsonl

Configure a router, managed switch, or firewall appliance to forward its logs to the computer's LAN IP and UDP port 5514. TCP is also available:

    ald listen --addr 0.0.0.0:5514 --protocol tcp --format cef --out firewall-events.jsonl

Use a high, unprivileged port such as 5514 rather than binding to 514. Configure the host firewall to permit inbound traffic only from trusted management networks or known device IPs. Do not expose the listener to the public internet. The listener is intentionally local-first and does not send logs to a cloud service.

TCP ingestion currently expects newline-delimited messages; RFC 6587 octet-counted framing is not implemented yet. UDP messages are parsed as received datagrams.

## Firewall analysis baseline

The current deterministic rules identify:
- Windows Filtering Platform block events (Security event IDs 5152 and 5157).
- Repeated blocked connections from one source and suspected multi-port scans (at least 10 blocked attempts to 5 or more destination ports within five minutes).
- Firewall service/protection disable indicators and selected Windows firewall policy/rule change event IDs.
- Common UFW, iptables, nftables, firewalld, CEF, and LEEF action/field conventions when they are present in the imported message or extension fields.

Findings are triage signals, not proof of compromise. Thresholds are intentionally conservative and should be tuned with representative network traffic before production deployment.

## Important collection limitations

Parsing a format does not mean the application can automatically retrieve logs from every device. Network appliances generally need to be configured to forward Syslog/CEF/LEEF to a reachable collector, or exported logs must be imported. SNMP is a separate telemetry protocol and is not a log format; it requires a dedicated, read-only device integration and per-vendor support.

The initial Windows/Linux native collector remains limited to the operating-system sources documented in the main README. Router, managed-switch, firewall-appliance, and hub integrations are not automatically discovered or configured. Proprietary vendor formats may require dedicated parsers and sample logs for validation.
