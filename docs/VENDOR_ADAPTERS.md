# Vendor-specific security adapters

The offline engine includes product-family-aware analysis adapters in addition to generic parsing and vendor fingerprint hints.

## Implemented adapter families

| Family | Structured fields / event signatures | Current detections |
|---|---|---|
| Fortinet FortiGate / FortiOS | CEF/LEEF/JSON key fields such as `type`, `subtype`, `action`, `srcip`, `dstip`, `dstport`, `policyid`, `logid` | Denied traffic, administrator login failures, configuration changes |
| MikroTik RouterOS | Syslog/message patterns including firewall/filter chains, RouterOS login messages, source/destination address fields | Firewall drops/rejects, login failures, unexpected reboot/power indicators |
| Cisco ASA / IOS | ASA `%ASA-...-106023`, IOS `%SEC-6-IPACCESSLOG`, configuration activity | ACL denials, ASA authentication failures, configuration changes |
| Microsoft Windows Defender | Defender Operational event IDs 1116, 1117, 5001, 5010, 5012, 5007 | Threat detection, remediation action, protection disabled, configuration changes |
| Linux Audit (auditd) | `USER_AUTH`, `USER_LOGIN`, `SYSCALL`, `EXECVE`, `CONFIG_CHANGE` and audit daemon health messages | Failed authentication, sensitive system operations, audit policy changes, degraded audit collection |

These are deterministic, explainable adapters. They do not load a neural model and do not send logs to a service. A family adapter only runs when a recognizable provider/source/signature or structured product field is present. A fingerprint by itself is not a security finding.

## Sample data and validation

The adapter tests use representative, sanitized log records based on documented field/event conventions. They are synthetic fixtures, not logs collected from customer networks or a claim that every firmware release has been validated. Real deployments should add sanitized samples from the exact device model, software version, and configured export format.

## Important coverage limits

- The adapter normalizes and analyzes common event families; it is not a complete parser for every vendor field, firmware, locale, or proprietary export.
- FortiGate and MikroTik exports differ by firmware and logging configuration. CEF/LEEF mappings and raw fields are preserved so additional mappings can be added safely.
- Cisco ASA and IOS message IDs and text differ across releases and feature sets.
- Defender event IDs depend on the enabled Windows Defender Operational channel and may be accompanied by XML EventData fields.
- Linux Audit records are multi-record events: SYSCALL, EXECVE, CWD, PATH, and PROCTITLE records sharing one audit serial should ideally be grouped by a future event assembler. The current adapter evaluates each normalized record and does not claim full serial-level reconstruction.
- Detection findings are triage signals, not proof of compromise. Confirm context and correlate adjacent events before taking action.
