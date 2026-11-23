# Log formats and native collection sources

The ingestion layer accepts line-oriented JSONL, Syslog (RFC 3164 and RFC 5424), CEF, LEEF, recognizable CSV, generic key/value text, and otherwise retains unrecognized lines as generic events. Raw fields are retained to support vendor-neutral analysis. This does not decode proprietary binary, encrypted, compressed-with-unknown-codec, or undocumented formats.

## Windows native collection

The Windows collector queries Security, System, Application, Microsoft Defender, Windows Firewall, PowerShell, Sysmon, WMI Activity, Task Scheduler, Terminal Services session/remote-connection, AppLocker, and Code Integrity event channels. Optional channels that are not installed or enabled are skipped; collection fails only when every configured channel is inaccessible or unavailable. Each channel query is capped at 5,000 newest records and has a 45-second timeout. Run elevated when the account lacks event-log permissions.

Useful additional sources that administrators may export/import include DNS Server, DHCP Server, IIS, Hyper-V, Failover Clustering, and third-party EDR/AV product logs. These are not queried automatically because they are optional roles/products and channel names vary by installation.

## Linux native collection

The Linux collector queries journald with a 20,000-record cap and a 45-second timeout. It also checks recent, readable files including auth/secure, syslog/messages, kernel, UFW, auditd, daemon, cron, mail, Fail2ban, boot, Nginx, Apache, and Lighttpd logs. File logs are included only when the file modification time falls within the requested lookback; each file is capped to its most recent 20,000 lines. Access may require root or membership in the appropriate journal/log-reading groups.

## Network devices and appliances

Routers, switches, firewalls, VPN gateways, wireless controllers, IDS/IPS, servers, hypervisors, containers, cloud audit exports, and IoT/industrial gateways can forward Syslog/CEF/LEEF over UDP or TCP to the listener. TCP supports newline-delimited messages and RFC 6587 octet-counted framing. Restrict listener exposure with host firewall rules and the sender IP/CIDR allowlist. Use a dedicated management/VLAN network where possible.

## Coverage limits

Generic ingestion and generic security rules allow useful analysis of unknown vendors when their events contain readable text or common structured fields. Vendor fingerprinting and adapters are heuristic and do not imply full support for every product/version. Proprietary binary protocols, encrypted payloads, undocumented fields, and disabled/missing audit sources require product-specific documentation or representative samples. No findings does not prove a system is safe.
