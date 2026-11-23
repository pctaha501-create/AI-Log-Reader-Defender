# Vendor-neutral ingestion and unknown-source handling

Automatic mode accepts JSONL, structured JSON documents (single objects, arrays, and common event/record/log wrappers), XML event documents, RFC 3164/5424 Syslog, CEF, LEEF, comma-separated CSV, tab-separated TSV, semicolon-separated tables, key/value text, and unstructured text.

Structured JSON and XML fields are flattened into searchable normalized aliases while the original record is retained in `raw_record` or the original line/document metadata. Common event identifiers, provider names, host names, timestamps, user names, IP addresses, severity, and message fields are normalized across differing field names and nested layouts. Unknown fields are preserved instead of discarded.

Automatic input is bounded to 64 MiB per input document; individual line scanners retain an 8 MiB line bound. Oversized inputs fail explicitly rather than being silently truncated. This is a local parser and does not fetch schemas or send data externally.

Unknown readable sources remain analyzable through generic security detections and preserved evidence. A proprietary binary, encrypted, compressed, or undocumented format still requires its decoder/specification or representative samples; no vendor-neutral parser can infer information that is not present in readable input. A recognized syntax does not imply complete semantic understanding of every vendor's event taxonomy.
