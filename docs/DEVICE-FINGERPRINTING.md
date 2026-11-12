# Vendor-neutral device identification

Device identification is enrichment, not a prerequisite for parsing. Structured manufacturer, product, model, and firmware fields take precedence. When they are absent, conservative signatures in host, provider, message, and raw payload may identify common device families. Unrecognized manufacturers and all original fields remain in the event's `Raw` map; the parser does not relabel an unknown product as a known brand.

The metadata keys added when known are `device_vendor`, `device_product`, `device_model`, `firmware_version`, and `device_type`. `device_identification` records whether metadata came from structured fields/signatures or remains unknown. This is heuristic fingerprinting, not machine-learning classification. Validate signatures against representative exports before relying on them operationally.

The parser remains standards-first: JSONL, Syslog RFC 3164/5424, CEF, and LEEF. New vendor-specific formats should be added as independent adapters while retaining unknown fields and raw payloads.
