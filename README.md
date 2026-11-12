# AI Log Reader & Defender

Local-first security log analysis for **Windows and Ubuntu/Linux**.

**Current milestone: M0.1.** This repository contains a portable Go CLI/core with deterministic baseline detections. It is not yet a trained AI model or a production endpoint-protection product.

## GitHub-only build and test

You do not need Go, a compiler, or a local development environment to build this project.

GitHub Actions automatically runs the following on pushes to `main` and pull requests:

- `go test ./...`
- `go vet ./...`
- Native Windows x64 and Ubuntu/Linux x64 builds
- Uploads both binaries as downloadable workflow artifacts

To run it manually, open the repository's **Actions** tab, choose **CI**, and select **Run workflow**. When the run finishes, open it and download the Windows or Linux artifact from **Artifacts**.

To publish versioned binaries, push a tag such as `v0.1.0`. The release workflow tests and builds both platforms and attaches the binaries to a GitHub Release. You can also run the release workflow manually to build downloadable artifacts; publishing a Release happens only for a `v*` tag.

## Local build (optional)

Requires Go 1.23 or newer:

```sh
go test ./...
go vet ./...
go build -o ald ./cmd/ald
```

Windows PowerShell:

```powershell
go build -o ald.exe ./cmd/ald
```

## Commands

```sh
ald version
ald analyze --input events.jsonl
ald analyze --input events.jsonl --json
ald collect --since 1h --out events.jsonl
```

Input is JSON Lines (one JSON object per line). Preferred fields include `timestamp`, `source`, `host`, `event_id`, `level`, `provider`, `message`, `user`, and `source_ip`. Unknown fields are preserved in the raw event map.

## Collection

- Windows: read-only Security event collection through `wevtutil.exe`. Permissions and available events depend on the host.
- Linux: read-only system journal collection through `journalctl`. Access depends on the current user's journal permissions.

Collection does not change system settings or take remediation actions.

## Architecture and safety

- Shared Go core for normalization, deterministic detections, and conservative batch correlation.
- Platform-specific collectors are isolated behind Go build tags.
- No Python, third-party Go modules, cloud calls, or model downloads are required for the current milestone.
- No public network listener, automatic process termination, quarantine, firewall changes, persistence, or other destructive response actions.
- A rule match is a triage signal, not proof of compromise.
- No claim of model training, LLM reasoning, exhaustive log coverage, or production readiness.

## Roadmap

1. Expand and validate Windows and Linux event collectors.
2. Add durable local storage, rotation, health checks, and a user interface.
3. Develop an anomaly/classification engine with labeled evaluation and measured precision, recall, and F1.
4. Optionally integrate a verified locally installed LLM without requiring cloud APIs.
5. Add explicit, auditable, reversible response workflows that always require user approval.

MIT License.
