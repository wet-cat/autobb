# AutoBB Usage Instructions

This document explains how to run AutoBB in both interactive and headless modes, and how to generate profit-focused markdown submission artifacts.

## 1) Prerequisites

- Python 3.10+
- Dependencies used by scanner modules (notably `requests`)
- Network connectivity to your authorized targets

> ⚠️ Only scan targets you own or have explicit written authorization to test.

## 2) Basic execution modes

AutoBB's entrypoint is `autobb_tui.py`.

### Interactive TUI mode

```bash
python autobb_tui.py
```

### Headless mode (CI/script friendly)

```bash
python autobb_tui.py --no-tui -t example.com
```

## 3) Core CLI options

| Option | Description |
|---|---|
| `-t, --targets DOMAIN [DOMAIN ...]` | Target domains to queue immediately |
| `--threads N` | Worker thread count (default: `25`) |
| `--timeout SECONDS` | HTTP timeout in seconds (default: `10`) |
| `--proxy URL` | Upstream HTTP proxy (e.g., `http://127.0.0.1:8080`) |
| `--no-tui` | Run headlessly and print terminal logs |
| `--export-md` | Export submission-oriented markdown artifacts under `reports/<domain>/` |
| `--confidence-threshold FLOAT` | Min confidence for primary submission queue (default: `0.70`) |
| `--niche ...` | Niche profile used for prioritization and reporting |
| `--outcomes-file JSON` | Optional historical outcomes file to tune KPI reporting |
| `--scan-mode {balanced,crazy,profit}` | Scan intensity profile (`balanced` default). Use `crazy` for max coverage, `profit` for high-signal triage |
| `--health-check` | Run a dependency/environment preflight and exit |
| `--health-check-json PATH` | Save preflight output as JSON |
| `--summary-json PATH` | Save machine-readable run summary JSON |
| `--fail-on-severity {critical,high,medium,low,info}` | Exit `2` if any finding at/above threshold exists |
| `--fail-on-findings N` | Exit `2` when total findings are `>= N` |
| `--auth-boundary-mode {block,report,allow}` | Enforce auth-boundary path handling from scope policy (`block` default) |

### Supported `--niche` values

- `authenticated_webapps`
- `graphql_api_auth` (default)
- `cloud_exposure_chain`
- `js_heavy_spa`

## 4) High-value report generation flow

Use these options together for best “accepted report rate” workflow:

```bash
python autobb_tui.py \
  --no-tui \
  -t target.com api.target.com \
  --scan-mode profit \
  --export-md \
  --confidence-threshold 0.75 \
  --niche graphql_api_auth \
  --outcomes-file outcomes.json
```

What this produces:

- `autobb_report_<timestamp>.json` (raw scan output)
- `reports/<domain>/SUMMARY.md`
- `reports/<domain>/<finding_id>.md`
- `reports/<domain>/<finding_id>.hackerone.txt`
- `reports/<domain>/<finding_id>.bugcrowd.txt`
- `reports/<domain>/CHAINS.md` (when exploit chains are detected)
- `reports/program_profiles.json` (rolling KPI memory)

## 5) Outcomes file format (`--outcomes-file`)

Provide a JSON array of report outcome objects, for example:

```json
[
  {
    "disposition": "accepted",
    "payout": 1200,
    "minutes_scan_to_submission": 18
  },
  {
    "disposition": "duplicate",
    "payout": 0,
    "minutes_scan_to_submission": 35
  },
  {
    "disposition": "informative",
    "payout": 0,
    "minutes_scan_to_submission": 22
  }
]
```

Recognized KPI fields:

- `disposition`: expected values include `accepted`, `duplicate`, `informative`
- `payout`: numeric payout for accepted reports
- `minutes_scan_to_submission`: numeric latency metric

## 6) Practical profit tuning tips

- Pick **one niche** per campaign (`--niche`) to avoid diluted signal.
- Use `--scan-mode profit` when optimizing for acceptance rate; use `--scan-mode crazy` only for wide recon sweeps.
- Raise `--confidence-threshold` if duplicates are too high.
- Keep `--outcomes-file` updated weekly for better KPI-driven tuning.
- Prioritize findings with higher submission score in `SUMMARY.md`.
- Review `CHAINS.md` first: chained issues usually provide larger payouts.

## 7) Troubleshooting

- If startup fails due to missing dependencies, install Python requirements (notably `requests`) before running.
- If markdown export is empty, verify:
  - targets are alive/in-scope,
  - confidence threshold is not too high,
  - findings were produced in the JSON report.

## 8) Preflight health checks

Run this before long scans to validate first-class dependencies and assumptions:

```bash
python autobb_tui.py --health-check -t example.com
```

Optional JSON output:

```bash
python autobb_tui.py --health-check --health-check-json health.json
```

Checks include:

- Python runtime
- `requests` and optional `beautifulsoup4`
- `nuclei` binary/version
- nuclei template directory discovery
- DNS resolution sanity check for supplied targets

## 9) Headless pipeline ergonomics

For CI/automation, emit a summary artifact and enforce failure gates:

```bash
python autobb_tui.py \
  --no-tui \
  -t target.com \
  --summary-json run-summary.json \
  --fail-on-severity high
```

Behavior:

- exit code `0`: scan completed and thresholds not tripped
- exit code `2`: configured quality gate tripped (`--fail-on-severity` / `--fail-on-findings`)

## 10) Resume + incremental scanning

```bash
python autobb_tui.py --no-tui -t target.com --resume --incremental --checkpoint-file scan.ckpt.json
```

- `--resume`: enables checkpoint loading/saving.
- `--incremental`: skips previously processed endpoint deltas.

## 11) Scope policy guardrails

Use a scope policy file to centrally enforce in-scope hosts, CIDRs, and paths before probing.

Example `scope-policy.json`:

```json
{
  "include_hosts": ["*.target.com"],
  "exclude_hosts": ["admin.internal.target.com"],
  "include_cidrs": [],
  "exclude_cidrs": ["10.0.0.0/8"],
  "allowed_paths": ["/api/*", "/graphql*", "/*"],
  "excluded_paths": ["/logout*", "/admin/delete*"],
  "auth_boundary_paths": ["/admin*", "/billing*"]
}
```

Run:

```bash
python autobb_tui.py --no-tui -t target.com --scope-policy scope-policy.json --auth-boundary-mode block
```

`auth_boundary_paths` are now actively enforced before endpoint probing/checker execution.

## 12) Verification workflow + reproducibility bundles

```bash
python autobb_tui.py --no-tui -t target.com --export-md --verify-before-export --generate-repro-bundles
```

- Verification performs multi-attempt baseline + variant replay checks and upgrades triage state to `ready-to-submit` only when reproducible signals are stable.
- Repro bundles are exported under `reports/<domain>/repro_bundles/<finding_id>/`.

## 13) Collaboration triage + API/webhook integrations

- Findings now carry lifecycle metadata (`triage_state`, `assignee`, `comments`, `history`) in JSON exports.
- Generic event streaming webhook:

```bash
python autobb_tui.py --no-tui -t target.com --event-webhook https://example.com/autobb-events
```

- Local API:

```bash
python autobb_tui.py --no-tui -t target.com --api-port 8787
```

Endpoints:
- `GET /health`
- `GET /stats`
- `GET /findings`
- `GET /events`
