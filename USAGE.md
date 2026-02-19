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
- Raise `--confidence-threshold` if duplicates are too high.
- Keep `--outcomes-file` updated weekly for better KPI-driven tuning.
- Prioritize findings with higher submission score in `SUMMARY.md`.
- Review `CHAINS.md` first: chained issues usually provide larger payouts.

## 7) Troubleshooting

- If startup fails with `NameError: name 'requests' is not defined`, install Python dependencies (including `requests`) before running.
- If markdown export is empty, verify:
  - targets are alive/in-scope,
  - confidence threshold is not too high,
  - findings were produced in the JSON report.
