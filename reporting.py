"""Markdown reporting utilities for AutoBB findings."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse


@dataclass
class ReportItem:
    """Grouped finding prepared for markdown rendering."""

    finding_id: str
    title: str
    fingerprint: str
    confidence: float
    grouped_findings: List

    @property
    def representative(self):
        return self.grouped_findings[0]


class ReportGenerator:
    """Create deduplicated markdown reports and summary indexes."""

    DEFAULT_CONFIDENCE_THRESHOLD = 0.70

    TITLE_TEMPLATES = {
        "CRITICAL": "[CRITICAL] {vuln_type} on {asset}",
        "HIGH": "[HIGH] {vuln_type} detected on {asset}",
        "MEDIUM": "[MEDIUM] Potential {vuln_type} on {asset}",
        "LOW": "[LOW] Possible {vuln_type} on {asset}",
        "INFO": "[INFO] {vuln_type} observation on {asset}",
    }

    IMPACT_BY_SEVERITY = {
        "CRITICAL": "Successful exploitation can result in severe compromise, including complete application or data takeover.",
        "HIGH": "Successful exploitation could lead to significant unauthorized access, data exposure, or account compromise.",
        "MEDIUM": "Successful exploitation could affect confidentiality or integrity and should be addressed with priority.",
        "LOW": "Impact appears limited but still weakens security posture and may support chained attacks.",
        "INFO": "No direct security impact is confirmed, but the issue provides useful attacker insight.",
    }

    def __init__(self, confidence_threshold: float | None = None):
        self.confidence_threshold = confidence_threshold or self.DEFAULT_CONFIDENCE_THRESHOLD

    def build_fingerprint(self, finding) -> str:
        endpoint = self._normalize_endpoint(finding.endpoint)
        payload_signature = hashlib.sha1(self._normalize_payload(finding.payload).encode()).hexdigest()[:12]
        raw = f"{finding.vuln_type}|{endpoint}|{finding.param.strip().lower()}|{payload_signature}"
        return hashlib.sha1(raw.encode()).hexdigest()

    def group_findings(self, findings: List) -> List[ReportItem]:
        grouped: Dict[str, List] = {}
        for finding in findings:
            fingerprint = self.build_fingerprint(finding)
            grouped.setdefault(fingerprint, []).append(finding)

        items: List[ReportItem] = []
        for fingerprint, grouped_findings in grouped.items():
            grouped_findings.sort(key=lambda f: (f.severity.rank, -f.confidence))
            primary = grouped_findings[0]
            fid = f"{primary.vuln_type.lower().replace(' ', '_')}-{fingerprint[:10]}"
            items.append(
                ReportItem(
                    finding_id=fid,
                    title=self._render_title(primary),
                    fingerprint=fingerprint,
                    confidence=max(f.confidence for f in grouped_findings),
                    grouped_findings=grouped_findings,
                )
            )

        return sorted(items, key=lambda item: (item.representative.severity.rank, -item.confidence))

    def export_domain_reports(self, domain: str, findings: List, reports_root: str = "reports") -> Dict[str, int]:
        domain_dir = Path(reports_root) / self._safe_dir(domain)
        domain_dir.mkdir(parents=True, exist_ok=True)

        report_items = self.group_findings(findings)
        primary_queue: List[ReportItem] = []
        manual_validation: List[ReportItem] = []

        for item in report_items:
            if item.confidence >= self.confidence_threshold:
                primary_queue.append(item)
            else:
                manual_validation.append(item)

            (domain_dir / f"{item.finding_id}.md").write_text(self.render_finding_report(item, domain), encoding="utf-8")

        (domain_dir / "SUMMARY.md").write_text(
            self.render_summary(domain, primary_queue, manual_validation),
            encoding="utf-8",
        )

        return {
            "total": len(report_items),
            "primary": len(primary_queue),
            "manual_validation": len(manual_validation),
        }

    def render_finding_report(self, item: ReportItem, domain: str) -> str:
        finding = item.representative
        proof_assets = sorted({f"{f.subdomain}{f.endpoint}" for f in item.grouped_findings})
        references = finding.references or []

        steps = [
            f"1. Target asset: `{finding.subdomain}` (in scope for `{domain}`).",
            f"2. Browse to endpoint: `{finding.endpoint}`.",
            f"3. Set parameter `{finding.param}` to payload: `{finding.payload}`.",
            "4. Send the request and observe the response evidence below.",
        ]

        lines = [
            f"# {item.title}",
            "",
            "## Metadata",
            f"- **Finding ID:** `{item.finding_id}`",
            f"- **Vulnerability type:** `{finding.vuln_type}`",
            f"- **Severity:** `{finding.severity.label}`",
            f"- **Confidence:** `{item.confidence:.2f}`",
            f"- **CWE:** `{finding.cwe}`",
            f"- **Fingerprint:** `{item.fingerprint}`",
            "",
            "## Affected asset + in-scope proof",
            f"- Root target: `{domain}`",
            f"- Affected host: `{finding.subdomain}`",
            "- Observed affected endpoints:",
            *[f"  - `{asset}`" for asset in proof_assets],
            "",
            "## Step-by-step reproduction",
            *steps,
            "",
            "## Request / response evidence",
            "### Request",
            "```http",
            finding.request or "N/A",
            "```",
            "",
            "### Response",
            "```http",
            finding.response or finding.evidence or "N/A",
            "```",
            "",
            "## Security impact",
            self.IMPACT_BY_SEVERITY.get(finding.severity.label, finding.description),
            "",
            "## Remediation",
            finding.remediation or "Apply input validation, output encoding, and least-privilege controls for this attack surface.",
            "",
            "## CWE and references",
            f"- CWE: `{finding.cwe}`",
            *[f"- {ref}" for ref in references],
            "",
        ]
        return "\n".join(lines)

    def render_summary(self, domain: str, primary_queue: List[ReportItem], manual_validation: List[ReportItem]) -> str:
        lines = [
            f"# AutoBB Summary Report - {domain}",
            "",
            f"- Confidence threshold for primary queue: `{self.confidence_threshold:.2f}`",
            f"- Primary submission candidates: `{len(primary_queue)}`",
            f"- Needs manual validation: `{len(manual_validation)}`",
            "",
            "## Primary submission queue",
        ]
        if primary_queue:
            lines.extend(self._summary_rows(primary_queue))
        else:
            lines.append("- No findings met the confidence threshold.")

        lines.extend(["", "## Needs manual validation"])
        if manual_validation:
            lines.extend(self._summary_rows(manual_validation))
        else:
            lines.append("- No low-confidence findings.")

        lines.append("")
        return "\n".join(lines)

    def _summary_rows(self, items: List[ReportItem]) -> List[str]:
        rows = []
        for item in items:
            finding = item.representative
            rows.append(
                f"- [{item.finding_id}]({item.finding_id}.md) — {finding.severity.label} — "
                f"{finding.vuln_type} on `{finding.subdomain}{finding.endpoint}` (confidence `{item.confidence:.2f}`)"
            )
        return rows

    def _render_title(self, finding) -> str:
        template = self.TITLE_TEMPLATES.get(finding.severity.label, "{vuln_type} on {asset}")
        return template.format(vuln_type=finding.vuln_type, asset=finding.subdomain)

    def _normalize_endpoint(self, endpoint: str) -> str:
        endpoint = (endpoint or "").strip()
        if not endpoint:
            return "/"
        parsed = urlparse(endpoint)
        if parsed.scheme or parsed.netloc:
            path = parsed.path or "/"
        else:
            path = endpoint.split("?", 1)[0]
        path = re.sub(r"/+", "/", path)
        return path.rstrip("/").lower() or "/"

    def _normalize_payload(self, payload: str) -> str:
        return re.sub(r"\s+", " ", (payload or "").strip().lower())

    def _safe_dir(self, value: str) -> str:
        return re.sub(r"[^a-zA-Z0-9._-]", "_", value)

