"""Markdown reporting utilities for AutoBB findings."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
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

    SEVERITY_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2, "INFO": 0.05}

    NICHE_ENDPOINT_HINTS = {
        "authenticated_webapps": ["/login", "/auth", "/session", "/account", "/admin"],
        "graphql_api_auth": ["/graphql", "/api", "/graphiql", "/v1", "/oauth"],
        "cloud_exposure_chain": ["/metadata", "/internal", "/debug", "/aws", "/gcp"],
        "js_heavy_spa": ["/api", "/graphql", "/socket", "/manifest", "/assets"],
    }

    VULN_ALIASES = {
        "idor": {"idor", "insecure direct object reference", "broken access control"},
        "directory listing": {"directory listing", "open directory"},
        "cors misconfiguration": {"cors misconfiguration", "weak cors", "cors"},
        "jwt weak algorithm": {"jwt weak algorithm", "jwt none algorithm", "jwt"},
        "server-side request forgery (ssrf)": {"ssrf", "server-side request forgery (ssrf)", "server side request forgery"},
        "cloud metadata exposure": {"cloud metadata exposure", "metadata exposure", "aws metadata exposure"},
        "subdomain takeover": {"subdomain takeover", "dangling dns"},
        "sensitive data exposure": {"sensitive data exposure", "information disclosure", "data exposure"},
    }

    def __init__(self, confidence_threshold: float | None = None, niche: str = "graphql_api_auth"):
        self.confidence_threshold = confidence_threshold or self.DEFAULT_CONFIDENCE_THRESHOLD
        self.niche = niche if niche in self.NICHE_ENDPOINT_HINTS else "graphql_api_auth"

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

    def export_domain_reports(
        self,
        domain: str,
        findings: List,
        reports_root: str = "reports",
        outcomes_file: str | None = None,
    ) -> Dict[str, int]:
        domain_dir = Path(reports_root) / self._safe_dir(domain)
        domain_dir.mkdir(parents=True, exist_ok=True)

        profile = ProgramProfileStore(reports_root=reports_root)
        if outcomes_file:
            profile.ingest_outcomes(outcomes_file, domain)

        report_items = self.group_findings(findings)
        chain_items = self.detect_exploit_chains(report_items)
        primary_queue: List[ReportItem] = []
        manual_validation: List[ReportItem] = []

        for item in report_items:
            in_scope = self.is_in_scope(domain, item.representative.subdomain)
            if item.confidence >= self.confidence_threshold and in_scope:
                primary_queue.append(item)
            else:
                manual_validation.append(item)

            (domain_dir / f"{item.finding_id}.md").write_text(self.render_finding_report(item, domain), encoding="utf-8")
            (domain_dir / f"{item.finding_id}.hackerone.txt").write_text(
                self.render_platform_submission(item, domain, platform="hackerone"),
                encoding="utf-8",
            )
            (domain_dir / f"{item.finding_id}.bugcrowd.txt").write_text(
                self.render_platform_submission(item, domain, platform="bugcrowd"),
                encoding="utf-8",
            )

        if chain_items:
            (domain_dir / "CHAINS.md").write_text(self.render_chain_report(chain_items), encoding="utf-8")

        primary_queue = sorted(primary_queue, key=lambda item: self.submission_score(item, domain), reverse=True)
        kpis = profile.record_scan(domain, report_items, primary_queue)
        tune = profile.profile_for(domain, self.niche)

        (domain_dir / "SUMMARY.md").write_text(
            self.render_summary(domain, primary_queue, manual_validation, chain_items, kpis, tune),
            encoding="utf-8",
        )

        return {
            "total": len(report_items),
            "primary": len(primary_queue),
            "manual_validation": len(manual_validation),
            "chains": len(chain_items),
            "niche": self.niche,
        }

    def render_finding_report(self, item: ReportItem, domain: str) -> str:
        finding = item.representative
        proof_assets = sorted({f"{f.subdomain}{f.endpoint}" for f in item.grouped_findings})
        references = finding.references or []

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
            f"- **Submission score:** `{self.submission_score(item, domain):.1f}`",
            "",
            "## Affected asset + in-scope proof",
            f"- Root target: `{domain}`",
            f"- Affected host: `{finding.subdomain}`",
            f"- In-scope check: `{'PASS' if self.is_in_scope(domain, finding.subdomain) else 'REVIEW'}`",
            "- Observed affected endpoints:",
            *[f"  - `{asset}`" for asset in proof_assets],
            "",
            "## Step-by-step reproduction",
            f"1. Target asset: `{finding.subdomain}` (in scope for `{domain}`).",
            f"2. Browse to endpoint: `{finding.endpoint}`.",
            f"3. Set parameter `{finding.param}` to payload: `{finding.payload}`.",
            "4. Send the request and observe the response evidence below.",
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

    def render_summary(
        self,
        domain: str,
        primary_queue: List[ReportItem],
        manual_validation: List[ReportItem],
        chain_items: List[Dict],
        kpis: Dict,
        tune: Dict,
    ) -> str:
        lines = [
            f"# AutoBB Summary Report - {domain}",
            "",
            f"- Niche profile: `{self.niche}`",
            f"- Confidence threshold for primary queue: `{self.confidence_threshold:.2f}`",
            f"- Primary submission candidates: `{len(primary_queue)}`",
            f"- Needs manual validation: `{len(manual_validation)}`",
            f"- Exploit chains detected: `{len(chain_items)}`",
            "",
            "## Program profile memory (rolling 7 days)",
            f"- Findings generated: `{kpis['findings_generated']}`",
            f"- Submitted: `{kpis['submitted']}`",
            f"- Accepted: `{kpis['accepted']}`",
            f"- Duplicate/Informative: `{kpis['duplicate_or_informative']}`",
            f"- Acceptance rate: `{kpis['acceptance_rate']:.1f}%`",
            f"- Duplicate rate: `{kpis['duplicate_rate']:.1f}%`",
            f"- Avg payout: `${kpis['avg_payout']:.2f}`",
            f"- Time scan→submission: `{kpis['avg_minutes_scan_to_submission']:.1f}` minutes",
            "",
            "## Program tuning hints",
            f"- Prioritize checks: `{', '.join(tune['priority_checks']) or 'none'}`",
            f"- Lower-priority checks: `{', '.join(tune['deprioritized_checks']) or 'none'}`",
            "",
            "## Primary submission queue",
        ]
        lines.extend(self._summary_rows(primary_queue, domain)) if primary_queue else lines.append("- No findings met confidence + scope checks.")

        lines.extend(["", "## Needs manual validation"])
        lines.extend(self._summary_rows(manual_validation, domain)) if manual_validation else lines.append("- No low-confidence or out-of-scope findings.")

        lines.extend(["", "## Exploit chains"])
        if chain_items:
            for chain in chain_items:
                lines.append(f"- `{chain['name']}` — {chain['severity']} — score `{chain['score']}` — {', '.join(chain['finding_ids'])}")
        else:
            lines.append("- No high-confidence exploit chains detected.")

        lines.append("")
        return "\n".join(lines)

    def detect_exploit_chains(self, items: List[ReportItem]) -> List[Dict]:
        by_type = {}
        for item in items:
            normalized = item.representative.vuln_type.lower().strip()
            by_type[normalized] = item

        chains = []
        patterns = [
            ("Subdomain takeover + session leakage", ["subdomain takeover", "sensitive data exposure"], "CRITICAL", 95),
            ("IDOR + sensitive endpoint enumeration", ["idor", "directory listing"], "HIGH", 82),
            ("Weak CORS + token exposure", ["cors misconfiguration", "jwt weak algorithm"], "HIGH", 80),
            ("SSRF + cloud metadata credential access", ["server-side request forgery (ssrf)", "cloud metadata exposure"], "CRITICAL", 96),
        ]

        for name, needed, severity, score in patterns:
            matched = []
            for required in needed:
                aliases = self.VULN_ALIASES.get(required, {required})
                hit = next((item for vuln, item in by_type.items() if vuln in aliases or any(a in vuln for a in aliases)), None)
                if hit:
                    matched.append(hit.finding_id)
            if len(set(matched)) >= 2:
                chains.append({"name": name, "severity": severity, "score": score, "finding_ids": sorted(set(matched))})

        return chains

    def render_chain_report(self, chains: List[Dict]) -> str:
        lines = ["# Exploit Chain Opportunities", ""]
        for chain in chains:
            lines.extend([
                f"## {chain['name']}",
                f"- Severity: `{chain['severity']}`",
                f"- Chain score: `{chain['score']}`",
                f"- Linked findings: `{', '.join(chain['finding_ids'])}`",
                "",
            ])
        return "\n".join(lines)

    def render_platform_submission(self, item: ReportItem, domain: str, platform: str = "hackerone") -> str:
        finding = item.representative
        intro = "HackerOne" if platform == "hackerone" else "Bugcrowd"
        return "\n".join([
            f"[{intro}] {item.title}",
            "",
            f"Asset: {finding.subdomain}{finding.endpoint}",
            f"Severity: {finding.severity.label}",
            f"Confidence: {item.confidence:.2f}",
            f"Submission score: {self.submission_score(item, domain):.1f}",
            "",
            "Reproduction:",
            f"1) Visit {finding.endpoint}",
            f"2) Set {finding.param}={finding.payload}",
            "3) Observe the response evidence below.",
            "",
            "Request:",
            finding.request or "N/A",
            "",
            "Response:",
            finding.response or finding.evidence or "N/A",
            "",
            "Impact:",
            self.IMPACT_BY_SEVERITY.get(finding.severity.label, finding.description),
            "",
            "Business risk framing:",
            f"Issue affects in-scope asset for {domain} and can enable account/data compromise in {self.niche} attack paths.",
        ])

    def submission_score(self, item: ReportItem, domain: str) -> float:
        finding = item.representative
        sev = self.SEVERITY_WEIGHT.get(finding.severity.label, 0.1)
        evidence_score = 1.0 if finding.request and (finding.response or finding.evidence) else 0.6
        scope_score = 1.0 if self.is_in_scope(domain, finding.subdomain) else 0.3
        niche_bonus = 1.15 if self.matches_niche(finding.endpoint) else 0.9
        return min(100.0, 100 * sev * item.confidence * evidence_score * scope_score * niche_bonus)

    def is_in_scope(self, domain: str, subdomain: str) -> bool:
        host = (subdomain or "").lower().strip()
        root = (domain or "").lower().strip()
        return bool(host) and (host == root or host.endswith(f".{root}"))

    def matches_niche(self, endpoint: str) -> bool:
        endpoint = (endpoint or "").lower()
        return any(hint in endpoint for hint in self.NICHE_ENDPOINT_HINTS.get(self.niche, []))

    def _summary_rows(self, items: List[ReportItem], domain: str) -> List[str]:
        rows = []
        for item in items:
            finding = item.representative
            rows.append(
                f"- [{item.finding_id}]({item.finding_id}.md) — {finding.severity.label} — "
                f"{finding.vuln_type} on `{finding.subdomain}{finding.endpoint}` "
                f"(confidence `{item.confidence:.2f}`, score `{self.submission_score(item, domain):.1f}`)"
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


class ProgramProfileStore:
    """Persist weekly KPI and per-program tuning memory in report artifacts."""

    def __init__(self, reports_root: str = "reports"):
        self.store_path = Path(reports_root) / "program_profiles.json"
        if self.store_path.exists():
            self.data = json.loads(self.store_path.read_text(encoding="utf-8"))
        else:
            self.data = {}

    def _save(self):
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.store_path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")

    def ingest_outcomes(self, outcomes_file: str, domain: str):
        path = Path(outcomes_file)
        if not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return
        if not isinstance(payload, list):
            return

        profile = self.data.setdefault(domain, {"history": [], "signals": {}, "outcomes": []})
        seen = {json.dumps(o, sort_keys=True) for o in profile.get("outcomes", [])}
        for outcome in payload:
            if isinstance(outcome, dict):
                key = json.dumps(outcome, sort_keys=True)
                if key not in seen:
                    profile["outcomes"].append(outcome)
                    seen.add(key)
        profile["outcomes"] = profile["outcomes"][-200:]
        self._save()

    def record_scan(self, domain: str, items: List[ReportItem], primary_queue: List[ReportItem]) -> Dict:
        profile = self.data.setdefault(domain, {"history": [], "signals": {}, "outcomes": []})
        profile["history"].append(
            {
                "scan_time": datetime.utcnow().isoformat(),
                "findings_generated": len(items),
                "submitted": len(primary_queue),
                "top_submission_scores": [round(float(item.confidence), 2) for item in primary_queue[:10]],
            }
        )
        profile["history"] = profile["history"][-20:]
        self._save()
        return self.kpis(domain)

    def kpis(self, domain: str) -> Dict:
        profile = self.data.get(domain, {})
        history = profile.get("history", [])[-7:]
        outcomes = profile.get("outcomes", [])[-100:]
        submitted = sum(i.get("submitted", 0) for i in history)
        accepted = sum(1 for o in outcomes if o.get("disposition") == "accepted")
        dup_or_info = sum(1 for o in outcomes if o.get("disposition") in {"duplicate", "informative"})
        payout_values = [float(o.get("payout", 0)) for o in outcomes if o.get("disposition") == "accepted"]
        submission_minutes = [
            float(o.get("minutes_scan_to_submission", 0))
            for o in outcomes
            if o.get("minutes_scan_to_submission") is not None
        ]

        return {
            "findings_generated": sum(i.get("findings_generated", 0) for i in history),
            "submitted": submitted,
            "accepted": accepted,
            "duplicate_or_informative": dup_or_info,
            "acceptance_rate": (100.0 * accepted / submitted) if submitted else 0.0,
            "duplicate_rate": (100.0 * dup_or_info / submitted) if submitted else 0.0,
            "avg_payout": (sum(payout_values) / len(payout_values)) if payout_values else 0.0,
            "avg_minutes_scan_to_submission": (sum(submission_minutes) / len(submission_minutes)) if submission_minutes else 0.0,
        }

    def profile_for(self, domain: str, niche: str) -> Dict:
        hints = {
            "authenticated_webapps": (["idor", "csrf", "auth-bypass", "session-tests"], ["banner-grab"]),
            "graphql_api_auth": (["graphql", "idor", "jwt", "introspection-bypass"], ["directory-listing"]),
            "cloud_exposure_chain": (["ssrf", "cloud-metadata", "subdomain-takeover"], ["clickjacking"]),
            "js_heavy_spa": (["xss", "api-discovery", "cors", "token-storage"], ["ssl-cipher-only"]),
        }
        priority, deprioritized = hints.get(niche, ([], []))
        _ = self.data.setdefault(domain, {"history": [], "signals": {}, "outcomes": []})
        return {"priority_checks": priority, "deprioritized_checks": deprioritized}
