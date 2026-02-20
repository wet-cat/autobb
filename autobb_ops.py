"""Operational helpers for scope policy, checkpoints, verification, triage, and API/webhooks."""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import threading
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


class ScopePolicy:
    def __init__(self, policy_file: Optional[str] = None):
        self.policy_file = policy_file
        self.policy = {
            "include_hosts": ["*"],
            "exclude_hosts": [],
            "include_cidrs": [],
            "exclude_cidrs": [],
            "allowed_paths": ["*"],
            "excluded_paths": [],
            "auth_boundary_paths": [],
        }
        if policy_file and Path(policy_file).exists():
            try:
                data = json.loads(Path(policy_file).read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self.policy.update({k: v for k, v in data.items() if k in self.policy and isinstance(v, list)})
            except Exception:
                pass

    def _match_any(self, value: str, patterns: List[str]) -> bool:
        return any(fnmatch.fnmatch(value, p) for p in (patterns or []))

    def host_allowed(self, host: str) -> bool:
        host = (host or "").lower().strip()
        if not host:
            return False
        includes = self.policy.get("include_hosts") or ["*"]
        if includes and not self._match_any(host, includes):
            return False
        if self._match_any(host, self.policy.get("exclude_hosts", [])):
            return False
        return True

    def ip_allowed(self, ip: str) -> bool:
        ip = (ip or "").strip()
        if not ip:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        include = self.policy.get("include_cidrs") or []
        exclude = self.policy.get("exclude_cidrs") or []
        if include:
            if not any(addr in ipaddress.ip_network(c, strict=False) for c in include):
                return False
        if any(addr in ipaddress.ip_network(c, strict=False) for c in exclude):
            return False
        return True

    def path_allowed(self, path: str) -> bool:
        path = (path or "/").strip() or "/"
        allowed = self.policy.get("allowed_paths") or ["*"]
        excluded = self.policy.get("excluded_paths") or []
        if allowed and not self._match_any(path, allowed):
            return False
        if self._match_any(path, excluded):
            return False
        return True

    def auth_boundary(self, path: str) -> bool:
        return self._match_any((path or "/").strip() or "/", self.policy.get("auth_boundary_paths", []))

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.policy)


class CheckpointStore:
    def __init__(self, path: str = "autobb_checkpoint.json"):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.data: Dict[str, Any] = {"domains": {}}
        if self.path.exists():
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(payload, dict):
                    self.data = payload
            except Exception:
                pass

    def _domain(self, domain: str) -> Dict[str, Any]:
        domains = self.data.setdefault("domains", {})
        return domains.setdefault(domain, {"hosts": {}, "updated": time.time()})

    def seen_host(self, domain: str, host: str) -> bool:
        return host in self._domain(domain).get("hosts", {})

    def seen_endpoint(self, domain: str, host: str, endpoint: str) -> bool:
        return endpoint in self._domain(domain).get("hosts", {}).get(host, {}).get("endpoints", [])

    def mark_endpoint(self, domain: str, host: str, endpoint: str):
        with self._lock:
            d = self._domain(domain)
            h = d.setdefault("hosts", {}).setdefault(host, {"endpoints": []})
            if endpoint not in h["endpoints"]:
                h["endpoints"].append(endpoint)
            d["updated"] = time.time()
            self.save()

    def save(self):
        with self._lock:
            self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")


class VerificationWorkflow:
    def __init__(self, http_engine):
        self.http = http_engine

    def verify_finding(self, finding) -> Dict[str, Any]:
        req = getattr(finding, "request", "") or ""
        endpoint = getattr(finding, "endpoint", "") or ""
        param = (getattr(finding, "param", "") or "").strip()
        payload = (getattr(finding, "payload", "") or "").strip()
        evidence = (getattr(finding, "evidence", "") or "").lower()
        if not req and not endpoint:
            return {"verified": False, "reason": "no_request_context", "checks": []}

        host = getattr(finding, "subdomain", "") or ""
        scheme = "https" if ":443" in host or host.startswith("https") else "http"
        base = host if host.startswith("http") else f"{scheme}://{host}"

        parsed = urlparse(endpoint if endpoint.startswith("http") else base + endpoint)
        url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"

        checks = []
        status_codes = []
        reflected = 0
        stable = 0
        for i in range(3):
            try:
                baseline = self.http.get(url)
                variant = self.http.get(url, params={param: payload} if param and payload else None)
                b_ok = bool(baseline and getattr(baseline, "status_code", 0) < 500)
                v_ok = bool(variant and getattr(variant, "status_code", 0) < 500)
                checks.append({"attempt": i + 1, "baseline_ok": b_ok, "variant_ok": v_ok})
                if b_ok and v_ok:
                    stable += 1
                    status_codes.extend([baseline.status_code, variant.status_code])
                body = ((getattr(variant, "text", "") or "") + " " + (getattr(baseline, "text", "") or "")).lower()
                if payload and payload.lower() in body:
                    reflected += 1
                if evidence and evidence[:80] in body:
                    reflected += 1
            except Exception:
                checks.append({"attempt": i + 1, "baseline_ok": False, "variant_ok": False})
            time.sleep(0.2)

        status_consistent = len(set(status_codes)) <= 2 if status_codes else False
        ok = stable >= 2 and (reflected >= 1 or status_consistent)
        reason = "reproducible" if ok else "not_reproducible"
        return {"verified": ok, "reason": reason, "attempts": len(checks), "checks": checks, "signals": {"stable": stable, "reflected": reflected, "status_consistent": status_consistent}}


class EventStreamer:
    def __init__(self, webhook_url: Optional[str] = None, requests_mod=None):
        self.webhook_url = (webhook_url or "").strip() or None
        self.requests = requests_mod
        self.events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def emit(self, event: Dict[str, Any]):
        with self._lock:
            self.events.append(event)
            self.events = self.events[-1000:]
        if self.webhook_url and self.requests:
            try:
                self.requests.post(self.webhook_url, json=event, timeout=3)
            except Exception:
                pass


class LocalAPIServer:
    def __init__(self, engine, host: str = "127.0.0.1", port: int = 8787):
        self.engine = engine
        self.host = host
        self.port = port
        self.httpd = None
        self.thread = None

    def start(self):
        engine = self.engine

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/health":
                    body = {"ok": True, "running": bool(engine._running)}
                elif self.path == "/stats":
                    body = engine.stats()
                elif self.path == "/findings":
                    body = {d: [f.to_dict() for f in t.findings] for d, t in engine.targets.items()}
                elif self.path == "/events":
                    body = {"events": getattr(engine, "event_stream", None).events if getattr(engine, "event_stream", None) else []}
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                payload = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format, *args):
                return

        self.httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
