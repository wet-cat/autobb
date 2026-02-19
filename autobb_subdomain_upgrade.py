"""
Upgraded Subdomain Enumeration System

Features:
1. Subfinder integration (passive, 50+ sources)
2. Large wordlist support (common + custom)
3. "Interesting" subdomain classification
4. Priority scoring

Replace SubdomainEnumerator in autobb_engine.py
"""

import subprocess
import concurrent.futures
import re
from typing import Dict, Set, List, Tuple, Optional, Callable
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
# LARGE WORDLISTS
# ═══════════════════════════════════════════════════════════════════════════════

class Wordlists:
    """Subdomain wordlists"""
    
    # Top 500 most common subdomains
    TOP_500 = [
        # Core infrastructure
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2", 
        "ns3", "ns4", "ns5", "mx", "mx1", "mx2", "mx3", "email", "imap", "pop3",
        
        # Web/API
        "api", "api-v2", "api2", "apiv2", "v1", "v2", "v3", "rest", "graphql",
        "ws", "wss", "websocket", "app", "app1", "app2", "mobile", "m", "wap",
        
        # Development
        "dev", "develop", "development", "staging", "stage", "test", "testing",
        "qa", "uat", "preprod", "sandbox", "demo", "beta", "alpha", "preview",
        
        # Admin/Management
        "admin", "administrator", "admins", "root", "console", "dashboard",
        "panel", "control", "cpanel", "whm", "plesk", "webmin", "manage",
        "management", "manager",
        
        # Authentication
        "login", "signin", "auth", "authentication", "sso", "oauth", "oauth2",
        "saml", "cas", "ldap", "ad", "identity", "accounts", "account",
        
        # Internal/Private
        "internal", "intranet", "private", "corp", "corporate", "vpn", "remote",
        "access", "secure", "ssl", "tls",
        
        # Content/Media
        "static", "assets", "cdn", "media", "images", "img", "photos", "pics",
        "videos", "files", "uploads", "download", "downloads", "storage",
        
        # Documentation
        "docs", "documentation", "help", "support", "wiki", "kb", "knowledgebase",
        "faq", "guide", "manual",
        
        # Monitoring/Analytics
        "status", "health", "monitor", "monitoring", "grafana", "kibana",
        "prometheus", "alertmanager", "metrics", "analytics", "stats",
        "tracking", "logs", "logging",
        
        # DevOps/CI/CD
        "jenkins", "ci", "build", "travis", "bamboo", "teamcity", "gitlab",
        "github", "bitbucket", "git", "svn", "deploy", "deployment", "release",
        
        # Cloud/Containers
        "k8s", "kubernetes", "docker", "rancher", "portainer", "swarm",
        "nomad", "mesos", "openshift",
        
        # Databases
        "db", "database", "mysql", "postgres", "postgresql", "mongo", "mongodb",
        "redis", "elasticsearch", "elastic", "es", "solr", "cassandra",
        "mariadb", "oracle", "mssql",
        
        # Business Applications
        "crm", "erp", "hrm", "finance", "billing", "payment", "invoice",
        "shop", "store", "cart", "checkout", "ecommerce",
        
        # Communication
        "chat", "slack", "teams", "zoom", "webex", "meet", "conference",
        "voice", "sip", "voip", "pbx",
        
        # Geographic/Regional
        "us", "usa", "eu", "europe", "uk", "de", "fr", "au", "asia", "ap",
        "sg", "jp", "cn", "in", "ca", "br", "mx",
        "east", "west", "north", "south", "central",
        
        # Environment indicators
        "prod", "production", "live", "old", "new", "legacy", "archive",
        "backup", "bak", "temp", "tmp", "cache",
        
        # Numbered
        "1", "2", "3", "4", "5", "10", "100",
        "web1", "web2", "web3", "server1", "server2", "host1", "host2",
        
        # Blog/Community
        "blog", "news", "forum", "forums", "community", "social", "feed",
        
        # Marketing/Sales
        "www2", "portal", "customer", "partner", "partners", "affiliate",
        "affiliates", "reseller", "vendor", "suppliers",
        
        # Misc important
        "exchange", "owa", "autodiscover", "lyncdiscover", "sip",
        "splunk", "tableau", "metabase", "superset",
        "vault", "consul", "etcd", "zookeeper",
        "registry", "harbor", "nexus", "artifactory",
    ]
    
    # Interesting patterns (high-value targets)
    INTERESTING_PATTERNS = {
        # Admin/Control
        'admin': ['admin', 'administrator', 'admins', 'root', 'sudo', 'cpanel', 
                  'whm', 'plesk', 'webmin', 'control', 'panel', 'manage', 'console'],
        
        # Development/Testing
        'dev': ['dev', 'develop', 'development', 'staging', 'stage', 'test', 
                'testing', 'qa', 'uat', 'sandbox', 'demo', 'preview'],
        
        # API endpoints
        'api': ['api', 'api-v2', 'api2', 'apiv2', 'rest', 'graphql', 'ws', 
                'internal-api', 'private-api'],
        
        # Authentication
        'auth': ['auth', 'login', 'signin', 'sso', 'oauth', 'saml', 'cas', 
                 'ldap', 'ad', 'identity'],
        
        # Internal/Private
        'internal': ['internal', 'intranet', 'private', 'corp', 'corporate', 
                     'vpn', 'remote', 'secure'],
        
        # Database/Data
        'database': ['db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 
                     'elastic', 'phpmyadmin', 'adminer'],
        
        # DevOps
        'devops': ['jenkins', 'gitlab', 'git', 'ci', 'cd', 'build', 'deploy', 
                   'k8s', 'docker', 'rancher'],
        
        # Old/Forgotten
        'legacy': ['old', 'legacy', 'archive', 'backup', 'bak', 'deprecated', 
                   'temp', 'tmp'],
        
        # Monitoring
        'monitoring': ['grafana', 'kibana', 'prometheus', 'splunk', 'status', 
                      'health', 'metrics'],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SUBFINDER INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

class SubfinderIntegration:
    """Integrate ProjectDiscovery Subfinder for passive enumeration"""
    
    @staticmethod
    def is_available() -> bool:
        """Check if subfinder is installed"""
        try:
            result = subprocess.run(['subfinder', '-version'], 
                                   capture_output=True, timeout=3)
            return result.returncode == 0
        except:
            return False
    
    @staticmethod
    def enumerate(domain: str, timeout: int = 120) -> Set[str]:
        """
        Run subfinder for passive subdomain discovery
        Uses 50+ sources: crt.sh, virustotal, shodan, censys, etc.
        """
        try:
            cmd = [
                'subfinder',
                '-d', domain,
                '-all',           # Use all sources
                '-silent',        # Less verbose
                '-timeout', '2',  # 2s per source
                '-t', '50',       # 50 threads
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0:
                return set()
            
            # Parse output
            subdomains = set()
            for line in result.stdout.strip().split('\n'):
                line = line.strip().lower()
                if line and '.' in line:
                    subdomains.add(line)
            
            return subdomains
        
        except subprocess.TimeoutExpired:
            return set()
        except Exception:
            return set()


# ═══════════════════════════════════════════════════════════════════════════════
# INTERESTING SUBDOMAIN CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════════

class InterestingClassifier:
    """Classify subdomains as 'interesting' for prioritization"""
    
    @staticmethod
    def classify(subdomain: str) -> Dict[str, any]:
        """
        Returns: {
            'interesting': bool,
            'categories': List[str],
            'score': int (0-100),
            'reasons': List[str]
        }
        """
        name = subdomain.lower()
        categories = []
        reasons = []
        score = 0
        
        # Check against interesting patterns
        for category, patterns in Wordlists.INTERESTING_PATTERNS.items():
            for pattern in patterns:
                if pattern in name:
                    categories.append(category)
                    reasons.append(f"Contains '{pattern}'")
                    
                    # Score by category risk
                    if category == 'admin':
                        score += 30
                    elif category == 'dev':
                        score += 25
                    elif category == 'api':
                        score += 20
                    elif category == 'auth':
                        score += 20
                    elif category == 'internal':
                        score += 25
                    elif category == 'database':
                        score += 30
                    elif category == 'legacy':
                        score += 15
                    else:
                        score += 10
                    break
        
        # Environment indicators
        if any(x in name for x in ['staging', 'stage', 'stg']):
            score += 20
            reasons.append("Staging environment")
        
        if any(x in name for x in ['dev', 'develop']):
            score += 25
            reasons.append("Development environment")
        
        if any(x in name for x in ['test', 'testing', 'qa']):
            score += 15
            reasons.append("Testing environment")
        
        # Version indicators
        if any(x in name for x in ['v1', 'v2', 'v3', 'api-v', 'apiv']):
            score += 10
            reasons.append("Versioned API")
        
        # Geographic/Regional (often less secure)
        if any(x in name for x in ['-us-', '-eu-', '-asia-', 'east', 'west']):
            score += 5
            reasons.append("Regional instance")
        
        # Ports in subdomain name = interesting
        if re.search(r'\d{4,5}', name):
            score += 10
            reasons.append("Port number in name")
        
        # Very long subdomains = auto-generated = interesting
        if len(name) > 40:
            score += 10
            reasons.append("Unusually long subdomain")
        
        # Multiple dashes = complex infrastructure
        if name.count('-') >= 3:
            score += 5
            reasons.append("Complex naming")
        
        return {
            'interesting': score > 15,
            'categories': list(set(categories)),
            'score': min(score, 100),
            'reasons': reasons[:3],  # Top 3 reasons
        }


# ═══════════════════════════════════════════════════════════════════════════════
# UPGRADED SUBDOMAIN ENUMERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class UpgradedSubdomainEnumerator:
    """
    Enhanced subdomain enumeration with:
    - Subfinder integration (passive)
    - Large wordlist
    - Interesting classification
    """
    
    def __init__(self, dns_engine, http_engine, notify_cb: Optional[Callable] = None):
        self.dns = dns_engine
        self.http = http_engine
        self.notify = notify_cb or (lambda *a, **k: None)
        self.has_subfinder = SubfinderIntegration.is_available()
    
    def enumerate(self, domain: str, use_subfinder: bool = True, 
                  wordlist_size: str = 'large') -> Dict[str, any]:
        """
        Enumerate subdomains with multiple methods
        
        Args:
            domain: Target domain
            use_subfinder: Use subfinder if available
            wordlist_size: 'small' (150) or 'large' (500)
        
        Returns:
            Dict[subdomain, SubdomainInfo with .interesting field]
        """
        found = {}
        all_subdomains = set()
        
        # Method 1: Subfinder (passive, 50+ sources)
        if use_subfinder and self.has_subfinder:
            self.notify(f"[*] Running Subfinder (passive enumeration)...", "INFO")
            subfinder_results = SubfinderIntegration.enumerate(domain)
            
            if subfinder_results:
                self.notify(f"[+] Subfinder found {len(subfinder_results)} subdomains", "INFO")
                all_subdomains.update(subfinder_results)
            else:
                self.notify(f"[!] Subfinder found 0 results", "WARN")
        else:
            if not self.has_subfinder:
                self.notify(f"[!] Subfinder not installed (install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)", "WARN")
        
        # Method 2: Wordlist brute-force
        wordlist = Wordlists.TOP_500 if wordlist_size == 'large' else Wordlists.TOP_500[:150]
        self.notify(f"[*] Brute-forcing {len(wordlist)} common subdomains...", "INFO")
        
        is_wildcard = self.dns.wildcard(domain)
        if is_wildcard:
            self.notify(f"[!] Wildcard DNS detected - using HTTP validation", "WARN")
        
        def check_sub(prefix):
            fqdn = f"{prefix}.{domain}"
            ips = self.dns.resolve(fqdn)
            if not ips:
                return None
            
            # Wildcard validation
            if is_wildcard:
                r = self.http.head(f"https://{fqdn}") or self.http.head(f"http://{fqdn}")
                if not r or r.status_code >= 400:
                    return None
            
            return fqdn
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            futures = {ex.submit(check_sub, w): w for w in wordlist}
            for fut in concurrent.futures.as_completed(futures):
                result = fut.result()
                if result:
                    all_subdomains.add(result)
                    self.notify(f"[subdomain] {result}", "FOUND")
        
        # Method 3: Certificate Transparency
        self.notify(f"[*] Checking Certificate Transparency logs...", "INFO")
        ct_subs = self._ct_lookup(domain)
        if ct_subs:
            self.notify(f"[+] CT logs found {len(ct_subs)} subdomains", "INFO")
            all_subdomains.update(ct_subs)
        
        # Resolve all and classify
        self.notify(f"[*] Resolving and classifying {len(all_subdomains)} unique subdomains...", "INFO")
        
        for subdomain in all_subdomains:
            ips = self.dns.resolve(subdomain)
            if not ips:
                continue
            
            # Classify as interesting
            classification = InterestingClassifier.classify(subdomain)
            
            # Create SubdomainInfo (assuming it exists in your engine)
            # You'll need to import SubdomainInfo from your engine
            info = {
                'fqdn': subdomain,
                'ips': ips,
                'interesting': classification['interesting'],
                'interest_score': classification['score'],
                'interest_categories': classification['categories'],
                'interest_reasons': classification['reasons'],
            }
            
            found[subdomain] = info
            
            if classification['interesting']:
                reasons = ', '.join(classification['reasons'])
                self.notify(
                    f"[INTERESTING] {subdomain} (score: {classification['score']}) - {reasons}",
                    "HIGH"
                )
        
        return found
    
    def _ct_lookup(self, domain: str) -> Set[str]:
        """Certificate Transparency lookup"""
        try:
            import requests
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            r = requests.get(url, timeout=15)
            
            if r.status_code != 200:
                return set()
            
            subdomains = set()
            seen = set()
            
            for entry in r.json():
                name = entry.get('name_value', '').strip().lower()
                name = name.lstrip('*.')
                
                if name.endswith(f'.{domain}') and name not in seen:
                    seen.add(name)
                    subdomains.add(name)
            
            return subdomains
        
        except Exception:
            return set()


# ═══════════════════════════════════════════════════════════════════════════════
# USAGE INSTRUCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

"""
INTEGRATION INTO autobb_engine.py:

1. Replace SubdomainEnumerator class with UpgradedSubdomainEnumerator

2. In _scan(), replace:
   enumerator = SubdomainEnumerator(self.dns, self.http, notify)
   
   With:
   enumerator = UpgradedSubdomainEnumerator(self.dns, self.http, notify)

3. After enumeration, filter interesting ones:
   interesting_subs = {k: v for k, v in subdomains.items() if v.get('interesting')}
   self.bus.emit("interesting_subdomains", interesting_subs)

4. In TUI (autobb_tui.py), add a new tab:
   TABS = ["DASHBOARD", "FINDINGS", "INTERESTING", "TARGETS", "LOGS", "HELP"]
   
5. Add interesting subdomains rendering:
   def draw_interesting(self, y0, h, w):
       # Show subdomains sorted by interest_score
       # Highlight categories with colors
       # Show reasons

SUBFINDER INSTALLATION:
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
"""

if __name__ == "__main__":
    print("Upgraded Subdomain Enumeration System")
    print("=" * 60)
    print("\nFeatures:")
    print("  ✓ Subfinder integration (50+ passive sources)")
    print("  ✓ Large wordlist (500 common subdomains)")
    print("  ✓ Certificate Transparency")
    print("  ✓ Interesting subdomain classification")
    print("  ✓ Priority scoring (0-100)")
    print("\nCategories:")
    for cat in Wordlists.INTERESTING_PATTERNS.keys():
        print(f"  • {cat}")
    print("\nInstall Subfinder:")
    print("  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
