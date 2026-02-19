"""
AutoBB Intelligent State Management & Prioritization System

Fixes:
1. Persistent state across scans (SQLite database)
2. Change detection (new subdomains, status flips, new endpoints)
3. Risk-based prioritization
4. Investigation mode for high-value targets
5. Queue processing that actually works

Add this to autobb_engine.py
"""

import sqlite3
import hashlib
import pickle
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

# ═══════════════════════════════════════════════════════════════════════════════
# PERSISTENT STATE DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

class StateDB:
    """Persistent state tracking across scans"""
    
    def __init__(self, db_path: str = "autobb_state.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_schema()
    
    def _init_schema(self):
        """Create tables for state tracking"""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                subdomain_count INTEGER,
                finding_count INTEGER,
                critical_count INTEGER,
                high_count INTEGER
            );
            
            CREATE TABLE IF NOT EXISTS subdomain_state (
                subdomain TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status_code INTEGER,
                is_alive BOOLEAN,
                ip_addresses TEXT,
                cname TEXT,
                technologies TEXT,  -- JSON array
                endpoints TEXT,     -- JSON array
                endpoints_hash TEXT -- Hash to detect changes
            );
            
            CREATE TABLE IF NOT EXISTS endpoint_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subdomain TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status_code INTEGER,
                params TEXT,        -- JSON array
                response_hash TEXT,
                risk_score INTEGER DEFAULT 0,
                UNIQUE(subdomain, endpoint)
            );
            
            CREATE TABLE IF NOT EXISTS status_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subdomain TEXT NOT NULL,
                endpoint TEXT,
                change_type TEXT NOT NULL, -- 'new_subdomain', 'status_flip', 'new_endpoint', etc
                old_value TEXT,
                new_value TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                investigated BOOLEAN DEFAULT 0,
                priority INTEGER DEFAULT 5  -- 1=critical, 5=low
            );
            
            CREATE TABLE IF NOT EXISTS findings_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT UNIQUE,
                domain TEXT,
                subdomain TEXT,
                vuln_type TEXT,
                severity TEXT,
                first_found TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_confirmed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                times_found INTEGER DEFAULT 1,
                false_positive BOOLEAN DEFAULT 0
            );
            
            CREATE INDEX IF NOT EXISTS idx_subdomain_domain ON subdomain_state(domain);
            CREATE INDEX IF NOT EXISTS idx_changes_priority ON status_changes(priority, investigated);
        """)
        self.conn.commit()
    
    def record_scan(self, domain: str, stats: Dict):
        """Record scan completion"""
        self.conn.execute("""
            INSERT INTO scan_history (domain, subdomain_count, finding_count, critical_count, high_count)
            VALUES (?, ?, ?, ?, ?)
        """, (domain, stats['subdomains'], stats['findings'], stats['critical'], stats['high']))
        self.conn.commit()
    
    def get_previous_subdomains(self, domain: str) -> Set[str]:
        """Get subdomains from previous scan"""
        cursor = self.conn.execute("""
            SELECT subdomain FROM subdomain_state WHERE domain = ?
        """, (domain,))
        return {row[0] for row in cursor.fetchall()}
    
    def update_subdomain(self, subdomain: str, domain: str, info: Dict) -> Dict:
        """Update subdomain state and detect changes"""
        changes = {}
        
        # Get previous state
        cursor = self.conn.execute("""
            SELECT status_code, is_alive, endpoints_hash FROM subdomain_state
            WHERE subdomain = ?
        """, (subdomain,))
        row = cursor.fetchone()
        
        endpoints_hash = hashlib.md5(str(sorted(info.get('endpoints', []))).encode()).hexdigest()
        
        if row:
            old_status, old_alive, old_hash = row
            
            # Detect status code flip (403→200, 404→200, etc)
            new_status = info.get('status_code', 0)
            if old_status != new_status:
                if old_status in (403, 404, 401, 500) and new_status == 200:
                    changes['status_flip'] = {'from': old_status, 'to': new_status, 'priority': 1}  # CRITICAL
                elif old_status == 200 and new_status in (403, 404):
                    changes['status_down'] = {'from': old_status, 'to': new_status, 'priority': 3}
            
            # Detect endpoint changes
            if old_hash != endpoints_hash:
                changes['endpoints_changed'] = {'priority': 2}  # HIGH
            
            # Update
            self.conn.execute("""
                UPDATE subdomain_state 
                SET last_seen = CURRENT_TIMESTAMP,
                    status_code = ?,
                    is_alive = ?,
                    endpoints = ?,
                    endpoints_hash = ?
                WHERE subdomain = ?
            """, (new_status, info.get('is_alive', False), 
                  str(info.get('endpoints', [])), endpoints_hash, subdomain))
        else:
            # New subdomain
            changes['new_subdomain'] = {'priority': 2}  # HIGH
            
            self.conn.execute("""
                INSERT INTO subdomain_state 
                (subdomain, domain, status_code, is_alive, endpoints, endpoints_hash)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (subdomain, domain, info.get('status_code', 0), 
                  info.get('is_alive', False), str(info.get('endpoints', [])), endpoints_hash))
        
        self.conn.commit()
        
        # Record changes
        for change_type, details in changes.items():
            self._record_change(subdomain, None, change_type, details)
        
        return changes
    
    def _record_change(self, subdomain: str, endpoint: Optional[str], change_type: str, details: Dict):
        """Record a detected change"""
        self.conn.execute("""
            INSERT INTO status_changes 
            (subdomain, endpoint, change_type, old_value, new_value, priority)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (subdomain, endpoint, change_type, 
              str(details.get('from', '')), str(details.get('to', '')),
              details.get('priority', 5)))
        self.conn.commit()
    
    def get_high_priority_changes(self, limit: int = 20) -> List[Dict]:
        """Get uninvestigated high-priority changes"""
        cursor = self.conn.execute("""
            SELECT id, subdomain, endpoint, change_type, old_value, new_value, priority
            FROM status_changes
            WHERE investigated = 0
            ORDER BY priority ASC, detected_at DESC
            LIMIT ?
        """, (limit,))
        
        changes = []
        for row in cursor.fetchall():
            changes.append({
                'id': row[0],
                'subdomain': row[1],
                'endpoint': row[2],
                'change_type': row[3],
                'old_value': row[4],
                'new_value': row[5],
                'priority': row[6],
            })
        return changes
    
    def mark_investigated(self, change_id: int):
        """Mark change as investigated"""
        self.conn.execute("UPDATE status_changes SET investigated = 1 WHERE id = ?", (change_id,))
        self.conn.commit()
    
    def get_scan_stats(self, domain: str, days: int = 30) -> Dict:
        """Get historical stats"""
        cursor = self.conn.execute("""
            SELECT COUNT(*), AVG(finding_count), AVG(critical_count)
            FROM scan_history
            WHERE domain = ? AND scan_date > datetime('now', '-' || ? || ' days')
        """, (domain, days))
        row = cursor.fetchone()
        
        return {
            'total_scans': row[0] or 0,
            'avg_findings': row[1] or 0,
            'avg_critical': row[2] or 0,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# RISK SCORING & PRIORITIZATION
# ═══════════════════════════════════════════════════════════════════════════════

class RiskScorer:
    """Calculate risk scores for endpoints and subdomains"""
    
    @staticmethod
    def score_endpoint(endpoint: str, subdomain: str, info: Dict) -> int:
        """
        Score endpoint risk (0-100, higher = more interesting)
        """
        score = 0
        path = endpoint.lower()
        
        # High-value paths
        if any(x in path for x in ['/admin', '/api', '/console', '/dashboard', '/debug']):
            score += 30
        
        if any(x in path for x in ['/v1/', '/v2/', '/v3/', '/internal/', '/private/']):
            score += 25
        
        # Authentication endpoints
        if any(x in path for x in ['/login', '/auth', '/oauth', '/token', '/session']):
            score += 20
        
        # File operations
        if any(x in path for x in ['/upload', '/download', '/file', '/import', '/export']):
            score += 20
        
        # Data endpoints
        if any(x in path for x in ['/user', '/account', '/profile', '/payment', '/billing']):
            score += 15
        
        # Params present = more attack surface
        if info.get('params'):
            score += len(info['params']) * 5
        
        # GraphQL/SOAP = complex
        if any(x in path for x in ['/graphql', '/graphiql', '/soap', '/wsdl']):
            score += 20
        
        # Status code matters
        status = info.get('status_code', 0)
        if status == 200:
            score += 10
        elif status == 403:
            score += 15  # Forbidden = might bypass
        elif status == 401:
            score += 12  # Auth required = interesting
        
        return min(score, 100)
    
    @staticmethod
    def score_subdomain(subdomain: str, info: Dict, changes: Dict) -> int:
        """
        Score subdomain risk (0-100)
        """
        score = 0
        
        # Changes are HIGH priority
        if changes:
            if 'status_flip' in changes:
                score += 40  # Status flip is GOLD
            if 'new_subdomain' in changes:
                score += 30
            if 'endpoints_changed' in changes:
                score += 25
        
        # Patterns in subdomain name
        name = subdomain.lower()
        if any(x in name for x in ['staging', 'dev', 'test', 'qa', 'uat', 'sandbox']):
            score += 20  # Dev environments = juicy
        
        if any(x in name for x in ['admin', 'api', 'internal', 'vpn', 'jenkins', 'gitlab']):
            score += 25
        
        if any(x in name for x in ['old', 'legacy', 'deprecated', 'backup']):
            score += 15  # Forgotten = vulnerable
        
        # Endpoint count
        endpoint_count = len(info.get('endpoints', []))
        score += min(endpoint_count * 2, 30)
        
        # Open ports
        ports = info.get('ports', [])
        if ports:
            # Dangerous ports
            if any(p in ports for p in [3306, 5432, 27017, 6379, 9200]):  # DB ports
                score += 20
            if any(p in ports for p in [22, 3389]):  # SSH, RDP
                score += 15
        
        return min(score, 100)


# ═══════════════════════════════════════════════════════════════════════════════
# INTELLIGENT INVESTIGATION MODE
# ═══════════════════════════════════════════════════════════════════════════════

class IntelligentInvestigator:
    """Deep investigation of high-priority targets"""
    
    def __init__(self, http_engine, checkers: Dict):
        self.http = http_engine
        self.checkers = checkers
    
    def investigate_status_flip(self, subdomain: str, endpoint: str, old_status: int, new_status: int) -> List:
        """
        Deep dive on status code flips (403→200, 404→200)
        This is where auth bypasses appear
        """
        findings = []
        base = f"https://{subdomain}" if subdomain else ""
        
        print(f"[INVESTIGATE] {subdomain}{endpoint}: {old_status}→{new_status}")
        
        # Test various bypass techniques
        bypass_tests = [
            ('X-Original-URL', endpoint),
            ('X-Rewrite-URL', endpoint),
            ('X-Forwarded-For', '127.0.0.1'),
            ('X-Custom-IP-Authorization', '127.0.0.1'),
            ('Referer', f'{base}/admin'),
        ]
        
        for header, value in bypass_tests:
            r = self.http.get(base + endpoint, headers={header: value})
            if r and r.status_code == 200 and old_status in (403, 401):
                findings.append({
                    'type': 'Auth Bypass via Header Manipulation',
                    'severity': 'CRITICAL',
                    'endpoint': endpoint,
                    'evidence': f'Header {header}: {value} bypassed {old_status}',
                })
        
        # Test path variations
        path_tests = [
            endpoint + '/.',
            endpoint + '/..',
            endpoint + '//',
            endpoint.rstrip('/') + '..;/',
            endpoint + '%20',
            endpoint + '%09',
            '/' + endpoint.lstrip('/').replace('/', '/./'),
        ]
        
        for test_path in path_tests:
            r = self.http.get(base + test_path)
            if r and r.status_code == 200:
                findings.append({
                    'type': 'Path Traversal Auth Bypass',
                    'severity': 'CRITICAL',
                    'endpoint': test_path,
                    'evidence': f'Path variation bypassed authentication',
                })
        
        return findings
    
    def investigate_new_endpoint(self, subdomain: str, endpoint: str) -> List:
        """
        Deep investigation of new endpoints
        """
        findings = []
        base = f"https://{subdomain}"
        
        # Run ALL checkers on this endpoint
        params = self._extract_params(base + endpoint)
        
        for name, checker in self.checkers.items():
            try:
                if name in ['sqli', 'xss', 'nosqli', 'ldapi', 'bizlogic']:
                    results = checker.check(base, endpoint, params)
                    findings.extend(results)
            except:
                pass
        
        return findings
    
    def _extract_params(self, url: str) -> Set[str]:
        """Extract parameters from URL"""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        return set(parse_qs(parsed.query).keys()) or {'id', 'q', 'search', 'user'}


# ═══════════════════════════════════════════════════════════════════════════════
# FIXED QUEUE PROCESSING
# ═══════════════════════════════════════════════════════════════════════════════

def fixed_run_all(self):
    """
    FIXED queue processing that actually works
    Replace the run_all() method in ScanEngine
    """
    self._running = True
    
    # Get queued targets
    queued = [d for d, t in self.targets.items() if t.status == "queued"]
    
    if not queued:
        self.bus.emit("log", {"msg": "No queued targets", "level": "WARN"})
        self._running = False
        return
    
    self.bus.emit("log", {"msg": f"Processing {len(queued)} queued targets", "level": "INFO"})
    
    # Process each target
    for i, domain in enumerate(queued, 1):
        try:
            self.bus.emit("log", {"msg": f"[{i}/{len(queued)}] Scanning {domain}", "level": "INFO"})
            self._scan(domain)
            
            # Update status to done
            self.targets[domain].status = "done"
            self.targets[domain].duration = time.time() - self.targets[domain].scan_start
            
            self.bus.emit("log", {"msg": f"✓ {domain} complete", "level": "INFO"})
        
        except Exception as e:
            self.bus.emit("log", {"msg": f"✗ {domain} failed: {e}", "level": "ERROR"})
            self.targets[domain].status = "failed"
    
    self._running = False
    self.bus.emit("all_done", None)
    self.bus.emit("log", {"msg": f"All {len(queued)} targets processed", "level": "INFO"})


# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION INSTRUCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

"""
TO INTEGRATE INTO autobb_engine.py:

1. Add StateDB to ScanEngine.__init__:
   self.state_db = StateDB()
   self.risk_scorer = RiskScorer()

2. Replace run_all() with fixed_run_all()

3. In _scan(), after subdomain enumeration, add:
   
   # Detect changes
   prev_subs = self.state_db.get_previous_subdomains(domain)
   new_subs = set(subdomains.keys()) - prev_subs
   
   if new_subs:
       notify(f"[!] {len(new_subs)} NEW subdomains detected!", "HIGH")
   
   # Update state and get changes
   for fqdn, info in subdomains.items():
       changes = self.state_db.update_subdomain(fqdn, domain, {
           'status_code': info.status_code,
           'is_alive': info.alive,
           'endpoints': list(info.endpoints),
       })
       
       if changes:
           notify(f"[CHANGE] {fqdn}: {changes}", "HIGH")

4. Priority-based scanning:
   
   # Score all subdomains
   scored = []
   for fqdn, info in subdomains.items():
       changes = self.state_db.get_previous_state(fqdn)
       score = self.risk_scorer.score_subdomain(fqdn, info, changes)
       scored.append((score, fqdn, info))
   
   # Scan highest risk first
   scored.sort(reverse=True)
   for score, fqdn, info in scored[:20]:  # Top 20
       if score > 50:
           notify(f"[HIGH RISK] {fqdn} (score: {score})", "HIGH")
           # Run full checks
       else:
           # Run quick checks only

5. At end of scan:
   self.state_db.record_scan(domain, target.stats())
"""

if __name__ == "__main__":
    print("AutoBB Intelligent State Management System")
    print("=" * 60)
    print("\nFeatures:")
    print("  ✓ Persistent state across scans")
    print("  ✓ Change detection (403→200, new endpoints, new subdomains)")
    print("  ✓ Risk-based prioritization")
    print("  ✓ Investigation mode for high-value targets")
    print("  ✓ Fixed queue processing")
    print("\nSee integration instructions in the code.")
