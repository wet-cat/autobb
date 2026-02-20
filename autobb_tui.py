#!/usr/bin/env python3
"""
AutoBB v5 — Real-time Terminal Dashboard
Full-featured curses TUI with live scanning, stats, and log feed
"""

import curses
import curses.textpad
import threading
import time
import textwrap
import os
import sys
import json
import signal
from datetime import datetime
from typing import List, Dict, Optional, Deque
from collections import deque

# Must be importable from the same directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from autobb_engine import ScanEngine, Severity, Finding, ScanTarget

# ─── Colour Palette ─────────────────────────────────────────────────────────────

def init_colors():
    curses.start_color()
    curses.use_default_colors()
    # pair_number, fg, bg
    curses.init_pair(1,  curses.COLOR_WHITE,   -1)          # default
    curses.init_pair(2,  curses.COLOR_RED,     -1)          # critical
    curses.init_pair(3,  curses.COLOR_YELLOW,  -1)          # high
    curses.init_pair(4,  curses.COLOR_CYAN,    -1)          # medium
    curses.init_pair(5,  curses.COLOR_GREEN,   -1)          # low / ok
    curses.init_pair(6,  curses.COLOR_MAGENTA, -1)          # info / accent
    curses.init_pair(7,  curses.COLOR_BLUE,    -1)          # subdomain
    curses.init_pair(8,  curses.COLOR_WHITE,   curses.COLOR_RED)    # critical badge
    curses.init_pair(9,  curses.COLOR_BLACK,   curses.COLOR_YELLOW) # high badge
    curses.init_pair(10, curses.COLOR_BLACK,   curses.COLOR_CYAN)   # medium badge
    curses.init_pair(11, curses.COLOR_BLACK,   curses.COLOR_GREEN)  # low badge
    curses.init_pair(12, curses.COLOR_BLACK,   curses.COLOR_WHITE)  # selected row
    curses.init_pair(13, curses.COLOR_WHITE,   curses.COLOR_BLUE)   # header bar
    curses.init_pair(14, curses.COLOR_CYAN,    -1)          # dim accent
    curses.init_pair(15, curses.COLOR_BLACK,   curses.COLOR_MAGENTA) # info badge

def init_colors():
    global C_DEFAULT, C_CRIT, C_HIGH, C_MED, C_LOW
    global C_ACCENT, C_SUB
    global C_BADGE_CRIT, C_BADGE_HIGH, C_BADGE_MED
    global C_BADGE_LOW, C_SEL, C_HEADER, C_DIM, C_BADGE_INFO

    curses.start_color()
    curses.use_default_colors()

    curses.init_pair(1,  curses.COLOR_WHITE,   -1)
    curses.init_pair(2,  curses.COLOR_RED,     -1)
    curses.init_pair(3,  curses.COLOR_YELLOW,  -1)
    curses.init_pair(4,  curses.COLOR_CYAN,    -1)
    curses.init_pair(5,  curses.COLOR_GREEN,   -1)
    curses.init_pair(6,  curses.COLOR_MAGENTA, -1)
    curses.init_pair(7,  curses.COLOR_BLUE,    -1)
    curses.init_pair(8,  curses.COLOR_WHITE,   curses.COLOR_RED)
    curses.init_pair(9,  curses.COLOR_BLACK,   curses.COLOR_YELLOW)
    curses.init_pair(10, curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(11, curses.COLOR_BLACK,   curses.COLOR_GREEN)
    curses.init_pair(12, curses.COLOR_BLACK,   curses.COLOR_WHITE)
    curses.init_pair(13, curses.COLOR_WHITE,   curses.COLOR_BLUE)
    curses.init_pair(14, curses.COLOR_CYAN,    -1)
    curses.init_pair(15, curses.COLOR_BLACK,   curses.COLOR_MAGENTA)

    C_DEFAULT     = curses.color_pair(1)
    C_CRIT        = curses.color_pair(2)  | curses.A_BOLD
    C_HIGH        = curses.color_pair(3)  | curses.A_BOLD
    C_MED         = curses.color_pair(4)
    C_LOW         = curses.color_pair(5)
    C_ACCENT      = curses.color_pair(6)  | curses.A_BOLD
    C_SUB         = curses.color_pair(7)
    C_BADGE_CRIT  = curses.color_pair(8)  | curses.A_BOLD
    C_BADGE_HIGH  = curses.color_pair(9)  | curses.A_BOLD
    C_BADGE_MED   = curses.color_pair(10) | curses.A_BOLD
    C_BADGE_LOW   = curses.color_pair(11) | curses.A_BOLD
    C_SEL         = curses.color_pair(12) | curses.A_BOLD
    C_HEADER      = curses.color_pair(13) | curses.A_BOLD
    C_DIM         = curses.color_pair(14)
    C_BADGE_INFO  = curses.color_pair(15) | curses.A_BOLD


def sev_color(s: Severity):
    return {
        Severity.CRITICAL: C_CRIT,
        Severity.HIGH:     C_HIGH,
        Severity.MEDIUM:   C_MED,
        Severity.LOW:      C_LOW,
        Severity.INFO:     C_DIM,
    }.get(s, C_DEFAULT)

def sev_badge(s: Severity):
    return {
        Severity.CRITICAL: C_BADGE_CRIT,
        Severity.HIGH:     C_BADGE_HIGH,
        Severity.MEDIUM:   C_BADGE_MED,
        Severity.LOW:      C_BADGE_LOW,
        Severity.INFO:     C_BADGE_INFO,
    }.get(s, C_DEFAULT)

# ─── Safe curses drawing helper ─────────────────────────────────────────────────

def safe_addstr(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w:
        return
    max_len = w - x - 1
    if max_len <= 0:
        return
    try:
        win.addstr(y, x, text[:max_len], attr)
    except curses.error:
        pass

def safe_hline(win, y, x, ch, n):
    h, w = win.getmaxyx()
    if y < 0 or y >= h:
        return
    n = min(n, w - x - 1)
    try:
        win.hline(y, x, ch, n)
    except curses.error:
        pass

# ─── TUI State ──────────────────────────────────────────────────────────────────

class UIState:
    TABS = ["DASHBOARD", "FINDINGS", "INTERESTING", "TARGETS", "LOGS", "HELP"]

    def __init__(self):
        self.tab         = 0          # active tab index
        self.log_lines:  Deque[Dict]  = deque(maxlen=500)
        self.findings:   List[Finding] = []
        self.interesting_events: List[Dict] = []  # NEW: Track interesting events
        self.find_sel    = 0          # selected finding
        self.find_scroll = 0
        self.find_filter = ""         # severity filter
        self.target_sel  = 0
        self.log_scroll  = 0
        self.status_msg  = ""
        self.input_mode  = False
        self.input_buf   = ""
        self.input_prompt = ""
        self.input_cb    = None
        self.detail_view: Optional[Finding] = None
        self.detail_scroll = 0
        self.paused      = False
        self.scan_phase: Dict[str, str] = {}
        self.counters    = {"critical": 0, "high": 0, "medium": 0,
                            "low": 0, "info": 0, "subdomains": 0, "targets": 0}

# ─── Panel Renderers ────────────────────────────────────────────────────────────

class Renderer:
    def __init__(self, stdscr, engine: ScanEngine, state: UIState):
        self.scr    = stdscr
        self.engine = engine
        self.state  = state

    # ─── Header ─────────────────────────────────────────────────────────────────

    def draw_header(self, h, w):
        s = self.state
        title = " ⚡ AutoBB v5 "
        # Fill header bar
        self.scr.attron(C_HEADER)
        safe_addstr(self.scr, 0, 0, " " * w)
        safe_addstr(self.scr, 0, 2, title)
        self.scr.attroff(C_HEADER)

        # Tabs
        x = len(title) + 4
        for i, tab in enumerate(UIState.TABS):
            label = f" {tab} "
            attr  = (C_ACCENT | curses.A_UNDERLINE) if i == s.tab else C_DEFAULT
            safe_addstr(self.scr, 0, x, label, attr)
            x += len(label) + 1

        # Live clock top-right
        clock = datetime.now().strftime(" %H:%M:%S ")
        safe_addstr(self.scr, 0, w - len(clock) - 1, clock, C_DIM)

    # ─── Footer ─────────────────────────────────────────────────────────────────

    def draw_footer(self, h, w):
        s = self.state
        tab_hints = {
            0: "[a] Add target  [s] Start scan  [Tab] Switch tab  [q] Quit",
            1: "[↑↓] Navigate  [Enter] Detail  [f] Filter  [Tab] Switch tab",
            2: "[↑↓] Navigate  [Tab] Switch tab",
            3: "[↑↓] Scroll  [Tab] Switch tab",
            4: "[Tab] Switch tab  [q] Quit",
        }
        hint = tab_hints.get(s.tab, "")
        safe_hline(self.scr, h - 2, 0, curses.ACS_HLINE, w)
        if s.input_mode:
            prompt = f" {s.input_prompt}: {s.input_buf}█"
            safe_addstr(self.scr, h - 1, 0, prompt[:w-1], C_ACCENT)
        elif s.status_msg:
            safe_addstr(self.scr, h - 1, 1, s.status_msg[:w-2], C_DIM)
        else:
            safe_addstr(self.scr, h - 1, 1, hint[:w-2], C_DIM)

    # ─── Dashboard tab ──────────────────────────────────────────────────────────

    def draw_dashboard(self, y0, h, w):
        s   = self.state
        st  = self.engine.stats()
        row = y0 + 1

        # ASCII banner
        banner_lines = [
            "  █████╗ ██╗   ██╗████████╗ ██████╗     ██████╗ ██████╗      ██╗   ██╗███████╗",
            " ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔══██╗██╔══██╗     ██║   ██║██╔════╝",
            " ███████║██║   ██║   ██║   ██║   ██║    ██████╔╝██████╔╝     ██║   ██║███████╗",
            " ██╔══██║██║   ██║   ██║   ██║   ██║    ██╔══██╗██╔══██╗     ╚██╗ ██╔╝╚════██║",
            " ██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ██████╔╝██████╔╝      ╚████╔╝ ███████║",
            " ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚═════╝ ╚═════╝        ╚═══╝  ╚══════╝",
        ]
        for i, line in enumerate(banner_lines):
            if row + i < h - 2:
                safe_addstr(self.scr, row + i, max(0, (w - len(line)) // 2), line, C_DIM)
        row += len(banner_lines) + 1

        safe_addstr(self.scr, row, (w - 46) // 2,
                    "Automated Bug Bounty Framework  •  v5.0", C_ACCENT)
        row += 2

        # Stat cards
        cards = [
            ("TARGETS",    st["targets"],    C_DEFAULT),
            ("SUBDOMAINS", st["subdomains"], C_SUB),
            ("FINDINGS",   st["findings"],   C_DEFAULT),
            ("CRITICAL",   st["critical"],   C_CRIT),
            ("HIGH",       st["high"],       C_HIGH),
            ("MEDIUM",     st["medium"],     C_MED),
            ("LOW",        st["low"],        C_LOW),
        ]
        card_w  = max(12, (w - 4) // len(cards))
        card_x  = 2
        for label, val, color in cards:
            if card_x + card_w > w - 1:
                break
            safe_hline(self.scr, row,     card_x, curses.ACS_HLINE, card_w - 2)
            safe_addstr(self.scr, row,     card_x,                     "┌" + "─"*(card_w-2) + "┐")
            safe_addstr(self.scr, row + 1, card_x, f"│{str(val).center(card_w - 2)}│", color | curses.A_BOLD)
            safe_addstr(self.scr, row + 2, card_x, f"│{label.center(card_w - 2)}│", C_DIM)
            safe_addstr(self.scr, row + 3, card_x,                     "└" + "─"*(card_w-2) + "┘")
            card_x += card_w

        row += 5

        # Scan phases
        if s.scan_phase:
            safe_addstr(self.scr, row, 2, "ACTIVE SCANS", C_ACCENT)
            row += 1
            for domain, phase in list(s.scan_phase.items())[:5]:
                if row >= h - 2:
                    break
                spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[int(time.time() * 6) % 10]
                line = f"  {spinner} {domain:<30}  {phase}"
                safe_addstr(self.scr, row, 2, line[:w-4], C_DIM)
                row += 1
            row += 1

        # Recent findings feed
        recent = sorted(s.findings, key=lambda f: f.timestamp, reverse=True)[:8]
        if recent:
            safe_addstr(self.scr, row, 2, "RECENT FINDINGS", C_ACCENT)
            row += 1
            safe_hline(self.scr, row, 2, curses.ACS_HLINE, w - 4)
            row += 1
            for f in recent:
                if row >= h - 2:
                    break
                badge_txt = f" {f.severity.label[:4]} "
                badge_col = sev_badge(f.severity)
                desc = f"  {f.subdomain}{f.endpoint}  [{f.vuln_type}]"
                ts   = f.timestamp[11:19]
                safe_addstr(self.scr, row, 2,               badge_txt, badge_col)
                safe_addstr(self.scr, row, 2 + len(badge_txt) + 1, desc[:w-20], sev_color(f.severity))
                safe_addstr(self.scr, row, w - 10,          ts, C_DIM)
                row += 1

    # ─── Findings tab ───────────────────────────────────────────────────────────

    def draw_findings(self, y0, h, w):
        s       = self.state
        sev_map = {"C": Severity.CRITICAL, "H": Severity.HIGH,
                   "M": Severity.MEDIUM,   "L": Severity.LOW, "": None}
        filt    = sev_map.get(s.find_filter.upper(), None)
        all_f   = sorted(s.findings, key=lambda x: x.severity)
        visible = [f for f in all_f if filt is None or f.severity == filt]

        # Detail pane
        if s.detail_view:
            self._draw_finding_detail(s.detail_view, y0, h, w)
            return

        # List header
        row = y0
        hdr = f"  {'SEV':<6}  {'TYPE':<40}  {'HOST':<30}  {'PATH'}"
        safe_addstr(self.scr, row, 0, hdr[:w-1], C_ACCENT | curses.A_BOLD)
        safe_hline(self.scr, row+1, 0, curses.ACS_HLINE, w)
        row += 2

        if not visible:
            safe_addstr(self.scr, row + 2, (w-20)//2, "No findings yet.", C_DIM)
            return

        # Clamp selection
        s.find_sel = max(0, min(s.find_sel, len(visible) - 1))
        visible_rows = h - row - 2
        # Scroll to keep selection visible
        if s.find_sel < s.find_scroll:
            s.find_scroll = s.find_sel
        elif s.find_sel >= s.find_scroll + visible_rows:
            s.find_scroll = s.find_sel - visible_rows + 1

        for i, f in enumerate(visible[s.find_scroll:s.find_scroll + visible_rows]):
            abs_i = i + s.find_scroll
            is_sel = abs_i == s.find_sel
            badge  = f" {f.severity.label[:4]:4} "
            stype  = f.vuln_type[:38]
            host   = f.subdomain[:28]
            path   = f.endpoint[:w - 90] if w > 90 else ""
            line   = f"  {badge}  {stype:<40}  {host:<30}  {path}"

            if is_sel:
                safe_addstr(self.scr, row + i, 0, " " * (w - 1), C_SEL)
                safe_addstr(self.scr, row + i, 0, line[:w-1], C_SEL)
            else:
                safe_addstr(self.scr, row + i, 0, line[:w-1], sev_color(f.severity))

        # Footer count
        filt_str = f"  Filter: {s.find_filter or 'ALL'}" if s.find_filter else ""
        safe_addstr(self.scr, h - 3, 0,
                    f" {len(visible)} findings{filt_str}  [Enter] detail  [f] filter  [Esc] clear",
                    C_DIM)

    def _draw_finding_detail(self, f: Finding, y0, h, w):
        s   = self.state
        row = y0

        # Title bar
        safe_addstr(self.scr, row, 0, f" ◀ [Esc] back   FINDING DETAIL   {f.id} ", C_HEADER)
        row += 1

        lines = []
        lines.append(("VULNERABILITY TYPE", f.vuln_type, sev_color(f.severity)))
        lines.append(("SEVERITY", f"{f.severity.label}  (CVSS {f.cvss})", sev_badge(f.severity)))
        lines.append(("CWE", f.cwe, C_DIM))
        lines.append(("TARGET", f.subdomain, C_SUB))
        lines.append(("ENDPOINT", f.endpoint, C_DEFAULT))
        lines.append(("PARAMETER", f.param or "—", C_DEFAULT))
        lines.append(("CONFIDENCE", f"{int(f.confidence*100)}%", C_DEFAULT))
        lines.append(("TIMESTAMP", f.timestamp, C_DIM))
        lines.append(("", "", C_DEFAULT))
        lines.append(("DESCRIPTION", f.description, C_DEFAULT))
        lines.append(("", "", C_DEFAULT))
        lines.append(("EVIDENCE", f.evidence[:400], C_MED))
        lines.append(("", "", C_DEFAULT))
        lines.append(("PAYLOAD", f.payload[:200] or "—", C_HIGH))
        lines.append(("", "", C_DEFAULT))
        lines.append(("REMEDIATION", f.remediation, C_LOW))
        lines.append(("", "", C_DEFAULT))
        for ref in f.references:
            lines.append(("REFERENCE", ref, C_DIM))

        flat = []
        for label, val, col in lines:
            if not label:
                flat.append(("", "", C_DEFAULT))
                continue
            flat.append((label + ":", "", C_ACCENT))
            for wrapped in textwrap.wrap(val, w - 6) or [""]:
                flat.append(("", "  " + wrapped, col))

        s.detail_scroll = max(0, min(s.detail_scroll, max(0, len(flat) - (h - row - 3))))
        for i, (lbl, val, col) in enumerate(flat[s.detail_scroll:s.detail_scroll + h - row - 3]):
            if row + i >= h - 2:
                break
            if lbl:
                safe_addstr(self.scr, row + i, 2, lbl, C_ACCENT | curses.A_BOLD)
            else:
                safe_addstr(self.scr, row + i, 2, val[:w-4], col)

        safe_addstr(self.scr, h - 3, 0,
                    f" ↑↓ scroll  [{s.detail_scroll+1}/{len(flat)}]  Esc to return", C_DIM)

    # ─── Interesting tab (High Priority) ────────────────────────────────────────
    
    def draw_interesting(self, y0, h, w):
        """Show high-priority findings AND interesting events (status flips, new subdomains)"""
        s = self.state
        row = y0
        
        # Header
        safe_addstr(self.scr, row, 0, "  🔥 INTERESTING DISCOVERIES", C_ACCENT | curses.A_BOLD)
        safe_addstr(self.scr, row + 1, 0, "  Critical findings, status flips, new subdomains, auth bypasses", C_DIM)
        safe_hline(self.scr, row + 2, 0, curses.ACS_HLINE, w)
        row += 3
        
        # Collect all interesting items
        items = []
        
        # 1. Add interesting events from logs (status flips, new subdomains)
        for event in s.interesting_events:
            items.append({
                'type': 'event',
                'priority': 1 if 'STATUS FLIP' in event['msg'] else 2,
                'label': '🚨 EVENT' if 'STATUS FLIP' in event['msg'] else '🆕 EVENT',
                'title': event['msg'][:60],
                'details': event['msg'][60:120] if len(event['msg']) > 60 else '',
                'level': event['level'],
                'ts': event['ts'],
            })
        
        # 2. Add high-priority findings
        interesting_keywords = [
            'auth bypass', 'status flip', 'business logic', 'mass assignment',
            'jwt', 'privilege', 'negative', 'zero', 'nosql', 'ldap',
            'host header', 'admin', 'api key'
        ]
        
        for f in s.findings:
            vuln_lower = f.vuln_type.lower()
            desc_lower = f.description.lower()
            
            # Include if critical OR has interesting keywords OR high confidence
            if (f.severity.label == "CRITICAL" or
                any(kw in vuln_lower or kw in desc_lower for kw in interesting_keywords) or
                f.confidence > 0.90):
                
                # Determine icon
                if f.severity.label == "CRITICAL":
                    icon = "💥 CRIT"
                elif 'auth bypass' in vuln_lower:
                    icon = "🔓 AUTH"
                elif 'jwt' in vuln_lower:
                    icon = "🎫 JWT"
                elif 'business logic' in vuln_lower:
                    icon = "🧠 LOGIC"
                elif any(x in vuln_lower for x in ['nosql', 'ldap', 'sqli']):
                    icon = "💉 INJECT"
                else:
                    icon = f"✓ {int(f.confidence*100)}%"
                
                items.append({
                    'type': 'finding',
                    'priority': f.severity.value,
                    'label': icon,
                    'title': f.vuln_type[:50],
                    'details': f"{f.subdomain[:30]}{f.endpoint[:20]}"[:48],
                    'level': f.severity.label,
                    'severity': f.severity,
                    'finding': f,
                })
        
        # Sort by priority (lower = more important)
        items.sort(key=lambda x: x['priority'])
        
        if not items:
            safe_addstr(self.scr, row + 3, (w-50)//2, 
                       "No interesting discoveries yet.", C_DIM)
            safe_addstr(self.scr, row + 5, (w-80)//2,
                       "Status flips, new subdomains, auth bypasses, and critical vulns appear here.", C_DIM)
            safe_addstr(self.scr, row + 7, (w-40)//2,
                       "Run a scan to find interesting items!", C_DIM)
            return
        
        # Display items
        visible_rows = h - row - 3
        for i, item in enumerate(items[:visible_rows]):
            if item['type'] == 'event':
                # Event display (status flip, new subdomain, etc)
                color = C_CRIT if item['level'] == 'CRITICAL' else C_HIGH
                label = f" {item['label']:<12} "
                title = item['title'][:w-20]
                
                safe_addstr(self.scr, row + i, 0, label, color | curses.A_BOLD)
                safe_addstr(self.scr, row + i, len(label) + 1, title, color)
            
            else:
                # Finding display
                label = f" {item['label']:<12} "
                title = f"{item['title']:<45}  {item['details']}"
                
                color = sev_color(item['severity'])
                safe_addstr(self.scr, row + i, 0, label, color | curses.A_BOLD)
                safe_addstr(self.scr, row + i, len(label) + 1, title[:w-len(label)-2], color)
        
        # Footer with counts
        event_count = sum(1 for x in items if x['type'] == 'event')
        finding_count = sum(1 for x in items if x['type'] == 'finding')
        
        safe_addstr(self.scr, h - 3, 0,
                   f" 🔥 {len(items)} interesting ({event_count} events, {finding_count} findings)  [↑↓] scroll", C_DIM)

    # ─── Targets tab ────────────────────────────────────────────────────────────

    def draw_targets(self, y0, h, w):
        s   = self.state
        row = y0
        hdr = f"  {'DOMAIN':<35}  {'STATUS':<12}  {'SUBS':<6}  {'FINDINGS':<10}  {'CRIT':<6}  {'HIGH'}"
        safe_addstr(self.scr, row, 0, hdr[:w-1], C_ACCENT | curses.A_BOLD)
        safe_hline(self.scr, row + 1, 0, curses.ACS_HLINE, w)
        row += 2

        targets = list(self.engine.targets.items())
        if not targets:
            safe_addstr(self.scr, row + 2, (w-28)//2, "No targets. Press [a] to add.", C_DIM)
            return

        s.target_sel = max(0, min(s.target_sel, len(targets) - 1))
        for i, (domain, t) in enumerate(targets):
            if row + i >= h - 2:
                break
            is_sel = i == s.target_sel
            status_col = {"queued": C_DIM, "scanning": C_HIGH, "done": C_LOW}.get(t.status, C_DEFAULT)
            spinner = ("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[int(time.time() * 6) % 10] + " ") if t.status == "scanning" else "  "
            dur = f"{t.duration:.0f}s" if t.duration else ""
            line = (f"  {domain:<35}  {spinner}{t.status:<10}  "
                    f"{len(t.subdomains):<6}  {len(t.findings):<10}  "
                    f"{t.critical_count:<6}  {t.high_count}  {dur}")
            attr = C_SEL if is_sel else status_col
            safe_addstr(self.scr, row + i, 0, " " * (w-1) if is_sel else "", C_SEL)
            safe_addstr(self.scr, row + i, 0, line[:w-1], attr)

    # ─── Logs tab ───────────────────────────────────────────────────────────────

    def draw_logs(self, y0, h, w):
        s    = self.state
        row  = y0
        logs = list(s.log_lines)
        visible_rows = h - row - 2

        safe_addstr(self.scr, row, 0,
                    f" SCAN LOG  [{len(logs)} lines]  [↑↓] scroll  [p] pause ",
                    C_ACCENT | curses.A_BOLD)
        safe_hline(self.scr, row + 1, 0, curses.ACS_HLINE, w)
        row += 2

        if not logs:
            safe_addstr(self.scr, row + 2, (w-16)//2, "No log entries yet.", C_DIM)
            return

        s.log_scroll = max(0, min(s.log_scroll, max(0, len(logs) - visible_rows)))
        visible = logs[s.log_scroll:s.log_scroll + visible_rows]
        level_colors = {
            "CRITICAL": C_CRIT, "HIGH": C_HIGH, "MEDIUM": C_MED, "LOW": C_LOW,
            "FOUND": C_SUB, "WARN": C_HIGH, "INFO": C_DIM, "ERROR": C_CRIT,
        }
        for i, entry in enumerate(visible):
            msg   = entry.get("msg", "")
            level = entry.get("level", "INFO")
            col   = level_colors.get(level.upper(), C_DEFAULT)
            ts    = datetime.fromtimestamp(entry.get("ts", 0)).strftime("%H:%M:%S")
            line  = f" {ts}  {msg}"
            safe_addstr(self.scr, row + i, 0, line[:w-1], col)

    # ─── Help tab ───────────────────────────────────────────────────────────────

    def draw_help(self, y0, h, w):
        row  = y0 + 1
        help_text = [
            ("KEYBOARD SHORTCUTS", None),
            ("", None),
            ("Global", None),
            ("  Tab / Shift+Tab    Switch between tabs", C_DEFAULT),
            ("  q / Ctrl+C        Quit (prompts if scanning)", C_DEFAULT),
            ("  r                 Refresh screen", C_DEFAULT),
            ("", None),
            ("Dashboard", None),
            ("  a                 Add a target domain", C_DEFAULT),
            ("  s                 Start scan on all queued targets", C_DEFAULT),
            ("  x                 Export JSON report", C_DEFAULT),
            ("", None),
            ("Findings", None),
            ("  ↑ / ↓             Navigate findings list", C_DEFAULT),
            ("  Enter             View detailed finding", C_DEFAULT),
            ("  f                 Filter by severity (C/H/M/L/blank=all)", C_DEFAULT),
            ("  Esc               Close detail view", C_DEFAULT),
            ("", None),
            ("Targets", None),
            ("  ↑ / ↓             Navigate target list", C_DEFAULT),
            ("", None),
            ("Logs", None),
            ("  ↑ / ↓             Scroll logs", C_DEFAULT),
            ("  p                 Pause/resume log scrolling", C_DEFAULT),
            ("", None),
            ("SEVERITY LEVELS", None),
            ("  CRITICAL  CVSS ≥ 9.0  — Immediate action required", C_CRIT),
            ("  HIGH      CVSS ≥ 7.0  — Fix within 24h", C_HIGH),
            ("  MEDIUM    CVSS ≥ 4.0  — Fix within sprint", C_MED),
            ("  LOW       CVSS ≥ 2.0  — Fix in next cycle", C_LOW),
            ("  INFO      CVSS < 2.0  — Informational", C_DIM),
            ("", None),
            ("LEGAL NOTICE", None),
            ("  Use only on targets you own or have explicit written", C_DIM),
            ("  authorization to test. Unauthorised testing is illegal.", C_DIM),
        ]
        for lbl, col in help_text:
            if row >= h - 2:
                break
            if col is None:
                safe_addstr(self.scr, row, 2, lbl, C_ACCENT | curses.A_BOLD)
            else:
                safe_addstr(self.scr, row, 2, lbl[:w-4], col)
            row += 1

    # ─── Master render ──────────────────────────────────────────────────────────

    def render(self):
        h, w = self.scr.getmaxyx()
        if h < 20 or w < 60:
            self.scr.clear()
            safe_addstr(self.scr, h//2, (w-30)//2, "Terminal too small (min 60×20)", C_CRIT)
            self.scr.refresh()
            return

        self.scr.erase()
        self.draw_header(h, w)
        self.draw_footer(h, w)

        tab = self.state.tab
        y0  = 1
        if   tab == 0: self.draw_dashboard(y0, h, w)
        elif tab == 1: self.draw_findings(y0, h, w)
        elif tab == 2: self.draw_interesting(y0, h, w)
        elif tab == 3: self.draw_targets(y0, h, w)
        elif tab == 4: self.draw_logs(y0, h, w)
        elif tab == 5: self.draw_help(y0, h, w)

        self.scr.refresh()

# ─── Input Modal ────────────────────────────────────────────────────────────────

def get_input(stdscr, prompt: str, h: int, w: int) -> str:
    """Simple inline input — properly blocks for input"""
    # CRITICAL: Save current settings
    was_nodelay = stdscr.nodelay(False)  # Disable nodelay
    stdscr.timeout(-1)  # Block forever
    
    curses.noecho()  # Manual echo
    curses.curs_set(1)
    
    # Clear and draw prompt
    safe_addstr(stdscr, h - 1, 0, " " * (w - 1))
    safe_addstr(stdscr, h - 1, 0, f" {prompt}: ", C_ACCENT)
    stdscr.refresh()
    
    result = ""
    x = len(prompt) + 4
    
    while True:
        try:
            ch = stdscr.get_wch()
        except curses.error:
            continue
        
        # Handle string input
        if isinstance(ch, str):
            if ch in ("\n", "\r"):
                break
            elif ch in ("\x7f", "\x08"):  # Backspace
                if result:
                    result = result[:-1]
                    x -= 1
                    safe_addstr(stdscr, h - 1, x, " ")
                    stdscr.move(h - 1, x)
            elif ch == "\x1b":  # Escape
                result = ""
                break
            elif ch.isprintable():
                result += ch
                safe_addstr(stdscr, h - 1, x, ch, C_DEFAULT)
                x += 1
        
        # Handle integer keycodes
        elif isinstance(ch, int):
            if ch in (curses.KEY_ENTER, 10, 13):
                break
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                if result:
                    result = result[:-1]
                    x -= 1
                    safe_addstr(stdscr, h - 1, x, " ")
                    stdscr.move(h - 1, x)
            # Convert printable ASCII ints to chars
            elif 32 <= ch <= 126:
                char = chr(ch)
                result += char
                safe_addstr(stdscr, h - 1, x, char, C_DEFAULT)
                x += 1
        
        stdscr.refresh()
    
    # CRITICAL: Restore settings
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(80)
    
    return result.strip()
    curses.curs_set(0)
    return result.strip()

# ─── Main TUI Loop ──────────────────────────────────────────────────────────────

def tui_main(stdscr, engine: ScanEngine):
    # Curses setup
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True)
    stdscr.timeout(80)  # ~12fps
    init_colors()

    state    = UIState()
    renderer = Renderer(stdscr, engine, state)
    scan_thread: Optional[threading.Thread] = None

    def drain_events():
        for evt in engine.bus.drain():
            t = evt["type"]
            if t == "log":
                msg = evt["data"]["msg"]
                level = evt["data"]["level"]
                
                state.log_lines.append({"msg": msg,
                                         "level": level,
                                         "ts": evt["ts"]})
                
                # Capture INTERESTING events from logs - IMPROVED patterns
                msg_lower = msg.lower()
                is_interesting = False
                
                # Check severity
                if level in ("HIGH", "CRITICAL", "WARN"):
                    is_interesting = True
                
                # Check emoji indicators
                if any(emoji in msg for emoji in ["🆕", "🚨", "⚠️", "🔓", "📊", "💥", "🔥"]):
                    is_interesting = True
                
                # Check keywords (case-insensitive)
                interesting_patterns = [
                    "new subdomain", "status flip", "auth bypass", "disappeared",
                    "403→200", "403->200", "404→200", "404->200", 
                    "401→200", "401->200", "500→200", "500->200",
                    "business logic", "negative value", "zero bypass",
                    "mass assignment", "jwt", "nosql", "ldap", 
                    "host header", "api key", "exposed", "takeover"
                ]
                
                if any(pattern in msg_lower for pattern in interesting_patterns):
                    is_interesting = True
                
                if is_interesting:
                    state.interesting_events.append({
                        "type": "log_event",
                        "msg": msg,
                        "level": level,
                        "ts": evt["ts"]
                    })
            
            elif t == "finding":
                f = evt["data"]
                state.findings.append(f)
                state.counters[f.severity.label.lower()] += 1
            elif t == "subdomain_count":
                # SET the count, don't add (event contains total, not delta)
                state.counters["subdomains"] = evt["data"]["count"]
            elif t == "phase":
                state.scan_phase[evt["data"]["domain"]] = evt["data"]["phase"]
            elif t == "scan_done":
                d = evt["data"]["domain"]
                if d in state.scan_phase:
                    del state.scan_phase[d]
                state.status_msg = f"Scan complete: {d} — {evt['data']['findings']} findings"
            elif t == "target_added":
                state.status_msg = f"Target added: {evt['data']}"
                state.counters["targets"] = len(engine.targets)
            elif t == "all_done":
                state.status_msg = "All scans finished. [x] to export."

    def start_scan():
        nonlocal scan_thread
        if scan_thread and scan_thread.is_alive():
            state.status_msg = "Scan already running."
            return
        def _run():
            engine.run_all()
        scan_thread = threading.Thread(target=_run, daemon=True)
        scan_thread.start()
        state.status_msg = "Scan started!"

    while True:
        h, w = stdscr.getmaxyx()
        drain_events()
        renderer.render()

        try:
            key = stdscr.get_wch()
        except curses.error:
            key = None

        if key is None:
            continue

        # ─ global keys ──────────────────────────────────────────────────────────
        if key in ("q", "Q") and not state.input_mode:
            if scan_thread and scan_thread.is_alive():
                state.status_msg = "Scan running. Press Q again to force quit."
                try:
                    key2 = stdscr.get_wch()
                    if key2 in ("q", "Q"):
                        break
                except Exception:
                    pass
            else:
                break

        elif key in ("\t", curses.KEY_STAB):
            state.tab = (state.tab + 1) % len(UIState.TABS)

        elif key == curses.KEY_BTAB:
            state.tab = (state.tab - 1) % len(UIState.TABS)

        elif key in ("r", "R"):
            stdscr.clear()

        # ─ dashboard keys ───────────────────────────────────────────────────────
        elif state.tab == 0:
            if key in ("a", "A"):
                domain = get_input(stdscr, "Add target domain", h, w)
                if domain:
                    engine.add_target(domain)

            elif key in ("s", "S"):
                start_scan()

            elif key in ("x", "X"):
                ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
                path = f"autobb_report_{ts}.json"
                engine.export_json(path, export_md=False)
                state.status_msg = f"Exported → {path}"

        # ─ findings keys ────────────────────────────────────────────────────────
        elif state.tab == 1:
            if state.detail_view:
                if key == curses.KEY_UP:
                    state.detail_scroll = max(0, state.detail_scroll - 1)
                elif key == curses.KEY_DOWN:
                    state.detail_scroll += 1
                elif key == 27:  # Esc
                    state.detail_view = None
                    state.detail_scroll = 0
            else:
                if key == curses.KEY_UP:
                    state.find_sel = max(0, state.find_sel - 1)
                elif key == curses.KEY_DOWN:
                    state.find_sel += 1
                elif key in (curses.KEY_ENTER, 10, 13):
                    sev_map = {"C": Severity.CRITICAL, "H": Severity.HIGH,
                               "M": Severity.MEDIUM,   "L": Severity.LOW, "": None}
                    filt    = sev_map.get(state.find_filter.upper(), None)
                    visible = sorted(state.findings, key=lambda x: x.severity)
                    if filt:
                        visible = [f for f in visible if f.severity == filt]
                    if 0 <= state.find_sel < len(visible):
                        state.detail_view   = visible[state.find_sel]
                        state.detail_scroll = 0
                elif key in ("f", "F"):
                    fv = get_input(stdscr, "Filter severity (C/H/M/L or blank)", h, w)
                    state.find_filter = fv.strip().upper()
                    state.find_sel    = 0
                elif key == 27:
                    state.find_filter = ""
                    state.find_sel    = 0

        # ─ interesting keys (same as findings) ──────────────────────────────────
        elif state.tab == 2:
            # Same controls as findings tab
            if key == curses.KEY_UP:
                state.find_sel = max(0, state.find_sel - 1)
            elif key == curses.KEY_DOWN:
                state.find_sel += 1

        # ─ targets keys ─────────────────────────────────────────────────────────
        elif state.tab == 3:
            if key == curses.KEY_UP:
                state.target_sel = max(0, state.target_sel - 1)
            elif key == curses.KEY_DOWN:
                state.target_sel += 1
            elif key in ("a", "A"):
                domain = get_input(stdscr, "Add target domain", h, w)
                if domain:
                    engine.add_target(domain)
            elif key in ("s", "S"):
                start_scan()

        # ─ logs keys ────────────────────────────────────────────────────────────
        elif state.tab == 4:
            if key == curses.KEY_UP:
                state.log_scroll = max(0, state.log_scroll - 1)
            elif key == curses.KEY_DOWN:
                state.log_scroll += 1
            elif key in ("p", "P"):
                state.paused = not state.paused
                state.status_msg = "Log paused" if state.paused else "Log resumed"

# ─── Entry Point ────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="AutoBB v5 — Automated Bug Bounty Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Launch interactive TUI
  %(prog)s -t example.com            # Immediately add and scan a target
  %(prog)s -t a.com b.com --threads 30
  %(prog)s --proxy http://127.0.0.1:8080 -t target.com

⚠  Only use against targets you own or have explicit written authorisation to test.
"""
    )
    parser.add_argument("-t", "--targets", nargs="+", metavar="DOMAIN",
                        help="Target domains to add immediately")
    parser.add_argument("--threads", type=int, default=25,
                        help="Scanner threads (default: 25)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("--proxy", metavar="URL",
                        help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--no-tui", action="store_true",
                        help="Run headlessly and output JSON only")
    parser.add_argument("--export-md", action="store_true",
                        help="Also export grouped markdown reports under reports/<domain>/")
    parser.add_argument("--confidence-threshold", type=float, default=0.70,
                        help="Minimum confidence to include in primary markdown submission queue (default: 0.70)")
    parser.add_argument("--niche", choices=["authenticated_webapps", "graphql_api_auth", "cloud_exposure_chain", "js_heavy_spa"],
                        default="graphql_api_auth",
                        help="Scanner/report niche profile to optimize high-value workflow (default: graphql_api_auth)")
    parser.add_argument("--outcomes-file", metavar="JSON",
                        help="Optional JSON array with prior submission outcomes to tune KPI accuracy")
    parser.add_argument("--scan-mode", choices=["balanced", "crazy", "profit"], default="balanced",
                        help="Scan intensity profile: balanced (default), crazy (max coverage), profit (high-signal)")
    parser.add_argument("--discord-webhook", metavar="URL",
                        help="Discord webhook URL for real-time finding alerts (or set DISCORD_WEBHOOK_URL)")
    args = parser.parse_args()

    discord_webhook = args.discord_webhook or os.getenv("DISCORD_WEBHOOK_URL")
    engine = ScanEngine(
        threads=args.threads,
        timeout=args.timeout,
        proxy=args.proxy,
        scan_mode=args.scan_mode,
        discord_webhook=discord_webhook,
    )

    if args.targets:
        for t in args.targets:
            engine.add_target(t)

    if args.no_tui:
        # Headless mode
        print(f"[*] AutoBB v5 — headless mode")
        print(f"[*] Targets: {args.targets}")
        print(f"[*] Scanning...")

        def print_events():
            while engine._running or not engine.bus._q.empty():
                for evt in engine.bus.drain():
                    if evt["type"] == "log":
                        d = evt["data"]
                        lvl = d.get("level","INFO")
                        col = {"CRITICAL":"\033[91m","HIGH":"\033[93m","FOUND":"\033[96m"}.get(lvl,"")
                        print(f"{col}[{lvl}] {d['msg']}\033[0m")
                time.sleep(0.05)

        t = threading.Thread(target=print_events, daemon=True)
        t.start()
        engine.run_all()
        t.join(timeout=1)

        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"autobb_report_{ts}.json"
        engine.export_json(path, export_md=args.export_md, confidence_threshold=args.confidence_threshold, niche=args.niche, outcomes_file=args.outcomes_file)
        print(f"\n[+] Report saved: {path}")
        if args.export_md:
            print(f"[+] Markdown reports: reports/<domain>/SUMMARY.md")
        stats = engine.stats()
        print(f"[+] Findings: {stats['findings']}  Critical: {stats['critical']}  High: {stats['high']}")
    else:
        # TUI mode
        os.environ.setdefault("TERM", "xterm-256color")
        curses.wrapper(tui_main, engine)
        # After exit, print summary
        stats = engine.stats()
        print(f"\n\033[1m AutoBB v5 — Session Summary\033[0m")
        print(f"  Targets:    {stats['targets']}")
        print(f"  Subdomains: {stats['subdomains']}")
        print(f"  Findings:   {stats['findings']}")
        print(f"  \033[91mCritical:   {stats['critical']}\033[0m")
        print(f"  \033[93mHigh:       {stats['high']}\033[0m")
        print(f"  \033[96mMedium:     {stats['medium']}\033[0m")
        print(f"  \033[92mLow:        {stats['low']}\033[0m")

        # Auto-export if findings exist
        if stats["findings"] > 0:
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = f"autobb_report_{ts}.json"
            engine.export_json(path, export_md=args.export_md, confidence_threshold=args.confidence_threshold, niche=args.niche, outcomes_file=args.outcomes_file)
            print(f"\n  Report:     {path}")
            if args.export_md:
                print("  Markdown:   reports/<domain>/SUMMARY.md")
        print()

if __name__ == "__main__":
    main()
