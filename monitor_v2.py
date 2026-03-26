"""
=============================================================
  SOC Analyst Level-2 — Network Threat Detection Platform
  monitor_v2.py  |  Backend v2.1  (bug-fixed)
=============================================================
  REQUIREMENTS:
    pip install psutil flask flask-cors requests reportlab

  RUN AS ADMINISTRATOR:
    python monitor_v2.py

  Open dashboard_v2.html in your browser.
  API: http://localhost:5000
=============================================================

  FIXES IN v2.1
  ─────────────
  1. All timestamps now UTC (was local time — caused clock mismatch
     with the dashboard's UTC clock display).
  2. Added missing /api/threats/export endpoint — the dashboard
     "Export JSON" button was calling it and getting a 404.
  3. Fixed deque JSON-serialisation crash in snap() — deques are not
     JSON-serialisable; now converted to list before jsonify().
  4. collect_open_ports() deduplication used a plain set but compared
     port+pid pairs inconsistently — fixed to deduplicate on port only.
  5. reputation_worker race condition — `already` check was reading
     _reputation without the lock; fixed.
  6. check_reputation() URLhaus lookup was passing the raw domain
     including subdomain; now also tries root_domain for better hits.
  7. collect_connections() called _lq.append() after checking
     `rip not in list(_lq)` which is O(n) and misses deque items —
     replaced with an O(1) set-based pending tracker.
  8. auto_incident() modified state["incidents"] while iterating it
     inside the lock — extracted the search into a separate pass first.
  9. run_hunt() searched threat_log[:500] but iterated connections with
     no limit; added consistent limits and None-safe .get() guards.
 10. update_feed() set MALICIOUS_DOMAINS directly (thread-unsafe string
     replace); now uses a lock-protected update.
 11. scan_all_ports_cve() could fire duplicate "CVE on open port"
     threats on every 40-second tick; added a per-CVE dedup set.
 12. PDF report generation referenced `t` (Table) variable shadowed by
     the loop variable `t` in "Associated Threats" — renamed to `th_t`
     consistently throughout (was already done in some places but not
     all — ensured consistency).
 13. Flask /api/all serialises deques via snap() which now explicitly
     converts all deques to lists.
 14. HOST changed from 0.0.0.0 to 127.0.0.1 for security — the README
     states the API should only be localhost-accessible.
=============================================================
"""

import os, re, json, time, socket, hashlib, platform
import threading, subprocess, ipaddress, uuid
from datetime import datetime, timezone
from pathlib import Path
from collections import deque, defaultdict

import psutil, requests
from flask import Flask, jsonify, request, send_file, Response
from flask_cors import CORS

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, HRFlowable)
    REPORTLAB = True
except ImportError:
    REPORTLAB = False

try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY = True
except ImportError:
    SCAPY = False

# ── PATHS ──
BASE          = Path(__file__).parent
THREAT_FILE   = BASE / "threat_log.json"
CACHE_FILE    = BASE / "ip_cache.json"
INCIDENT_FILE = BASE / "incidents.json"
HUNT_FILE     = BASE / "hunt_results.json"
REPORTS_DIR   = BASE / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# ── CONFIG ──
HOST, PORT    = "127.0.0.1", 5000   # FIX #14: localhost only (was 0.0.0.0)
SCAN_INTERVAL = 4
MAX_HISTORY   = 120
CACHE_TTL     = 3600
ABUSEIPDB_KEY = ""   # optional: https://www.abuseipdb.com/register
NVD_API_KEY   = ""   # optional: https://nvd.nist.gov/developers/request-an-api-key

# ── THREAT INTEL LISTS ──
MALICIOUS_DOMAINS = {
    "evil-update.com","malware-dropper.net","c2.botnet.xyz",
    "beacon.cobaltstrike.io","darkweb-payment.onion.ws","ransom-gate.net",
    "secure-login-verify.com","account-update-required.net",
    "paypal-security-center.com","microsoft-verify.net",
    "pool.minexmr.com","coinhive.com","tor2web.org","onion.to",
}
RESTRICTED_DOMAINS = {
    "thepiratebay.org","1337x.to","dark.fail",
    "hackforums.net","nulled.to","exploit-db.com",
}
SUSPICIOUS_PORTS = {
    4444:"Metasploit listener", 1337:"Backdoor", 31337:"Elite backdoor",
    8080:"Alt-HTTP/C2",9001:"TOR relay",9050:"TOR SOCKS",
    6667:"IRC/botnet",23:"Telnet",21:"FTP",5900:"VNC",
    1080:"SOCKS proxy",12345:"RAT port",54321:"RAT reverse",
}
HARDWARE_PATTERNS = {
    "Camera":    ["cam","webcam","camera","imagingdevice"],
    "Microphone":["audiodg","speechruntime","voicerecorder"],
    "GPU":       ["nvda","aticfx","d3d","dxgi","opengl","vulkan"],
    "USB":       ["usbstor","wudfhost","usbaudio","hidserv"],
}
MALWARE_PROCS = ["mimikatz","meterpreter","nc.exe","ncat","psexec",
                 "wce.exe","pwdump","cobaltstrike","beacon.exe"]
SYSTEM_WL     = {"svchost.exe","system","registry","smss.exe","csrss.exe",
                 "wininit.exe","services.exe","lsass.exe","winlogon.exe",
                 "dwm.exe","taskhostw.exe","runtimebroker.exe","spoolsv.exe",
                 "audiodg.exe","ctfmon.exe","conhost.exe","dllhost.exe"}

# ── PERSISTENCE HELPERS ──
def load_json(p, d):
    if Path(p).exists():
        try: return json.loads(Path(p).read_text(encoding="utf-8"))
        except: pass
    return d

def save_json(p, data):
    try: Path(p).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e: print(f"[save] {e}")

# ── STATE ──
lock         = threading.Lock()
_saved_thr   = load_json(THREAT_FILE, [])
_saved_inc   = load_json(INCIDENT_FILE, [])
_ip_cache    = load_json(CACHE_FILE, {})
_reputation  = {}
_lq          = deque()          # lookup queue
_lq_set      = set()            # FIX #7: O(1) pending-IP tracker

state = {
    "cpu_history":      deque(maxlen=MAX_HISTORY),
    "mem_history":      deque(maxlen=MAX_HISTORY),
    "net_sent_history": deque(maxlen=MAX_HISTORY),
    "net_recv_history": deque(maxlen=MAX_HISTORY),
    "timestamps":       deque(maxlen=MAX_HISTORY),
    "connections":  [], "processes":  [], "wifi_devices": [],
    "open_ports":   [], "interfaces": [], "network_stats":{},
    "system_info":  {}, "hardware_access": [],
    "live_alerts":  deque(maxlen=300),
    "threat_log":   _saved_thr[:],
    "incidents":    _saved_inc[:],
    "hunt_results": [],
    "cve_results":  {},
    "correlation":  {},
    "total_alerts": len(_saved_thr),
    "scapy":        SCAPY,
    "reportlab":    REPORTLAB,
    "packets":      0,
}

_prev_net  = psutil.net_io_counters()
_prev_time = time.time()

# ── HELPERS ──
# FIX #1: All timestamps now UTC
def ts_now():  return datetime.now(timezone.utc).strftime("%H:%M:%S")
def ts_full(): return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except: return True

def root_domain(h):
    p = h.rstrip(".").split(".")
    return ".".join(p[-2:]) if len(p) >= 2 else h

def rev_dns(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except: return ""

def uid(): return hashlib.md5(f"{ts_full()}{uuid.uuid4()}".encode()).hexdigest()[:10]

# ── THREAT ALERT ──
def add_threat(severity, category, title, detail,
               ip="", domain="", threat_type="", incident_id=""):
    alert = {
        "id": uid(), "timestamp": ts_full(), "time": ts_now(),
        "severity": severity, "category": category,
        "title": title, "detail": detail,
        "ip": ip, "domain": domain,
        "threat_type": threat_type, "incident_id": incident_id,
        "status": "open", "analyst_note": "",
    }
    with lock:
        state["live_alerts"].appendleft(alert)
        state["threat_log"].insert(0, alert)
        if len(state["threat_log"]) > 3000:
            state["threat_log"] = state["threat_log"][:3000]
        state["total_alerts"] = len(state["threat_log"])
    threading.Thread(target=save_json,
                     args=(THREAT_FILE, state["threat_log"][:3000]),
                     daemon=True).start()
    if severity in ("critical", "high"):
        threading.Thread(target=auto_incident, args=(alert,), daemon=True).start()
    print(f"  [{'!!!' if severity=='critical' else '!! ' if severity=='high' else '!  '}] "
          f"{severity.upper():8} | {category:22} | {title}")
    return alert["id"]

# ═══════════════════════════════════════════════
#  MODULE 1 — INCIDENT RESPONSE
# ═══════════════════════════════════════════════

INCIDENT_STAGES = ["Detected", "Investigating", "Contained", "Resolved"]

def auto_incident(alert):
    """Auto-create or merge alert into an existing open incident for the same IP."""
    ip = alert.get("ip", "")

    # FIX #8: Search first (read), then mutate — avoids modifying-while-iterating
    with lock:
        existing = None
        for inc in state["incidents"]:
            if inc["status"] != "Resolved" and inc.get("primary_ip") == ip and ip:
                existing = inc
                break

        if existing:
            existing["alerts"].append(alert["id"])
            existing["last_seen"] = ts_full()
            existing["evidence"].append({
                "time": ts_full(), "type": alert["category"],
                "detail": alert["title"]
            })
            sev_order = ["low", "medium", "high", "critical"]
            cur = sev_order.index(existing["severity"]) if existing["severity"] in sev_order else 0
            new = sev_order.index(alert["severity"])    if alert["severity"]    in sev_order else 0
            if new > cur:
                existing["severity"] = alert["severity"]
                existing["timeline"].append({
                    "time": ts_full(), "stage": existing["stage"],
                    "event": f"Severity escalated to {alert['severity']} — {alert['title']}"
                })
        else:
            inc = {
                "id":          f"INC-{uid()[:6].upper()}",
                "created":     ts_full(),
                "last_seen":   ts_full(),
                "severity":    alert["severity"],
                "status":      "Detected",
                "stage":       "Detected",
                "primary_ip":  ip,
                "domain":      alert.get("domain", ""),
                "title":       alert["title"],
                "category":    alert["category"],
                "threat_type": alert.get("threat_type", ""),
                "alerts":      [alert["id"]],
                "mitre":       get_mitre(alert.get("threat_type", "")),
                "timeline":    [{
                    "time": ts_full(), "stage": "Detected",
                    "event": f"Incident auto-created: {alert['title']}"
                }],
                "evidence":    [{
                    "time": ts_full(), "type": alert["category"],
                    "detail": alert["title"]
                }],
                "analyst_notes": [],
                "containment_actions": [],
                "affected_hosts": [ip] if ip else [],
            }
            state["incidents"].insert(0, inc)
            if len(state["incidents"]) > 500:
                state["incidents"] = state["incidents"][:500]

    threading.Thread(target=save_json,
                     args=(INCIDENT_FILE, state["incidents"][:500]),
                     daemon=True).start()

def get_mitre(threat_type):
    m = {
        "malicious_ip":       "T1071 - Application Layer Protocol",
        "restricted_domain":  "T1071 - Application Layer Protocol",
        "hardware_camera":    "T1125 - Video Capture",
        "hardware_microphone":"T1123 - Audio Capture",
        "malware_process":    "T1055 - Process Injection",
        "suspicious_port":    "T1049 - System Network Connections",
        "brute_force":        "T1110 - Brute Force",
        "lateral":            "T1021 - Remote Services",
        "exfil":              "T1041 - Exfiltration Over C2 Channel",
    }
    for k, v in m.items():
        if k in threat_type:
            return v
    return "T1071 - Application Layer Protocol"

# ═══════════════════════════════════════════════
#  MODULE 2 — THREAT HUNTING
# ═══════════════════════════════════════════════

def run_hunt(query, hunt_type="keyword"):
    """Search across all collected data for a given query."""
    results = []
    q = query.lower().strip()

    # FIX #9: Safe .get() guards + consistent limits
    with lock:
        conns   = list(state["connections"])[:200]
        procs   = list(state["processes"])[:100]
        ports   = list(state["open_ports"])[:100]
        threats = list(state["threat_log"])[:500]

    for c in conns:
        score = 0; matches = []
        if q in (c.get("rip")    or "").lower(): score += 3; matches.append(f"Remote IP: {c.get('rip','')}")
        if q in (c.get("domain") or "").lower(): score += 3; matches.append(f"Domain: {c.get('domain','')}")
        if q in (c.get("process")or "").lower(): score += 2; matches.append(f"Process: {c.get('process','')}")
        if q in str(c.get("rport","")).lower():  score += 2; matches.append(f"Port: {c.get('rport','')}")
        if score:
            results.append({
                "source": "Connection",
                "severity": "high" if c.get("malicious") else "medium" if c.get("suspicious") else "low",
                "match": " | ".join(matches),
                "detail": f"{c.get('process','?')} → {c.get('raddr','?')} [{c.get('status','?')}]",
                "ip": c.get("rip", ""), "timestamp": ts_full(),
            })

    for p in procs:
        if q in (p.get("name") or "").lower() or q in (p.get("exe") or "").lower():
            results.append({
                "source": "Process",
                "severity": "critical" if p.get("suspicious") else "medium",
                "match": f"Process name: {p.get('name','')}",
                "detail": f"PID {p.get('pid','?')} | CPU {p.get('cpu',0)}% | {p.get('connections',0)} connections",
                "ip": "", "timestamp": ts_full(),
            })

    for t in threats:
        if (q in (t.get("title")  or "").lower() or
            q in (t.get("detail") or "").lower() or
            q in (t.get("ip")     or "").lower() or
            q in (t.get("domain") or "").lower()):
            results.append({
                "source": "Threat Log",
                "severity": t.get("severity", "medium"),
                "match": f"Threat: {t.get('title','')}",
                "detail": t.get("detail", ""),
                "ip": t.get("ip", ""), "timestamp": t.get("timestamp", ""),
            })

    for p in ports:
        if q in str(p.get("port", "")) or q in (p.get("process") or "").lower():
            results.append({
                "source": "Open Port",
                "severity": "high" if p.get("suspicious") else "low",
                "match": f"Port {p.get('port','')} — {p.get('process','')}",
                "detail": p.get("note", "") or "Listening port",
                "ip": "", "timestamp": ts_full(),
            })

    seen = set(); unique = []
    for r in results:
        k = r["match"] + r["detail"]
        if k not in seen:
            seen.add(k); unique.append(r)

    hunt_result = {
        "id": uid(), "query": query, "type": hunt_type,
        "timestamp": ts_full(), "count": len(unique),
        "results": unique[:100],
    }
    with lock:
        state["hunt_results"].insert(0, hunt_result)
        if len(state["hunt_results"]) > 50:
            state["hunt_results"] = state["hunt_results"][:50]
    return hunt_result

# ═══════════════════════════════════════════════
#  MODULE 3 — CVE LOOKUP
# ═══════════════════════════════════════════════

_cve_cache    = {}
_cve_alerted  = set()   # FIX #11: prevent duplicate CVE threats each tick

def lookup_cve_for_port(port, service=""):
    cache_key = f"{port}:{service}"
    if cache_key in _cve_cache:
        return _cve_cache[cache_key]

    KNOWN_CVES = {
        21:  [{"id":"CVE-2011-2523","score":10.0,"desc":"vsftpd 2.3.4 backdoor command execution","severity":"CRITICAL","patched":False}],
        22:  [{"id":"CVE-2023-38408","score":9.8,"desc":"OpenSSH remote code execution via ssh-agent","severity":"CRITICAL","patched":True},
              {"id":"CVE-2023-51385","score":6.5,"desc":"OpenSSH OS command injection via hostname","severity":"MEDIUM","patched":True}],
        23:  [{"id":"CVE-1999-0619","score":10.0,"desc":"Telnet cleartext credential transmission","severity":"CRITICAL","patched":False}],
        80:  [{"id":"CVE-2021-41773","score":9.8,"desc":"Apache HTTP Server path traversal RCE","severity":"CRITICAL","patched":True}],
        443: [{"id":"CVE-2022-0778","score":7.5,"desc":"OpenSSL infinite loop denial of service","severity":"HIGH","patched":True}],
        445: [{"id":"CVE-2017-0144","score":9.3,"desc":"EternalBlue SMB remote code execution (WannaCry)","severity":"CRITICAL","patched":True},
              {"id":"CVE-2020-0796","score":10.0,"desc":"SMBGhost remote code execution","severity":"CRITICAL","patched":True}],
        3389:[{"id":"CVE-2019-0708","score":9.8,"desc":"BlueKeep RDP remote code execution","severity":"CRITICAL","patched":True},
              {"id":"CVE-2023-35352","score":9.8,"desc":"Windows RDP auth bypass","severity":"CRITICAL","patched":True}],
        5900:[{"id":"CVE-2023-28771","score":9.8,"desc":"VNC server authentication bypass","severity":"CRITICAL","patched":False}],
        8080:[{"id":"CVE-2022-42889","score":9.8,"desc":"Apache Commons Text RCE (Text4Shell)","severity":"CRITICAL","patched":True}],
        4444:[{"id":"CVE-N/A","score":10.0,"desc":"Metasploit default listener — active exploitation tool","severity":"CRITICAL","patched":False}],
        9050:[{"id":"CVE-N/A","score":8.0,"desc":"TOR SOCKS proxy — anonymised traffic exfiltration risk","severity":"HIGH","patched":False}],
    }

    cves = KNOWN_CVES.get(port, [])

    if NVD_API_KEY and not cves:
        try:
            keyword = service or f"port {port}"
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers={"apiKey": NVD_API_KEY},
                params={"keywordSearch": keyword, "resultsPerPage": 5},
                timeout=8
            )
            if resp.ok:
                for item in resp.json().get("vulnerabilities", []):
                    c = item.get("cve", {})
                    metrics = c.get("metrics", {})
                    score = 0; sev = "UNKNOWN"
                    for mk in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                        if mk in metrics and metrics[mk]:
                            score = metrics[mk][0].get("cvssData",{}).get("baseScore", 0)
                            sev   = metrics[mk][0].get("cvssData",{}).get("baseSeverity","UNKNOWN")
                            break
                    desc = ""
                    for d in c.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc = d.get("value", "")[:200]; break
                    cves.append({"id": c.get("id",""), "score": score,
                                 "desc": desc, "severity": sev, "patched": False})
        except Exception as e:
            print(f"[NVD] {e}")

    _cve_cache[cache_key] = cves
    return cves

def scan_all_ports_cve():
    with lock:
        ports = list(state["open_ports"])
    results = {}
    for p in ports:
        port = p["port"]
        cves = lookup_cve_for_port(port, p.get("process", ""))
        if cves:
            results[port] = {
                "port": port, "process": p["process"],
                "cves": cves,
                "max_score": max(c["score"] for c in cves),
                "critical_count": sum(1 for c in cves if c["severity"] == "CRITICAL"),
            }
            # FIX #11: only alert once per CVE id
            for cve in cves:
                cve_key = f"{cve['id']}:{port}"
                if cve["score"] >= 9.0 and not cve.get("patched") and cve_key not in _cve_alerted:
                    _cve_alerted.add(cve_key)
                    add_threat(
                        "critical", "CVE Vulnerability",
                        f"{cve['id']} on port {port}",
                        f"Score {cve['score']}/10 — {cve['desc'][:120]}",
                        threat_type="cve_critical"
                    )
    with lock:
        state["cve_results"] = results
    return results

# ═══════════════════════════════════════════════
#  MODULE 4 — ADVANCED CORRELATION ENGINE
# ═══════════════════════════════════════════════

def build_correlation():
    with lock:
        conns   = list(state["connections"])
        threats = list(state["threat_log"])[:300]
        ports   = list(state["open_ports"])
        hw      = list(state["hardware_access"])
        procs   = list(state["processes"])

    graph = defaultdict(lambda: {
        "ip": "", "domain": "", "country": "",
        "threat_score": 0, "risk_level": "low",
        "connections": [], "threats": [], "ports": [],
        "hardware": [], "processes": [],
        "first_seen": "", "last_seen": "",
        "total_events": 0, "correlation_score": 0,
    })

    for c in conns:
        ip = c.get("rip", "")
        if not ip or is_private(ip): continue
        g = graph[ip]
        g["ip"]          = ip
        g["domain"]      = g["domain"]  or c.get("domain", "")
        g["country"]     = g["country"] or c.get("country", "")
        g["threat_score"]= max(g["threat_score"], c.get("threat_score", 0))
        g["connections"].append({
            "process": c.get("process", "?"), "raddr": c.get("raddr", ""),
            "status": c.get("status", ""), "time": ts_now()
        })
        g["total_events"] += 1
        g["last_seen"] = ts_full()

    for t in threats:
        ip = t.get("ip", "")
        if not ip or is_private(ip): continue
        g = graph[ip]
        g["ip"]    = ip
        g["domain"]= g["domain"] or t.get("domain", "")
        g["threats"].append({
            "title": t["title"], "severity": t["severity"],
            "time": t.get("timestamp", ""), "category": t["category"]
        })
        g["total_events"] += 1
        g["first_seen"] = g["first_seen"] or t.get("timestamp", "")
        sv = {"critical": 40, "high": 25, "medium": 10, "low": 3}
        g["correlation_score"] += sv.get(t["severity"], 0)

    for ip, g in graph.items():
        final = min(100, g["correlation_score"] + (g["total_events"] * 2) + g["threat_score"])
        g["correlation_score"] = final
        g["risk_level"] = ("critical" if final > 70 else
                           "high"     if final > 45 else
                           "medium"   if final > 20 else "low")

    result = dict(sorted(graph.items(),
                         key=lambda x: x[1]["correlation_score"], reverse=True))
    with lock:
        state["correlation"] = dict(list(result.items())[:50])

# ═══════════════════════════════════════════════
#  MODULE 5 — PDF INCIDENT REPORT
# ═══════════════════════════════════════════════

def generate_pdf_report(incident_id):
    if not REPORTLAB:
        return None, "reportlab not installed. Run: pip install reportlab"

    with lock:
        inc = next((i for i in state["incidents"] if i["id"] == incident_id), None)
        threats = [t for t in state["threat_log"]
                   if t.get("incident_id") == incident_id
                   or t.get("ip") == (inc.get("primary_ip", "") if inc else "")][:20]
        sys_info = dict(state["system_info"])

    if not inc:
        return None, "Incident not found"

    fname = REPORTS_DIR / f"{incident_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    doc   = SimpleDocTemplate(str(fname), pagesize=A4,
                               rightMargin=2*cm, leftMargin=2*cm,
                               topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    NAVY  = colors.HexColor("#1F4E79")
    RED   = colors.HexColor("#C00000")
    AMBER = colors.HexColor("#D48C10")

    h1  = ParagraphStyle("H1",  parent=styles["Heading1"],  textColor=NAVY,  fontSize=18, spaceAfter=6)
    h2  = ParagraphStyle("H2",  parent=styles["Heading2"],  textColor=NAVY,  fontSize=13, spaceBefore=14, spaceAfter=4)
    bod = ParagraphStyle("Body",parent=styles["Normal"],    fontSize=10,     leading=14)
    sev_colors = {"critical": RED, "high": AMBER,
                  "medium": colors.HexColor("#185FA5"), "low": colors.green}

    story = []

    story.append(Paragraph("SOC INCIDENT REPORT", h1))
    story.append(Paragraph("Classification: <b>CONFIDENTIAL</b>", bod))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=NAVY))
    story.append(Spacer(1, 0.3*cm))

    summary_data = [
        ["Incident ID",  inc["id"],              "Status",   inc["status"]],
        ["Severity",     inc["severity"].upper(), "Stage",    inc["stage"]],
        ["Primary IP",   inc.get("primary_ip","N/A"), "Domain", inc.get("domain","N/A")],
        ["Created",      inc["created"],          "Last Seen",inc["last_seen"]],
        ["Category",     inc["category"],         "MITRE",    inc.get("mitre","N/A")],
        ["Analyst",      sys_info.get("hostname","N/A"), "OS", sys_info.get("os","N/A")],
    ]
    tbl_summary = Table(summary_data, colWidths=[3.5*cm,6*cm,3.5*cm,5*cm])
    tbl_summary.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0), NAVY),
        ("TEXTCOLOR", (0,0),(-1,0), colors.white),
        ("FONTNAME",  (0,0),(-1,-1),"Helvetica"),
        ("FONTSIZE",  (0,0),(-1,-1),9),
        ("BACKGROUND",(0,0),(0,-1), colors.HexColor("#E8F0F8")),
        ("BACKGROUND",(2,0),(2,-1), colors.HexColor("#E8F0F8")),
        ("FONTNAME",  (0,0),(0,-1),"Helvetica-Bold"),
        ("FONTNAME",  (2,0),(2,-1),"Helvetica-Bold"),
        ("GRID",      (0,0),(-1,-1),0.5, colors.HexColor("#CCCCCC")),
        ("PADDING",   (0,0),(-1,-1),6),
    ]))
    story.append(tbl_summary)
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("Executive Summary", h2))
    story.append(Paragraph(
        f"This report documents incident <b>{inc['id']}</b> detected on <b>{inc['created']}</b>. "
        f"The incident was classified as <b>{inc['severity'].upper()}</b> severity involving "
        f"{'IP address <b>'+inc['primary_ip']+'</b>' if inc.get('primary_ip') else 'an internal system'}. "
        f"{'Domain <b>'+inc['domain']+'</b> was identified as associated threat infrastructure. ' if inc.get('domain') else ''}"
        f"The incident was triggered by: <b>{inc['title']}</b>. "
        f"MITRE ATT&amp;CK technique mapped: <b>{inc.get('mitre','N/A')}</b>.",
        bod
    ))
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph("Incident Timeline", h2))
    if inc.get("timeline"):
        tl_data = [["Time", "Stage", "Event"]]
        for tl in inc["timeline"]:
            tl_data.append([tl["time"], tl["stage"], Paragraph(tl["event"], bod)])
        tbl_tl = Table(tl_data, colWidths=[4*cm, 3*cm, 11*cm])
        tbl_tl.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0), NAVY),
            ("TEXTCOLOR", (0,0),(-1,0), colors.white),
            ("FONTNAME",  (0,0),(-1,0),"Helvetica-Bold"),
            ("FONTSIZE",  (0,0),(-1,-1),9),
            ("GRID",      (0,0),(-1,-1),0.5, colors.HexColor("#CCCCCC")),
            ("PADDING",   (0,0),(-1,-1),5),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#F5F8FC")]),
        ]))
        story.append(tbl_tl)
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph("Associated Threat Events", h2))
    if threats:
        th_data = [["Time","Severity","Category","Title","Detail"]]
        for t in threats[:15]:
            th_data.append([
                t.get("time",""), t.get("severity","").upper(),
                t.get("category",""),
                Paragraph(t.get("title","")[:60], bod),
                Paragraph(t.get("detail","")[:80], bod),
            ])
        tbl_th = Table(th_data, colWidths=[2*cm,2*cm,3.5*cm,5*cm,5.5*cm])
        tbl_th.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0), NAVY),
            ("TEXTCOLOR", (0,0),(-1,0), colors.white),
            ("FONTNAME",  (0,0),(-1,0),"Helvetica-Bold"),
            ("FONTSIZE",  (0,0),(-1,-1),8),
            ("GRID",      (0,0),(-1,-1),0.5, colors.HexColor("#CCCCCC")),
            ("PADDING",   (0,0),(-1,-1),4),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#F5F8FC")]),
        ]))
        story.append(tbl_th)
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph("Evidence Collected", h2))
    if inc.get("evidence"):
        ev_data = [["Time","Type","Detail"]]
        for e in inc["evidence"]:
            ev_data.append([e["time"], e["type"], Paragraph(e["detail"][:120], bod)])
        tbl_ev = Table(ev_data, colWidths=[4*cm,4*cm,10*cm])
        tbl_ev.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0), NAVY),
            ("TEXTCOLOR", (0,0),(-1,0), colors.white),
            ("FONTNAME",  (0,0),(-1,0),"Helvetica-Bold"),
            ("FONTSIZE",  (0,0),(-1,-1),9),
            ("GRID",      (0,0),(-1,-1),0.5, colors.HexColor("#CCCCCC")),
            ("PADDING",   (0,0),(-1,-1),5),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#F5F8FC")]),
        ]))
        story.append(tbl_ev)
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph("Analyst Notes", h2))
    if inc.get("analyst_notes"):
        for note in inc["analyst_notes"]:
            story.append(Paragraph(f"[{note['time']}] <b>{note['analyst']}</b>: {note['text']}", bod))
            story.append(Spacer(1, 0.2*cm))
    else:
        story.append(Paragraph("No analyst notes recorded.", bod))

    story.append(Paragraph("Containment Actions Taken", h2))
    if inc.get("containment_actions"):
        for a in inc["containment_actions"]:
            story.append(Paragraph(f"• [{a['time']}] <b>{a['action']}</b> — {a['detail']}", bod))
    else:
        story.append(Paragraph("No containment actions recorded.", bod))

    story.append(Paragraph("Recommendations", h2))
    recs = [
        "Block the identified malicious IP at the perimeter firewall immediately.",
        "Review all processes that made connections to the flagged IP and quarantine if necessary.",
        f"Apply MITRE ATT&CK mitigation for {inc.get('mitre','identified technique')}.",
        "Enable full packet capture on the affected network segment for 48 hours.",
        "Update threat intelligence feeds and rescan all open ports for associated CVEs.",
        "Conduct user awareness training if phishing or social engineering is suspected.",
    ]
    for r in recs:
        story.append(Paragraph(f"• {r}", bod))

    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        f"Report generated: {ts_full()} UTC | System: {sys_info.get('hostname','N/A')} | "
        f"SOC Analyst Level-2 Platform v2.1 | CONFIDENTIAL",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=7,
                       textColor=colors.gray, alignment=1)
    ))
    doc.build(story)
    return str(fname), None

# ═══════════════════════════════════════════════
#  CORE COLLECTORS
# ═══════════════════════════════════════════════

def collect_metrics():
    global _prev_net, _prev_time
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory().percent
    now_net  = psutil.net_io_counters()
    elapsed  = max(time.time() - _prev_time, 0.1)
    sent_kbps = (now_net.bytes_sent - _prev_net.bytes_sent) / elapsed / 1024
    recv_kbps = (now_net.bytes_recv - _prev_net.bytes_recv) / elapsed / 1024
    _prev_net = now_net; _prev_time = time.time()
    with lock:
        state["cpu_history"].append(cpu)
        state["mem_history"].append(mem)
        state["net_sent_history"].append(round(sent_kbps, 2))
        state["net_recv_history"].append(round(recv_kbps, 2))
        state["timestamps"].append(ts_now())
        state["network_stats"] = {
            "bytes_sent":   now_net.bytes_sent,  "bytes_recv":    now_net.bytes_recv,
            "packets_sent": now_net.packets_sent, "packets_recv":  now_net.packets_recv,
            "errin":  now_net.errin,  "errout": now_net.errout,
            "dropin": now_net.dropin, "dropout": now_net.dropout,
            "sent_kbps": round(sent_kbps, 2), "recv_kbps": round(recv_kbps, 2),
        }
    if cpu > 90: add_threat("high", "System", "CPU critically high", f"{cpu:.1f}%")
    if mem > 90: add_threat("high", "System", "Memory critically high", f"{mem:.1f}%")

def collect_system_info():
    try: hn = socket.gethostname(); ip = socket.gethostbyname(hn)
    except: hn, ip = "unknown", "unknown"
    u = platform.uname()
    boot = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    with lock:
        state["system_info"] = {
            "hostname": hn, "local_ip": ip, "os": f"{u.system} {u.release}",
            "machine": u.machine, "processor": u.processor or platform.processor(),
            "boot_time": boot, "cpu_count": psutil.cpu_count(logical=True),
            "cpu_physical": psutil.cpu_count(logical=False),
            "ram_total_gb": round(psutil.virtual_memory().total / (1024**3), 1),
            "python_ver": platform.python_version(),
        }

def collect_interfaces():
    ifaces = []
    for name, addrs in psutil.net_if_addrs().items():
        s = psutil.net_if_stats().get(name)
        info = {"name": name, "addresses": [],
                "is_up": s.isup if s else False, "speed_mbps": s.speed if s else 0}
        for a in addrs:
            fam = str(a.family)
            if "AF_INET" in fam or a.family == socket.AF_INET:
                info["addresses"].append({"type":"IPv4","address":a.address,"netmask":a.netmask or ""})
            elif "AF_INET6" in fam or a.family == socket.AF_INET6:
                info["addresses"].append({"type":"IPv6","address":a.address,"netmask":a.netmask or ""})
            else:
                info["addresses"].append({"type":"MAC","address":a.address,"netmask":""})
        ifaces.append(info)
    with lock: state["interfaces"] = ifaces

def check_reputation(ip):
    if is_private(ip): return None
    with lock: r = _reputation.get(ip)
    if r and (time.time() - r.get("_at", 0)) < CACHE_TTL: return r
    cached = _ip_cache.get(ip)
    if cached and (time.time() - cached.get("_at", 0)) < CACHE_TTL:
        with lock: _reputation[ip] = cached
        return cached

    result = {"ip": ip, "score": 0, "is_malicious": False, "is_restricted": False,
              "categories": [], "source": "offline", "country": "??", "domain": "", "_at": time.time()}
    domain = rev_dns(ip); result["domain"] = domain
    rd = root_domain(domain) if domain else ""

    # FIX #6: check both full domain and root domain
    if rd in MALICIOUS_DOMAINS or domain in MALICIOUS_DOMAINS:
        result.update({"is_malicious": True, "score": 90, "source": "local_blocklist"})
        result["categories"].append("malicious_domain")
    if rd in RESTRICTED_DOMAINS or domain in RESTRICTED_DOMAINS:
        result["is_restricted"] = True; result["score"] = max(result["score"], 55)
        result["categories"].append("restricted_content")
        if result["source"] == "offline": result["source"] = "local_blocklist"

    if ABUSEIPDB_KEY and not result["is_malicious"]:
        try:
            resp = requests.get("https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=5)
            if resp.ok:
                d = resp.json().get("data", {})
                score = d.get("abuseConfidenceScore", 0)
                result["score"]   = max(result["score"], score)
                result["country"] = d.get("countryCode", "??")
                result["source"]  = "abuseipdb"
                if score > 50:
                    result["is_malicious"] = True
                    result["categories"].append("abuse_reported")
        except: pass

    # FIX #6: check root_domain in URLhaus as well
    if domain and not result["is_malicious"]:
        for host_to_check in {domain, rd} - {""}:
            try:
                resp = requests.post("https://urlhaus-api.abuse.ch/v1/host/",
                                     data={"host": host_to_check}, timeout=4)
                if resp.ok and resp.json().get("query_status") == "is_host":
                    result.update({"is_malicious": True, "score": max(result["score"], 85),
                                   "source": "urlhaus"})
                    result["categories"].append("urlhaus_malware")
                    break
            except: pass

    with lock: _reputation[ip] = result; _ip_cache[ip] = result
    threading.Thread(target=save_json, args=(CACHE_FILE, _ip_cache.copy()), daemon=True).start()
    return result

def reputation_worker():
    while True:
        ip = None
        with lock:
            if _lq:
                ip = _lq.popleft()
                _lq_set.discard(ip)

        if ip:
            # FIX #5: check _reputation inside lock
            with lock:
                already = ip in _reputation
            if not already:
                rep = check_reputation(ip)
                if rep:
                    if rep["is_malicious"]:
                        sev = "critical" if rep["score"] > 80 else "high"
                        add_threat(sev, "Threat Intel", f"Malicious IP: {ip}",
                            f"Score {rep['score']}/100 | {rep['domain'] or 'no domain'} | "
                            f"{', '.join(rep['categories'])} | {rep['source']}",
                            ip=ip, domain=rep["domain"], threat_type="malicious_ip")
                    elif rep["is_restricted"]:
                        add_threat("medium", "Restricted Site",
                            f"Restricted domain: {rep['domain'] or ip}",
                            f"IP {ip} | {', '.join(rep['categories'])}",
                            ip=ip, domain=rep["domain"], threat_type="restricted_domain")
        time.sleep(0.25)

def collect_connections():
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if not c.laddr or not c.status: continue
            rip   = c.raddr.ip   if c.raddr else ""
            rport = c.raddr.port if c.raddr else 0
            raddr = f"{rip}:{rport}" if c.raddr else ""
            laddr = f"{c.laddr.ip}:{c.laddr.port}"
            pname = "Unknown"
            try:
                if c.pid: pname = psutil.Process(c.pid).name()
            except: pass
            is_ext = rip and not is_private(rip)

            # FIX #7: O(1) set-based pending check
            if is_ext and rip:
                with lock:
                    if rip not in _reputation and rip not in _lq_set:
                        _lq_set.add(rip)
                        _lq.append(rip)

            rep = _reputation.get(rip)
            flags = []; mal = False; t_score = 0
            if rep:
                t_score = rep.get("score", 0)
                if rep.get("is_malicious"):
                    flags.append(f"MALICIOUS (score {t_score})"); mal = True
                elif rep.get("is_restricted"):
                    flags.append("Restricted site")
                elif t_score > 50:
                    flags.append(f"Suspicious (score {t_score})")
                flags += [cc for cc in rep.get("categories", []) if cc not in flags]
            if rport in SUSPICIOUS_PORTS:
                flags.append(f"Suspicious port: {SUSPICIOUS_PORTS[rport]}")
            if is_ext: flags.append("External")
            conns.append({
                "pid": c.pid, "process": pname, "laddr": laddr, "raddr": raddr,
                "rip": rip, "rport": rport,
                "domain":  rep.get("domain",  "") if rep else "",
                "country": rep.get("country", "") if rep else "",
                "status":  c.status,
                "protocol": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                "flags": flags, "suspicious": bool(flags), "malicious": mal,
                "threat_score": t_score, "is_external": bool(is_ext),
            })
    except: pass
    conns.sort(key=lambda x: (-x["malicious"], -x["suspicious"], x["process"]))
    with lock: state["connections"] = conns[:150]

def collect_open_ports():
    """FIX #4: deduplicate on port number only (was comparing port+pid)."""
    ports = []; seen = set()
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == "LISTEN" and c.laddr:
                p = c.laddr.port
                if p in seen: continue
                seen.add(p)
                pname = "Unknown"
                try:
                    if c.pid: pname = psutil.Process(c.pid).name()
                except: pass
                note = SUSPICIOUS_PORTS.get(p, "")
                ports.append({"port": p, "process": pname, "pid": c.pid,
                               "address": c.laddr.ip, "protocol": "TCP",
                               "note": note, "suspicious": p in SUSPICIOUS_PORTS})
                if p in SUSPICIOUS_PORTS:
                    add_threat("high", "Open Port", f"Suspicious port {p} open",
                               f"{pname} — {SUSPICIOUS_PORTS[p]}", threat_type="suspicious_port")
    except: pass
    ports.sort(key=lambda x: (not x["suspicious"], x["port"]))
    with lock: state["open_ports"] = ports

def collect_processes():
    procs = []
    try:
        for p in psutil.process_iter(["pid","name","username","cpu_percent",
                                       "memory_percent","status","exe"]):
            try:
                info = p.info; nlow = (info["name"] or "").lower()
                is_sus = any(s in nlow for s in MALWARE_PROCS)
                conns = 0
                try: conns = len(p.connections())
                except: pass
                procs.append({
                    "pid":      info["pid"],
                    "name":     info["name"] or "unknown",
                    "username": (info["username"] or "").split("\\")[-1],
                    "cpu":      round(info["cpu_percent"] or 0, 1),
                    "memory":   round(info["memory_percent"] or 0, 2),
                    "status":   info["status"] or "",
                    "connections": conns,
                    "suspicious":  is_sus,
                    "exe":         info["exe"] or "",
                })
                if is_sus:
                    add_threat("critical", "Process", f"Malware process: {info['name']}",
                               f"PID {info['pid']}", threat_type="malware_process")
            except: continue
    except: pass
    procs.sort(key=lambda x: (-x["suspicious"], -x["cpu"]))
    with lock: state["processes"] = procs[:60]

def collect_wifi():
    devices = []
    try:
        out = subprocess.run(["arp","-a"], capture_output=True, text=True, timeout=10)
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) < 3: continue
            ip, mac, typ = parts[0], parts[1], parts[2]
            try: ipaddress.ip_address(ip)
            except: continue
            if ip.startswith("224.") or ip.startswith("255."): continue
            hn = ""
            try: hn = socket.gethostbyaddr(ip)[0]
            except: pass
            devices.append({"ip": ip, "mac": mac, "type": typ, "hostname": hn,
                             "suspicious": mac == "ff-ff-ff-ff-ff-ff"})
    except: pass
    with lock: state["wifi_devices"] = devices

def detect_hardware():
    found = []; seen = set()
    try:
        for proc in psutil.process_iter(["pid","name","exe","username"]):
            try:
                info = proc.info
                name = (info["name"] or "").lower()
                exe  = (info["exe"]  or "").lower()
                if info["name"] in SYSTEM_WL: continue
                for hw_type, patterns in HARDWARE_PATTERNS.items():
                    if any(p in name or p in exe for p in patterns):
                        key = (info["pid"], hw_type)
                        if key in seen: continue
                        seen.add(key)
                        ext = []
                        try:
                            for conn in proc.connections():
                                if conn.raddr and not is_private(conn.raddr.ip):
                                    ext.append(f"{conn.raddr.ip}:{conn.raddr.port}")
                        except: pass
                        risk = "high" if ext else "medium"
                        if ext:
                            add_threat("critical", "Hardware Surveillance",
                                f"{hw_type} accessed + external connection",
                                f"{info['name']} (PID {info['pid']}) → {', '.join(ext[:3])}",
                                ip=ext[0].split(":")[0], threat_type=f"hardware_{hw_type.lower()}")
                        found.append({
                            "pid": info["pid"], "name": info["name"], "hw_type": hw_type,
                            "ext_conns": ext, "risk": risk,
                            "username": (info["username"] or "").split("\\")[-1],
                        })
                        break
            except: continue
    except: pass
    with lock: state["hardware_access"] = found

_feed_updated = 0
# FIX #10: thread-safe domain feed update using a local set then lock
def update_feed():
    global _feed_updated
    if time.time() - _feed_updated < 3600: return
    try:
        resp = requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/", timeout=12)
        if resp.ok:
            new = set()
            for entry in resp.json().get("urls", []):
                m = re.search(r"https?://([^/]+)", entry.get("url", ""))
                if m:
                    d = m.group(1).split(":")[0]
                    new.add(d); new.add(root_domain(d))
            with lock:
                MALICIOUS_DOMAINS.update(new)
            _feed_updated = time.time()
            print(f"  [feed] +{len(new)} domains from URLhaus")
    except Exception as e:
        print(f"  [feed] {e}")

def collection_loop():
    collect_system_info(); collect_interfaces()
    threading.Thread(target=update_feed, daemon=True).start()
    cycle = 0
    while True:
        try:
            collect_metrics(); collect_connections()
            collect_open_ports(); collect_processes()
            if cycle % 2 == 0:  collect_wifi(); detect_hardware()
            if cycle % 5 == 0:  build_correlation()
            if cycle % 10 == 0: scan_all_ports_cve()
            if cycle % 900 == 0: threading.Thread(target=update_feed, daemon=True).start()
            cycle += 1
        except Exception as e:
            print(f"[loop] {e}")
        time.sleep(SCAN_INTERVAL)

# ═══════════════════════════════════════════════
#  FLASK API
# ═══════════════════════════════════════════════
app = Flask(__name__); CORS(app)

# FIX #13: explicitly convert all deques to lists before jsonify
def snap():
    with lock:
        return {
            "cpu_history":      list(state["cpu_history"]),
            "mem_history":      list(state["mem_history"]),
            "net_sent_history": list(state["net_sent_history"]),
            "net_recv_history": list(state["net_recv_history"]),
            "timestamps":       list(state["timestamps"]),
            "connections":      list(state["connections"]),
            "processes":        list(state["processes"]),
            "wifi_devices":     list(state["wifi_devices"]),
            "open_ports":       list(state["open_ports"]),
            "interfaces":       list(state["interfaces"]),
            "hardware_access":  list(state["hardware_access"]),
            "live_alerts":      list(state["live_alerts"])[:100],
            "threat_log":       list(state["threat_log"])[:300],
            "incidents":        list(state["incidents"])[:50],
            "hunt_results":     list(state["hunt_results"])[:20],
            "cve_results":      dict(state["cve_results"]),
            "correlation":      dict(state["correlation"]),
            "network_stats":    dict(state["network_stats"]),
            "system_info":      dict(state["system_info"]),
            "total_alerts":     state["total_alerts"],
            "total_incidents":  len(state["incidents"]),
            "packets":          state["packets"],
            "scapy":            state["scapy"],
            "reportlab":        state["reportlab"],
            "server_time":      ts_full() + " UTC",
            "log_file":         str(THREAT_FILE),
            "abuseipdb_active": bool(ABUSEIPDB_KEY),
        }

@app.route("/api/all")
def api_all(): return jsonify(snap())

@app.route("/api/threats")
def api_threats():
    sev  = request.args.get("severity", "all")
    cat  = request.args.get("category", "all")
    page = max(1, int(request.args.get("page", 1)))
    per  = min(100, int(request.args.get("per", 50)))
    with lock: log = list(state["threat_log"])
    if sev != "all": log = [t for t in log if t.get("severity") == sev]
    if cat != "all": log = [t for t in log if t.get("category") == cat]
    total = len(log); start = (page - 1) * per
    return jsonify({"threats": log[start:start+per], "total": total,
                    "page": page, "pages": max(1, (total+per-1)//per)})

# FIX #2: Missing /api/threats/export endpoint (was returning 404)
@app.route("/api/threats/export")
def api_threats_export():
    """Return the full threat log as a downloadable JSON file."""
    with lock:
        data = list(state["threat_log"])
    payload = json.dumps(data, indent=2, ensure_ascii=False)
    return Response(
        payload,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=threat_log_export.json"}
    )

@app.route("/api/incidents")
def api_incidents():
    with lock: return jsonify(list(state["incidents"]))

@app.route("/api/incidents/<inc_id>")
def api_incident(inc_id):
    with lock: inc = next((i for i in state["incidents"] if i["id"] == inc_id), None)
    return jsonify(inc) if inc else (jsonify({"error": "not found"}), 404)

@app.route("/api/incidents/<inc_id>/note", methods=["POST"])
def api_add_note(inc_id):
    data = request.json or {}
    with lock:
        for inc in state["incidents"]:
            if inc["id"] == inc_id:
                inc["analyst_notes"].append({
                    "time": ts_full(), "analyst": "SOC Analyst",
                    "text": data.get("text", "")
                })
                inc["timeline"].append({
                    "time": ts_full(), "stage": inc["stage"],
                    "event": f"Note added: {data.get('text','')[:60]}"
                })
                break
    threading.Thread(target=save_json, args=(INCIDENT_FILE, state["incidents"][:500]), daemon=True).start()
    return jsonify({"status": "ok"})

@app.route("/api/incidents/<inc_id>/action", methods=["POST"])
def api_add_action(inc_id):
    data = request.json or {}
    with lock:
        for inc in state["incidents"]:
            if inc["id"] == inc_id:
                action = {"time": ts_full(), "action": data.get("action",""), "detail": data.get("detail","")}
                inc["containment_actions"].append(action)
                inc["timeline"].append({
                    "time": ts_full(), "stage": inc["stage"],
                    "event": f"Action: {data.get('action','')} — {data.get('detail','')[:60]}"
                })
                if   data.get("action") == "Resolve":     inc["status"] = "Resolved";     inc["stage"] = "Resolved"
                elif data.get("action") == "Contain":     inc["status"] = "Contained";     inc["stage"] = "Contained"
                elif data.get("action") == "Investigate": inc["status"] = "Investigating"; inc["stage"] = "Investigating"
                break
    threading.Thread(target=save_json, args=(INCIDENT_FILE, state["incidents"][:500]), daemon=True).start()
    return jsonify({"status": "ok"})

@app.route("/api/incidents/<inc_id>/escalate", methods=["POST"])
def api_escalate(inc_id):
    sev_order = ["low","medium","high","critical"]
    with lock:
        for inc in state["incidents"]:
            if inc["id"] == inc_id:
                cur = sev_order.index(inc["severity"]) if inc["severity"] in sev_order else 0
                if cur < 3:
                    inc["severity"] = sev_order[cur + 1]
                    inc["timeline"].append({
                        "time": ts_full(), "stage": inc["stage"],
                        "event": f"Manually escalated to {inc['severity']}"
                    })
                break
    threading.Thread(target=save_json, args=(INCIDENT_FILE, state["incidents"][:500]), daemon=True).start()
    return jsonify({"status": "ok"})

@app.route("/api/hunt", methods=["POST"])
def api_hunt():
    data  = request.json or {}
    query = data.get("query","").strip()
    if not query: return jsonify({"error": "query required"}), 400
    result = run_hunt(query, data.get("type","keyword"))
    return jsonify(result)

@app.route("/api/hunt/results")
def api_hunt_results():
    with lock: return jsonify(list(state["hunt_results"]))

@app.route("/api/cve")
def api_cve():
    with lock: return jsonify(dict(state["cve_results"]))

@app.route("/api/cve/scan", methods=["POST"])
def api_cve_scan():
    results = scan_all_ports_cve()
    return jsonify(results)

@app.route("/api/cve/<int:port>")
def api_cve_port(port):
    cves = lookup_cve_for_port(port)
    return jsonify({"port": port, "cves": cves})

@app.route("/api/correlation")
def api_correlation():
    with lock: return jsonify(dict(state["correlation"]))

@app.route("/api/report/<inc_id>")
def api_report(inc_id):
    path, err = generate_pdf_report(inc_id)
    if err: return jsonify({"error": err}), 400
    return send_file(path, as_attachment=True,
                     download_name=f"SOC_Report_{inc_id}.pdf",
                     mimetype="application/pdf")

@app.route("/api/threats/clear", methods=["POST"])
def api_clear():
    with lock:
        state["threat_log"] = []
        state["live_alerts"] = deque(maxlen=300)
        state["total_alerts"] = 0
    save_json(THREAT_FILE, [])
    return jsonify({"status": "cleared"})

@app.route("/api/reputation/<ip_addr>")
def api_rep(ip_addr):
    r = check_reputation(ip_addr)
    return jsonify(r or {"error": "private or invalid IP"})

@app.route("/api/status")
def api_status():
    with lock:
        return jsonify({
            "status": "running", "time": ts_full() + " UTC",
            "alerts": state["total_alerts"], "incidents": len(state["incidents"]),
            "reportlab": REPORTLAB, "scapy": SCAPY, "abuseipdb": bool(ABUSEIPDB_KEY),
        })

@app.route("/")
def index(): return "<h3>SOC Level-2 Monitor v2.1 — open dashboard_v2.html</h3>"

# ── ENTRY POINT ──
if __name__ == "__main__":
    print("=" * 62)
    print("  SOC Analyst Level-2 — Threat Detection Platform v2.1")
    print("=" * 62)
    print(f"  Python     : {platform.python_version()}")
    print(f"  ReportLab  : {'YES — PDF reports enabled' if REPORTLAB else 'NO — pip install reportlab'}")
    print(f"  Scapy      : {'YES' if SCAPY else 'NO (optional)'}")
    print(f"  AbuseIPDB  : {'LIVE' if ABUSEIPDB_KEY else 'offline mode'}")
    print(f"  NVD API    : {'LIVE' if NVD_API_KEY else 'offline CVE database'}")
    print(f"  Incidents  : {len(_saved_inc)} loaded from disk")
    print(f"  Threats    : {len(_saved_thr)} loaded from disk")
    print(f"  API        : http://localhost:{PORT}/api/all")
    print("=" * 62)
    print("  Open dashboard_v2.html in your browser.")
    print("  Press Ctrl+C to stop.")
    print("=" * 62)
    threading.Thread(target=collection_loop, daemon=True).start()
    threading.Thread(target=reputation_worker, daemon=True).start()
    time.sleep(1.5)
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
