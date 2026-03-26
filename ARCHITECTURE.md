# SOC Platform v2.1 — Architecture & Code Walkthrough

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     dashboard_v2.html                        │
│          (Browser — polls /api/all every 4 seconds)          │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP fetch to localhost:5000
┌────────────────────────▼────────────────────────────────────┐
│                      monitor_v2.py                           │
│                  Flask REST API — port 5000                  │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │   psutil    │  │  AbuseIPDB   │  │  URLhaus / NVD API │  │
│  │ (OS layer)  │  │  (IP rep.)   │  │ (malware / CVEs)   │  │
│  └─────────────┘  └──────────────┘  └────────────────────┘  │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  in-memory state dict  (lock-protected)             │    │
│  │  cpu_history · connections · processes · ports      │    │
│  │  threat_log · incidents · hunt_results · cve_results│    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  Thread 1: collection_loop   (every 4s)                     │
│  Thread 2: reputation_worker (continuous queue drain)        │
│  Thread N: save_json         (daemon, per-write)             │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  threat_log.json · incidents.json · ip_cache.json   │    │
│  │                  (persistent files)                  │    │
│  └─────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

---

## Threading Model

```
Main Thread
├── app.run() — Flask (threaded=True, handles concurrent API requests)
│
├── collection_loop (daemon thread)
│   ├── every 4s:  collect_metrics, collect_connections,
│   │               collect_open_ports, collect_processes
│   ├── every 8s:  collect_wifi, detect_hardware
│   ├── every 20s: build_correlation
│   ├── every 40s: scan_all_ports_cve
│   └── every 1hr: update_feed (URLhaus)
│
├── reputation_worker (daemon thread)
│   └── drains _lq queue, calls check_reputation() per IP
│       └── spawns save_json threads (daemon, fire-and-forget)
│
└── auto_incident (daemon thread, spawned per critical/high alert)
    └── creates or merges incidents
        └── spawns save_json thread
```

All access to `state`, `_reputation`, `_ip_cache`, `_lq`, `_lq_set`, and `MALICIOUS_DOMAINS` is protected by the global `lock` (threading.Lock).

---

## Module Breakdown

### Collectors (`collect_*` functions)

These run in the `collection_loop` thread and update `state` under the lock.

| Function | What it collects | Frequency |
|---|---|---|
| `collect_metrics()` | CPU%, memory%, network KB/s, timestamps | Every 4s |
| `collect_system_info()` | Hostname, OS, RAM, CPU count | Once at startup |
| `collect_interfaces()` | Network interface details | Once at startup |
| `collect_connections()` | All active TCP/UDP connections | Every 4s |
| `collect_open_ports()` | All LISTEN-state ports | Every 4s |
| `collect_processes()` | Top 60 processes by CPU | Every 4s |
| `collect_wifi()` | ARP table (LAN devices) | Every 8s |
| `detect_hardware()` | Camera/mic/GPU/USB process access | Every 8s |

---

### Module 1 — Incident Response

**Key functions:** `auto_incident()`, `get_mitre()`

When `add_threat()` is called with severity `critical` or `high`, it spawns `auto_incident()` in a daemon thread. This function:

1. Searches for an **existing open incident** for the same IP (under lock)
2. If found: appends the alert ID, updates `last_seen`, escalates severity if needed
3. If not found: creates a new `INC-XXXXXX` incident with full timeline, evidence, and MITRE mapping

Incidents are stored in `state["incidents"]` (capped at 500) and persisted to `incidents.json`.

**Stage flow:**
```
Detected → Investigating → Contained → Resolved
```

Stages are set by POST to `/api/incidents/<id>/action` with action `"Investigate"`, `"Contain"`, or `"Resolve"`.

---

### Module 2 — Threat Hunting

**Key function:** `run_hunt(query, hunt_type)`

Searches 4 data sources simultaneously:
1. `state["connections"]` — matches on IP, domain, process name, port
2. `state["processes"]` — matches on name, exe path
3. `state["threat_log"][:500]` — matches on title, detail, IP, domain
4. `state["open_ports"]` — matches on port number, process name

Results are deduplicated by `match + detail` string, scored by source severity, and returned as a list of up to 100 items.

Hunt results are stored in `state["hunt_results"]` (capped at 50) for the "Past Results" view.

---

### Module 3 — CVE Lookup

**Key functions:** `lookup_cve_for_port()`, `scan_all_ports_cve()`

Two data sources:
1. **Offline database** (`KNOWN_CVES` dict): covers ports 21, 22, 23, 80, 443, 445, 3389, 5900, 8080, 4444, 9050 with hard-coded CVE data
2. **NVD API** (optional, requires `NVD_API_KEY`): live lookups for ports not in the offline database

Results are cached in `_cve_cache` (module-level dict, not persisted). The `_cve_alerted` set prevents duplicate threat alerts across scan cycles.

---

### Module 4 — Correlation Engine

**Key function:** `build_correlation()`

Runs every 20 seconds. Builds a graph where each node is an external IP, aggregating:
- All connections to that IP
- All threat log entries for that IP
- Severity-weighted score: critical=40pts, high=25, medium=10, low=3

Final correlation score = `min(100, severity_score + (total_events × 2) + threat_score)`

Risk levels: >70 = critical, >45 = high, >20 = medium, ≤20 = low

Top 50 IPs by score are stored in `state["correlation"]`.

---

### Module 5 — PDF Report Generator

**Key function:** `generate_pdf_report(incident_id)`

Uses ReportLab to generate a structured A4 PDF with:
- Cover / summary table (incident metadata)
- Executive summary paragraph
- Incident timeline table
- Associated threat events table
- Evidence collected table
- Analyst notes
- Containment actions
- Recommendations (static list, contextualised with MITRE technique)
- Footer with generation timestamp

PDFs are saved to `reports/` and streamed back via `send_file()`.

---

### Reputation System

**Key functions:** `check_reputation()`, `reputation_worker()`

**Flow:**
1. `collect_connections()` identifies external IPs
2. If not already in `_reputation` or `_lq_set`, adds to queue: `_lq.append(ip); _lq_set.add(ip)`
3. `reputation_worker()` (continuous daemon thread) drains the queue at 0.25s intervals
4. `check_reputation()` checks in order:
   - In-memory cache (`_reputation`)
   - On-disk cache (`ip_cache.json`, 1hr TTL)
   - Local blocklist (`MALICIOUS_DOMAINS`, `RESTRICTED_DOMAINS`)
   - AbuseIPDB API (if key set)
   - URLhaus API (checks both full domain and root domain)
5. Result stored in `_reputation` and `_ip_cache` (persisted to disk)

---

## State Object Reference

```python
state = {
    # Rolling history (deque, maxlen=120)
    "cpu_history":      deque,
    "mem_history":      deque,
    "net_sent_history": deque,
    "net_recv_history": deque,
    "timestamps":       deque,

    # Live snapshots (replaced each scan cycle)
    "connections":     list,    # max 150 items
    "processes":       list,    # max 60 items
    "wifi_devices":    list,
    "open_ports":      list,
    "interfaces":      list,
    "hardware_access": list,
    "network_stats":   dict,
    "system_info":     dict,

    # Persistent logs
    "live_alerts":  deque,      # maxlen=300
    "threat_log":   list,       # max 3000, persisted to threat_log.json
    "incidents":    list,       # max 500, persisted to incidents.json

    # Module-specific results
    "hunt_results": list,       # max 50
    "cve_results":  dict,       # {port: CVEResult}
    "correlation":  dict,       # {ip: CorrelationNode}, max 50

    # Counters / flags
    "total_alerts": int,
    "scapy":        bool,
    "reportlab":    bool,
    "packets":      int,
}
```

---

## Dashboard JavaScript Architecture

The dashboard is a single-file vanilla JS application with no build system or framework.

**Polling:**  `fetchAll()` runs on startup and every 4 seconds via `setInterval`. It fetches `/api/all`, updates the `D` global, and calls `renderTab(activeTab())`.

**Tab system:** `tab(name)` toggles CSS classes on `.tab` and `.panel` elements. Each tab has a corresponding `render*()` function that reads from `D`.

**Charts:** Chart.js line charts are initialised once and updated via `chart.data.labels = ...` + `chart.update('none')` for smooth updates without re-creating the DOM element.

**Mutating actions** (add note, resolve incident, escalate) call the API directly via `fetch()` and then call `fetchAll()` to refresh state.

**Key design decisions:**
- No reactive framework — just direct DOM manipulation via `innerHTML`
- All rendering is idempotent — calling `renderThreats()` twice produces the same output
- Filters (severity, category, search) are all client-side on the already-fetched data, so they're instant
