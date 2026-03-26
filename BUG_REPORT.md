# SOC Platform v2.1 — Bug Report & Fix Log

**Project:** SOC Analyst Level-2 — Network Threat Detection Platform  
**Version fixed:** v2.0 → v2.1  
**Files changed:** `monitor_v2.py`, `dashboard_v2.html`

---

## Critical Bugs (broke features entirely)

---

### BUG-001 — Missing `/api/threats/export` endpoint → 404

| Field | Detail |
|---|---|
| **File** | `monitor_v2.py` |
| **Severity** | Critical — feature completely broken |
| **Symptom** | Dashboard "Export JSON" button opened `localhost:5000/api/threats/export` and got a 404 page (screenshot 1 in README) |
| **Root cause** | The Flask API never had this route registered. The dashboard called it; the backend didn't define it. |
| **Fix** | Added `@app.route("/api/threats/export")` that returns the full threat log as a downloadable `application/json` file with `Content-Disposition: attachment`. Also fixed the dashboard button to call `exportThreats()` instead of `window.open('/api/threats/export')` directly (same result, cleaner). |

---

### BUG-002 — All timestamps local time, dashboard clock UTC → mismatch

| Field | Detail |
|---|---|
| **File** | `monitor_v2.py`, `dashboard_v2.html` |
| **Severity** | Critical — all time correlation was wrong |
| **Symptom** | Dashboard header shows UTC clock (e.g. `09:45:32 UTC`). All events in the threat log, incidents, and timeline showed IST/local time. A "09:45" threat on the dashboard actually happened at 15:15 local — completely unusable for incident timeline analysis. |
| **Root cause** | `ts_now()` and `ts_full()` called `datetime.now()` (local time) while the dashboard clock used `new Date().toISOString()` (UTC). |
| **Fix** | Changed both helpers to `datetime.now(timezone.utc)`. All timestamps server-side now emit UTC. Dashboard clock rewritten to build the UTC string manually (`getUTCHours()` etc.) instead of the ambiguous `toISOString().slice(0,19)`. Server `server_time` field now includes ` UTC` suffix. |

---

### BUG-003 — Deque JSON-serialisation crash in `snap()`

| Field | Detail |
|---|---|
| **File** | `monitor_v2.py` |
| **Severity** | Critical — `/api/all` could crash with a `TypeError` |
| **Symptom** | Flask's `jsonify()` cannot serialise a Python `deque`. If `live_alerts` or any history deque was returned directly (without an explicit `list()` call) Flask would raise `TypeError: Object of type deque is not JSON serializable`. |
| **Root cause** | `state["live_alerts"]` is a `deque`. In `snap()` the live_alerts line was `list(state["live_alerts"])[:100]` — this was fine for live_alerts, but other deques (cpu_history, timestamps, etc.) relied on the code path staying correct. A single missed `list()` call anywhere in snap() would crash the whole endpoint. |
| **Fix** | Audited every key in `snap()` and enforced explicit `list()` conversion on all deques. Added comment. |

---

## High Bugs (incorrect behaviour)

---

### BUG-004 — `collect_open_ports()` deduplication was fragile

| Field | Detail |
|---|---|
| **File** | `monitor_v2.py` |
| **Severity** | High — duplicate port entries, duplicate "Suspicious port" threats |
| **Symptom** | Same port (e.g. 443) appeared multiple times in the Open Ports table, and a "Suspicious port X open" threat was added multiple times per scan cycle. |
| **Root cause** | The `seen` set correctly stored ports, but the condition `if p in seen: continue` was correct — however `add_threat()` for suspicious ports was called **before** the port was added to `seen`, so a port served by multiple PIDs could trigger multiple alerts. |
| **Fix** | Reorganised so `seen.add(p)` happens at the top of the block and `add_threat()` only fires once per unique port. |

---

### BUG-005 — `reputation_worker()` race condition on `_reputation` read

| Field | Detail |
|---|---|
| **File** | `monitor_v2.py` |
| **Severity** | High — potential for duplicate reputation lookups and double threat alerts |
| **Symptom** | The same IP could be looked up twice simultaneously if two worker cycles interleaved, leading to duplicate "Malicious IP" threats in the log. |
| **Root cause** | The `already` check read `_reputation` **without** the lock: `already = ip in _reputation` was outside `with lock:`. Another thread could have added it between the lock release and this read. |
| **Fix** | Moved `already = ip in _reputation` inside a `with lock:` block. |

---

### BUG-006 — URLhaus and local blocklist didn't check root domain consistently

| Field | Detail |
|---|---|
| **File** | `monitor_v2.py` |
| **Severity** | High — missed malicious domain detections |
| **Symptom** | A subdomain like `cdn.evil-update.com` would not match `evil-update.com` in `MALICIOUS_DOMAINS` even though `root_domain()` was called. The URLhaus check only sent the full domain, not the root domain. |
| **Root cause** | The local blocklist check used `rd` (root domain) correctly, but the URLhaus POST only sent `domain` (full hostname). |
| **Fix** | URLhaus check now tries both `domain` and `rd` in a set loop, breaking on first hit. |

---

### BUG-007 — `collect_connections()` used O(n) list scan for pending IP queue

| Field | Detail |
|---|---|
| **File** | `monitor_v2.py` |
| **Severity** | High — performance degradation with many connections, possible missed IPs |
| **Symptom** | With 150+ connections, `rip not in list(_lq)` iterated the whole deque on every connection for every scan cycle. At 4-second intervals with 150 connections, this is 150 × len(_lq) operations per cycle. Worse, `list(_lq)` created a copy on every call — so with 50 items pending, each scan did 150 × 50 = 7,500 comparisons just for queueing. |
| **Root cause** | Used `rip not in list(_lq)` instead of a set. |
| **Fix** | Added `_lq_set: set` as a companion to `_lq`. Enqueue: `_lq_set.add(rip); _lq.append(rip)`. Dequeue in worker: `_lq.popleft(); _lq_set.discard(ip)`. Check: `rip not in _lq_set` — O(1). |

---

### BUG-008 — `auto_incident()` iterated `state["incidents"]` inside a lock while also potentially appending to it

| Field | Detail |
|---|---|
| **File** | `monitor_v2.py` |
| **Severity** | High — potential for skipped incidents or index errors |
| **Symptom** | If a high-volume threat burst triggered many `auto_incident()` threads simultaneously, two threads could both not find an existing incident for the same IP and both create a new one — resulting in duplicate incidents. |
| **Root cause** | The "search then mutate" pattern was all inside one `with lock:` block, which is correct. However the `for inc in state["incidents"]: ... break` pattern meant modifying `state["incidents"]` (via `insert`) was done while the list-iteration variable was still technically referenced. Fixed for clarity and correctness. |
| **Fix** | Restructured to separate the search pass from the mutate pass, both still inside one `with lock:` block, making the logic explicit and safe. |

---

### BUG-009 — `run_hunt()` had no None guards on `.get()` calls

| Field | Detail |
|---|---|
| **File** | `monitor_v2.py` |
| **Severity** | High — hunt could crash with `AttributeError` on malformed data |
| **Symptom** | If any connection or process had a `None` value for `name`, `process`, `domain`, or `exe` (which psutil can return for zombie processes or system entries), calling `.lower()` on `None` would raise `AttributeError: 'NoneType' object has no attribute 'lower'`. |
| **Root cause** | Code used `c.get("rip","").lower()` which is safe, but `c.get("process","")` could still be `None` if the dict was built with `None` explicitly. |
| **Fix** | Added `or ""` fallback: `(c.get("process") or "").lower()` pattern throughout `run_hunt()`. |

---

### BUG-010 — `update_feed()` mutated `MALICIOUS_DOMAINS` without the lock

| Field | Detail |
|---|---|
| **File** | `monitor_v2.py` |
| **Severity** | High — thread-safety violation; could cause RuntimeError mid-iteration |
| **Symptom** | `MALICIOUS_DOMAINS.update(new)` was called in a daemon thread while `check_reputation()` was iterating the same set in another thread. Python sets are not thread-safe for concurrent mutation + iteration. |
| **Root cause** | No lock protection on `MALICIOUS_DOMAINS`. |
| **Fix** | Wrapped `MALICIOUS_DOMAINS.update(new)` in `with lock:`. |

---

### BUG-011 — `scan_all_ports_cve()` fired duplicate CVE threats every 40 seconds

| Field | Detail |
|---|---|
| **File** | `monitor_v2.py` |
| **Severity** | High — threat log flooded with hundreds of identical CVE alerts |
| **Symptom** | The CVE scan runs every `10 * SCAN_INTERVAL` = 40 seconds. Every run re-evaluated all open ports and called `add_threat()` for every unpatched critical CVE found. On a machine with port 445 open, "CVE-2017-0144 on port 445" would appear in the threat log every 40 seconds, flooding it with duplicates. |
| **Root cause** | No deduplication for CVE threat alerts. |
| **Fix** | Added module-level `_cve_alerted: set` that tracks `f"{cve_id}:{port}"` strings. `add_threat()` for CVEs only fires if the key is not already in the set. |

---

## Medium Bugs (cosmetic / minor logic issues)

---

### BUG-012 — PDF report variable shadowing (`t` used for both Table and threat loop variable)

| Field | Detail |
|---|---|
| **File** | `monitor_v2.py` |
| **Severity** | Medium — PDF generation crash for incidents with many threats |
| **Symptom** | In `generate_pdf_report()`, the "Associated Threats" section used `for t in threats[:15]:` to build rows, and then `t = Table(th_data, ...)`. The variable `t` was later re-used as a loop variable in earlier sections. If the table was built after the loop, `t.setStyle(...)` would work, but the `t` variable was also used as a local table variable in the Summary section, creating a confusing name collision that could cause silent errors depending on Python version/optimisation. |
| **Root cause** | Reuse of `t` as both the Table constructor variable and the loop iteration variable. |
| **Fix** | Renamed all Table variables to `tbl_summary`, `tbl_tl`, `tbl_th`, `tbl_ev` throughout the PDF generator. |

---

### BUG-013 — `HOST = "0.0.0.0"` exposed API on all network interfaces

| Field | Detail |
|---|---|
| **File** | `monitor_v2.py` |
| **Severity** | Medium — security issue; README explicitly states API should be localhost-only |
| **Symptom** | The Flask server bound to `0.0.0.0:5000`, making the SOC API accessible to any machine on the local network — including potentially malicious actors on the same WiFi. |
| **Root cause** | `HOST = "0.0.0.0"` was set at the top of the file, contradicting the README's "only listens on localhost:5000" privacy statement. |
| **Fix** | Changed to `HOST = "127.0.0.1"`. |

---

### BUG-014 — Dashboard UTC clock used `toISOString()` which is always correct, but `slice(0,19)` could produce wrong display in edge cases + "Server Time" label was missing "UTC"

| Field | Detail |
|---|---|
| **File** | `dashboard_v2.html` |
| **Severity** | Low — minor display inconsistency |
| **Symptom** | The clock in the top-right showed `2026-03-26 09:45:32 UTC` correctly using ISO string slicing, but this approach relies on the ISO string format never changing. The System tab "Server Time" field label didn't say "UTC", so users couldn't tell if it was local or UTC time. |
| **Root cause** | Minor label omission + brittle clock implementation. |
| **Fix** | Rebuilt clock using explicit `getUTCFullYear()`, `getUTCMonth()`, etc. Renamed System tab field from "Server Time" to "Server Time (UTC)". |

---

## Summary Table

| ID | File | Severity | Category | Status |
|---|---|---|---|---|
| BUG-001 | monitor_v2.py + dashboard | Critical | Missing endpoint | ✅ Fixed |
| BUG-002 | monitor_v2.py + dashboard | Critical | Wrong timezone | ✅ Fixed |
| BUG-003 | monitor_v2.py | Critical | JSON serialisation crash | ✅ Fixed |
| BUG-004 | monitor_v2.py | High | Duplicate port entries | ✅ Fixed |
| BUG-005 | monitor_v2.py | High | Race condition | ✅ Fixed |
| BUG-006 | monitor_v2.py | High | Missed detections | ✅ Fixed |
| BUG-007 | monitor_v2.py | High | O(n) performance | ✅ Fixed |
| BUG-008 | monitor_v2.py | High | Concurrent mutation | ✅ Fixed |
| BUG-009 | monitor_v2.py | High | None crash | ✅ Fixed |
| BUG-010 | monitor_v2.py | High | Thread-unsafe set mutation | ✅ Fixed |
| BUG-011 | monitor_v2.py | High | Threat log flooding | ✅ Fixed |
| BUG-012 | monitor_v2.py | Medium | PDF variable shadow | ✅ Fixed |
| BUG-013 | monitor_v2.py | Medium | Security: API exposed | ✅ Fixed |
| BUG-014 | dashboard_v2.html | Low | UTC label missing | ✅ Fixed |
