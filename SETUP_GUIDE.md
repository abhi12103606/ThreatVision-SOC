# SOC Platform v2.1 — Setup & Troubleshooting Guide

---

## Requirements

| Item | Minimum | Recommended |
|---|---|---|
| OS | Windows 10 | Windows 11 |
| Python | 3.8 | 3.11+ |
| RAM | 256 MB free | 512 MB+ |
| Browser | Edge / Chrome / Firefox | Chrome |
| Network | Any | Run on the machine you want to monitor |

---

## Installation (Step by Step)

### Step 1 — Install Python

If you don't have Python yet:

```powershell
# Check if installed
python --version

# If not found — install from python.org (recommended)
# https://www.python.org/downloads/
# IMPORTANT: check "Add Python to PATH" during installation
```

After installing, close and reopen PowerShell, then verify:

```powershell
python --version   # should print Python 3.x.x
pip --version      # should print pip 23.x.x
```

---

### Step 2 — Install required packages

```powershell
pip install psutil flask flask-cors requests reportlab
```

Optional packages (for enhanced capabilities):

```powershell
# Deep packet inspection — requires Npcap first:
# https://npcap.com/#download
pip install scapy
```

---

### Step 3 — (Optional) Configure API keys

Open `monitor_v2.py` in a text editor. Near the top, find:

```python
ABUSEIPDB_KEY = ""   # paste your key here
NVD_API_KEY   = ""   # paste your key here
```

**AbuseIPDB** (free, 1000 checks/day): https://www.abuseipdb.com/register  
**NVD API key** (free): https://nvd.nist.gov/developers/request-an-api-key

Both are optional. The platform runs fully in offline mode without them.

---

### Step 4 — Run as Administrator

Administrator rights are required to enumerate all network connections and process details.

```powershell
# Right-click PowerShell → "Run as Administrator"
cd D:\ThreatVision-SOC-main
python monitor_v2.py
```

Expected startup output:

```
==============================================================
  SOC Analyst Level-2 — Threat Detection Platform v2.1
==============================================================
  Python     : 3.11.x
  ReportLab  : YES — PDF reports enabled
  Scapy      : YES
  AbuseIPDB  : offline mode
  NVD API    : offline CVE database
  Incidents  : 0 loaded from disk
  Threats    : 0 loaded from disk
  API        : http://localhost:5000/api/all
==============================================================
  Open dashboard_v2.html in your browser.
  Press Ctrl+C to stop.
==============================================================
```

---

### Step 5 — Open the dashboard

Double-click `dashboard_v2.html` in Windows Explorer, or drag it into Chrome/Edge.

The dashboard will connect automatically. The status dot will turn **green** and show **LIVE** within a few seconds.

---

## File Structure

```
ThreatVision-SOC-main/
│
├── monitor_v2.py       ← Python backend (run this)
├── dashboard_v2.html   ← Open this in your browser
│
├── threat_log.json     ← Auto-generated: persists across restarts
├── incidents.json      ← Auto-generated: incident store
├── ip_cache.json       ← Auto-generated: IP reputation cache (1hr TTL)
├── hunt_results.json   ← Auto-generated: saved hunt results
│
├── reports/            ← Auto-generated: PDF reports go here
│
├── BUG_REPORT.md       ← This fix release's bug documentation
├── API_REFERENCE.md    ← Full API documentation
└── SETUP_GUIDE.md      ← This file
```

---

## Troubleshooting

---

### "Export JSON" button showed 404

**Was:** The button called `/api/threats/export` which didn't exist in v2.0.  
**Fixed in v2.1:** The endpoint now exists and returns a downloadable JSON file.  
**If still happening:** Make sure you're running the new `monitor_v2.py` (v2.1). Check the startup banner says "v2.1".

---

### Dashboard clock doesn't match threat timestamps

**Was:** Timestamps were in local time (IST), the clock showed UTC — so all events were offset.  
**Fixed in v2.1:** All timestamps are now UTC. Both the clock and all logged events use UTC.  
**If still happening:** You may have old `threat_log.json` or `incidents.json` from v2.0 on disk. These will have local-time timestamps mixed with the new UTC ones. You can either leave them (they'll look inconsistent) or clear them: delete both JSON files and restart.

---

### Dashboard shows "OFFLINE" banner

1. Check PowerShell — is `monitor_v2.py` still running? If it exited, restart it.
2. Check if another app is using port 5000:
   ```powershell
   netstat -ano | findstr :5000
   ```
   If something else is using it, change `PORT = 5001` in `monitor_v2.py` and update `const API='http://localhost:5001'` in `dashboard_v2.html`.
3. Check Windows Firewall — it shouldn't block localhost connections, but if you're using a third-party firewall, whitelist `python.exe` on port 5000.

---

### "Access Denied" errors in PowerShell when starting

You must run PowerShell as **Administrator**. Without admin rights:
- `psutil.net_connections()` may fail to list all connections
- Process names may show "Unknown" for system processes
- Hardware access detection may be incomplete

---

### PDF report returns "reportlab not installed"

```powershell
pip install reportlab
```

Then restart `monitor_v2.py`. The System tab will show `ReportLab: ✓ Installed`.

---

### Threat log fills up with hundreds of "Suspicious port X open" duplicates

**Was a bug in v2.0.** Fixed in v2.1 — each CVE/port alert now only fires once per session.  
To clear existing duplicates: click **Clear** in the Threat Log tab, or delete `threat_log.json` and restart.

---

### AbuseIPDB not working (no live threat scores)

1. Check you've set `ABUSEIPDB_KEY = "your_key"` in `monitor_v2.py`
2. Check you have internet access
3. Check you haven't exceeded the 1000 checks/day free limit
4. The platform works fine in offline mode — it just won't check scores against the live AbuseIPDB database

---

### CVE scan shows no results

1. Click **⚡ Scan All Open Ports** in the CVE Scanner tab
2. Wait 5–10 seconds (NVD API calls can be slow if key is configured)
3. If no ports show CVEs, your open ports may not be in the offline CVE database. Only well-known ports (22, 80, 443, 445, 3389, etc.) have offline data.
4. Check the Open Ports tab first — if no ports are listed, the scan has nothing to check.

---

### "No connections" in the Connections tab

- Run as Administrator — without it, some connections are hidden
- Some VPNs or firewall software intercept connections before psutil can see them
- Try switching the filter from "All" to "External" — local connections may still appear

---

### Correlation tab is empty after startup

The correlation engine runs every `5 × 4s = 20 seconds`. Wait at least 20 seconds after starting, then switch to the Correlation tab. If still empty, there are no external IPs with multiple data points yet.

---

## Performance Notes

| Metric | Typical value |
|---|---|
| Memory usage | 40–80 MB |
| CPU usage (idle scan) | <1% |
| Disk writes | Small — JSON files, <5 MB total |
| Network overhead | Minimal — only outbound reputation API calls |
| Startup time to first data | ~5 seconds |

The platform is designed to run continuously in the background. It uses daemon threads so it exits cleanly with Ctrl+C.
