# 🛡️ SOC Analyst Level-2 — Network Threat Detection Platform

A real-time Security Operations Center (SOC) dashboard built by a CS graduate with hands-on experience in fraud analysis and cybersecurity. Monitors live network traffic on Windows, detects threats using external intelligence feeds, flags malicious connections, hardware surveillance attempts, and suspicious processes — with full incident response workflows, threat hunting, CVE scanning, and persistent storage.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.x-lightgrey)
![Platform](https://img.shields.io/badge/Platform-Windows%2011-0078D4)
![License](https://img.shields.io/badge/License-MIT-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-red)

---

## 📸 Screenshots

> Dashboard running live on my Windows 11 machine (Grandhi Abhishek) — showing real network data with 150+ active connections

| Overview | Threat Log | Incident Response |
|---|---|---|
| Live CPU, Memory, Network charts | Persistent saved threats | Auto-created incidents with MITRE mapping |

*Add your own screenshots here after running the project*

---

## 🔍 What It Does

I wanted to understand what a real SOC analyst sees day-to-day, so I built a lightweight personal SIEM (Security Information and Event Management) tool that runs locally on Windows. Version 2 upgrades the original monitor with a full analyst workflow — going beyond detection into response, hunting, and reporting. It:

- **Monitors all active network connections** on your machine in real time
- **Resolves every external IP** to its domain name via reverse DNS
- **Scores IPs for threat level** using AbuseIPDB and URLhaus threat feeds
- **Auto-creates and manages security incidents** for critical/high alerts — with stage tracking, analyst notes, containment actions, and escalation
- **Threat hunting** — search across all live data by keyword, IP, domain, or process
- **CVE scanning** — maps open ports to known vulnerabilities (NVD database + offline fallback)
- **Correlates alerts by IP** — groups events into an evidence graph to identify coordinated attacks
- **Detects hardware surveillance** — flags processes accessing camera/mic while sending data externally
- **Saves all threats and incidents persistently** to JSON — survives restarts
- **Generates PDF incident reports** via ReportLab
- **Maps detections to MITRE ATT&CK** techniques for professional SOC reporting

---

## ⚙️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    dashboard_v2.html                      │
│          (Live UI — polls API every 4 seconds)            │
└──────────────────────────┬───────────────────────────────┘
                           │ HTTP (localhost:5000)
┌──────────────────────────▼───────────────────────────────┐
│                     monitor_v2.py                         │
│               Flask REST API Backend                      │
├───────────────────────────────────────────────────────────┤
│  ┌────────────┐  ┌─────────────┐  ┌────────────────────┐  │
│  │   psutil   │  │  AbuseIPDB  │  │  URLhaus / NVD API │  │
│  │ (system +  │  │  (IP rep.)  │  │ (malware / CVEs)   │  │
│  │  network)  │  │             │  │                    │  │
│  └────────────┘  └─────────────┘  └────────────────────┘  │
│                                                           │
│  Module 1 — Incident Response   (auto-create, stage, PDF)│
│  Module 2 — Threat Hunting      (keyword / IP search)    │
│  Module 3 — CVE Lookup          (NVD + offline fallback) │
│  Module 4 — Correlation Engine  (evidence graph by IP)   │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  threat_log.json · incidents.json · ip_cache.json   │  │
│  │                  (persistent)                        │  │
│  └─────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────┘
```

---

## 🚨 Detection Capabilities

### Network Threat Intelligence
| Check | Source | Description |
|---|---|---|
| Malicious IP | AbuseIPDB (live) | IPs reported for abuse, C2, scanning |
| Malware domain | URLhaus (live feed) | Domains hosting malware/ransomware |
| Local blocklist | Built-in | TOR exits, phishing, cryptominers, RAT infra |
| Restricted sites | Built-in | Known piracy, exploit forums, dark web gateways |
| Suspicious ports | Built-in | Metasploit (4444), TOR (9050), backdoors, RAT ports |

### MITRE ATT&CK Mapped Rules
| Rule | MITRE ID | Trigger |
|---|---|---|
| C2 Communication | T1071 | Connection to malicious IP or domain |
| Video Capture | T1125 | Process accessing camera with external connection |
| Audio Capture | T1123 | Process accessing microphone with external connection |
| Process Injection | T1055 | Known malware process name detected |
| Network Connections | T1049 | Process listening on suspicious port |
| Brute Force | T1110 | ≥5 failed auth in 60s |
| Lateral Movement | T1021 | SMB/RDP to multiple internal hosts |
| Exfiltration over C2 | T1041 | Bulk transfer or confirmed C2 channel |

### CVE Vulnerability Scanning
Automatically scans all open ports and maps them to known CVEs including:
- **EternalBlue** (CVE-2017-0144) on port 445 — WannaCry SMB exploit
- **BlueKeep** (CVE-2019-0708) on port 3389 — RDP RCE
- **vsftpd backdoor** (CVE-2011-2523) on port 21
- **OpenSSH RCE** (CVE-2023-38408) on port 22
- And more via the NVD API when a key is configured

### Hardware Surveillance Detection
Detects processes accessing:
- 📷 **Camera** — webcam, imaging devices
- 🎤 **Microphone** — audio drivers, speech runtime
- 🖥️ **GPU** — DirectX, Vulkan, CUDA
- 🔌 **USB devices** — HID, USB storage

**Critical alert fires** when any hardware-accessing process simultaneously has an external network connection — strong indicator of spyware.

---

## 🗂️ Project Structure

```
soc-threat-detection/
│
├── monitor_v2.py       # Python backend — data collection + Flask API
├── dashboard_v2.html   # Live web dashboard — connects to API
├── threat_log.json     # Auto-generated — persistent threat storage (up to 3,000)
├── incidents.json      # Auto-generated — persistent incident storage (up to 500)
├── ip_cache.json       # Auto-generated — IP reputation cache (1hr TTL)
├── hunt_results.json   # Auto-generated — saved threat hunt results
├── reports/            # Auto-generated — exported PDF incident reports
└── README.md
```

---

## 🚀 Installation & Setup

### Requirements
- Windows 10 / 11
- Python 3.8+
- Google Chrome / Edge / Firefox

### Step 1 — Install dependencies
```bash
pip install psutil flask flask-cors requests reportlab
```

### Step 2 — Optional: Install enhanced capabilities
```bash
# Deep packet inspection (requires Npcap on Windows)
pip install scapy

# PDF reports (already included above)
pip install reportlab
```

### Step 3 — Optional: Enable live threat intelligence
Get a free API key from [AbuseIPDB](https://www.abuseipdb.com/register) (1,000 checks/day free)
and/or [NVD](https://nvd.nist.gov/developers/request-an-api-key) for live CVE lookups.

Open `monitor_v2.py` and set near the top:
```python
ABUSEIPDB_KEY = "your_abuseipdb_key_here"
NVD_API_KEY   = "your_nvd_key_here"
```

Both are optional — the platform runs in offline mode without them.

### Step 4 — Run as Administrator
Right-click PowerShell → **Run as Administrator** (needed for full connection and process visibility):
```bash
python monitor_v2.py
```

You should see:
```
==============================================================
  SOC Analyst Level-2 — Threat Detection Platform v2.1
==============================================================
  Python     : 3.x.x
  ReportLab  : YES — PDF reports enabled
  Scapy      : YES
  AbuseIPDB  : LIVE
  NVD API    : LIVE
  Incidents  : 0 loaded from disk
  Threats    : 0 loaded from disk
  API        : http://localhost:5000/api/all
==============================================================
  Open dashboard_v2.html in your browser.
  Press Ctrl+C to stop.
==============================================================
```

### Step 5 — Open the dashboard
Double-click `dashboard_v2.html` in your browser. It auto-connects to the API.

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/all` | Full system snapshot — all data |
| GET | `/api/threats` | Paginated threat log (filter by severity/category) |
| GET | `/api/incidents` | All incidents |
| GET | `/api/incidents/<id>` | Single incident detail |
| POST | `/api/incidents/<id>/note` | Add analyst note to incident |
| POST | `/api/incidents/<id>/action` | Add containment action / resolve |
| POST | `/api/incidents/<id>/escalate` | Escalate incident severity |
| POST | `/api/hunt` | Run a threat hunt query |
| GET | `/api/hunt/results` | Past hunt results |
| GET | `/api/cve` | CVE scan results for all open ports |
| POST | `/api/cve/scan` | Trigger a fresh CVE scan |
| GET | `/api/cve/<port>` | CVEs for a specific port |
| GET | `/api/correlation` | Alert correlation graph by IP |
| GET | `/api/report/<inc_id>` | Download PDF incident report |
| GET | `/api/reputation/<ip>` | Check reputation of any IP |
| GET | `/api/threats/export` | Download full threat log as JSON file |
| POST | `/api/threats/clear` | Clear all saved threats |
| GET | `/api/status` | Backend health check |

### Threat log filters
```
GET /api/threats?severity=critical&category=Threat+Intel&page=1&per=50
```

---

## 🧪 Testing

### Test 1 — Check IP reputation
```
http://localhost:5000/api/reputation/185.220.101.42
```
Expected: TOR exit node detected

### Test 2 — View all live connections
```
http://localhost:5000/api/all
```
Check the `connections` array — every external IP will have domain, country, and threat score

### Test 3 — Trigger a CVE scan
```
POST http://localhost:5000/api/cve/scan
```
Expected: Open ports mapped to known CVEs with CVSS scores

### Test 4 — Hardware access
Open your Camera app → check the **Hardware Access** tab in the dashboard

### Test 5 — Persistent log
Stop `monitor_v2.py` → restart it → open **Threat Log** tab — all previous threats and incidents are still there

### Test 6 — Threat hunt
Run a hunt for a known IP or process name via the **Threat Hunting** tab in the dashboard

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Backend | Python 3, Flask, Flask-CORS |
| System monitoring | psutil |
| Threat intelligence | AbuseIPDB API, URLhaus API |
| Vulnerability data | NVD (NIST) API + offline CVE fallback |
| Packet capture | Scapy (optional) |
| PDF reports | ReportLab |
| DNS resolution | socket (built-in) |
| Frontend | Vanilla HTML, CSS, JavaScript |
| Charts | Chart.js |
| Storage | JSON flat files (no database needed) |
| Network scan | arp -a (Windows built-in) |
| OS | Windows 11 |

**Relevant skills from this project:** Python · Flask · REST API · Network Security · Log Analysis · Threat Intelligence · MITRE ATT&CK · Incident Response · CVE Analysis · SOC Analysis · JavaScript

---

## 📊 What Was Tested

- ✅ Tested live on **Windows 11** with real network traffic
- ✅ **150+ active connections** monitored and classified simultaneously
- ✅ Real-time CPU, Memory, and Network throughput metrics confirmed accurate
- ✅ **Reverse DNS resolution** successfully resolving external IPs to domains
- ✅ Known malicious IP `185.220.101.42` (TOR exit node) correctly identified
- ✅ **URLhaus feed** auto-updates malicious domain list hourly
- ✅ Persistent threat log and incident store confirmed working across restarts
- ✅ Hardware access detection tested with Camera app on Windows 11
- ✅ CVE scan correctly flagging EternalBlue on SMB port 445
- ✅ Incident auto-created and escalated for critical-severity threats
- ✅ PDF report generated successfully for a resolved incident

---

## 🔐 Privacy & Safety

- All monitoring is **local only** — no data leaves your machine
- The Flask API only listens on `localhost:5000` — not accessible from outside
- IP reputation checks are one-way lookups to public APIs (no personal data sent)
- All log files (`threat_log.json`, `incidents.json`) are stored locally in the project folder only

---

## 🚧 Potential Improvements

- [ ] Email/SMS alerts for critical threats
- [ ] SQLite database instead of JSON for larger deployments
- [ ] Geo-IP map visualization of external connections
- [ ] Scheduled PDF report generation
- [ ] Windows Service auto-start on boot
- [ ] Integration with Splunk / Elastic SIEM
- [ ] Multi-host monitoring (agent-based)
- [ ] User authentication for the dashboard

---

## 👨‍💻 Author

**Grandhi Abhishek**  
B.Tech Computer Science — Lovely Professional University | Cybersecurity Enthusiast

- 📧 grandhiabhishek487@gmail.com
- 🔗 [linkedin.com/in/abhishek-grandhi-2556a3220](https://linkedin.com/in/abhishek-grandhi-2556a3220)

Built this as a personal hands-on project coming from a background in fraud analysis and cybersecurity. Having worked as a Chargeback Fraud Analyst reviewing high-volume financial transaction records to detect anomalous patterns, and previously as a Cybersecurity Intern analysing system and web activity logs — I wanted to apply that same analytical thinking to network-level threat detection and build a tool that actually monitors a real machine in real time rather than just studying theory.

---

## 📄 License

MIT License — free to use, modify and distribute.

---

## 🙏 Acknowledgements

- [AbuseIPDB](https://www.abuseipdb.com) — IP reputation database
- [URLhaus by abuse.ch](https://urlhaus.abuse.ch) — Malware URL feed
- [NVD / NIST](https://nvd.nist.gov) — National Vulnerability Database
- [MITRE ATT&CK](https://attack.mitre.org) — Threat technique framework
- [psutil](https://github.com/giampaolo/psutil) — Cross-platform system monitoring
- [ReportLab](https://www.reportlab.com) — PDF generation
