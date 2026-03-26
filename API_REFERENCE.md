# SOC Platform v2.1 — API Reference

**Base URL:** `http://localhost:5000`  
**All timestamps:** UTC  
**Content-Type:** `application/json` for POST requests

---

## Quick Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/all` | Full system snapshot (primary polling endpoint) |
| GET | `/api/threats` | Paginated + filtered threat log |
| GET | `/api/threats/export` | Download full threat log as JSON file |
| POST | `/api/threats/clear` | Wipe all saved threats |
| GET | `/api/incidents` | All incidents |
| GET | `/api/incidents/<id>` | Single incident detail |
| POST | `/api/incidents/<id>/note` | Add analyst note |
| POST | `/api/incidents/<id>/action` | Update stage / add containment action |
| POST | `/api/incidents/<id>/escalate` | Escalate severity one level |
| POST | `/api/hunt` | Run a threat hunt |
| GET | `/api/hunt/results` | Previous hunt results |
| GET | `/api/cve` | Current CVE scan results |
| POST | `/api/cve/scan` | Trigger fresh CVE scan |
| GET | `/api/cve/<port>` | CVEs for a specific port |
| GET | `/api/correlation` | Alert correlation graph by IP |
| GET | `/api/report/<inc_id>` | Download PDF incident report |
| GET | `/api/reputation/<ip>` | Check reputation of any IP |
| GET | `/api/status` | Backend health check |

---

## Endpoint Details

### GET `/api/all`

Returns a complete system snapshot. The dashboard polls this every 4 seconds.

**Response fields:**

```json
{
  "cpu_history":      [float],         // last 120 CPU% readings
  "mem_history":      [float],         // last 120 memory% readings
  "net_sent_history": [float],         // KB/s sent history
  "net_recv_history": [float],         // KB/s received history
  "timestamps":       [string],        // HH:MM:SS UTC per reading
  "connections": [{
    "pid":          int,
    "process":      string,
    "laddr":        "ip:port",
    "raddr":        "ip:port",
    "rip":          string,
    "rport":        int,
    "domain":       string,
    "country":      string,            // 2-letter ISO code or "??"
    "status":       string,            // ESTABLISHED, LISTEN, TIME_WAIT…
    "protocol":     "TCP"|"UDP",
    "flags":        [string],
    "suspicious":   bool,
    "malicious":    bool,
    "threat_score": int,               // 0-100
    "is_external":  bool
  }],
  "processes": [{
    "pid":         int,
    "name":        string,
    "username":    string,
    "cpu":         float,
    "memory":      float,
    "status":      string,
    "connections": int,
    "suspicious":  bool,
    "exe":         string
  }],
  "open_ports": [{
    "port":      int,
    "process":   string,
    "pid":       int,
    "address":   string,
    "protocol":  "TCP",
    "note":      string,               // e.g. "Metasploit listener"
    "suspicious": bool
  }],
  "hardware_access": [{
    "pid":       int,
    "name":      string,
    "hw_type":   "Camera"|"Microphone"|"GPU"|"USB",
    "ext_conns": [string],             // list of "ip:port" strings
    "risk":      "high"|"medium",
    "username":  string
  }],
  "wifi_devices": [{
    "ip":         string,
    "mac":        string,
    "type":       string,
    "hostname":   string,
    "suspicious": bool
  }],
  "live_alerts":  [ThreatObject],      // most recent 100
  "threat_log":   [ThreatObject],      // most recent 300
  "incidents":    [IncidentObject],    // most recent 50
  "cve_results":  {port: CVEResult},
  "correlation":  {ip: CorrelationNode},
  "network_stats": { bytes_sent, bytes_recv, packets_sent, packets_recv,
                     errin, errout, dropin, dropout, sent_kbps, recv_kbps },
  "system_info":  { hostname, local_ip, os, machine, processor, boot_time,
                    cpu_count, cpu_physical, ram_total_gb, python_ver },
  "total_alerts":    int,
  "total_incidents": int,
  "packets":         int,
  "scapy":           bool,
  "reportlab":       bool,
  "server_time":     "YYYY-MM-DD HH:MM:SS UTC",
  "abuseipdb_active": bool
}
```

---

### GET `/api/threats`

Paginated and filtered threat log.

**Query parameters:**

| Param | Values | Default |
|---|---|---|
| `severity` | `critical`, `high`, `medium`, `low`, `all` | `all` |
| `category` | `Threat Intel`, `CVE Vulnerability`, `Hardware Surveillance`, `Open Port`, `Process`, `System`, `all` | `all` |
| `page` | integer ≥ 1 | `1` |
| `per` | integer 1–100 | `50` |

**Example:**
```
GET /api/threats?severity=critical&category=Threat+Intel&page=1&per=25
```

**Response:**
```json
{
  "threats": [ThreatObject],
  "total":   int,
  "page":    int,
  "pages":   int
}
```

---

### ThreatObject schema

```json
{
  "id":          string,               // 10-char hex ID
  "timestamp":   "YYYY-MM-DD HH:MM:SS",
  "time":        "HH:MM:SS",
  "severity":    "critical"|"high"|"medium"|"low",
  "category":    string,
  "title":       string,
  "detail":      string,
  "ip":          string,
  "domain":      string,
  "threat_type": string,
  "incident_id": string,
  "status":      "open",
  "analyst_note": string
}
```

---

### GET `/api/threats/export`

Returns the full threat log (up to 3,000 entries) as a downloadable JSON file.  
No query parameters. Response `Content-Disposition: attachment; filename=threat_log_export.json`.

---

### POST `/api/threats/clear`

Clears all threats from memory and disk. No body required.

```json
{ "status": "cleared" }
```

---

### GET `/api/incidents`

Returns all incidents (up to 500) as an array of IncidentObjects.

---

### IncidentObject schema

```json
{
  "id":          "INC-XXXXXX",
  "created":     "YYYY-MM-DD HH:MM:SS",
  "last_seen":   "YYYY-MM-DD HH:MM:SS",
  "severity":    "critical"|"high"|"medium"|"low",
  "status":      "Detected"|"Investigating"|"Contained"|"Resolved",
  "stage":       "Detected"|"Investigating"|"Contained"|"Resolved",
  "primary_ip":  string,
  "domain":      string,
  "title":       string,
  "category":    string,
  "threat_type": string,
  "alerts":      [string],             // alert IDs linked to this incident
  "mitre":       "T1071 - ...",
  "timeline": [{
    "time":  string,
    "stage": string,
    "event": string
  }],
  "evidence": [{
    "time":   string,
    "type":   string,
    "detail": string
  }],
  "analyst_notes": [{
    "time":    string,
    "analyst": "SOC Analyst",
    "text":    string
  }],
  "containment_actions": [{
    "time":   string,
    "action": string,
    "detail": string
  }],
  "affected_hosts": [string]
}
```

---

### POST `/api/incidents/<id>/note`

Add an analyst note to an incident.

**Request body:**
```json
{ "text": "Confirmed C2 beacon — IP belongs to known TOR exit node." }
```

**Response:** `{ "status": "ok" }`

---

### POST `/api/incidents/<id>/action`

Update incident stage and record a containment action.

**Request body:**
```json
{
  "action": "Investigate"|"Contain"|"Resolve",
  "detail": "Blocked IP at perimeter firewall (rule #47)"
}
```

Special action values that change stage:
- `"Resolve"` → sets status and stage to `"Resolved"`
- `"Contain"` → sets to `"Contained"`
- `"Investigate"` → sets to `"Investigating"`

Any other action string is recorded in the timeline without changing stage.

**Response:** `{ "status": "ok" }`

---

### POST `/api/incidents/<id>/escalate`

Escalates incident severity one level (low → medium → high → critical). Has no effect if already critical.

**Request body:** `{}` (empty JSON object)  
**Response:** `{ "status": "ok" }`

---

### POST `/api/hunt`

Run a threat hunt across all live data sources.

**Request body:**
```json
{
  "query": "185.220.101.42",
  "type": "keyword"|"ip"|"domain"|"process"|"port"
}
```

**Response:**
```json
{
  "id":        string,
  "query":     string,
  "type":      string,
  "timestamp": string,
  "count":     int,
  "results": [{
    "source":    "Connection"|"Process"|"Threat Log"|"Open Port",
    "severity":  string,
    "match":     string,
    "detail":    string,
    "ip":        string,
    "timestamp": string
  }]
}
```

---

### POST `/api/cve/scan`

Triggers a fresh CVE scan of all currently open ports. Blocks until complete (usually <1 second for offline database).

**Response:** Same as `GET /api/cve`

```json
{
  "<port>": {
    "port":           int,
    "process":        string,
    "cves": [{
      "id":       "CVE-YYYY-NNNNN",
      "score":    float,
      "desc":     string,
      "severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW",
      "patched":  bool
    }],
    "max_score":      float,
    "critical_count": int
  }
}
```

---

### GET `/api/reputation/<ip>`

Check the reputation of any IP address (uses AbuseIPDB if key configured, URLhaus, and local blocklists).

**Example:** `GET /api/reputation/185.220.101.42`

**Response:**
```json
{
  "ip":            "185.220.101.42",
  "score":         100,
  "is_malicious":  true,
  "is_restricted": false,
  "categories":    ["abuse_reported"],
  "source":        "abuseipdb",
  "country":       "DE",
  "domain":        "tor-exit-node.example.com"
}
```

---

### GET `/api/report/<inc_id>`

Generates and streams a PDF incident report. Response is `application/pdf` with `Content-Disposition: attachment`.

**Example:** `GET /api/report/INC-A1B2C3`

Returns `400` with `{ "error": "..." }` if reportlab not installed or incident not found.

---

### GET `/api/status`

Health check endpoint.

```json
{
  "status":    "running",
  "time":      "YYYY-MM-DD HH:MM:SS UTC",
  "alerts":    int,
  "incidents": int,
  "reportlab": bool,
  "scapy":     bool,
  "abuseipdb": bool
}
```
