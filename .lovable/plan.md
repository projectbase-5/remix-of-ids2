

# Plan: Log Query Engine + Attack Simulator

## 1. Log Storage & Query Engine

### What exists
The Hunt page (`ThreatHunter.tsx`) already queries `incident_logs`, `predictions`, and `ip_reputation` with filters (IP, severity, time range, score). However, it does **not** query `network_traffic` or `flow_metrics_log` directly — the two most important tables for analyst investigation.

### Changes

**Backend — `docs/event_query_engine.py`** (Create)
- Python module that queries Supabase REST API across all event tables: `network_traffic`, `flow_metrics_log`, `incident_logs`, `live_alerts`, `predictions`
- Accepts filter parameters: IP, time range, protocol, attack type, severity
- Returns unified results sorted by timestamp

**Frontend — Enhance `ThreatHunter.tsx`**
- Add a new "Log Search" tab alongside existing Filter Search / Advanced Hunts / Hunt Results tabs
- This tab queries `network_traffic` and `live_alerts` directly from Supabase with full filter support
- Add filters: protocol, port, payload keyword search (ilike on `payload_preview`), attack type dropdown
- Add a category dropdown for quick searches: "All Traffic", "DNS Anomalies", "C2 Alerts", "Suspicious Only"
- Results show: timestamp, source IP, dest IP, protocol, port, packet size, payload preview, suspicious flag

## 2. Attack Simulation Engine

### What exists
The Detection Engine page has start/stop controls but no simulation capability.

### Changes

**Backend — `docs/attack_simulator.py`** (Create)
- Python module with functions: `simulate_port_scan()`, `simulate_ddos()`, `simulate_beacon()`, `simulate_exfiltration()`
- Each function generates synthetic packets and sends them to the `ingest-traffic` edge function
- Configurable parameters: target IP, duration, intensity

**Frontend — New `AttackSimulator.tsx` component**
- Card-based UI with simulation types: Port Scan, DoS Flood, C2 Beacon, Data Exfiltration
- Each card has: description, configurable parameters (target IP, duration), Run button
- Simulation runs client-side by inserting test records into `network_traffic` and `live_alerts` via Supabase (for demo/testing purposes)
- Status indicator showing active simulation, results count
- Add to Detection Engine page as a new "Simulations" tab

**Wire into Index.tsx and DashboardSidebar**
- No new page needed — add as a tab inside the existing Engine page

## Files to Create/Modify

| File | Action |
|------|--------|
| `docs/event_query_engine.py` | Create — Python query module |
| `docs/attack_simulator.py` | Create — Python simulation module |
| `src/components/ThreatHunter.tsx` | Modify — Add "Log Search" tab querying network_traffic and live_alerts |
| `src/components/AttackSimulator.tsx` | Create — Simulation UI component |
| `src/components/DetectionEngine.tsx` | Modify — Add "Simulations" tab with AttackSimulator |

