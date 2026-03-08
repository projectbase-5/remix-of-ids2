

# Integrate All 5 Modules Into the IDS Agent Pipeline

## Current State

| Module | Python File | Integrated in ids_agent.py? |
|--------|------------|---------------------------|
| Threat Intel Enricher | **MISSING** | No |
| Response Manager | `docs/response_manager.py` | No |
| Risk Scoring Engine | `docs/risk_scoring_engine.py` | No |
| Asset Discovery | **MISSING** | No |
| Notification Dispatcher | `docs/notification_dispatcher.py` | No |

The three existing modules (`response_manager.py`, `risk_scoring_engine.py`, `notification_dispatcher.py`) are standalone scripts that are never imported or called from `ids_agent.py`. The alert pipeline currently ends at `alert_manager.process(alerts)` → POST to Supabase. None of the downstream modules are wired in.

## Plan

### 1. Create `docs/threat_intel_enricher.py`
- Class `ThreatIntelEnricher` that takes alerts and enriches them by calling the existing `enrich-alert` edge function (which already calls `check-ip-reputation`)
- For each alert's `source_ip` and `destination_ip`, fetch reputation data
- Attach enrichment to alert metadata before it's sent to the database
- Cache results to avoid redundant lookups (TTL-based)

### 2. Create `docs/asset_discovery.py`
- Class `AssetDiscovery` that tracks unique IPs seen in network traffic
- On each packet, check if IP exists in local cache; if new, upsert to `asset_inventory` table via REST API
- Track `first_seen`, `last_seen`, `connection_count`, open ports, protocols
- Periodic sync to update `last_seen` for known assets

### 3. Integrate all modules into `docs/ids_agent.py`
Update the main agent loop to follow this pipeline:

```text
packets → detectors → alerts
                        ↓
              threat_intel_enricher (enrich alerts)
                        ↓
              alert_manager.process() (dedup + send to DB)
                        ↓
              asset_discovery.update() (track IPs from packets)
                        ↓
              risk_scoring (periodic, every 5 min)
                        ↓
              response_manager.auto_respond() (for high-score incidents)
                        ↓
              notification_dispatcher.dispatch() (for critical alerts)
```

Changes to `ids_agent.py`:
- Import `ThreatIntelEnricher`, `ResponseManager`, `NotificationDispatcher`, `AssetDiscovery`
- Instantiate each module with Supabase credentials
- Before `alert_manager.process()`, run alerts through `threat_intel_enricher.enrich()`
- After sending packets, call `asset_discovery.update(packets)`
- Add periodic risk scoring call (every 300s)
- After alert_manager processes alerts, pass high-severity alerts to `response_manager.auto_respond()` and `notification_dispatcher.dispatch()`

### 4. No frontend changes needed
All frontend pages already exist and display the relevant data:
- **Threat Intel page**: reads from `ip_reputation` table
- **Incidents page**: reads from `incident_logs` and `response_actions`
- **Assets page**: reads from `asset_inventory`
- **Notifications page**: reads from `notification_configs`
- **Risk Score dashboard**: reads from `host_risk_scores`

The backend modules populate these tables; the frontend already renders them.

## Files to Create/Modify

| File | Action |
|------|--------|
| `docs/threat_intel_enricher.py` | Create |
| `docs/asset_discovery.py` | Create |
| `docs/ids_agent.py` | Modify — import and wire all 5 modules |
| `docs/alert_manager.py` | No changes needed |

