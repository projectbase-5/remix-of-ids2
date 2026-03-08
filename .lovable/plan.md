

# Modules 5, 6, 7 — Implementation Plan

## Current State Analysis

| Module | What Exists | Gap |
|--------|-------------|-----|
| **Network Topology** | `ThreatMap.tsx` shows geographic threat distribution | No device-to-device connections or network graph |
| **Data Retention** | Tables grow unbounded | No archival, compression, or cleanup |
| **Notifications** | `send-alert-notification` edge function + `AlertNotifications.tsx` UI with email/webhook | No Python dispatcher for agent-side notifications |

---

## Module 5 — Network Topology Mapper

### Python Agent: `docs/network_mapper.py`

- Discovers devices from captured traffic (source/dest IP pairs)
- Builds adjacency graph tracking connections between hosts
- Identifies gateway nodes (high connection count)
- Pushes topology data to `ingest-traffic` as `topology: {nodes: [...], edges: [...]}`

### Database: `network_topology` Table

| Column | Type | Description |
|--------|------|-------------|
| id | uuid | Primary key |
| source_ip | text | Node A |
| destination_ip | text | Node B |
| connection_count | integer | Times observed |
| protocols | jsonb | Protocols used (TCP, UDP) |
| first_seen / last_seen | timestamptz | Time range |
| bytes_transferred | bigint | Total data volume |

### UI: `src/components/NetworkTopology.tsx`

- Force-directed graph visualization using node/edge data
- Nodes sized by connection count (gateways larger)
- Edges colored by traffic volume
- Click node to show asset details from `asset_inventory`
- Add "Topology" tab to main dashboard

### Modify `ingest-traffic`

- Accept `topology[]` payload
- Upsert connection records

---

## Module 6 — Data Retention Engine

### Python Agent: `docs/data_retention_manager.py`

- Configurable retention policies per table
- Calls `cleanup-data` edge function periodically
- Logs cleanup statistics locally

### Database: `retention_policies` Table

| Column | Type | Description |
|--------|------|-------------|
| id | uuid | Primary key |
| table_name | text | Target table |
| retention_days | integer | Keep data for N days |
| archive_before_delete | boolean | Copy to archive first |
| is_active | boolean | Enable/disable policy |

### Edge Function: `supabase/functions/cleanup-data/index.ts`

- Reads active retention policies
- For each table, deletes rows where `created_at < now() - retention_days`
- Optionally archives to `archived_events` table before deletion
- Returns cleanup statistics

### UI: `src/components/DataRetention.tsx`

- Policy management interface (table, days, archive flag)
- Manual "Run Cleanup" button
- Cleanup history log
- Storage usage estimates
- Add "Retention" tab to dashboard

---

## Module 7 — Notification Dispatcher (Python)

### Python Agent: `docs/notification_dispatcher.py`

- Multi-channel dispatcher: email, Slack, webhook, SMS
- Reads configs from `notification_configs` table (existing)
- Called by `incident_scoring_engine.py` or `response_manager.py` when thresholds are met
- Supports batching and rate limiting
- Logs dispatch results

### Integration Points

- `incident_scoring_engine.py` calls dispatcher for `score >= 100`
- `response_manager.py` calls dispatcher for executed actions
- Deduplication via `dedupe_key` (60-second window)

### Channels

| Channel | Implementation |
|---------|----------------|
| Email | Call `send-alert-notification` edge function |
| Webhook | Direct HTTP POST |
| Slack | Webhook URL or future connector |
| SMS | Placeholder for Twilio integration |

---

## Files Summary

| Action | File |
|--------|------|
| **Create** | `docs/network_mapper.py` — topology discovery agent |
| **Create** | `docs/data_retention_manager.py` — retention automation |
| **Create** | `docs/notification_dispatcher.py` — multi-channel dispatcher |
| **Create** | `supabase/functions/cleanup-data/index.ts` — data cleanup |
| **Create** | `src/components/NetworkTopology.tsx` — graph visualization |
| **Create** | `src/components/DataRetention.tsx` — retention policies UI |
| **Modify** | `supabase/functions/ingest-traffic/index.ts` — accept topology payload |
| **Modify** | `src/pages/Index.tsx` — add Topology and Retention tabs |
| **Migration** | Create `network_topology` and `retention_policies` tables |

