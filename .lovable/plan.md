

# Asset Inventory — Implementation Plan

## Purpose

Track and classify hosts on the network so alerts gain context. Instead of "alert from 192.168.1.10", analysts see "alert from Developer Laptop (192.168.1.10)".

## Plan

### 1. Database: `asset_inventory` Table

| Column | Type | Default |
|--------|------|---------|
| id | uuid | gen_random_uuid() |
| ip_address | text (unique) | — |
| hostname | text | null |
| device_type | text | 'unknown' |
| os | text | null |
| owner | text | null |
| department | text | null |
| criticality | text | 'medium' |
| is_active | boolean | true |
| last_seen | timestamptz | now() |
| first_seen | timestamptz | now() |
| mac_address | text | null |
| open_ports | jsonb | '[]' |
| services | jsonb | '[]' |
| notes | text | null |
| created_at / updated_at | timestamptz | now() |

RLS: full public access (matches project pattern). Unique index on `ip_address`.

### 2. Python Agent: `docs/asset_inventory.py`

- Passive discovery: extracts unique IPs from captured packets and upserts to `asset_inventory` via the `ingest-traffic` endpoint
- Device classification heuristics based on port/protocol patterns (e.g., port 22+80+443 = server, port 3389 = Windows workstation, DHCP = endpoint)
- Updates `last_seen` on every sighting
- Exposes `classify_device(ip, open_ports, services)` for other modules

### 3. Modify `ingest-traffic` Edge Function

- Accept optional `assets[]` payload
- Upsert into `asset_inventory` (match on `ip_address`, update `last_seen` and merge `open_ports`/`services`)

### 4. UI: Asset Inventory Component + Tab

Create `src/components/AssetInventory.tsx`:

- Table view of all assets with search/filter by device type, criticality, active status
- Manual add/edit asset form (IP, hostname, device type, owner, criticality)
- "Last Seen" indicator with stale detection (>24h = warning)
- Asset count summary cards (servers, workstations, unknown, inactive)

Add "Assets" tab to `src/pages/Index.tsx`.

### 5. Enrich Alerts with Asset Context

Modify `src/components/AlertsPanel.tsx`:
- When displaying alerts, look up `source_ip` in a cached asset map
- Show hostname + device type badge next to IP addresses

---

## Files Summary

| Action | File |
|--------|------|
| **Migration** | Create `asset_inventory` table |
| **Create** | `docs/asset_inventory.py` |
| **Create** | `src/components/AssetInventory.tsx` |
| **Modify** | `supabase/functions/ingest-traffic/index.ts` — accept assets payload |
| **Modify** | `src/pages/Index.tsx` — add Assets tab |
| **Modify** | `src/components/AlertsPanel.tsx` — show asset context on alerts |

