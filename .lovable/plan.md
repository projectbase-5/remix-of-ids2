

# Threat Intelligence Enrichment — Real API Integration

## Problem

The current `check-ip-reputation` edge function uses **hardcoded IP ranges** and fake heuristics. No real external threat intelligence APIs are called. Alerts show no enrichment data (reputation, country, threat context).

## Plan

### 1. Upgrade `check-ip-reputation` Edge Function

Replace the `analyzeIPThreat()` hardcoded logic with real API calls:

- **AbuseIPDB** (`api.abuseipdb.com/api/v2/check`) — returns abuse confidence score, country, usage type, ISP, total reports
- **Fallback**: If no API key is configured, keep the existing heuristic logic as a graceful degradation

The function will:
1. Check cache (existing logic, keep as-is)
2. Call AbuseIPDB API with the IP
3. Map response to our schema: `reputation_score` = `abuseConfidenceScore`, `country_code`, `is_tor`/`is_vpn`/`is_proxy` from usage type, `abuse_reports` = `totalReports`
4. Upsert into `ip_reputation` (existing logic)

Requires: User adds `ABUSEIPDB_API_KEY` as a Supabase secret.

### 2. Create `enrich-alert` Edge Function

New edge function that auto-enriches alerts with threat intel:

- Accepts `{ source_ip, destination_ip }` (or an alert ID)
- Calls `check-ip-reputation` internally for both IPs
- Returns enriched context: reputation scores, country, threat types, whether IPs are known malicious
- Optionally called from `ingest-traffic` when new alerts are inserted

### 3. Auto-Enrich in `ingest-traffic`

Modify the existing `ingest-traffic` function:
- After inserting alerts, for each new alert call `check-ip-reputation` on the source IP (internal function call)
- Store the enrichment result in the alert's `metadata` field (already a JSONB column on `live_alerts`)
- This way every alert arriving from the Python agent gets enriched automatically

### 4. Domain Reputation Lookup

Add domain lookup capability to the edge function:
- Accept optional `domain` parameter alongside `ip_address`
- For domains, resolve to IP first, then check reputation
- Store domain-level intel in alert metadata

### 5. Update Dashboard UI

Modify `ThreatIntelligenceDashboard.tsx` and `AlertsPanel.tsx`:
- Show enrichment data on alerts: reputation badge, country flag, threat type tags
- Add domain lookup input alongside IP lookup
- Show API source (AbuseIPDB vs cached vs heuristic) on results

## Files

| Action | File |
|--------|------|
| Modify | `supabase/functions/check-ip-reputation/index.ts` — real AbuseIPDB API call |
| Create | `supabase/functions/enrich-alert/index.ts` — alert enrichment endpoint |
| Modify | `supabase/functions/ingest-traffic/index.ts` — auto-enrich new alerts |
| Modify | `src/components/ThreatIntelligenceDashboard.tsx` — show enrichment source, domain lookup |
| Modify | `src/components/AlertsPanel.tsx` — display reputation badges on alerts |
| Modify | `src/hooks/useThreatIntelligence.ts` — add domain lookup, enrichAlert method |

## Secret Required

User must add `ABUSEIPDB_API_KEY` (free tier: 1000 checks/day at https://www.abuseipdb.com/account/api). Without it, the function falls back to the existing heuristic engine.

