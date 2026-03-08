

# Incident Scoring Engine — Implementation Plan

## Current State

| Component | What Exists | Gap |
|-----------|-------------|-----|
| **Alert processing** | `ingest-traffic` inserts individual alerts into `live_alerts` | No aggregation into prioritized incidents |
| **Correlation** | `useThreatCorrelation` groups by IP + detects kill chain sequences | Only runs in-browser, not server-side |
| **Incident creation** | `useIntegratedDetection` creates incidents for high-score events | Per-event, not aggregated |
| **Scoring** | `calculateCompositeScore()` in correlation hook | Not applied to incident prioritization queue |

**Result**: Alerts appear individually in the panel. No unified incident with "port scan + beacon + DNS anomaly = critical incident".

---

## Plan

### 1. Server-Side Incident Scoring Edge Function

Create `supabase/functions/score-incidents/index.ts`:

- Called periodically or on-demand
- Aggregates recent `live_alerts` by `source_ip` within a time window
- Applies scoring formula:
  ```
  score = Σ(severity_weight × recency_factor) × attack_diversity_bonus × sequence_bonus
  ```
- Creates or updates rows in a new `scored_incidents` table
- Marks alerts as "aggregated" to avoid double-counting

### 2. New Database Table: `scored_incidents`

| Column | Type | Description |
|--------|------|-------------|
| `id` | uuid | Primary key |
| `source_ip` | text | Aggregation key |
| `total_score` | integer | Computed priority score |
| `alert_count` | integer | Number of aggregated alerts |
| `attack_types` | jsonb | Unique attack types detected |
| `severity` | text | Derived from score: critical/high/medium/low |
| `first_alert_at` | timestamptz | Earliest alert timestamp |
| `last_alert_at` | timestamptz | Most recent alert |
| `status` | text | open/investigating/resolved |
| `alert_ids` | jsonb | Array of linked alert UUIDs |
| `created_at` / `updated_at` | timestamptz | Audit timestamps |

### 3. Python Agent: `incident_scoring_engine.py`

Create `docs/incident_scoring_engine.py`:

- Local scoring logic for near-real-time prioritization
- Same formula as edge function (consistency)
- Pushes aggregated incidents to `ingest-traffic` as `{ incidents: [...] }`
- Keeps a sliding window cache of recent alerts per source IP

### 4. Modify `ingest-traffic` Edge Function

- Accept optional `incidents[]` payload alongside `alerts[]`
- Insert/upsert into `scored_incidents` table
- Return `incidents_inserted` count

### 5. UI: Incident Priority Queue

Modify `src/components/IncidentResponse.tsx`:

- Add "Priority Queue" tab showing `scored_incidents` sorted by `total_score` desc
- Each row shows: score badge, IP, attack type tags, alert count, time window
- Click to expand linked alerts
- One-click "Investigate" promotes to full incident workflow

### 6. Scoring Formula (Technical Detail)

```text
SEVERITY_WEIGHTS = { critical: 25, high: 15, medium: 8, low: 3 }

For each source_ip in window:
  base = Σ SEVERITY_WEIGHTS[alert.severity]
  diversity = unique_attack_types.length × 10
  sequence = has_kill_chain_sequence ? 30 : 0
  recency = alerts_in_last_5_min × 1.5 + alerts_in_last_15_min × 1.0
  
  total_score = base + diversity + sequence + recency

Severity mapping:
  critical: score ≥ 100
  high: score ≥ 60
  medium: score ≥ 30
  low: score < 30
```

---

## Files Summary

| Action | File |
|--------|------|
| **Create** | `supabase/functions/score-incidents/index.ts` — aggregation + scoring |
| **Create** | `docs/incident_scoring_engine.py` — agent-side scoring |
| **Modify** | `supabase/functions/ingest-traffic/index.ts` — accept incidents payload |
| **Modify** | `src/components/IncidentResponse.tsx` — Priority Queue tab |
| **Migration** | Create `scored_incidents` table with RLS policies |

