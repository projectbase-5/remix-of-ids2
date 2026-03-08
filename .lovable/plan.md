
# Correlation Engine Enhancement Plan

## Current State Analysis

The correlation engine has two components:

1. **`useThreatCorrelation` hook** - Groups events by source IP within a 15-minute window, maps attack types to kill chain phases (Recon → Exploit → C2 → Exfil), calculates composite scores, and flags multi-stage attacks.

2. **`ThreatCorrelator` component** - Provides statistics and simple correlation types (IP, attack pattern, time-based) but runs only in-memory on the threats array.

3. **`CorrelationEngine` component** - Displays kill chain visualization and real-time correlation groups from Supabase incident_logs.

### Gaps Identified

| Gap | Current State | Needed |
|-----|---------------|--------|
| **Persistence** | In-memory only, lost on refresh | Store correlation groups and chains in Supabase |
| **Cross-table linking** | Only uses `incident_logs` | Link `live_alerts` + `incident_logs` + `predictions` for full picture |
| **Attack chain sequences** | Has kill chain mapping but no temporal sequencing | Score sequences (recon→exploit→beacon) higher than random phases |
| **Incident scoring** | Basic average + multiplier | Weighted scoring with temporal decay, phase progression bonus, TTP alignment |
| **Historical correlation** | 15-minute window only | Allow querying historical chains for forensics |

---

## Plan

### 1. Database: Correlation Tables

Create two new tables to persist correlation data:

**`correlation_groups`** — stores detected attack chains
- `id`, `source_ip`, `composite_score`, `phases` (jsonb), `is_multi_stage`, `escalated`, `first_seen`, `last_seen`, `created_at`

**`correlation_events`** — links events to groups
- `id`, `group_id` (FK), `event_type` (incident_log | live_alert | prediction), `event_id`, `timestamp`, `attack_type`, `phase`, `threat_score`

### 2. Enhanced Correlation Hook

Modify `src/hooks/useThreatCorrelation.ts`:

- **Temporal sequence scoring** — reward events that follow kill chain order (recon before exploit before c2)
- **Persist groups** — upsert detected groups to `correlation_groups` table
- **Link multiple sources** — correlate across `incident_logs`, `live_alerts`, and high-confidence `predictions`
- **Weighted composite score formula**:
  ```
  score = baseAvg × phaseBonus × sequenceBonus × recencyMultiplier
  ```
- **Configurable window** — support 15m, 1h, 24h correlation windows

### 3. Cross-Table Aggregation

Create `src/hooks/useCorrelationAggregator.ts`:

- Fetch recent events from all three tables
- Normalize into a common `CorrelationEvent` shape
- Deduplicate by IP + attack type + 1-minute window
- Feed unified events to the correlation engine

### 4. Attack Chain Sequence Detection

Add sequence pattern matching in `useThreatCorrelation`:

```text
Patterns:
  RECON_TO_EXFIL: [reconnaissance → exploitation → command_control → exfiltration]
  DELIVERY_CHAIN: [delivery → exploitation → installation]
  LATERAL_MOVE: [exploitation → installation → command_control]

Score bonus: +20 for 3-phase sequence, +40 for 4+ phase sequence in order
```

### 5. UI Enhancements

Modify `src/components/CorrelationEngine.tsx`:

- Add "Historical Mode" toggle to query persisted chains beyond 15 minutes
- Show sequence match indicator (e.g., "Recon → Exploit → C2" badge)
- Add "Escalate to Incident" button that creates a formal incident_log entry
- Show linked events from all sources with type badges

### 6. Build Error Fix

Modify `vite.config.ts`:
- Add `workbox.maximumFileSizeToCacheInBytes: 3 * 1024 * 1024` to fix PWA precache limit error

---

## Files Summary

| Action | File |
|--------|------|
| **Migration** | Create `correlation_groups` and `correlation_events` tables |
| **Modify** | `vite.config.ts` — fix workbox size limit |
| **Modify** | `src/hooks/useThreatCorrelation.ts` — add persistence, sequence scoring |
| **Create** | `src/hooks/useCorrelationAggregator.ts` — cross-table event aggregation |
| **Modify** | `src/components/CorrelationEngine.tsx` — historical mode, sequence badges, escalation |
