

# Attack Timeline Builder — Implementation Plan

## Purpose

Reconstruct attack sequences per source IP by correlating alerts, incidents, and hunt results into a chronological timeline. Analysts see the full kill chain: port scan -> exploit -> beacon -> exfiltration.

## Plan

### 1. Python Agent: `docs/attack_timeline_builder.py`

- Queries `live_alerts`, `scored_incidents`, and `hunt_results` for a given source IP
- Orders events chronologically and maps each to a kill chain phase (reconnaissance, exploitation, command-and-control, exfiltration, etc.)
- Detects multi-stage attack patterns (e.g., scan followed by exploit within 5 minutes)
- Pushes assembled timelines to `ingest-traffic` as `attack_timelines[]`

### 2. Database: `attack_timelines` Table

| Column | Type |
|--------|------|
| id | uuid (PK) |
| source_ip | text |
| timeline_events | jsonb (array of {timestamp, event_type, phase, description, severity, ref_id}) |
| kill_chain_phases | jsonb (detected phases) |
| total_events | integer |
| first_event_at | timestamptz |
| last_event_at | timestamptz |
| is_active | boolean (default true) |
| created_at / updated_at | timestamptz |

RLS: full public access (matches project pattern).

### 3. Modify `ingest-traffic` Edge Function

- Accept optional `attack_timelines[]` payload
- Upsert by `source_ip` (merge events, update timestamps)

### 4. UI: `src/components/AttackTimeline.tsx`

- Vertical timeline visualization showing events in chronological order
- Each event shows: time, type, phase badge (color-coded by kill chain stage), description
- Filter by source IP dropdown
- Kill chain progress bar showing which phases were detected
- "Build Timeline" button that assembles timeline client-side from `live_alerts` + `scored_incidents` + `hunt_results` for a selected IP
- Summary cards: total attacks tracked, active timelines, most advanced kill chain

### 5. Add "Timeline" Tab to Dashboard

- New tab trigger in `src/pages/Index.tsx`
- New `TabsContent` rendering `AttackTimeline`

## Files Summary

| Action | File |
|--------|------|
| **Create** | `docs/attack_timeline_builder.py` |
| **Create** | `src/components/AttackTimeline.tsx` |
| **Modify** | `supabase/functions/ingest-traffic/index.ts` — accept `attack_timelines[]` |
| **Modify** | `src/pages/Index.tsx` — add Timeline tab |
| **Migration** | Create `attack_timelines` table |

