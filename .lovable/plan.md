

# Modules 8 & 9 — Threat Hunting Engine + Risk Score Calculator

## Current State

| Module | Exists | Gap |
|--------|--------|-----|
| **Threat Hunting** | `ThreatHunter.tsx` — filter-based search across incidents/predictions/IP reputation | No Python agent, no advanced queries (rare destinations, DNS entropy) |
| **Risk Scoring** | `incident_scoring_engine.py` scores incidents per source IP | No per-host composite risk score combining alerts + anomalies + reputation; no network-wide risk on Overview |

---

## Module 8 — Threat Hunting Engine

### Python Agent: `docs/threat_hunting_engine.py`

- Pre-built hunt queries:
  - **Rare destinations**: find hosts contacting IPs seen by < N other hosts
  - **DNS entropy**: flag hostnames with high Shannon entropy (DGA detection)
  - **Beaconing**: detect periodic connections (low jitter intervals)
  - **Data exfil**: find hosts with abnormally high outbound bytes
- Each query posts results to `ingest-traffic` as `hunt_results[]`
- Exposes `run_hunt(query_type, params)` callable from other modules

### Database: `hunt_results` Table

| Column | Type |
|--------|------|
| id | uuid |
| hunt_type | text (rare_destination, dns_entropy, beaconing, data_exfil) |
| source_ip | text |
| target | text (destination IP or domain) |
| score | numeric |
| details | jsonb |
| created_at | timestamptz |

### UI: Enhance `ThreatHunter.tsx`

- Add "Advanced Hunts" section with one-click buttons for each hunt type
- Display `hunt_results` in a dedicated results tab
- Show entropy scores and beaconing intervals visually

### Modify `ingest-traffic`

- Accept `hunt_results[]` payload and insert into table

---

## Module 9 — Risk Score Calculator

### Python Agent: `docs/risk_scoring_engine.py`

- Computes per-host risk score:
  ```
  risk = alert_score + anomaly_score + reputation_penalty + asset_criticality_weight
  ```
  - `alert_score`: sum of severity weights from `scored_incidents` for that IP
  - `anomaly_score`: count of anomaly predictions × 5
  - `reputation_penalty`: (100 - reputation_score) from `ip_reputation`
  - `asset_criticality_weight`: critical=2x, high=1.5x, medium=1x, low=0.5x
- Pushes results to `host_risk_scores` table
- Computes **network-wide risk** = weighted average of all active host scores

### Database: `host_risk_scores` Table

| Column | Type |
|--------|------|
| id | uuid |
| ip_address | text (unique) |
| hostname | text |
| alert_score | integer |
| anomaly_score | integer |
| reputation_score | integer |
| asset_multiplier | numeric |
| total_risk | integer |
| risk_level | text (critical/high/medium/low) |
| updated_at | timestamptz |
| created_at | timestamptz |

### UI: `src/components/RiskScoreDashboard.tsx`

- Network Risk Score gauge (0-100) at the top
- Top 10 riskiest hosts table with breakdown columns
- Risk trend chart (recharts)
- Manual "Recalculate" button that computes scores client-side from existing tables

### Overview Page Enhancement

- Add a **Network Risk Score** card to the Overview grid (above Recent Threats)
- Shows the aggregate score with color coding (green/yellow/red)

---

## Files Summary

| Action | File |
|--------|------|
| **Create** | `docs/threat_hunting_engine.py` |
| **Create** | `docs/risk_scoring_engine.py` |
| **Create** | `src/components/RiskScoreDashboard.tsx` |
| **Modify** | `src/components/ThreatHunter.tsx` — add advanced hunt buttons + hunt_results display |
| **Modify** | `supabase/functions/ingest-traffic/index.ts` — accept hunt_results payload |
| **Modify** | `src/pages/Index.tsx` — add Risk tab + Network Risk card on Overview |
| **Migration** | Create `hunt_results` and `host_risk_scores` tables |

