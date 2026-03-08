# Enable Demo Data Across All Pages

## Problem

Currently, only 5 pages respond to demo mode: Overview, Monitor, Events, Alerts, and Detection Engine (via `dataStore`). The remaining ~16 pages fetch directly from Supabase and show empty states when demo mode is on.

## Approach

Pass `isDemoMode` to every component and add local synthetic data generation when demo mode is active. Each component will check `isDemoMode` and either show generated demo data or fetch from Supabase.

## Pages Needing Demo Data


| Page            | Component                   | Current Data Source             | Demo Data Needed                   |
| --------------- | --------------------------- | ------------------------------- | ---------------------------------- |
| Incidents       | IncidentResponse            | Supabase `scored_incidents`     | Synthetic incidents with timelines |
| Correlation     | CorrelationEngine           | Supabase `correlation_events`   | Synthetic correlation groups       |
| Threat Intel    | ThreatIntelligenceDashboard | Supabase `ip_reputation`        | Fake IP reputations, threat feeds  |
| Assets          | AssetInventory              | Supabase `asset_inventory`      | Sample network assets              |
| Topology        | NetworkTopology             | Supabase `network_topology`     | Sample topology edges/nodes        |
| Timeline        | AttackTimeline              | Supabase `attack_timelines`     | Sample kill-chain timelines        |
| Hunt            | ThreatHunter                | Supabase `hunt_results`         | Sample hunt results                |
| Risk Dashboard  | RiskScoreDashboard          | Supabase `host_risk_scores`     | Sample risk scores                 |
| ML Models       | MLModelManager              | Supabase `ml_models`            | Sample trained models              |
| Inference       | RealtimeInference           | Supabase `predictions`          | Sample predictions                 |
| Adaptive        | AdaptiveLearning            | Supabase `adaptive_configs`     | Sample configs                     |
| ML Metrics      | MLMetricsDashboard          | Supabase `model_evaluations`    | Sample evaluations                 |
| Detection Rules | EnhancedRuleManager         | Supabase `detection_rules`      | Sample Snort/Suricata rules        |
| Malware Sigs    | MalwareSignatureManager     | Supabase (malware data)         | Sample signatures                  |
| Datasets        | DatasetManager              | Local hook                      | Already works locally              |
| Retention       | DataRetention               | Supabase `retention_policies`   | Sample policies                    |
| Notifications   | AlertNotifications          | Supabase `notification_configs` | Sample notification configs        |


## Implementation

### 1. Create `src/lib/demoData.ts`

A single file containing all synthetic demo datasets — arrays of fake incidents, assets, topology edges, risk scores, ML models, rules, etc. This keeps demo logic centralized and out of component files.

### 2. Update `src/pages/Index.tsx`

Pass `isDemoMode={dataStore.isDemoMode}` prop to every component in the `renderContent()` switch statement.

### 3. Update each component

For each of the ~16 components above:

- Accept an `isDemoMode?: boolean` prop
- In the data-fetching `useEffect`, check `isDemoMode`: if true, load from `demoData.ts` instead of calling Supabase
- Demo data loads instantly (no loading spinner)

### Files Changed


| File                  | Change                                            |
| --------------------- | ------------------------------------------------- |
| `src/lib/demoData.ts` | **New** — all demo datasets                       |
| `src/pages/Index.tsx` | Pass `isDemoMode` to all components               |
| 16 component files    | Accept `isDemoMode` prop, use demo data when true |


### Key Design Decisions

- Demo data is static snapshots with realistic values (IPs, timestamps, scores)
- Components that already receive `dataStore` (Overview, Events, Alerts, Engine) continue as-is — they already work
- NetworkMonitor already accepts `isDemoMode` — no change needed
- DatasetManager works locally — no change needed  
  
make sure when the demo mode is turned back to off all the datas that are displayed on the demo mode shoudl be erased and should be ready to fetch when the real attack comes  
