

# Pipeline Verification: Regex Detection, ML Models, and Correlation Engine

## Summary of Findings

After inspecting the codebase, here is the status of each module and what needs to be fixed or connected.

---

## 1. Regex Payload Detection — FUNCTIONAL

**Status: Fully wired in the Python agent pipeline.**

- `ids_agent.py` lines 130-171: `evaluate_regex_rules()` checks `payload_preview` against active regex patterns fetched from the `detection_rules` table via `rule_fetcher.py`.
- Matched rules generate alerts with `detection_module: "regex_engine"` and a `dedupe_key`, which are sent through `AlertManager` to the `ingest-traffic` edge function.
- The edge function (`ingest-traffic/index.ts`) inserts these alerts into `live_alerts` with dedup checking.
- `payload_preview` is extracted from raw packets in `packet_callback()` (line 194) using scapy's `Raw` layer.

**Verdict: No changes needed.** Regex detection works end-to-end when the Python agent is running. The only prerequisite is that `detection_rules` rows with `rule_type = 'regex'` exist in the database.

---

## 2. ML Models — PARTIALLY CONNECTED

**Status: Feature extraction is real, but inference uses in-memory client-side models only.**

- `useNetworkFeatureExtractor.ts` extracts real ML features (sliding window aggregates, flag derivation, port-to-service mapping) from `NetworkEvent` objects — this is solid.
- `RealtimeInference.tsx` runs inference on a 1-second interval against live `networkEvents` from the data store, using `useMLPipeline` for prediction.
- `useMLPipeline` trains/predicts using `mlAlgorithms.ts` (client-side Random Forest and PCA from `ml-random-forest` and `ml-pca`).
- Predictions are persisted to the `predictions` table in Supabase.

**Gap: ML models do NOT consume flow data from `flow_metrics_log` or raw `network_traffic` DB rows directly.** They only process events already loaded into the client-side `useIDSDataStore`. In live mode (agent running), network traffic rows arrive via realtime subscription and get processed. In demo mode, synthetic events are used.

**Verdict: The ML pipeline is functional but client-side only.** Models train and predict on real feature vectors extracted from network events. They are not purely visual demonstrations. However, they don't query historical `network_traffic` or `flow_metrics_log` for batch training — training data comes from the `training_data` table or client-side events.

**No changes proposed** — this is working as designed for a browser-based IDS dashboard.

---

## 3. Correlation Engine — FUNCTIONAL but needs verification of alert flow

**Status: Fully wired with multi-source aggregation.**

- `CorrelationEngine.tsx` uses `useCorrelationAggregator` to fetch events from **three sources in parallel**: `incident_logs`, `live_alerts`, and `predictions` (anomalies with confidence >= 0.7).
- These aggregated events are fed into `useThreatCorrelation` which groups by source IP, maps attack types to kill chain phases, detects multi-stage sequences, and calculates composite scores.
- Real-time subscriptions on `incident_logs` (INSERT) and `live_alerts` (INSERT) feed new events into the correlation engine as they arrive.
- High-scoring groups (>= 60) are persisted to `correlation_groups` and `correlation_events` tables.
- Escalation creates new `incident_logs` entries typed as `multi_stage_attack`.

**The full flow:**
```text
Python Agent → ingest-traffic edge fn → live_alerts table
                                           ↓ (realtime subscription)
                                    CorrelationEngine
                                           ↓
                                    correlation_groups (persisted)
                                           ↓ (escalate)
                                    incident_logs (multi_stage_attack)
```

**Verdict: Alerts do feed into correlation.** The pipeline is complete. When the Python agent sends alerts, they land in `live_alerts`, which triggers the realtime subscription in `CorrelationEngine`, which processes them through the correlation logic.

---

## Overall Assessment

| Module | Status | Action Needed |
|--------|--------|---------------|
| Regex Payload Detection | Fully functional | None — works when agent runs |
| ML Models | Functional (client-side) | None — extracts real features, trains real models |
| Correlation Engine | Fully functional | None — aggregates all three data sources |

**All three modules are wired into the pipeline and operational.** No code changes are required. The system works end-to-end when the Python IDS agent (`ids_agent.py`) is running and sending data to the `ingest-traffic` edge function.

