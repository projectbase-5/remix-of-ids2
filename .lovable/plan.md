

# ML Detection Pipeline — From Simulation to Real

## Current State

The ML pipeline has all the UI pieces but three critical gaps:

1. **Training uses fake data** — the web worker generates random synthetic samples instead of pulling from the `network_traffic` / `training_data` tables.
2. **Inference features are mostly simulated** — `RealtimeInference.convertNetworkEventToFeatures()` fills most fields with `Math.random()` or hardcoded values instead of deriving them from actual packet metadata.
3. **No model update pipeline** — there's no mechanism to retrain on new data or detect model drift.

## Plan

### 1. Real Network Feature Extraction

**File: `src/hooks/useNetworkFeatureExtractor.ts`** (new)

Create a utility hook/module that converts real `network_traffic` rows and `NetworkEvent` objects into proper ML feature vectors:

- Map `protocol` (TCP/UDP/ICMP) to numeric
- Derive `src_bytes`/`dst_bytes` from `packet_size`
- Compute connection-level aggregates from the sliding window of recent events: `count` (connections to same destination in last 2s), `srv_count`, `serror_rate`, `same_srv_rate`, etc.
- Detect `land` (source IP == destination IP)
- Use `port` to infer `service` (80→http, 22→ssh, etc.)
- Use `flags` array from the event to derive `flag` feature (SYN, RST, etc.)
- Compute `dst_host_count`, `dst_host_srv_count` from the recent event window

This replaces the hardcoded/random values in `RealtimeInference.convertNetworkEventToFeatures()`.

**File: `src/components/RealtimeInference.tsx`** (modify)

- Replace `convertNetworkEventToFeatures()` with the new extractor
- Remove all `Math.random()` calls from feature creation

### 2. Train on Real Data

**File: `src/workers/mlTraining.worker.ts`** (modify)

Accept an optional `trainingData` payload in the message instead of always generating synthetic data:

```text
Worker receives:
  { type: 'train', algorithm: 'RandomForest', trainingData?: { features, labels } }

If trainingData is provided → use it
If not → fall back to synthetic generation (keeps the "quick demo" path working)
```

**File: `src/hooks/useMLWorker.ts`** (modify)

- Update `trainInWorker(algorithm, trainingData?)` to accept optional real data

**File: `src/components/MLModelManager.tsx`** (modify)

- Add a "Train on Live Data" button that:
  1. Fetches recent rows from `network_traffic` (last N rows, e.g. 500-1000)
  2. Fetches labeled data from `training_data` table if available
  3. Runs feature extraction on them
  4. Passes the real feature matrix + labels to the worker
- Keep existing buttons as "Train on Synthetic Data" for quick testing

### 3. Model Update Pipeline

**File: `src/hooks/useModelUpdatePipeline.ts`** (new)

A hook that manages automated model refresh:

- **Drift detection**: Track prediction distribution over a sliding window. If the ratio of attack/benign predictions shifts significantly from the training distribution (configurable threshold, default 10%), flag drift.
- **Scheduled retraining trigger**: When drift is detected or a configurable time interval passes (e.g. 24h), prompt the user or auto-retrain using the latest `training_data` + recent `network_traffic`.
- **Model versioning**: When retraining completes, save the new model to `ml_models` with an incremented version, and optionally deactivate the old one.
- **Feedback loop**: When an analyst marks an incident as false positive/resolved in `incident_logs`, write a row to `training_data` with the corrected label so future training improves.

**File: `src/components/AdaptiveLearning.tsx`** (modify)

- Wire up the drift detection stats and retraining controls from the new hook
- Show drift score, last retrained timestamp, pending feedback count

### 4. Database: Store Feedback Labels

**Migration**: Add a `feedback_label` column to `predictions` table (or use existing `actual_label` column which already exists but is unused). No new table needed — `predictions.actual_label` and `predictions.feedback_provided` are already there.

Write an RPC or simple update to let analysts provide ground-truth labels on predictions, which feeds back into training data.

## Technical Details

- **Feature window aggregation** needs access to the recent ~100 events kept in `useIDSDataStore`. The extractor will accept the event + the current window array.
- **Worker data transfer**: Real training data (1000 rows x 40 features) is ~320KB as a typed array — well within `postMessage` limits.
- **No new dependencies** required. All computation uses existing `ml-matrix`, `ml-pca`, `ml-random-forest`.
- **Existing prediction flow** (`useIntegratedDetection.processLogEntry`) already has good feature extraction for log entries — we align the network feature extractor to produce compatible vectors.

## Files Summary

| Action | File |
|--------|------|
| Create | `src/hooks/useNetworkFeatureExtractor.ts` |
| Create | `src/hooks/useModelUpdatePipeline.ts` |
| Modify | `src/workers/mlTraining.worker.ts` |
| Modify | `src/hooks/useMLWorker.ts` |
| Modify | `src/components/MLModelManager.tsx` |
| Modify | `src/components/RealtimeInference.tsx` |
| Modify | `src/components/AdaptiveLearning.tsx` |
| Migration | Update `predictions.actual_label` usage (no schema change needed) |

