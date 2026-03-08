

# Move ML Training to Web Worker

## Problem
ML training (data generation, preprocessing, model training) runs on the main UI thread, freezing the browser despite the yield points added earlier. The CPU-intensive algorithms (especially GBDT with 50 trees) block the thread for long stretches between yields.

## Solution
Create a dedicated Web Worker that handles all CPU-heavy work. The main thread only sends a message and receives results.

```text
UI Thread                    Web Worker
   │                            │
   ├─ postMessage({algorithm}) ──►
   │                            ├─ generateSyntheticData()
   │  ◄── progress(30%) ───────┤
   │                            ├─ preprocessData()
   │  ◄── progress(60%) ───────┤
   │                            ├─ trainModel()
   │  ◄── progress(90%) ───────┤
   │                            ├─ calculateMetrics()
   │  ◄── result({metrics}) ───┤
   │                            │
   ▼ Update UI + save to DB     ▼
```

## Files to Create

### 1. `src/workers/mlTraining.worker.ts`
A self-contained Web Worker that:
- Contains all ML algorithm classes inline (C4.5, GBDT, DTSVMHybrid, RandomForest)
- Contains data generation, normalization, SMOTE, feature extraction logic
- Cannot import from `node_modules` that use Node APIs, so the `ml-random-forest` and `ml-pca` dependencies need special handling
- Listens for `{ type: 'train', algorithm }` messages
- Posts back `{ type: 'progress', value }` and `{ type: 'result', metrics, algorithm }` messages

**Key constraint**: `ml-random-forest` and `ml-pca` use `ml-matrix` which should work in workers via Vite's worker bundling. Vite supports `new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' })` which bundles dependencies.

### 2. `src/hooks/useMLWorker.ts`
A hook that:
- Creates/manages the Worker instance
- Exposes `trainInWorker(algorithm)` returning a Promise
- Forwards progress updates to a callback
- Handles cleanup on unmount

## Files to Modify

### 3. `src/components/MLModelManager.tsx`
- Import and use `useMLWorker` instead of calling `mlPipeline.preprocessData` + `mlPipeline.trainModel` directly
- `trainNewModel` sends work to the worker, receives metrics back
- Still uses `mlPipeline.saveModelToDatabase` on the main thread (needs Supabase client)
- Progress bar driven by worker progress messages

### 4. `src/hooks/useMLPipeline.ts`
- Add a new `saveMetricsToDatabase` method that accepts raw metrics (so the component can save worker results without needing a full MLModel with a live classifier instance)
- Existing methods remain for non-worker use cases (e.g., `predict` for realtime inference)

## Technical Notes
- Vite bundles worker dependencies automatically when using `new URL('./worker.ts', import.meta.url)`
- The worker won't return a live classifier object (can't transfer class instances across threads), so realtime inference will still use main-thread prediction with a fallback heuristic or re-instantiate from saved model data
- No changes to `mlAlgorithms.ts` — the worker will import it directly since Vite bundles it

