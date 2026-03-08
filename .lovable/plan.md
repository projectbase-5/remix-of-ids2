

# Plan: Model Training Pipeline + Alert Suppression Engine

## 1. Model Training Pipeline (`docs/model_training_pipeline.py`)

### Current State
The frontend ML pipeline is complete — `MLModelManager.tsx` already supports training all 4 algorithms (Random Forest, C4.5, GBDT, DT+SVM), saving to `ml_models` and `model_evaluations` tables, and displaying accuracy/confusion matrices. Training runs client-side via Web Workers.

What's missing is a **Python backend module** that can train models on the server side using data from the `training_data` table, enabling batch training outside the browser.

### Changes

**Create `docs/model_training_pipeline.py`**
- Class `ModelTrainingPipeline` with Supabase REST API access
- `load_dataset()` — fetch from `training_data` table, split into train/test
- `train_model(algorithm)` — train Random Forest, C4.5, GBDT, or DT+SVM using scikit-learn
- `evaluate_model()` — compute accuracy, precision, recall, F1, confusion matrix
- `save_model()` — upsert results to `ml_models` and `model_evaluations` tables
- `run_full_pipeline(algorithm)` — orchestrate load → train → evaluate → save

**No frontend changes needed** — `MLModelManager.tsx` already reads from `ml_models` and `model_evaluations` and displays all metrics including confusion matrices.

---

## 2. Alert Suppression / Noise Reduction

### Current State
No suppression logic exists anywhere. The `alert_manager.py` does deduplication (same alert type + IP within 60s), but there's no concept of trusted hosts, severity thresholds, or suppression rules.

### Changes

**Create `docs/alert_suppression_engine.py`**
- Class `AlertSuppressionEngine`
- Fetches suppression rules from a new `suppression_rules` DB table
- Rule types: trusted IP (always suppress), severity threshold (ignore below threshold), rate limit (max N alerts per IP per window), pattern ignore (suppress by alert_type regex)
- `evaluate(alerts) → filtered_alerts` — returns only non-suppressed alerts
- Tracks suppression stats (total suppressed, by rule, by IP)

**Create DB migration** — new `suppression_rules` table:
- `id`, `rule_type` (trusted_ip, severity_filter, rate_limit, pattern_ignore), `value` (IP/pattern/threshold), `description`, `is_active`, `created_at`, `updated_at`

**Modify `docs/ids_agent.py`** — add suppression step between detection and alert_manager:
```
alerts → suppression_engine.evaluate() → alert_manager.process()
```

**Modify `src/components/EnhancedRuleManager.tsx`** — add a "Suppression Rules" tab with:
- List of active suppression rules
- Add/edit/delete rules (trusted IP, severity filter, rate limit, pattern ignore)
- Stats showing how many alerts were suppressed

---

## Files to Create/Modify

| File | Action |
|------|--------|
| `docs/model_training_pipeline.py` | Create |
| `docs/alert_suppression_engine.py` | Create |
| `docs/ids_agent.py` | Modify — wire suppression before alert_manager |
| `src/components/EnhancedRuleManager.tsx` | Modify — add Suppression Rules tab |
| DB migration | Create `suppression_rules` table |

