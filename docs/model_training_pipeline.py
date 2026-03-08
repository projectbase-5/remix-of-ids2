"""
Model Training Pipeline
========================
Server-side ML training pipeline using scikit-learn.

Fetches training data from the Supabase ``training_data`` table,
trains one of four supported algorithms, evaluates performance,
and upserts results to ``ml_models`` and ``model_evaluations``.

Supported algorithms:
    - Random Forest
    - C4.5 (Decision Tree with entropy criterion)
    - GBDT (Gradient Boosted Decision Trees)
    - DT+SVM (Decision Tree feature selection + SVM classifier)

Prerequisites:
    pip install scikit-learn requests numpy

Usage:
    python docs/model_training_pipeline.py --algorithm random_forest
"""

import os
import json
import time
import uuid
import argparse
import requests
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    classification_report,
)
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.pipeline import Pipeline

SUPABASE_URL = os.environ.get(
    "SUPABASE_URL", "https://saeofugyscjfgqqnqowk.supabase.co"
)
SUPABASE_KEY = os.environ.get("SUPABASE_ANON_KEY", "YOUR_SUPABASE_ANON_KEY")

ALGORITHMS = {
    "random_forest": "Random Forest",
    "c45": "C4.5 Decision Tree",
    "gbdt": "Gradient Boosted DT",
    "dt_svm": "DT + SVM",
}


class ModelTrainingPipeline:
    """End-to-end training pipeline backed by Supabase REST API."""

    def __init__(self, supabase_url=SUPABASE_URL, supabase_key=SUPABASE_KEY):
        self.base_url = f"{supabase_url}/rest/v1"
        self.headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.label_encoder = LabelEncoder()
        self.feature_names = []
        self.model = None
        self.model_name = ""

    # ------------------------------------------------------------------
    # 1. Load dataset
    # ------------------------------------------------------------------
    def load_dataset(self, dataset_id=None, test_size=0.2):
        """
        Fetch training data from Supabase and split into train/test.
        Uses ``processed_features`` if available, otherwise ``features``.
        """
        url = f"{self.base_url}/training_data?select=*&order=created_at.desc&limit=1000"
        if dataset_id:
            url += f"&dataset_id=eq.{dataset_id}"

        resp = requests.get(url, headers=self.headers, timeout=15)
        resp.raise_for_status()
        rows = resp.json()

        if not rows:
            raise ValueError("No training data found in database")

        print(f"[PIPELINE] Loaded {len(rows)} training records")

        # Extract features and labels
        X_raw, y_raw = [], []
        for row in rows:
            feats = row.get("processed_features") or row.get("features", {})
            if isinstance(feats, str):
                feats = json.loads(feats)
            label = row.get("label", "normal")
            X_raw.append(feats)
            y_raw.append(label)

        # Convert feature dicts to numpy array
        all_keys = sorted({k for d in X_raw for k in d.keys()})
        self.feature_names = all_keys
        X = np.array([[d.get(k, 0) for k in all_keys] for d in X_raw], dtype=float)

        # Handle NaN/Inf
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

        # Encode labels
        y = self.label_encoder.fit_transform(y_raw)

        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        classes = list(self.label_encoder.classes_)
        print(f"[PIPELINE] Features: {len(all_keys)} | Classes: {classes}")
        print(f"[PIPELINE] Train: {len(self.X_train)} | Test: {len(self.X_test)}")
        return self

    # ------------------------------------------------------------------
    # 2. Train model
    # ------------------------------------------------------------------
    def train_model(self, algorithm="random_forest"):
        """Train a model using the specified algorithm."""
        if self.X_train is None:
            raise RuntimeError("Call load_dataset() first")

        self.model_name = ALGORITHMS.get(algorithm, algorithm)
        print(f"[PIPELINE] Training {self.model_name}...")

        start = time.time()

        if algorithm == "random_forest":
            self.model = Pipeline([
                ("scaler", StandardScaler()),
                ("clf", RandomForestClassifier(
                    n_estimators=100,
                    max_depth=20,
                    min_samples_split=5,
                    random_state=42,
                    n_jobs=-1,
                )),
            ])
        elif algorithm == "c45":
            self.model = Pipeline([
                ("scaler", StandardScaler()),
                ("clf", DecisionTreeClassifier(
                    criterion="entropy",
                    max_depth=20,
                    min_samples_split=5,
                    random_state=42,
                )),
            ])
        elif algorithm == "gbdt":
            self.model = Pipeline([
                ("scaler", StandardScaler()),
                ("clf", GradientBoostingClassifier(
                    n_estimators=100,
                    max_depth=6,
                    learning_rate=0.1,
                    random_state=42,
                )),
            ])
        elif algorithm == "dt_svm":
            # Stage 1: Decision Tree for feature selection
            dt = DecisionTreeClassifier(criterion="entropy", max_depth=10, random_state=42)
            dt.fit(self.X_train, self.y_train)
            importances = dt.feature_importances_
            top_k = min(20, len(importances))
            top_indices = np.argsort(importances)[-top_k:]

            self.X_train = self.X_train[:, top_indices]
            self.X_test = self.X_test[:, top_indices]
            self.feature_names = [self.feature_names[i] for i in top_indices]

            # Stage 2: SVM on selected features
            self.model = Pipeline([
                ("scaler", StandardScaler()),
                ("clf", SVC(kernel="rbf", probability=True, random_state=42)),
            ])
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")

        self.model.fit(self.X_train, self.y_train)
        elapsed = round((time.time() - start) * 1000)
        print(f"[PIPELINE] Training complete in {elapsed}ms")
        return elapsed

    # ------------------------------------------------------------------
    # 3. Evaluate model
    # ------------------------------------------------------------------
    def evaluate_model(self):
        """Compute all metrics on the test set."""
        if self.model is None:
            raise RuntimeError("Call train_model() first")

        start = time.time()
        y_pred = self.model.predict(self.X_test)
        testing_time = round((time.time() - start) * 1000)

        classes = list(self.label_encoder.classes_)
        is_binary = len(classes) == 2
        avg = "binary" if is_binary else "weighted"

        acc = accuracy_score(self.y_test, y_pred)
        prec = precision_score(self.y_test, y_pred, average=avg, zero_division=0)
        rec = recall_score(self.y_test, y_pred, average=avg, zero_division=0)
        f1 = f1_score(self.y_test, y_pred, average=avg, zero_division=0)
        cm = confusion_matrix(self.y_test, y_pred).tolist()

        # ROC AUC (if model supports predict_proba)
        roc = None
        if hasattr(self.model, "predict_proba"):
            try:
                y_prob = self.model.predict_proba(self.X_test)
                if is_binary:
                    roc = roc_auc_score(self.y_test, y_prob[:, 1])
                else:
                    roc = roc_auc_score(self.y_test, y_prob, multi_class="ovr", average="weighted")
            except Exception:
                pass

        # Per-class performance
        report = classification_report(self.y_test, y_pred, target_names=classes, output_dict=True, zero_division=0)
        class_perf = {k: v for k, v in report.items() if k in classes}

        # Feature importance (for tree-based models)
        feature_importance = {}
        clf = self.model.named_steps.get("clf")
        if hasattr(clf, "feature_importances_"):
            for name, imp in zip(self.feature_names, clf.feature_importances_):
                feature_importance[name] = round(float(imp), 4)

        # Detection rate (for attack classes — anything not 'normal' or 'benign')
        attack_mask = np.array([
            self.label_encoder.classes_[l].lower() not in ("normal", "benign")
            for l in self.y_test
        ])
        if attack_mask.sum() > 0:
            detection_rate = recall_score(
                self.y_test[attack_mask],
                y_pred[attack_mask],
                average="weighted",
                zero_division=0,
            )
        else:
            detection_rate = None

        # False positive rate
        normal_mask = ~attack_mask
        if normal_mask.sum() > 0:
            fp = np.sum((y_pred[normal_mask] != self.y_test[normal_mask]))
            fpr = fp / normal_mask.sum()
        else:
            fpr = None

        metrics = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc, 4) if roc else None,
            "confusion_matrix": cm,
            "class_performance": class_perf,
            "feature_importance": feature_importance,
            "detection_rate": round(detection_rate, 4) if detection_rate else None,
            "false_positive_rate": round(fpr, 4) if fpr is not None else None,
            "testing_time_ms": testing_time,
        }

        print(f"[PIPELINE] Accuracy: {acc:.4f} | F1: {f1:.4f} | ROC-AUC: {roc or 'N/A'}")
        return metrics

    # ------------------------------------------------------------------
    # 4. Save model to database
    # ------------------------------------------------------------------
    def save_model(self, algorithm, training_time_ms, metrics, dataset_id=None):
        """Upsert model record and evaluation to Supabase."""
        model_id = str(uuid.uuid4())

        # Insert ml_models record
        model_record = {
            "id": model_id,
            "name": f"{self.model_name} (Server)",
            "algorithm": algorithm,
            "version": "1.0",
            "status": "trained",
            "is_active": True,
            "model_config": {
                "algorithm": algorithm,
                "trained_by": "server_pipeline",
                "features_count": len(self.feature_names),
                "train_samples": len(self.X_train),
                "test_samples": len(self.X_test),
            },
            "feature_importance": metrics.get("feature_importance", {}),
            "training_dataset_id": dataset_id,
        }

        resp = requests.post(
            f"{self.base_url}/ml_models",
            json=model_record,
            headers=self.headers,
            timeout=10,
        )
        if resp.status_code not in (200, 201):
            print(f"[PIPELINE] Failed to save model: {resp.status_code} {resp.text[:200]}")
            return None

        # Insert model_evaluations record
        eval_record = {
            "model_id": model_id,
            "dataset_id": dataset_id,
            "evaluation_type": "server_training",
            "accuracy": metrics["accuracy"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1_score": metrics["f1_score"],
            "roc_auc": metrics.get("roc_auc"),
            "confusion_matrix": metrics["confusion_matrix"],
            "class_performance": metrics.get("class_performance"),
            "detection_rate": metrics.get("detection_rate"),
            "false_positive_rate": metrics.get("false_positive_rate"),
            "training_time_ms": training_time_ms,
            "testing_time_ms": metrics.get("testing_time_ms"),
        }

        resp = requests.post(
            f"{self.base_url}/model_evaluations",
            json=eval_record,
            headers=self.headers,
            timeout=10,
        )
        if resp.status_code not in (200, 201):
            print(f"[PIPELINE] Failed to save evaluation: {resp.status_code} {resp.text[:200]}")

        print(f"[PIPELINE] Model saved: {model_id}")
        return model_id

    # ------------------------------------------------------------------
    # 5. Full pipeline
    # ------------------------------------------------------------------
    def run_full_pipeline(self, algorithm="random_forest", dataset_id=None):
        """Orchestrate: load → train → evaluate → save."""
        print("=" * 60)
        print(f"  Model Training Pipeline — {ALGORITHMS.get(algorithm, algorithm)}")
        print("=" * 60)

        self.load_dataset(dataset_id=dataset_id)
        training_time = self.train_model(algorithm)
        metrics = self.evaluate_model()
        model_id = self.save_model(algorithm, training_time, metrics, dataset_id)

        print("=" * 60)
        print(f"  Pipeline complete — Model ID: {model_id}")
        print(f"  Accuracy: {metrics['accuracy']:.4f}")
        print(f"  F1 Score: {metrics['f1_score']:.4f}")
        print("=" * 60)
        return model_id


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDS Model Training Pipeline")
    parser.add_argument(
        "--algorithm",
        choices=list(ALGORITHMS.keys()),
        default="random_forest",
        help="Algorithm to train",
    )
    parser.add_argument("--dataset-id", default=None, help="Optional dataset UUID")
    args = parser.parse_args()

    pipeline = ModelTrainingPipeline()
    pipeline.run_full_pipeline(algorithm=args.algorithm, dataset_id=args.dataset_id)
