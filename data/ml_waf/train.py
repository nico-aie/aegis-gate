#!/usr/bin/env python3
"""
Train LightGBM WAF classifier and export to ONNX for Rust inference.

Usage:
    pip install -r requirements.txt
    python3 train.py                   # train + export
    python3 train.py --export-only     # skip training, re-export ONNX from waf_model.txt
"""
import json
import os
import sys
import time

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from features import NUM_FEATURES, FEATURE_NAMES, extract_features

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "SRBH2020")
UNIFIED_PATH   = os.path.join(HERE, "dataset_unified.csv")
HARDNEG_PATH   = os.path.join(HERE, "legit_hardneg.csv")
MODEL_TXT_PATH = os.path.join(HERE, "waf_model.txt")
ONNX_PATH      = os.path.join(HERE, "waf_model.onnx")
LABEL_MAP_PATH = os.path.join(HERE, "label_map.json")


# ── Data ──────────────────────────────────────────────────────────────────────

def load_data() -> pd.DataFrame:
    if os.path.exists(UNIFIED_PATH):
        print(f"Loading unified dataset: {UNIFIED_PATH}")
        df = pd.read_csv(UNIFIED_PATH).dropna(subset=["text", "category"])
    else:
        print("Unified dataset not found — loading SRBH2020 (run build_dataset.py to merge all sources)")
        frames = [
            pd.read_csv(os.path.join(DATA_DIR, "dataset_capec_combine.csv")),
            pd.read_csv(os.path.join(DATA_DIR, "dataset_capec_transfer.csv")),
        ]
        df = pd.concat(frames, ignore_index=True).dropna(subset=["text", "category"])

    # Merge hard-negative legitimate samples (reduces FP on double-encoded URLs)
    if os.path.exists(HARDNEG_PATH):
        hn = pd.read_csv(HARDNEG_PATH).dropna(subset=["text", "category"])
        df = pd.concat([df, hn], ignore_index=True)
        print(f"  Hard-negatives: +{len(hn):,} samples from {HARDNEG_PATH}")

    # Binary classification: Normal vs Attack
    df["category"] = df["category"].apply(lambda c: "Normal" if c == "Normal" else "Attack")

    print(f"  Total samples : {len(df):,}")
    print(f"  Class counts  : {df['category'].value_counts().to_dict()}")
    return df


def build_features(texts: list[str]) -> np.ndarray:
    print("Extracting features...")
    t0 = time.perf_counter()
    X = np.array([extract_features(t) for t in texts], dtype=np.float32)
    elapsed = time.perf_counter() - t0
    print(f"  {len(texts) / elapsed:,.0f} samples/sec  ({elapsed:.1f}s)")
    return X


# ── Train ─────────────────────────────────────────────────────────────────────

def train_model(X_train, y_train, X_val, y_val) -> lgb.Booster:
    params = {
        "objective": "binary",
        "metric": "binary_logloss",
        "num_leaves": 127,
        "learning_rate": 0.02,
        "feature_fraction": 0.8,
        "bagging_fraction": 0.8,
        "bagging_freq": 5,
        "min_child_samples": 10,
        "reg_alpha": 0.1,
        "reg_lambda": 0.1,
        "is_unbalance": True,
        "n_jobs": -1,
        "verbose": -1,
    }
    train_set = lgb.Dataset(X_train, label=y_train, feature_name=FEATURE_NAMES)
    val_set = lgb.Dataset(X_val, label=y_val, reference=train_set)

    print("\nTraining LightGBM (binary: Normal=0 / Attack=1)...")
    t0 = time.perf_counter()
    booster = lgb.train(
        params,
        train_set,
        num_boost_round=2000,
        valid_sets=[val_set],
        callbacks=[lgb.early_stopping(100), lgb.log_evaluation(200)],
    )
    print(f"  Training time : {time.perf_counter() - t0:.1f}s")
    booster.save_model(MODEL_TXT_PATH)
    print(f"  Native model  -> {MODEL_TXT_PATH}")
    return booster


# ── Evaluate ──────────────────────────────────────────────────────────────────

FAIL_CSV_PATH = os.path.join(HERE, "fail_cases.csv")


def evaluate(
    booster: lgb.Booster,
    X_test,
    y_test,
    texts_test: list[str],
) -> None:
    # binary: predict() returns shape (N,) — probability of Attack (class 1)
    y_prob = booster.predict(X_test)
    y_pred = (y_prob >= 0.5).astype(int)

    print(f"\n{'='*55}")
    print(f" Evaluation  (Normal=0 / Attack=1)")
    print(f"{'='*55}")
    print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"], digits=4))

    # ── Save fail cases ───────────────────────────────────────────────────────
    CLASS_NAMES = ["Normal", "Attack"]
    mask = y_pred != y_test
    n_fail = mask.sum()
    fail_indices = np.where(mask)[0]

    fail_df = pd.DataFrame({
        "true":      [CLASS_NAMES[i] for i in y_test[mask]],
        "pred":      [CLASS_NAMES[i] for i in y_pred[mask]],
        "prob_attack": y_prob[mask].round(4),
        "text":      [texts_test[i] for i in fail_indices],
    })
    fail_df = fail_df.sort_values("prob_attack", ascending=False)
    fail_df.to_csv(FAIL_CSV_PATH, index=False, encoding="utf-8")

    print(f"\n Fail cases saved : {FAIL_CSV_PATH}")
    print(f" Total errors     : {n_fail:,} / {len(y_test):,} ({n_fail/len(y_test)*100:.2f}%)")
    print(f"{'='*55}")


# ── ONNX export ───────────────────────────────────────────────────────────────

def export_onnx(booster: lgb.Booster) -> None:
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType

    print("Exporting ONNX model...")
    initial_type = [("X", FloatTensorType([None, NUM_FEATURES]))]
    onnx_model = onnxmltools.convert_lightgbm(
        booster,
        initial_types=initial_type,
        zipmap=False,
    )
    onnxmltools.utils.save_model(onnx_model, ONNX_PATH)
    size_mb = os.path.getsize(ONNX_PATH) / 1024 / 1024
    print(f"  Saved -> {ONNX_PATH}  ({size_mb:.1f} MB)")


# ── Benchmark ─────────────────────────────────────────────────────────────────

def benchmark_python(booster: lgb.Booster, X_test: np.ndarray) -> None:
    print("\nPython inference benchmark  (latency = per-request, amortised)")
    hdr = f"  {'batch':>6}  {'req/s':>10}  {'mean':>9}  {'p50':>9}  {'p95':>9}  {'p99':>9}  {'max':>9}"
    print(hdr)
    print("  " + "-" * 73)

    reps_map = {1: 2_000, 100: 500, 1_000: 100, 10_000: 20}

    for batch in [1, 100, 1_000, 10_000]:
        if batch > len(X_test):
            continue
        idx = np.linspace(0, len(X_test) - 1, batch, dtype=int)
        sample = X_test[idx]

        for _ in range(5):
            booster.predict(sample)

        reps = reps_map.get(batch, 100)
        latencies_ms = np.empty(reps)
        for i in range(reps):
            t0 = time.perf_counter()
            booster.predict(sample)
            latencies_ms[i] = (time.perf_counter() - t0) / batch * 1_000

        rps = 1_000.0 / latencies_ms.mean()
        f   = lambda v: f"{v:.3f}ms"
        print(
            f"  {batch:>6}  {rps:>10,.0f}"
            f"  {f(latencies_ms.mean()):>9}"
            f"  {f(float(np.percentile(latencies_ms, 50))):>9}"
            f"  {f(float(np.percentile(latencies_ms, 95))):>9}"
            f"  {f(float(np.percentile(latencies_ms, 99))):>9}"
            f"  {f(float(latencies_ms.max())):>9}"
        )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    export_only = "--export-only" in sys.argv

    # Bug fix: --export-only must NOT reload data / refit LabelEncoder,
    # otherwise label_map.json gets overwritten with potentially different
    # class ordering, breaking the existing model.
    if export_only:
        if not os.path.exists(MODEL_TXT_PATH):
            print(f"ERROR: {MODEL_TXT_PATH} not found. Run without --export-only first.")
            sys.exit(1)
        print(f"Re-exporting ONNX from existing model: {MODEL_TXT_PATH}")
        booster = lgb.Booster(model_file=MODEL_TXT_PATH)
        export_onnx(booster)
        return

    df = load_data()

    # Binary labels: Normal=0, Attack=1
    label_map = {"0": "Normal", "1": "Attack"}
    with open(LABEL_MAP_PATH, "w") as f:
        json.dump(label_map, f, indent=2)

    y = (df["category"] == "Attack").astype(int).values
    texts = df["text"].tolist()
    X = build_features(texts)

    # 3-way split: 70% train / 10% val (early stopping) / 20% test (final eval)
    X_tmp, X_test, y_tmp, y_test, _, texts_test = train_test_split(
        X, y, texts, test_size=0.2, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_tmp, y_tmp, test_size=0.125, random_state=42, stratify=y_tmp
    )
    print(f"  Train: {len(X_train):,}   Val: {len(X_val):,}   Test: {len(X_test):,}")

    booster = train_model(X_train, y_train, X_val, y_val)
    evaluate(booster, X_test, y_test, texts_test)
    export_onnx(booster)
    benchmark_python(booster, X_test)

    print("\nDone. Next steps:")
    print("  cd waf_infer && cargo run --release   # Rust benchmark")
    print("  python build_dataset.py               # rebuild unified dataset if sources change")


if __name__ == "__main__":
    main()
