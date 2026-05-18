#!/usr/bin/env python3
"""
Per-source evaluation of the trained WAF model.

Loads waf_model.txt and evaluates on each data source independently so you
can see exactly where the model is strong or weak — rather than looking at
a mixed random test split.

Usage:
    python evaluate.py [--source legitimate|malicious|srbh|csic|huggingface|modern|all]

Note: sources overlap with training data (no retraining done).
      This measures per-source diagnostic accuracy, not true held-out generalization.
      To get true hold-out, use --holdout flag (loads clean copies not in unified CSV).
"""
import json
import os
import sys
import time
from collections import defaultdict

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

from features import extract_features, NUM_FEATURES
from build_dataset import (
    load_malicious, load_legitimate, load_srbh2020,
    load_hf_waf_dataset, load_modern_payloads,
    _parse_csic_file, _classify_anomalous,
)

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH    = os.path.join(HERE, "waf_model.txt")
LABEL_MAP_PATH = os.path.join(HERE, "label_map.json")
REPORT_PATH   = os.path.join(HERE, "eval_report.csv")


# ── helpers ───────────────────────────────────────────────────────────────────

def load_csic2010_full() -> list[tuple[str, str]]:
    base = os.path.join(HERE, "csic2010")
    rows: list[tuple[str, str]] = []
    for fname in ("normalTrafficTraining.txt", "normalTrafficTest.txt"):
        path = os.path.join(base, fname)
        if os.path.exists(path):
            rows.extend(_parse_csic_file(path, lambda *_: "Normal"))
    anom = os.path.join(base, "anomalousTrafficTest.txt")
    if os.path.exists(anom):
        rows.extend(_parse_csic_file(anom, _classify_anomalous))
    return rows


def predict(booster: lgb.Booster, rows: list[tuple[str, str]]) -> tuple[np.ndarray, np.ndarray]:
    texts = [t for t, _ in rows]
    X = np.array([extract_features(t) for t in texts], dtype=np.float32)
    probs = booster.predict(X)          # (n, num_classes)
    preds = np.argmax(probs, axis=1)
    return preds, probs


def int_labels(rows: list[tuple[str, str]], label2idx: dict[str, int]) -> np.ndarray:
    return np.array([label2idx.get(cat, -1) for _, cat in rows])


def report_source(
    source_name: str,
    rows: list[tuple[str, str]],
    booster: lgb.Booster,
    class_names: list[str],
    label2idx: dict[str, int],
    normal_idx: int,
) -> dict:
    if not rows:
        print(f"\n  [{source_name}] EMPTY — skipping")
        return {}

    t0 = time.perf_counter()
    preds, probs = predict(booster, rows)
    elapsed = time.perf_counter() - t0

    y_true = int_labels(rows, label2idx)

    # filter rows whose true label isn't in the model (e.g. unseen class)
    valid = y_true >= 0
    preds_v  = preds[valid]
    y_true_v = y_true[valid]

    acc = accuracy_score(y_true_v, preds_v)

    # binary Normal vs Attack
    y_bin_true = (y_true_v != normal_idx).astype(int)
    y_bin_pred = (preds_v  != normal_idx).astype(int)
    tp = int(((y_bin_true == 1) & (y_bin_pred == 1)).sum())
    fp = int(((y_bin_true == 0) & (y_bin_pred == 1)).sum())
    fn = int(((y_bin_true == 1) & (y_bin_pred == 0)).sum())
    tn = int(((y_bin_true == 0) & (y_bin_pred == 0)).sum())
    bin_acc     = (tp + tn) / len(y_bin_true) if len(y_bin_true) else 0
    precision_a = tp / (tp + fp) if (tp + fp) else 0
    recall_a    = tp / (tp + fn) if (tp + fn) else 0
    f1_a        = 2 * precision_a * recall_a / (precision_a + recall_a) if (precision_a + recall_a) else 0

    # class distribution
    dist: dict[str, int] = defaultdict(int)
    for _, cat in rows:
        dist[cat] += 1

    sep = "=" * 65
    print(f"\n{sep}")
    print(f" Source : {source_name}  ({len(rows):,} samples, {elapsed:.1f}s)")
    print(f"{sep}")
    print(f" Class distribution:")
    for cat, n in sorted(dist.items(), key=lambda x: -x[1]):
        print(f"   {cat:<42} {n:>7,}")
    print(f"\n Multi-class accuracy : {acc:.4f}")

    # use only labels present in this source
    present_labels = sorted(set(y_true_v))
    present_names  = [class_names[i] for i in present_labels]
    print(classification_report(
        y_true_v, preds_v,
        labels=present_labels, target_names=present_names, digits=4,
    ))

    print(f" Binary (Normal vs Attack) accuracy : {bin_acc:.4f}")
    print(f"   Attack  precision={precision_a:.4f}  recall={recall_a:.4f}  f1={f1_a:.4f}")
    print(f"   TP={tp}  FP={fp}  FN={fn}  TN={tn}")

    # top confusion pairs
    errors_mask = preds_v != y_true_v
    n_errors = errors_mask.sum()
    if n_errors > 0:
        pairs: dict[tuple[str, str], int] = defaultdict(int)
        for t, p in zip(y_true_v[errors_mask], preds_v[errors_mask]):
            pairs[(class_names[t], class_names[p])] += 1
        top_pairs = sorted(pairs.items(), key=lambda x: -x[1])[:8]
        print(f"\n Top confusion pairs ({n_errors:,} errors / {len(y_true_v):,}):")
        for (true_lbl, pred_lbl), cnt in top_pairs:
            print(f"   {true_lbl:<42} -> {pred_lbl:<42} {cnt:>5,}")

    return {
        "source":      source_name,
        "samples":     len(rows),
        "multi_acc":   round(acc, 4),
        "binary_acc":  round(bin_acc, 4),
        "attack_prec": round(precision_a, 4),
        "attack_rec":  round(recall_a, 4),
        "attack_f1":   round(f1_a, 4),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


# ── source registry ───────────────────────────────────────────────────────────

SOURCES = {
    "legitimate":  lambda: load_legitimate(1000000),    # all Normal
    "malicious":   load_malicious,                       # curated attack payloads
    "srbh":        load_srbh2020,                        # SRBH2020 CSV (has noise)
    "csic":        load_csic2010_full,                   # CSIC 2010 raw HTTP
    "huggingface": load_hf_waf_dataset,                  # HuggingFace parquet
    "modern":      load_modern_payloads,                 # PayloadsAllTheThings
}


# ── main ──────────────────────────────────────────────────────────────────────

def parse_args() -> list[str]:
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--source" and i < len(sys.argv):
            val = sys.argv[i + 1]
            if val == "all":
                return list(SOURCES.keys())
            return [v.strip() for v in val.split(",")]
        if arg.startswith("--source="):
            val = arg.split("=", 1)[1]
            if val == "all":
                return list(SOURCES.keys())
            return [v.strip() for v in val.split(",")]
    # default: the three cleanest sources as requested
    return ["legitimate", "malicious", "modern"]


def main() -> None:
    if not os.path.exists(MODEL_PATH):
        print(f"ERROR: {MODEL_PATH} not found. Run train.py first.")
        sys.exit(1)

    with open(LABEL_MAP_PATH) as f:
        label_map: dict[str, str] = json.load(f)
    class_names = [label_map[str(i)] for i in range(len(label_map))]
    label2idx   = {name: int(idx) for idx, name in label_map.items()}
    normal_idx  = label2idx.get("Normal", -1)

    print(f"Loading model: {MODEL_PATH}")
    booster = lgb.Booster(model_file=MODEL_PATH)
    print(f"Classes ({len(class_names)}): {class_names}")

    sources_to_run = parse_args()
    unknown = [s for s in sources_to_run if s not in SOURCES]
    if unknown:
        print(f"ERROR: unknown source(s): {unknown}")
        print(f"Valid: {list(SOURCES.keys())}")
        sys.exit(1)

    all_results: list[dict] = []
    for src_name in sources_to_run:
        print(f"\nLoading {src_name} ...")
        rows = SOURCES[src_name]()
        result = report_source(src_name, rows, booster, class_names, label2idx, normal_idx)
        if result:
            all_results.append(result)

    # ── summary table ─────────────────────────────────────────────────────────
    if len(all_results) > 1:
        sep = "=" * 65
        print(f"\n\n{sep}")
        print(" SUMMARY")
        print(f"{sep}")
        hdr = f"  {'Source':<14} {'Samples':>8}  {'Multi-Acc':>9}  {'Bin-Acc':>7}  {'Atk-P':>6}  {'Atk-R':>6}  {'Atk-F1':>7}"
        print(hdr)
        print(f"  {'-'*70}")
        for r in all_results:
            print(
                f"  {r['source']:<14} {r['samples']:>8,}  "
                f"{r['multi_acc']:>9.4f}  {r['binary_acc']:>7.4f}  "
                f"{r['attack_prec']:>6.4f}  {r['attack_rec']:>6.4f}  {r['attack_f1']:>7.4f}"
            )

    # save CSV
    if all_results:
        pd.DataFrame(all_results).to_csv(REPORT_PATH, index=False)
        print(f"\nReport saved -> {REPORT_PATH}")


if __name__ == "__main__":
    main()
