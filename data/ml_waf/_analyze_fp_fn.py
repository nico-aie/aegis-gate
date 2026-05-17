import sys, pandas as pd, numpy as np
sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, r"c:\Users\rmuser\Workspaces\ml_waf")
from features import extract_features, FEATURE_NAMES

import pickle, json, os
HERE = r"c:\Users\rmuser\Workspaces\ml_waf"

# Load model
import lightgbm as lgb
booster = lgb.Booster(model_file=os.path.join(HERE, "waf_model.txt"))

def score(text):
    f = extract_features(text)
    prob = booster.predict([f])[0]
    return float(prob)

def top_features(text):
    f = extract_features(text)
    return [(FEATURE_NAMES[i], f[i]) for i in range(len(f)) if f[i] != 0]

# ══════════════════════════════════════════════════════════════════════
print("=" * 70)
print("FALSE POSITIVES — Legitimate bị predict là Attack (10,867 cases)")
print("=" * 70)

legit = pd.read_csv(os.path.join(HERE, "eval_data", "legitimate.csv"))
legit_texts = legit["text"].fillna("").tolist()

# Score in batches
print("Scoring legitimate data...")
BATCH = 50000
all_scores = []
for i in range(0, len(legit_texts), BATCH):
    batch = legit_texts[i:i+BATCH]
    feats = [extract_features(t) for t in batch]
    probs = booster.predict(feats)
    all_scores.extend(probs)
    print(f"  {min(i+BATCH, len(legit_texts)):,}/{len(legit_texts):,}", end="\r")

all_scores = np.array(all_scores)
fp_mask = all_scores >= 0.5
fp_indices = np.where(fp_mask)[0]
fp_scores = all_scores[fp_mask]
fp_texts = [legit_texts[i] for i in fp_indices]

print(f"\nTotal FP: {len(fp_indices):,}")
print(f"\nScore distribution of FP:")
for t in [0.5, 0.7, 0.9, 0.95, 0.99]:
    n = (fp_scores >= t).sum()
    print(f"  >= {t:.2f}: {n:5} ({n/len(fp_scores)*100:.1f}%)")

# Pattern analysis
print("\n--- Pattern analysis of FP ---")
patterns = {
    "Double %25 encoding": lambda t: "%25" in t,
    "Non-ASCII %XX heavy": lambda t: t.count("%") > 5 and any(int(t[i+1:i+3],16) > 127 for i in range(len(t)-3) if t[i]=="%" and t[i+1:i+3].isalnum()),
    "Very long URL (>500)": lambda t: len(t.split("\n")[0]) > 500,
    "Many special chars":   lambda t: sum(1 for c in t if c in "'\"><;=%&+") > 20,
    "SQL keywords":         lambda t: any(k in t.lower() for k in ["select","union","insert","drop","where"]),
    "XSS patterns":         lambda t: any(k in t.lower() for k in ["<script","javascript:","onerror","alert("]),
    "Path traversal":       lambda t: "../" in t or "%2e%2e" in t.lower(),
    "Base64-like in URL":   lambda t: any(len(p) > 40 and p.replace("+","").replace("/","").replace("=","").isalnum() for p in t.split("/")),
    "SSRF keywords":        lambda t: any(k in t for k in ["127.0.0.1","localhost","169.254."]),
}
for label, fn in patterns.items():
    try:
        n = sum(1 for t in fp_texts if fn(t))
        if n > 0:
            print(f"  {label:<30}: {n:5} ({n/len(fp_texts)*100:.1f}%)")
    except Exception:
        pass

# Show top 20 highest-confidence FP
print("\n--- Top 20 FP (highest confidence = model most wrong) ---")
top_idx = np.argsort(fp_scores)[::-1][:20]
for i in top_idx:
    t = fp_texts[i]
    lines = t.split("\n")
    first = lines[0][:160]
    hdrs  = lines[1:3]
    print(f"\n  score={fp_scores[i]:.4f}  {first}")
    for h in hdrs:
        print(f"           {h[:120]}")
    feats = [(n, v) for n, v in top_features(t) if n not in ("request_len","method_id","path_len","entropy","digit_ratio","upper_ratio")]
    if feats:
        print(f"           features: {feats[:5]}")

# ══════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("FALSE NEGATIVES — Modern attacks missed (6 cases)")
print("=" * 70)

modern = pd.read_csv(os.path.join(HERE, "eval_data", "modern.csv"))
modern_texts = modern["text"].fillna("").tolist()
modern_cats  = modern["category"].fillna("").tolist()

feats_all = [extract_features(t) for t in modern_texts]
scores_all = booster.predict(feats_all)

fn_mask = scores_all < 0.5
fn_indices = np.where(fn_mask)[0]
print(f"Total FN: {len(fn_indices)}")
for i in fn_indices:
    t = modern_texts[i]
    cat = modern_cats[i]
    s = scores_all[i]
    print(f"\n  score={s:.4f}  cat={cat}")
    print(f"  Request: {t[:300]}")
    f = top_features(t)
    print(f"  Features: {f}")
