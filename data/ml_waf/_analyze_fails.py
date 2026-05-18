import pandas as pd
import sys

sys.stdout.reconfigure(encoding="utf-8")

df = pd.read_csv(r"c:\Users\rmuser\Workspaces\ml_waf\fail_cases.csv")
fn = df[df["true"] == "Attack"].copy()
fp = df[df["true"] == "Normal"].copy()

print("=" * 70)
print(f"FALSE NEGATIVES: Attack -> predicted Normal  ({len(fn)} cases)")
print("Nguy hiem: attack lọt qua WAF")
print("=" * 70)

print("\nPhan bo prob_attack (thap = model chac la Normal):")
for t in [0.1, 0.2, 0.3, 0.4, 0.5]:
    n = (fn["prob_attack"] < t).sum()
    print(f"  < {t:.1f} : {n:4d}  ({n/len(fn)*100:.1f}%)")

print("\n--- Top 15 FN nguy hiem nhat (model tin nhat la Normal) ---")
for _, row in fn.nsmallest(15, "prob_attack").iterrows():
    text = str(row["text"])
    first_line = text.split("\n")[0][:180]
    headers = text.split("\n")[1:] if "\n" in text else []
    print(f"  prob={row['prob_attack']:.4f}  {first_line}")
    for h in headers[:2]:
        print(f"           {h[:100]}")
    print()

print()
print("=" * 70)
print(f"FALSE POSITIVES: Normal -> predicted Attack  ({len(fp)} cases)")
print("Block nham legitimate traffic")
print("=" * 70)

print("\n--- Top 15 FP model tin nhat la Attack ---")
for _, row in fp.nlargest(15, "prob_attack").iterrows():
    text = str(row["text"])
    first_line = text.split("\n")[0][:180]
    headers = text.split("\n")[1:] if "\n" in text else []
    print(f"  prob={row['prob_attack']:.4f}  {first_line}")
    for h in headers[:2]:
        print(f"           {h[:100]}")
    print()

# pattern analysis
print()
print("=" * 70)
print("PATTERN ANALYSIS - False Negatives (attack type hints)")
print("=" * 70)

keywords = {
    "SQL injection": ["select", "union", "insert", "drop", "sleep(", "waitfor", "--", "1=1", "' or", "' and"],
    "XSS":           ["<script", "javascript:", "onerror=", "onload=", "alert(", "<img", "<svg"],
    "Path traversal":["../", "%2e%2e", "etc/passwd", "win.ini"],
    "Command inject":["cmd", "/bin/", "bash", "wget", "curl ", "; ls", "| cat"],
    "SSTI":          ["{{", "}}", "${", "<%="],
    "XXE":           ["<!entity", "system \"", "file://"],
    "Scanner":       ["nikto", "sqlmap", "nmap", "acunetix"],
    "Short/simple":  [],  # fallback
}

fn_texts = fn["text"].str.lower().fillna("")
counts = {}
for label, kws in keywords.items():
    if kws:
        mask = fn_texts.apply(lambda t: any(k in t for k in kws))
        counts[label] = mask.sum()
    else:
        counts[label] = 0

no_match = len(fn)
for label, c in counts.items():
    if c > 0:
        no_match -= c
        print(f"  {label:<20} {c:>5} FN  ({c/len(fn)*100:.1f}%)")
print(f"  {'No clear pattern':<20} ~{max(no_match,0):>4} FN  (obfuscated/encoded)")
