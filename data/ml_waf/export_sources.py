#!/usr/bin/env python3
"""
Export each WAF data source to eval_data/<source>.csv for Rust evaluation.

Run once, then use Rust for fast per-source evaluation:
    python export_sources.py
    cd waf_infer && cargo run --release -- --source all
"""
import os
import pandas as pd

from build_dataset import (
    load_malicious, load_legitimate, load_srbh2020,
    load_hf_waf_dataset, load_modern_payloads,
    _parse_csic_file, _classify_anomalous,
)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "eval_data")


def save(name: str, rows: list[tuple[str, str]]) -> None:
    path = os.path.join(OUT_DIR, f"{name}.csv")
    df = pd.DataFrame(rows, columns=["text", "category"])
    df.to_csv(path, index=False)
    counts = df["category"].value_counts().to_dict()
    print(f"  Saved {len(df):,} rows -> {path}")
    for cat, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"    {cat:<44} {n:>7,}")


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


def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    print(f"Exporting sources to {OUT_DIR}/\n")

    print("[1/6] legitimate ...")
    save("legitimate", load_legitimate(1_000_000))   # effectively all

    print("\n[2/6] malicious ...")
    save("malicious", load_malicious())

    print("\n[3/6] srbh ...")
    save("srbh", load_srbh2020())

    print("\n[4/6] csic ...")
    save("csic", load_csic2010_full())

    print("\n[5/6] huggingface ...")
    save("huggingface", load_hf_waf_dataset())

    print("\n[6/6] modern ...")
    save("modern", load_modern_payloads())

    print(f"\nDone. Next step:")
    print(f"  cd waf_infer")
    print(f"  cargo run --release               # evaluate legitimate + malicious + modern")
    print(f"  cargo run --release -- --source all    # evaluate all 6 sources")
    print(f"  cargo run --release -- --bench-only    # benchmark only")


if __name__ == "__main__":
    main()
