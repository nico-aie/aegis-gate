#!/usr/bin/env python3
"""Corpus replay against a live WAF, sampled & rate-limited so the
behavior_burst detector doesn't poison the FP measurement.

Reads NDJSON cases (one per line):
  {id, class, label, method, path, expected_action, query?, body?, headers?}

Emits a PSV summary + a per-case JSONL.
"""
import argparse, json, random, sys, time, urllib.request, urllib.error, ssl

def case_to_request(case, target):
    path = case.get("path", "/")
    q = case.get("query")
    url = target.rstrip("/") + path
    if q:
        url += ("&" if "?" in url else "?") + q
    method = case.get("method", "GET").upper()
    body = case.get("body")
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
    elif isinstance(body, str):
        body = body.encode()
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605",
        "Accept": "text/html,application/json;q=0.9",
        "Accept-Language": "en-US,en;q=0.8",
    }
    # case-supplied headers override defaults
    for k, v in (case.get("headers") or {}).items():
        if k.lower() == "host":  # don't fight Host
            continue
        headers[k] = v
    return method, url, headers, body

def send(method, url, headers, body, ctx, timeout=5):
    req = urllib.request.Request(url=url, data=body, method=method, headers=headers)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            code = resp.status
            rh = {k.lower(): v for k, v in resp.getheaders()}
    except urllib.error.HTTPError as e:
        code = e.code
        rh = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
    except Exception as e:
        return 0, {}, (time.perf_counter() - t0) * 1000.0, str(e)
    return code, rh, (time.perf_counter() - t0) * 1000.0, ""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    ap.add_argument("--input", required=True)
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--per-class-max", type=int, default=40)
    ap.add_argument("--out-psv", required=True)
    ap.add_argument("--out-jsonl", required=True)
    ap.add_argument("--rate-sleep", type=float, default=0.05)  # 20 RPS-ish per source
    ap.add_argument("--seed", type=int, default=0xA351)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    by_class = {}
    with open(args.input) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                c = json.loads(line)
            except Exception:
                continue
            by_class.setdefault(c.get("class", "?"), []).append(c)

    sample = []
    for cls, cases in sorted(by_class.items()):
        rng.shuffle(cases)
        sample.extend(cases[: args.per_class_max])
    rng.shuffle(sample)
    sample = sample[: args.n]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    counts = {}
    with open(args.out_psv, "w") as psv, open(args.out_jsonl, "w") as jl:
        psv.write("class|expected|n|block|allow|other|ai_in_rule|p50_ms|p95_ms\n")
        rows = {}  # class -> list of result dicts
        for i, c in enumerate(sample):
            method, url, headers, body = case_to_request(c, args.target)
            code, rh, ms, err = send(method, url, headers, body, ctx)
            rule = rh.get("x-waf-rule-id", "")
            action = rh.get("x-waf-action", "")
            ai_hit = "ai" in [r.strip() for r in rule.split(",")] if rule else False
            obs = {
                "id": c.get("id"), "class": c.get("class"),
                "expected": c.get("expected_action"), "path": c.get("path"),
                "method": method, "http": code, "action": action,
                "rule": rule, "ai_in_rule": ai_hit, "ms": round(ms, 2),
                "err": err,
            }
            jl.write(json.dumps(obs) + "\n")
            rows.setdefault(c.get("class", "?"), []).append(obs)
            time.sleep(args.rate_sleep)
            if (i + 1) % 50 == 0:
                print(f"  progress: {i+1}/{len(sample)}", flush=True)

        for cls, lst in sorted(rows.items()):
            n = len(lst)
            blk = sum(1 for r in lst if r["action"] == "block" or r["http"] == 403)
            alw = sum(1 for r in lst if r["action"] == "allow" or (r["action"] == "" and r["http"] not in (403, 0)))
            oth = n - blk - alw
            ai  = sum(1 for r in lst if r["ai_in_rule"])
            ms = sorted(r["ms"] for r in lst)
            def pct(p): return ms[min(int(len(ms) * p), len(ms) - 1)] if ms else 0.0
            expected = lst[0]["expected"] or "?"
            psv.write(f"{cls}|{expected}|{n}|{blk}|{alw}|{oth}|{ai}|{pct(0.5):.1f}|{pct(0.95):.1f}\n")
            counts[cls] = {"n": n, "blk": blk, "alw": alw, "ai": ai}

    print(json.dumps(counts, indent=2))

if __name__ == "__main__":
    main()
