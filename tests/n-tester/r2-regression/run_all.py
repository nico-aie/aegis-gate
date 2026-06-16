#!/usr/bin/env python3
"""
run_all.py — Aegis-Gate round-2 regression runner (pure Python stdlib, zero deps).

Runs EVERY case under cases/<class>/cases.json against the WAF using raw sockets,
so it can set headers a browser/curl-lite cannot (Host, Origin, Cookie, Upgrade,
duplicate/CRLF headers) and can drive real WebSocket frames. No pip installs.

Usage:
    python3 run_all.py                      # whole suite
    python3 run_all.py injection-sqli xss   # one or more classes
    python3 run_all.py --list               # list classes + counts
    WAF_BASE_URL=http://localhost:8080 python3 run_all.py
    python3 run_all.py --base-url http://127.0.0.1:8080 --sid mysid

Verdict (in order): X-WAF-Action header -> X-Aegis-Decision -> HTTP status
    action allow -> allow | block -> block | challenge/rate_limit -> challenge |
    timeout/circuit_breaker -> block | else status: 403/413 -> block, 429 -> challenge,
    101/2xx/3xx/401/404 -> allow, conn err -> error
WebSocket: handshake !=101 -> block ; close 1008/1009/1003 after a frame -> block ; else allow.

Every response's always-on X-WAF-* headers (action, rule-id, risk-score, mode, cache,
tier, overhead-latency) are captured per case and rolled into the report: decision
breakdown, which rules fired, WAF overhead percentiles, and per-IP risk saturation.

Outputs (in reports/):
    run-<ts>.jsonl          per-case records (incl. X-WAF-* fields)
    run-<ts>.summary.json   machine summary (incl. waf_actions, rule_fires, overhead_ms)
    run-<ts>.md + latest.md human-readable analysis (WAF posture, rule attribution,
                            per-class detect%, FP/FN with status/action/risk/rule,
                            bypass-by-evasion breakdown)
Exit 0 iff no false-negatives AND no false-positives AND no errors.
"""
import argparse, base64, glob, json, os, re, socket, ssl, struct, sys, time
from collections import defaultdict
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
CASES_DIR = os.path.join(HERE, "cases")
REPORT_DIR = os.path.join(HERE, "reports")

BASE = os.environ.get("WAF_BASE_URL", "http://localhost:8080")
SID = os.environ.get("AEGIS_SID", "regression-dummy-sid")
TIMEOUT = float(os.environ.get("AEGIS_TIMEOUT", "7"))
MAX_REPEAT = int(os.environ.get("AEGIS_MAX_REPEAT", "40"))

C = {"R": "\033[31m", "G": "\033[32m", "Y": "\033[33m", "B": "\033[34m", "D": "\033[2m", "N": "\033[0m"}
if not sys.stdout.isatty():
    C = {k: "" for k in C}

# ----------------------------------------------------------------- low level
def target(base):
    u = urlparse(base)
    scheme = u.scheme or "http"
    host = u.hostname or "localhost"
    port = u.port or (443 if scheme == "https" else 80)
    return scheme, host, port

SCHEME, HOST, PORT = target(BASE)

def _connect():
    s = socket.create_connection((HOST, PORT), TIMEOUT)
    if SCHEME == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=HOST)
    s.settimeout(TIMEOUT)
    return s

def _read_all(s, cap=65536):
    buf = b""
    try:
        while len(buf) < cap:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf and len(buf) > 0:
                # we have headers; for our purposes the status line is enough,
                # but keep reading briefly for short bodies / closes
                if len(buf) > 16384:
                    break
    except (socket.timeout, OSError):
        pass
    return buf

def _has(headers, name):
    return any(k.lower() == name for k in headers)

# Always-on X-WAF-* observability headers (crates/aegis-control/src/interop/
# headers.rs) → the canonical field names we record per case. The X-Aegis-*
# pair below is the gated diagnostic fallback (only present with a bench
# token); we read it too so the runner still works if someone enables it.
WAF_HEADER_MAP = {
    "x-waf-action": "action",          # allow|block|challenge|rate_limit|timeout|circuit_breaker
    "x-waf-rule-id": "rule_id",        # firing rule/detector, or "none"
    "x-waf-risk-score": "risk",        # cumulative per-IP risk (0-100)
    "x-waf-detector-score": "detector",# this request's detector sum
    "x-waf-tier": "tier",              # matched route tier
    "x-waf-cache": "cache",            # HIT|MISS|BYPASS
    "x-waf-mode": "mode",              # enforce|log_only
    "x-waf-overhead-latency": "latency",  # per-request WAF cost, ms
    "x-waf-request-id": "request_id",
    "x-aegis-decision": "aegis_decision",
    "x-aegis-rule-id": "aegis_rule",
}

def parse_waf_headers(head):
    """Pull the X-WAF-* / X-Aegis-* response headers out of a raw header block
    into a flat dict keyed by the names in WAF_HEADER_MAP."""
    meta = {}
    for ln in head.split("\r\n")[1:]:
        if ":" not in ln:
            continue
        name, val = ln.split(":", 1)
        key = WAF_HEADER_MAP.get(name.strip().lower())
        if key:
            meta[key] = val.strip()
    return meta

def waf_rule(meta):
    """Normalized firing rule — prefer the always-on X-WAF-Rule-Id, treat the
    literal `none` as no attribution, fall back to the diagnostic header."""
    r = meta.get("rule_id") or meta.get("aegis_rule") or ""
    return "" if r.lower() == "none" else r

def waf_verdict(status, meta):
    """Authoritative decision: X-WAF-Action header first (always on), then the
    gated X-Aegis-Decision, then HTTP status. rate_limit collapses into the
    challenge bucket; timeout/circuit_breaker mean the request did not pass."""
    act = (meta.get("action") or meta.get("aegis_decision") or "").lower()
    if act == "allow":
        return "allow"
    if act == "block":
        return "block"
    if act in ("challenge", "rate_limit"):
        return "challenge"
    if act in ("timeout", "circuit_breaker"):
        return "block"
    # 400 with no X-WAF-* headers = the HTTP parser (hyper) rejected the request
    # framing before the WAF ran. Common when a case puts raw spaces / control
    # bytes in the request-line URI. Not a WAF decision — bucket it separately so
    # it neither inflates FN ("attack allowed") nor counts as a detector catch.
    if status == 400 and not act:
        return "rejected"
    return code_verdict(status)

def http_raw(method, path, headers, body, auth):
    """Send a fully-controlled raw HTTP/1.1 request. Returns (status:int, meta:dict)
    where meta holds the parsed X-WAF-* observability headers (see parse_waf_headers)."""
    headers = dict(headers or {})
    lines = ["%s %s HTTP/1.1" % (method, path)]
    if not _has(headers, "host"):
        hp = HOST if PORT in (80, 443) else "%s:%d" % (HOST, PORT)
        lines.append("Host: " + hp)
    for k, v in headers.items():
        lines.append("%s: %s" % (k, v))
    if auth == "session" and not _has(headers, "cookie"):
        lines.append("Cookie: sid=" + SID)
    if body is not None and not _has(headers, "content-length") and not _has(headers, "transfer-encoding"):
        lines.append("Content-Length: %d" % len(body))
    if not _has(headers, "connection"):
        lines.append("Connection: close")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")
    if body is not None:
        raw += body
    try:
        s = _connect()
        s.sendall(raw)
        resp = _read_all(s)
        s.close()
    except Exception:
        return 0, {}
    if not resp:
        return 0, {}
    head = resp.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    first = head.split("\r\n", 1)[0]
    m = re.search(r"HTTP/\d\.\d\s+(\d{3})", first)
    status = int(m.group(1)) if m else 0
    meta = parse_waf_headers(head)
    meta["status"] = status
    return status, meta

# ----------------------------------------------------------------- websocket
def ws_frame(opcode, payload):
    b1 = 0x80 | opcode
    n = len(payload)
    mask = os.urandom(4)
    if n < 126:
        hdr = bytes([b1, 0x80 | n])
    elif n < 65536:
        hdr = bytes([b1, 0x80 | 126]) + struct.pack("!H", n)
    else:
        hdr = bytes([b1, 0x80 | 127]) + struct.pack("!Q", n)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return hdr + mask + masked

WS_OP = {"text": 1, "binary": 2, "ping": 9, "pong": 10, "close": 8}

def ws_run(ws, auth):
    """Drive a WebSocket handshake (+frames). Returns (verdict:str, meta:dict)
    where meta holds the X-WAF-* headers stamped on the handshake response."""
    path = ws.get("handshake_path", "/ws/live")
    headers = dict(ws.get("handshake_headers", {}))
    key = base64.b64encode(os.urandom(16)).decode()
    # build handshake honoring forged Origin/Cookie/etc from the case
    lines = ["GET %s HTTP/1.1" % path]
    if not _has(headers, "host"):
        hp = HOST if PORT in (80, 443) else "%s:%d" % (HOST, PORT)
        lines.append("Host: " + hp)
    # standard upgrade headers (only add if case didn't override)
    base_up = {"upgrade": "websocket", "connection": "Upgrade",
               "sec-websocket-version": "13", "sec-websocket-key": key}
    for k, v in headers.items():
        lines.append("%s: %s" % (k, v))
    for k, v in base_up.items():
        if not _has(headers, k):
            lines.append({"upgrade": "Upgrade", "connection": "Connection",
                          "sec-websocket-version": "Sec-WebSocket-Version",
                          "sec-websocket-key": "Sec-WebSocket-Key"}[k] + ": " + v)
    if auth == "session" and not _has(headers, "cookie"):
        lines.append("Cookie: sid=" + SID)
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")
    try:
        s = _connect()
        s.sendall(raw)
        # read handshake response
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(2048)
            if not chunk:
                break
            resp += chunk
            if len(resp) > 8192:
                break
    except Exception:
        return "error", {}
    first = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace") if resp else ""
    head = resp.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    m = re.search(r"HTTP/\d\.\d\s+(\d{3})", first)
    status = int(m.group(1)) if m else 0
    meta = parse_waf_headers(head)
    meta["status"] = status
    act = (meta.get("action") or meta.get("aegis_decision") or "").lower()
    if act in ("allow", "block", "challenge", "rate_limit"):
        if act != "allow":
            try: s.close()
            except Exception: pass
            return ("challenge" if act == "rate_limit" else act), meta
    if status != 101:
        try: s.close()
        except Exception: pass
        return ("challenge" if status == 429 else "block"), meta
    # upgraded — send frames, look for a policy close
    verdict = "allow"
    try:
        for fr in ws.get("frames", []):
            payload = base64.b64decode(fr.get("payload_b64", "")) if fr.get("payload_b64") else b""
            s.sendall(ws_frame(WS_OP.get(fr.get("opcode", "text"), 1), payload))
        s.settimeout(3)
        data = s.recv(4096)
        if data and (data[0] & 0x0F) == 0x08:  # close frame
            if len(data) >= 4:
                code = struct.unpack("!H", data[2:4])[0]
                if code in (1008, 1009, 1003):
                    verdict = "block"
                elif code == 1013:
                    verdict = "challenge"
    except (socket.timeout, OSError):
        pass
    except Exception:
        verdict = "block"
    try: s.close()
    except Exception: pass
    return verdict, meta

# ----------------------------------------------------------------- verdict
def code_verdict(status):
    if status in (403, 413):
        return "block"
    if status == 429:
        return "challenge"
    if status == 0:
        return "error"
    return "allow"

def classify(expected, actual):
    if actual == "error":
        return False, "error"
    if expected == "allow":
        return (actual == "allow"), ("ok" if actual == "allow" else "false_positive")
    # block or challenge expected -> caught if block/challenge
    caught = actual in ("block", "challenge")
    return caught, ("ok" if caught else "false_negative")

# ----------------------------------------------------------------- per case
def run_case(c):
    """Returns (kind:str, actual_verdict:str, meta:dict). meta carries the
    X-WAF-* observability headers from the (decisive) response."""
    r = c["request"]
    method = r["method"]; path = r["path"]; auth = r.get("auth", "none")
    body = None
    if r.get("body") is not None:
        body = base64.b64decode(r["body"]) if r.get("body_b64") else r["body"].encode("latin-1", "replace")
    # informational / non-executable
    if r.get("execute") is False:
        return "skip", "skip", {}
    ws = c.get("ws")
    if ws and not ws.get("handshake_only", True) and ws.get("frames"):
        v, meta = ws_run(ws, auth)
        return "frame", v, meta                       # ws frame case
    if ws:
        v, meta = ws_run(ws, auth)
        return "ws", v, meta                          # ws handshake-only
    # burst (rate-limit)
    rep = 0
    for t in c.get("tags", []):
        if t.startswith("repeat:"):
            rep = min(int(t.split(":")[1]), MAX_REPEAT)
    if rep > 1:
        hit, hit_meta = "allow", {}
        for _ in range(rep):
            st, meta = http_raw(method, path, r.get("headers"), body, auth)
            a = waf_verdict(st, meta)
            if a in ("block", "challenge"):
                hit, hit_meta = a, meta               # keep the decisive response
        return "burst", hit, hit_meta
    st, meta = http_raw(method, path, r.get("headers"), body, auth)
    return "http", waf_verdict(st, meta), meta

# ----------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("classes", nargs="*")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--base-url")
    ap.add_argument("--sid")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--delay", type=float, default=float(os.environ.get("AEGIS_DELAY", "0")),
                    help="seconds to sleep between cases (defeats per-IP velocity/recon blocking)")
    ap.add_argument("--reset", action="store_true",
                    help="POST the admin control reset_state before running (clears per-IP state)")
    ap.add_argument("--reset-url", default=os.environ.get("AEGIS_RESET_URL", "http://localhost:9443/__waf_control/reset_state"))
    ap.add_argument("--secret", default=os.environ.get("AEGIS_CTRL_SECRET", "waf-hackathon-2026-ctrl"))
    args = ap.parse_args()
    global BASE, SCHEME, HOST, PORT, SID
    if args.base_url:
        BASE = args.base_url; SCHEME, HOST, PORT = target(BASE)
    if args.sid:
        SID = args.sid

    files = sorted(glob.glob(os.path.join(CASES_DIR, "*", "cases.json")))
    if args.classes:
        want = set(args.classes)
        files = [f for f in files if os.path.basename(os.path.dirname(f)) in want]

    if args.list:
        print("%-22s %6s %7s %7s" % ("CLASS", "TOTAL", "ATTACK", "BENIGN"))
        for f in files:
            d = json.load(open(f))
            a = sum(1 for c in d if c["expect"]["verdict"] != "allow")
            print("%-22s %6d %7d %7d" % (os.path.basename(os.path.dirname(f)), len(d), a, len(d) - a))
        return

    if args.reset:
        try:
            import urllib.request
            req = urllib.request.Request(args.reset_url, data=b"{}", method="POST",
                                         headers={"X-Benchmark-Secret": args.secret,
                                                  "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                print("%sreset_state -> %d%s" % (C["D"], r.status, C["N"]))
        except Exception as e:
            print("%sreset failed: %s%s" % (C["Y"], e, C["N"]))

    os.makedirs(REPORT_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    jl = open(os.path.join(REPORT_DIR, "run-%s.jsonl" % ts), "w")
    per = defaultdict(lambda: dict(total=0, pass_=0, fp=0, fn=0, err=0, skip=0, rej=0))
    G = dict(total=0, pass_=0, fp=0, fn=0, err=0, skip=0, rej=0)
    fails = []
    rejected = []                     # 400s the HTTP parser killed before the WAF ran
    # X-WAF-* telemetry accumulators (built from response headers)
    actions = defaultdict(int)        # raw X-WAF-Action counts
    modes = defaultdict(int)          # X-WAF-Mode counts (enforce/log_only)
    rule_fires = defaultdict(int)     # which rules/detectors actually fired
    latencies = []                    # X-WAF-Overhead-Latency samples (ms)
    risk_seen = 0; risk_saturated = 0 # how many responses carried risk, & how many were maxed

    def _num(v, cast):
        try: return cast(v)
        except (TypeError, ValueError): return None

    print("%sAegis-Gate r2 regression (python)%s  base=%s  sid=%s…  (%s)" %
          (C["B"], C["N"], BASE, SID[:8], time.strftime("%H:%M:%S")))
    for f in files:
        cls = os.path.basename(os.path.dirname(f))
        cases = json.load(open(f))
        print("%s▸ %s%s %s(%d)%s" % (C["B"], cls, C["N"], C["D"], len(cases), C["N"]))
        for c in cases:
            if args.delay:
                time.sleep(args.delay)
            p = per[cls]; p["total"] += 1; G["total"] += 1
            meta = {}
            try:
                kind, actual, meta = run_case(c)
            except Exception as e:
                kind, actual, meta = "http", "error", {"err": str(e)[:60]}
            if actual == "skip":
                p["skip"] += 1; G["skip"] += 1
                rec = dict(id=c["id"], cls=cls, result="skip", actual="skip",
                           expected=c["expect"]["verdict"], name=c["name"],
                           method=c["request"]["method"], path=c["request"]["path"], rule_id="")
                jl.write(json.dumps(rec) + "\n"); continue
            if actual == "rejected":
                p["rej"] += 1; G["rej"] += 1
                rec = dict(id=c["id"], cls=cls, result="rejected", actual="rejected",
                           expected=c["expect"]["verdict"], name=c["name"],
                           method=c["request"]["method"], path=c["request"]["path"],
                           rule_id="", http_status=meta.get("status", 400))
                rejected.append(rec); jl.write(json.dumps(rec) + "\n")
                if args.verbose:
                    print("  %sREJD%s %-12s status=400 (malformed framing — pre-WAF) %s" %
                          (C["Y"], C["N"], c["id"], c["name"][:40]))
                continue
            # fold the X-WAF-* headers into the run-wide telemetry
            rule = waf_rule(meta)
            if meta.get("action"): actions[meta["action"].lower()] += 1
            if meta.get("mode"):   modes[meta["mode"].lower()] += 1
            if rule:               rule_fires[rule] += 1
            lat = _num(meta.get("latency"), float)
            if lat is not None:    latencies.append(lat)
            risk = _num(meta.get("risk"), int)
            if risk is not None:
                risk_seen += 1
                if risk >= 100:    risk_saturated += 1
            ok, k = classify(c["expect"]["verdict"], actual)
            rec = dict(id=c["id"], cls=cls, expected=c["expect"]["verdict"], actual=actual,
                       result="pass" if ok else "fail", kind="ok" if ok else k, rule_id=rule,
                       method=c["request"]["method"], path=c["request"]["path"],
                       tags=c.get("tags", []), severity=c.get("severity", ""),
                       source=c.get("source", ""), name=c["name"],
                       # X-WAF-* observability captured for this case
                       waf_action=meta.get("action", ""), waf_mode=meta.get("mode", ""),
                       http_status=meta.get("status", 0), risk_score=meta.get("risk", ""),
                       detector_score=meta.get("detector", ""), tier=meta.get("tier", ""),
                       cache=meta.get("cache", ""), latency_ms=meta.get("latency", ""),
                       request_id=meta.get("request_id", ""))
            jl.write(json.dumps(rec) + "\n")
            if ok:
                p["pass_"] += 1; G["pass_"] += 1
                if args.verbose:
                    print("  %sPASS%s %-12s exp=%-9s got=%-9s %sact=%s rule=%s risk=%s%s" %
                          (C["G"], C["N"], c["id"], c["expect"]["verdict"], actual,
                           C["D"], meta.get("action", "-"), rule or "-", meta.get("risk", "-"), C["N"]))
            else:
                if k == "false_positive": p["fp"] += 1; G["fp"] += 1
                elif k == "false_negative": p["fn"] += 1; G["fn"] += 1
                else: p["err"] += 1; G["err"] += 1
                fails.append(rec)
                print("  %sFAIL%s %-12s exp=%-9s got=%-9s %s[%s]%s %s%s rule=%s risk=%s%s %s" %
                      (C["R"], C["N"], c["id"], c["expect"]["verdict"], actual, C["Y"], k, C["N"],
                       C["D"], meta.get("action", "-"), rule or "-", meta.get("risk", "-"), C["N"],
                       c["name"][:40]))
    jl.close()

    # ---- console summary ----
    print("\n%s── per-class ──%s" % (C["B"], C["N"]))
    print("%-22s %6s %6s %5s %5s %5s %5s %5s" % ("CLASS", "TOTAL", "PASS", "FP", "FN", "ERR", "SKIP", "REJD"))
    for cls in sorted(per):
        p = per[cls]
        col = C["R"] if (p["fp"] or p["fn"] or p["err"]) else C["G"]
        print("%s%-22s%s %6d %6d %5d %5d %5d %5d %5d" %
              (col, cls, C["N"], p["total"], p["pass_"], p["fp"], p["fn"], p["err"], p["skip"], p["rej"]))
    print("%s── totals ──%s" % (C["B"], C["N"]))
    print("%-22s %6d %6d %5d %5d %5d %5d %5d" % ("TOTAL", G["total"], G["pass_"], G["fp"], G["fn"], G["err"], G["skip"], G["rej"]))
    print("\n  %sfalse negatives (attacks allowed): %d%s" % (C["R"], G["fn"], C["N"]))
    print("  %sfalse positives (benign blocked):  %d%s" % (C["Y"], G["fp"], C["N"]))
    if G["err"]:
        print("  %serrors (no verdict — WAF down?):    %d%s" % (C["R"], G["err"], C["N"]))
    if G["rej"]:
        print("  %srejected (400 malformed pre-WAF): %d  ← harness sent invalid framing; URL-encode to test the WAF%s" % (C["Y"], G["rej"], C["N"]))

    # ---- X-WAF-* telemetry summary ----
    def pct(vals, q):
        if not vals: return None
        s = sorted(vals); i = min(len(s) - 1, int(round((len(s) - 1) * q)))
        return s[i]
    mode_str = ", ".join("%s=%d" % (m, n) for m, n in sorted(modes.items())) or "—"
    act_str = " ".join("%s=%d" % (a, n) for a, n in sorted(actions.items(), key=lambda x: -x[1])) or "—"
    print("\n%s── X-WAF-* telemetry ──%s" % (C["B"], C["N"]))
    print("  mode:      %s" % mode_str)
    print("  actions:   %s" % act_str)
    if latencies:
        print("  overhead:  avg %.3f · p50 %.3f · p95 %.3f · max %.3f ms (n=%d)"
              % (sum(latencies) / len(latencies), pct(latencies, .5), pct(latencies, .95), max(latencies), len(latencies)))
    if risk_seen:
        print("  risk=100:  %d/%d responses maxed%s" %
              (risk_saturated, risk_seen, "  ← per-IP risk saturated (reset_state?)" if risk_saturated > risk_seen * 0.5 else ""))
    if "log_only" in modes:
        print("  %s⚠ log_only responses present — 'blocks' pass through with 2xx; verdict still read from X-WAF-Action%s" % (C["Y"], C["N"]))

    # ---- machine summary ----
    den = G["total"] - G["skip"] - G["rej"]   # rejected cases never reached the WAF
    lat_stats = (dict(avg=round(sum(latencies) / len(latencies), 3), p50=pct(latencies, .5),
                      p95=pct(latencies, .95), max=max(latencies), n=len(latencies)) if latencies else None)
    summ = dict(ts=ts, base_url=BASE, total=G["total"], pass_=G["pass_"], fp=G["fp"],
                fn=G["fn"], err=G["err"], skip=G["skip"], rejected=G["rej"],
                detection_rate=round(G["pass_"] / den * 100, 1) if den else 0,
                waf_modes=dict(modes), waf_actions=dict(actions),
                rule_fires=dict(sorted(rule_fires.items(), key=lambda x: -x[1])),
                overhead_ms=lat_stats, risk_seen=risk_seen, risk_saturated=risk_saturated)
    json.dump(summ, open(os.path.join(REPORT_DIR, "run-%s.summary.json" % ts), "w"), indent=2)

    # ---- markdown report ----
    FAIL_CAP = 60  # cap long FN/FP tables; full detail always lives in the jsonl
    md = os.path.join(REPORT_DIR, "run-%s.md" % ts)

    def fail_table(o, rows, title):
        """Render a capped FN/FP table enriched with the X-WAF-* response data
        (HTTP status, the WAF's own action, per-IP risk, and the firing rule)."""
        o.write("\n## %s (%d)\n\n" % (title, len(rows)))
        o.write("| id | class | method | path | status | action | risk | rule |\n")
        o.write("|---|---|---|---|--:|---|--:|---|\n")
        for r in rows[:FAIL_CAP]:
            o.write("| %s | %s | %s | `%s` | %s | %s | %s | %s |\n" % (
                r["id"], r["cls"], r["method"], r["path"].replace("\n", " ")[:60],
                r.get("http_status", "") or "—", r.get("waf_action", "") or "—",
                r.get("risk_score", "") or "—", r["rule_id"] or "—"))
        if len(rows) > FAIL_CAP:
            o.write("\n_…and %d more — see `run-%s.jsonl`._\n" % (len(rows) - FAIL_CAP, ts))

    with open(md, "w") as o:
        o.write("# Aegis-Gate r2 regression — run report (python runner)\n\n")
        o.write("- **When:** %s   **Target:** `%s`\n" % (ts, BASE))
        o.write("- **Total:** %d · **Pass:** %d · **FN (attacks allowed):** %d · **FP (benign blocked):** %d · **Errors:** %d · **Skipped:** %d · **Rejected (pre-WAF 400):** %d\n"
                % (G["total"], G["pass_"], G["fn"], G["fp"], G["err"], G["skip"], G["rej"]))
        o.write("- **Detection rate (pass / WAF-evaluated):** %s%%  _(excludes skipped + rejected)_\n" % (summ["detection_rate"]))

        # ---- run context, straight from the X-WAF-* headers ----
        o.write("\n## WAF posture (from `X-WAF-*` headers)\n\n")
        o.write("| Signal | Value |\n|---|---|\n")
        o.write("| Mode (`X-WAF-Mode`) | %s |\n" %
                (", ".join("%s × %d" % (m, n) for m, n in sorted(modes.items())) or "—"))
        o.write("| Decisions (`X-WAF-Action`) | %s |\n" %
                (" · ".join("%s × %d" % (a, n) for a, n in sorted(actions.items(), key=lambda x: -x[1])) or "—"))
        if summ["overhead_ms"]:
            ls = summ["overhead_ms"]
            o.write("| WAF overhead (`X-WAF-Overhead-Latency`) | avg %.3f · p50 %.3f · p95 %.3f · max %.3f ms (n=%d) |\n"
                    % (ls["avg"], ls["p50"], ls["p95"], ls["max"], ls["n"]))
        if risk_seen:
            o.write("| Per-IP risk maxed (`X-WAF-Risk-Score`=100) | %d / %d responses |\n" % (risk_saturated, risk_seen))
        if "log_only" in modes:
            o.write("\n> ⚠️ **`log_only` responses present** — in that mode an attack returns `X-WAF-Action: block` "
                    "but still gets a 2xx and reaches the upstream. Verdicts here come from `X-WAF-Action`, "
                    "not the HTTP status, so detection numbers stay correct.\n")
        if risk_seen and risk_saturated > risk_seen * 0.5:
            o.write("\n> ⚠️ **Per-IP risk is saturated** (most responses show `X-WAF-Risk-Score: 100`). "
                    "All test traffic shares one client IP, so earlier attacks poison the cumulative score and "
                    "can taint later benign cases. Run with `--reset` (or space cases with `--delay`) for a clean read.\n")
        if G["err"]:
            o.write("\n> ⚠️ %d cases got no verdict — confirm the WAF is up at `%s`.\n" % (G["err"], BASE))

        # ---- rule attribution (now populated from X-WAF-Rule-Id) ----
        if rule_fires:
            o.write("\n## Rules that fired (`X-WAF-Rule-Id`)\n\n```\n")
            for rid, n in sorted(rule_fires.items(), key=lambda x: -x[1]):
                o.write("%5d  %s\n" % (n, rid))
            o.write("```\n")

        o.write("\n## Per-class\n\n| Class | Total | Pass | FP | FN | Err | Skip | Rejd | Detect%% |\n|---|--:|--:|--:|--:|--:|--:|--:|--:|\n")
        for cls in sorted(per):
            p = per[cls]; ex = p["total"] - p["skip"] - p["rej"]
            dr = "%.0f" % (p["pass_"] / ex * 100) if ex else "-"
            o.write("| %s | %d | %d | %d | %d | %d | %d | %d | %s |\n" %
                    (cls, p["total"], p["pass_"], p["fp"], p["fn"], p["err"], p["skip"], p["rej"], dr))
        fn = [r for r in fails if r["kind"] == "false_negative"]
        fp = [r for r in fails if r["kind"] == "false_positive"]
        er = [r for r in fails if r["kind"] == "error"]
        if fn:
            fail_table(o, fn, "❌ False negatives — attacks that slipped through")
            ev = defaultdict(int)
            for r in fn:
                for t in r.get("tags", []):
                    if t.startswith("evasion:"):
                        ev[t] += 1
            if ev:
                o.write("\n**Slipped-through by evasion technique:**\n\n```\n")
                for t, n in sorted(ev.items(), key=lambda x: -x[1]):
                    o.write("%4d  %s\n" % (n, t))
                o.write("```\n")
        if fp:
            fail_table(o, fp, "⚠️ False positives — benign blocked")
            # which rule is over-blocking benign traffic?
            byrule = defaultdict(int)
            for r in fp:
                byrule[r["rule_id"] or "(no rule — status/risk gate)"] += 1
            o.write("\n**Benign blocks by firing rule:**\n\n```\n")
            for rid, n in sorted(byrule.items(), key=lambda x: -x[1]):
                o.write("%5d  %s\n" % (n, rid))
            o.write("```\n")
        if er:
            o.write("\n## 🔌 Errors — no verdict (%d)\n\n" % len(er))
            for r in er:
                o.write("- %s (%s) %s %s\n" % (r["id"], r["cls"], r["method"], r["path"][:60]))
        if rejected:
            o.write("\n## 🚫 Rejected before the WAF — malformed framing (%d)\n\n" % len(rejected))
            o.write("These returned **HTTP 400 with no `X-WAF-*` headers**: hyper rejected the "
                    "request line before the detector chain ran — almost always a raw space or "
                    "control byte in the URI. They are **not** WAF misses, but they also don't "
                    "exercise the WAF. Fix by URL-encoding the payload in the case generator.\n\n")
            byc = defaultdict(int)
            for r in rejected:
                byc[r["cls"]] += 1
            o.write("| Class | Rejected |\n|---|--:|\n")
            for cls, n in sorted(byc.items(), key=lambda x: -x[1]):
                o.write("| %s | %d |\n" % (cls, n))
            o.write("\n<details><summary>%d affected cases</summary>\n\n" % len(rejected))
            for r in rejected[:FAIL_CAP]:
                o.write("- `%s` %s %s `%s`\n" % (r["id"], r["cls"], r["method"], r["path"].replace("\n", " ")[:70]))
            if len(rejected) > FAIL_CAP:
                o.write("\n_…and %d more — see the jsonl._\n" % (len(rejected) - FAIL_CAP))
            o.write("\n</details>\n")
        o.write("\n---\n_per-case log: run-%s.jsonl · summary: run-%s.summary.json_\n" % (ts, ts))
    # latest.md
    try:
        import shutil
        shutil.copyfile(md, os.path.join(REPORT_DIR, "latest.md"))
    except Exception:
        pass

    print("\n%sreport: %s%s  (also reports/latest.md)" % (C["B"], md, C["N"]))
    sys.exit(0 if (G["fn"] == 0 and G["fp"] == 0 and G["err"] == 0) else 1)

if __name__ == "__main__":
    main()
