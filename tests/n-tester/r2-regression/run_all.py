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

Verdict (in order): X-Aegis-Decision header -> HTTP status
    403/413 -> block | 429 -> challenge | 101/2xx/3xx/401/404 -> allow | conn err -> error
WebSocket: handshake !=101 -> block ; close 1008/1009/1003 after a frame -> block ; else allow.

Outputs (in reports/):
    run-<ts>.jsonl          per-case records
    run-<ts>.summary.json   machine summary
    run-<ts>.md + latest.md human-readable analysis (per-class detect%, FP/FN inline,
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

def http_raw(method, path, headers, body, auth):
    """Send a fully-controlled raw HTTP/1.1 request. Returns (status:int, decision:str|None, rule:str|None)."""
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
        return 0, None, None
    if not resp:
        return 0, None, None
    head = resp.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    first = head.split("\r\n", 1)[0]
    m = re.search(r"HTTP/\d\.\d\s+(\d{3})", first)
    status = int(m.group(1)) if m else 0
    decision = rule = None
    for ln in head.split("\r\n")[1:]:
        low = ln.lower()
        if low.startswith("x-aegis-decision:"):
            decision = ln.split(":", 1)[1].strip().lower()
        elif low.startswith("x-aegis-rule-id:"):
            rule = ln.split(":", 1)[1].strip()
    return status, decision, rule

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
    """Drive a WebSocket handshake (+frames). Returns verdict string."""
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
        return "error"
    first = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace") if resp else ""
    head = resp.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    dec = None
    for ln in head.split("\r\n")[1:]:
        if ln.lower().startswith("x-aegis-decision:"):
            dec = ln.split(":", 1)[1].strip().lower()
    m = re.search(r"HTTP/\d\.\d\s+(\d{3})", first)
    status = int(m.group(1)) if m else 0
    if dec in ("allow", "block", "challenge"):
        if dec != "allow":
            try: s.close()
            except Exception: pass
            return dec
    if status != 101:
        try: s.close()
        except Exception: pass
        return "challenge" if status == 429 else "block"
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
    return verdict

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
    r = c["request"]
    method = r["method"]; path = r["path"]; auth = r.get("auth", "none")
    expected = c["expect"]["verdict"]
    body = None
    if r.get("body") is not None:
        body = base64.b64decode(r["body"]) if r.get("body_b64") else r["body"].encode("latin-1", "replace")
    # informational / non-executable
    if r.get("execute") is False:
        return "skip", "skip", ""
    ws = c.get("ws")
    if ws and not ws.get("handshake_only", True) and ws.get("frames"):
        return "frame", ws_run(ws, auth), ""          # ws frame case
    if ws:
        return "ws", ws_run(ws, auth), ""             # ws handshake-only
    # burst (rate-limit)
    rep = 0
    for t in c.get("tags", []):
        if t.startswith("repeat:"):
            rep = min(int(t.split(":")[1]), MAX_REPEAT)
    if rep > 1:
        hit = "allow"
        for _ in range(rep):
            st, dec, rule = http_raw(method, path, r.get("headers"), body, auth)
            a = dec if dec in ("allow", "block", "challenge") else code_verdict(st)
            if a in ("block", "challenge"):
                hit = a
        return "burst", hit, ""
    st, dec, rule = http_raw(method, path, r.get("headers"), body, auth)
    actual = dec if dec in ("allow", "block", "challenge") else code_verdict(st)
    return "http", actual, (rule or "")

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
    per = defaultdict(lambda: dict(total=0, pass_=0, fp=0, fn=0, err=0, skip=0))
    G = dict(total=0, pass_=0, fp=0, fn=0, err=0, skip=0)
    fails = []

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
            try:
                kind, actual, rule = run_case(c)
            except Exception as e:
                kind, actual, rule = "http", "error", str(e)[:40]
            if actual == "skip":
                p["skip"] += 1; G["skip"] += 1
                rec = dict(id=c["id"], cls=cls, result="skip", actual="skip",
                           expected=c["expect"]["verdict"], name=c["name"],
                           method=c["request"]["method"], path=c["request"]["path"], rule_id="")
                jl.write(json.dumps(rec) + "\n"); continue
            ok, k = classify(c["expect"]["verdict"], actual)
            rec = dict(id=c["id"], cls=cls, expected=c["expect"]["verdict"], actual=actual,
                       result="pass" if ok else "fail", kind="ok" if ok else k, rule_id=rule,
                       method=c["request"]["method"], path=c["request"]["path"],
                       tags=c.get("tags", []), severity=c.get("severity", ""),
                       source=c.get("source", ""), name=c["name"])
            jl.write(json.dumps(rec) + "\n")
            if ok:
                p["pass_"] += 1; G["pass_"] += 1
                if args.verbose:
                    print("  %sPASS%s %-12s exp=%-9s got=%s" % (C["G"], C["N"], c["id"], c["expect"]["verdict"], actual))
            else:
                if k == "false_positive": p["fp"] += 1; G["fp"] += 1
                elif k == "false_negative": p["fn"] += 1; G["fn"] += 1
                else: p["err"] += 1; G["err"] += 1
                fails.append(rec)
                print("  %sFAIL%s %-12s exp=%-9s got=%-9s %s[%s]%s %s" %
                      (C["R"], C["N"], c["id"], c["expect"]["verdict"], actual, C["Y"], k, C["N"], c["name"][:48]))
    jl.close()

    # ---- console summary ----
    print("\n%s── per-class ──%s" % (C["B"], C["N"]))
    print("%-22s %6s %6s %5s %5s %5s %5s" % ("CLASS", "TOTAL", "PASS", "FP", "FN", "ERR", "SKIP"))
    for cls in sorted(per):
        p = per[cls]
        col = C["R"] if (p["fp"] or p["fn"] or p["err"]) else C["G"]
        print("%s%-22s%s %6d %6d %5d %5d %5d %5d" %
              (col, cls, C["N"], p["total"], p["pass_"], p["fp"], p["fn"], p["err"], p["skip"]))
    print("%s── totals ──%s" % (C["B"], C["N"]))
    print("%-22s %6d %6d %5d %5d %5d %5d" % ("TOTAL", G["total"], G["pass_"], G["fp"], G["fn"], G["err"], G["skip"]))
    print("\n  %sfalse negatives (attacks allowed): %d%s" % (C["R"], G["fn"], C["N"]))
    print("  %sfalse positives (benign blocked):  %d%s" % (C["Y"], G["fp"], C["N"]))
    if G["err"]:
        print("  %serrors (no verdict — WAF down?):    %d%s" % (C["R"], G["err"], C["N"]))

    # ---- machine summary ----
    den = G["total"] - G["skip"]
    summ = dict(ts=ts, base_url=BASE, total=G["total"], pass_=G["pass_"], fp=G["fp"],
                fn=G["fn"], err=G["err"], skip=G["skip"],
                detection_rate=round(G["pass_"] / den * 100, 1) if den else 0)
    json.dump(summ, open(os.path.join(REPORT_DIR, "run-%s.summary.json" % ts), "w"), indent=2)

    # ---- markdown report ----
    md = os.path.join(REPORT_DIR, "run-%s.md" % ts)
    with open(md, "w") as o:
        o.write("# Aegis-Gate r2 regression — run report (python runner)\n\n")
        o.write("- **When:** %s   **Target:** `%s`\n" % (ts, BASE))
        o.write("- **Total:** %d · **Pass:** %d · **FN (attacks allowed):** %d · **FP (benign blocked):** %d · **Errors:** %d · **Skipped:** %d\n"
                % (G["total"], G["pass_"], G["fn"], G["fp"], G["err"], G["skip"]))
        o.write("- **Detection rate (pass / executed):** %s%%\n" % (summ["detection_rate"]))
        if G["err"]:
            o.write("\n> ⚠️ %d cases got no verdict — confirm the WAF is up at `%s`.\n" % (G["err"], BASE))
        o.write("\n## Per-class\n\n| Class | Total | Pass | FP | FN | Err | Skip | Detect%% |\n|---|--:|--:|--:|--:|--:|--:|--:|\n")
        for cls in sorted(per):
            p = per[cls]; ex = p["total"] - p["skip"]
            dr = "%.0f" % (p["pass_"] / ex * 100) if ex else "-"
            o.write("| %s | %d | %d | %d | %d | %d | %d | %s |\n" %
                    (cls, p["total"], p["pass_"], p["fp"], p["fn"], p["err"], p["skip"], dr))
        fn = [r for r in fails if r["kind"] == "false_negative"]
        fp = [r for r in fails if r["kind"] == "false_positive"]
        er = [r for r in fails if r["kind"] == "error"]
        if fn:
            o.write("\n## ❌ False negatives — attacks that slipped through (%d)\n\n" % len(fn))
            o.write("| id | class | method | path | rule |\n|---|---|---|---|---|\n")
            for r in fn:
                o.write("| %s | %s | %s | `%s` | %s |\n" %
                        (r["id"], r["cls"], r["method"], r["path"].replace("\n", " ")[:70], r["rule_id"] or "—"))
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
            o.write("\n## ⚠️ False positives — benign blocked (%d)\n\n" % len(fp))
            o.write("| id | class | method | path | rule |\n|---|---|---|---|---|\n")
            for r in fp:
                o.write("| %s | %s | %s | `%s` | %s |\n" %
                        (r["id"], r["cls"], r["method"], r["path"].replace("\n", " ")[:70], r["rule_id"] or "—"))
        if er:
            o.write("\n## 🔌 Errors — no verdict (%d)\n\n" % len(er))
            for r in er:
                o.write("- %s (%s) %s %s\n" % (r["id"], r["cls"], r["method"], r["path"][:60]))
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
