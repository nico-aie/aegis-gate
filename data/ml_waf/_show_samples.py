import json, glob, random
random.seed(42)

files = glob.glob(r"c:/Users/rmuser/Workspaces/ml_waf/legitimate/Legitimate/*.json")
random.shuffle(files)

g_simple, g_query, post_body, put_patch, unusual = [], [], [], [], []

for path in files[:80]:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            records = json.load(f)
        if isinstance(records, dict):
            records = [records]
        for r in records[:300]:
            method = r.get("method", "").upper()
            url = r.get("url", "")
            body = r.get("data") or ""
            if isinstance(body, (dict, list)):
                body = json.dumps(body)

            if method == "GET" and "?" not in url and len(g_simple) < 4:
                g_simple.append((path, r))
            elif method == "GET" and "?" in url and 50 < len(url) < 200 and len(g_query) < 4:
                g_query.append((path, r))
            elif method == "POST" and body and len(post_body) < 5:
                post_body.append((path, r))
            elif method in ("PUT", "PATCH", "DELETE") and len(put_patch) < 3:
                put_patch.append((path, r))
            elif method == "GET" and len(url) > 300 and len(unusual) < 3:
                unusual.append((path, r))
    except Exception:
        pass


def show(title, items):
    print("\n" + "=" * 78)
    print(" " + title)
    print("=" * 78)
    for i, (path, r) in enumerate(items, 1):
        site = path.split("browsing_2024_")[-1].replace(".json", "") if "browsing_2024_" in path else path.split("/")[-1]
        print(f"\n--- Sample {i}  (from: {site}) ---")
        print(f"  Method  : {r['method']}")
        url = r["url"]
        print(f"  URL     : {url[:200]}" + ("...[truncated]" if len(url) > 200 else ""))
        h = r.get("headers", {})
        print(f"  Host    : {h.get('Host', '-')}")
        ua = h.get("User-Agent", "-")
        print(f"  UA      : {ua[:90]}")
        ct = h.get("Content-Type", "-")
        if ct != "-":
            print(f"  C-Type  : {ct}")
        ref = h.get("Referer", "-")
        if ref != "-":
            print(f"  Referer : {ref[:90]}")
        body = r.get("data") or ""
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        if body:
            safe = body[:250].encode("ascii", "backslashreplace").decode("ascii")
            print(f"  Body    : {safe}" + ("..." if len(body) > 250 else ""))


show("1. GET requests - simple paths (no query)", g_simple)
show("2. GET requests - with query string", g_query)
show("3. POST requests - with payload body", post_body)
show("4. PUT / PATCH / DELETE requests", put_patch)
show("5. Unusual - very long GET URLs", unusual)
