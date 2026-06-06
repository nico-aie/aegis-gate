# Smart Caching — QC Feature Description & Verification Guide

> **Audience:** QC / testers. Describes what the smart-caching feature does,
> how to turn it on, and a step-by-step checklist to verify every behavior and
> safety guard. **Status:** Phase 1 shipped (L1 in-process per node).

---

## 1. What the feature does (plain language)

The WAF can **cache responses from an upstream** and serve repeat requests
straight from memory, **without contacting the backend** again. The operator
chooses, **per upstream**, which URL paths are cacheable (e.g. `/static/`,
`/assets/`, `/favicon.ico`).

Key properties a tester must keep in mind:

- **Opt-in per upstream + path.** Nothing is cached unless a pool has a
  `cache:` block and the request path matches one of its rules.
- **GET/HEAD only.**
- **Never caches CRITICAL-tier traffic** — a hard rule that cannot be turned off.
- **Never caches per-user/authenticated content** — requests with `Authorization`
  or `Cookie`, or responses with `Set-Cookie`, are not cached.
- **Honors the origin** — responses marked `Cache-Control: no-store / private /
  no-cache` are not cached.
- **Memory-bounded** — each pool has a byte budget; oversized responses are
  never stored, so the cache cannot exhaust WAF memory.
- **L1 = in-process, per node.** The stats you see are *this node's* in-memory
  cache. A Redis "L2" shared tier is planned but **not wired yet**.
- **Purge is fleet-wide** — flushing the cache on one node clears every node
  (via Redis pub/sub), when the Redis state backend is configured.

### The one header to watch: `X-WAF-Cache`

Every WAF response carries it:

| Value | Meaning |
|---|---|
| `MISS` | Eligible + not in cache → forwarded to upstream, and stored if cacheable. |
| `HIT` | Served from cache; **the upstream was NOT contacted**. |
| `BYPASS` | Not eligible for caching (reason in the audit log `cache_bypass_reason`). |

Read it with curl: `curl -ki -X GET https://<waf>/static/app.css` and look at
the `X-WAF-Cache:` header, or `curl -ksD - -o /dev/null <url>`.

---

## 2. How to enable it (setup for testing)

Add a `cache:` block to the upstream pool in the WAF config, then restart.
Example for the dev `stub-pool` (`config/dev.yaml`):

```yaml
upstreams:
  stub-pool:
    members: [{ addr: "127.0.0.1:9999" }]
    cache:
      enabled: true
      default_ttl: "60s"
      max_total_bytes: 67108864     # 64 MiB budget for this pool
      max_entry_bytes: 1048576      # responses bigger than 1 MiB are not stored
      rules:
        - prefix: "/static/"        # only paths starting with /static/ are cacheable
          ttl: "5m"
        # - prefix: "/assets/"
        #   content_types: ["text/css", "application/javascript", "image/*"]
```

For the CRITICAL-tier test, add a route whose tier is critical:

```yaml
routes:
  - { id: secure, path: "/secure/", match_type: prefix,
      upstream: stub-pool, tier_override: critical }
```

Restart: `make restart-copilot` (or `make run-dev`). The dashboard's **Routing &
Upstreams** page shows a **Smart cache** card once the WAF is up.

---

## 3. Verification checklist

For each row: send the request(s), read `X-WAF-Cache`. **PASS** = observed value
matches *Expected*. The data plane is on `:8080` (HTTP) / `:8443` (HTTPS) in dev;
the dashboard/admin API is on `:9443`.

| # | Scenario | Steps | Expected |
|---|---|---|---|
| 1 | **Basic MISS → HIT** | `GET /static/app.css` twice | 1st = `MISS`, 2nd = `HIT`; **response body identical** both times |
| 2 | **HIT skips upstream** | After #1, stop/break the upstream, repeat the GET | Still `HIT`, still returns the cached body (proves upstream not contacted) |
| 3 | **Unmatched path** | `GET /api/orders` (no matching rule) | `BYPASS` |
| 4 | **Authenticated** | `GET /static/app.css` with `Authorization: Bearer x` | `BYPASS` |
| 5 | **Has cookie** | `GET /static/app.css` with `Cookie: s=1` | `BYPASS` |
| 6 | **Wrong method** | `POST /static/app.css` | `BYPASS` |
| 7 | **CRITICAL tier never cached** | `GET /secure/app.css` twice (critical route) | **Both `BYPASS`** — never HIT, even on a cacheable-looking path |
| 8 | **Origin says no-store** | Upstream returns `Cache-Control: no-store`; `GET` twice | 2nd is **not** `HIT` (not stored) |
| 9 | **Response sets cookie** | Upstream returns `Set-Cookie`; `GET` twice | 2nd is **not** `HIT` (not stored — would leak per-user data) |
| 10 | **Deception armor** | Rule has `content_types: [text/css]`; upstream returns `text/html`; `GET` twice | 2nd is **not** `HIT` (type mismatch → not stored) |
| 11 | **Too big** | Upstream body > `max_entry_bytes`; `GET` twice | Served fine, but 2nd is **not** `HIT` (over per-entry cap) |
| 12 | **Encoding correctness** | `GET` with `Accept-Encoding: gzip` ×2, then `Accept-Encoding: identity` ×2 | Each encoding HITs **its own** entry; a gzip body is never served to the identity request (no garbled body) |
| 13 | **Vary safety** | Upstream returns `Vary: Cookie`; `GET` twice | 2nd is **not** `HIT` (varies on an unkeyed header) |
| 14 | **TTL expiry** | `GET` (HIT), wait > rule `ttl`, `GET` again | After TTL → `MISS` again (re-fetched) |
| 15 | **Flush** | Warm an entry (HIT), `POST /__waf_control/flush_cache` (header `X-Benchmark-Secret: <secret>`), `GET` again | After flush → `MISS` |
| 16 | **Fleet-wide flush** *(multi-node)* | 2 nodes behind LB, warm the path on **both**, flush on node A, GET on **node B** | Node B → `MISS` (purge propagated via Redis pub/sub) |
| 17 | **Stats endpoint** | `GET https://<waf>:9443/api/cache/stats` | JSON with one row per cached pool: `entries`, `bytes`, `hit`, `miss`, `hit_ratio`, `evictions`, `backend: "in_memory"` |
| 18 | **Dashboard card** | Open **Routing & Upstreams** in the console | "Smart cache" card shows the pool, an **`L1 · in-memory`** badge, hit ratio climbing, a memory-budget bar, and entries/hits/misses/evictions |

### Pass/fail summary criteria

- **Critical:** #1, #7, #4/#5/#9 (authenticated/per-user never cached), #12
  (no mis-encoded bodies) **must pass** — these are correctness/security.
- **Functional:** #2, #3, #6, #8, #10, #11, #13, #14, #15, #17, #18.
- **Multi-node:** #16 (only when testing a >1-node deployment with Redis).

---

## 4. How to read results / debug

- **`X-WAF-Cache` missing entirely** → this isn't an interop build, or you're
  hitting the admin plane instead of the data plane.
- **First GET to a cached path is `BYPASS` (not `MISS`)** → the pool has no
  matching `cache:` rule for that path; re-check the config + restart.
- **Never `HIT`** → check the upstream actually returns `200`, no `Set-Cookie`,
  no `Cache-Control: no-store`, and (if `content_types` is set) a matching type.
- **Bypass reason** is recorded in the audit log as `cache_bypass_reason`
  (`critical_tier`, `authorization`, `cookie`, `method`, `no_match`,
  `set_cookie`, `content_type`, `origin_no_store`, …).

---

## 5. Out of scope for this phase (do NOT expect)

- **No shared/Redis cache store yet** — the cache is per node; two nodes warm
  independently (the stats are per node, badge says `L1 · in-memory`). Only the
  *purge* is fleet-wide.
- **No conditional revalidation** (ETag / `If-None-Match`) — an expired entry is
  re-fetched in full, not revalidated.
- **No serve-stale-on-error** yet.
- **No per-prefix purge** — `flush_cache` clears the whole pool (coarse but safe).

See `plans/future/smart-caching.md` for the full design + later phases.
