# Behavioral Anomaly Detection

## Purpose

Signature-based detection catches known attacks. Behavioral analysis catches **unknown** attacks by looking at how a client interacts with the site rather than what payloads it sends. Real users browse in recognizable patterns; bots, scrapers, and attackers don't.

## Signals

### Request interval regularity

Real users click, read, type, pause. Their inter-request intervals have high variance — short gaps mixed with long ones.

Bots often request at perfectly regular intervals (e.g., every 500ms). Very **low variance** in inter-request timing is a strong bot indicator.

**Computation:** for each session, track the last N inter-request intervals and compute their coefficient of variation. CV < 0.2 with N ≥ 10 is suspicious.

### Path entropy

Real users visit a small number of pages repeatedly. Scanners hit a large variety of unrelated paths.

**Computation:** Shannon entropy of the distribution of visited paths within a session. Very **high entropy** (unique path per request) over many requests indicates a scanner.

### Missing expected headers

Real browsers always send `Referer` on in-site navigation, `Accept-Language`, and `Accept`. Bots often skip these.

**Score:** +5 risk for each missing expected header on non-initial requests.

### Unusual method distribution

A normal browsing session is mostly `GET` with some `POST`. Sessions with unusual ratios (e.g., 100% `HEAD`, or many `OPTIONS`, or mixed `PUT`/`DELETE` on endpoints not used by the frontend) are suspicious.

### Failed auth ratio

A session with many failed authentications relative to successes is either a forgotten-password case or credential stuffing. See also [brute force detection](./detection-brute-force.md).

### Error rate

A session whose requests produce many 404s / 403s / 500s is probably a scanner.

### Parameter fuzzing signature

Same endpoint hit many times with slightly different parameters — a signature of fuzzing tools.

## Session tracking

State is kept in `DashMap<SessionKey, SessionRecord>` where:

```rust
struct SessionRecord {
    first_seen: Instant,
    last_seen: Instant,
    request_history: VecDeque<RequestRecord>,  // last N requests
    path_histogram: HashMap<String, u32>,
    status_histogram: HashMap<u16, u32>,
    method_histogram: HashMap<Method, u32>,
}

struct RequestRecord {
    timestamp: Instant,
    path: String,
    method: Method,
    status: u16,
}
```

`SessionKey` is the composite key `(client_ip, device_fingerprint, session_cookie)`. Sessions expire after configurable inactivity (default 30 minutes).

## Scoring

Each signal contributes to a behavioral anomaly score, added to the main risk score:

```
anomaly_score = 
    (regularity_penalty * 20) +        // 0-20 points
    (path_entropy_penalty * 15) +      // 0-15 points
    (missing_headers * 5) +            // 5 per missing header
    (method_unusualness * 10) +        // 0-10 points
    (error_rate_penalty * 15) +        // 0-15 points
    (fuzz_signature * 25)              // 0 or 25
```

Score is recomputed on each request (incrementally updated, not from scratch). A rising score triggers challenges and eventually blocks via the [risk engine](./risk-scoring.md).

## Configuration

```yaml
behavior:
  session_ttl_s: 1800
  max_history_per_session: 100
  thresholds:
    regularity_cv_max: 0.2
    path_entropy_max: 4.0
    min_requests_before_scoring: 5
  enabled: true
```

## Implementation

- `src/behavior/tracker.rs` — session store, per-request history
- `src/behavior/anomaly.rs` — signal computations and scoring
- `src/behavior/velocity.rs` — transaction velocity (see separate doc)

## Design notes

- Scoring is **incremental** — adding a new request is O(1) amortized
- Sessions expire to bound memory
- False positives are mitigated by requiring a minimum number of requests before scoring kicks in (configurable)
- Behavioral signals layer **on top of** signature detection, not instead of — a request can trigger both
