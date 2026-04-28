# SQL Injection Detection

## Purpose

Detect attempts to inject SQL into query parameters, request bodies, headers, and paths. SQLi is one of the most impactful web vulnerabilities — successful exploitation can leak entire databases — and it's one of the most common attack patterns on the internet.

## Detection strategy

The detector uses **layered matching**:

1. **Aho-Corasick literal matching** — fast multi-pattern search for common SQL tokens and signatures
2. **Regex fallback** — for patterns that require grouping, alternation, or word-boundary matching
3. **Context scoring** — multiple weak signals combine into a detection

A single keyword like `SELECT` is not enough (legitimate content can contain it). The detector requires **multiple signals** or a **single high-confidence signal** to flag.

## Pattern categories

### Boolean-based blind

- `' OR '1'='1`
- `' OR 1=1 --`
- `" OR ""="`
- `' AND 1=0 UNION SELECT`

### Union-based

- `UNION SELECT`
- `UNION ALL SELECT`
- Balanced parentheses with `SELECT`

### Error-based

- `AND EXTRACTVALUE(`
- `AND UPDATEXML(`
- `CONVERT(INT, (SELECT`

### Time-based blind

- `SLEEP(`
- `BENCHMARK(`
- `WAITFOR DELAY`
- `PG_SLEEP(`

### Stacked queries

- `; DROP TABLE`
- `; INSERT INTO`
- `; UPDATE`

### Comment injection

- `--`, `#`, `/*`, `*/` in contexts that don't expect them
- `/*!50000` MySQL version comments
- `;%00`

### Function calls

- `LOAD_FILE(`, `INTO OUTFILE`, `INTO DUMPFILE`
- `xp_cmdshell`, `sp_configure`

### Encoding evasion

The detector decodes common encodings before matching:

- URL encoding (`%27` → `'`)
- Double URL encoding
- HTML entity encoding (`&#39;`)
- Unicode escapes (`\u0027`)
- MySQL hex (`0x27`)

## Surfaces inspected

For each request:

- URL path
- Query string (all parameters)
- Request body (up to `max_body_scan_bytes`, default 64 KB)
- Cookie values
- Custom headers configured for inspection

Request body scanning is content-type aware:

- `application/x-www-form-urlencoded` → URL-decode params, scan each
- `application/json` → recursive value scan
- `multipart/form-data` → scan each part
- Plain text / unknown → scan raw

## Scoring

Each match increments a sub-score. A request is flagged when the sub-score crosses a threshold (default 20). Single high-confidence patterns (e.g., `UNION SELECT ... FROM`) score 25 and flag immediately.

## Configuration

```yaml
detection:
  sqli:
    enabled: true
    sensitivity: high          # low | medium | high
    max_body_scan_bytes: 65536
    score_threshold: 20
    risk_increment: 40         # risk score added when triggered
```

- `low` — only high-confidence patterns match
- `medium` — standard pattern set
- `high` — includes experimental and edge-case patterns

## Actions on detection

- Add `risk_increment` to the request's risk score
- Emit an audit log with the matched pattern and evidence snippet
- Mark the request for caching bypass
- Depending on tier policy and final risk score, the request is either allowed, challenged, or blocked

## False positive mitigation

- Words like `SELECT`, `UPDATE` alone never trigger
- Detection is scored, not absolute — multiple weak hits needed for most categories
- Whitelisted paths / parameters can skip specific patterns via rule engine
- `log_only` sensitivity mode for tuning before enforcement

## Implementation

- `src/detection/sqli.rs` — pattern set, Aho-Corasick automaton, regex list, scorer

## Performance

- Aho-Corasick is O(n) in input length, matching hundreds of patterns in a single pass
- Body scanning is bounded by `max_body_scan_bytes` to prevent resource exhaustion
- Pre-compiled automata live in the config struct, refreshed on hot-reload
