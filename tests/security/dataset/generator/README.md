# v4 adversarial dataset generator

Programmatic generator for ~200k attack test-cases + ~10k FP-prone
clean baselines, used to stress-test detector coverage on
Aegis-Gate. Produces NDJSON (one case per line) rather than nested
JSON so the corpus streams cheaply at scale.

## Run

```bash
# Default — 200k attacks, 10k clean, seed=42
python3 tests/security/dataset/generator/generate_v4.py

# Smaller smoke-test run (~5s)
python3 tests/security/dataset/generator/generate_v4.py --count 5000 --clean-count 500

# Different deterministic seed
python3 tests/security/dataset/generator/generate_v4.py --seed 17

# Custom output dir
python3 tests/security/dataset/generator/generate_v4.py --out-dir /tmp/dataset-test
```

**Inputs:** none — every payload, path, header, and obfuscation
lives in the script itself.
**Outputs:**
- `tests/security/dataset/attacks_v4.ndjson` (~90 MB)
- `tests/security/dataset/clean_baselines_v4.ndjson` (~3 MB)
- `tests/security/dataset/attacks_v4.meta.json` (per-class counts +
  generator config)

Determinism: stable IDs from `sha1(class|idx|payload+path+query+body)`.
Re-running with the same `--seed` yields byte-identical output.

## What's in the corpus

21 attack classes; counts at default scale (200k):

| Class | Cases | Notes |
|---|---|---|
| sqli | 18,000 | classic / union / blind / time-based / stacked / OOB / second-order / DB-specific (MySQL, MSSQL, PG, Oracle) |
| xss | 18,000 | reflected / DOM / SVG / mXSS / polyglots / event handlers / framework-{{}} |
| evasion_chain | 18,000 | sqli + xss + ssrf + cmd payloads with heavy multi-layer obfuscation |
| recon | 22,000 | `/.env`, `/.git/config`, `/.aws/credentials`, `/wp-admin`, `/actuator/*`, etc. |
| polyglot | 16,000 | hybrid payloads (sqli + xss / ssrf + log4shell / path + svg-onload) |
| ssrf | 14,000 | localhost / IMDS (AWS/GCP/Azure/Alibaba/OpenStack) / file:// / gopher:// / IPv6 / DNS rebinding |
| path_traversal | 14,000 | `../` + URL-encoded slashes + UTF-8 overlong + UNC + null-byte |
| command_injection | 14,000 | shell metachars / `$()` / backticks / `${IFS}` / reverse shells / Win+PS |
| ssti | 10,000 | Jinja2 / Twig / ERB / Velocity / Freemarker / SpEL / Handlebars / Mako / Pebble / Pug |
| xxe | 8,000 | external entity / parameter entity / OOB / php://filter / jar://|
| header_injection | 6,000 | CRLF / Host-header / X-Forwarded-* / cache poisoning |
| open_redirect | 6,000 | `//evil.com` / scheme tricks / `@` confusion / encoded slashes |
| ldap_injection | 6,000 | wildcards / OR injection / null-byte / DN escapes |
| nosql_injection | 6,000 | Mongo `$ne` / `$gt` / `$where` / `$regex` / JS escape |
| log4shell | 4,000 | `${jndi:...}` + multi-layer `${lower:}` / `${env:}` obfuscation |
| graphql_abuse | 4,000 | introspection / deep nesting / batching / mutation abuse |
| rce_deserialization | 4,000 | Java ysoserial / PHP unserialize / Python pickle / Ruby Marshal / .NET BinaryFormatter |
| prototype_pollution | 4,000 | `__proto__` / `constructor.prototype` in JSON + query |
| jwt_abuse | 3,000 | `alg=none` / weak HMAC / `kid` SQLi / `kid` traversal |
| http_smuggling | 3,000 | TE/CL conflicts / chunked-encoding tricks |
| websocket | 2,000 | upgrade-bound CSRF / smuggling-adjacent |

13 obfuscation primitives, applied per-class based on what makes
sense:

| Obf | What it does |
|---|---|
| `none` | identity (the base payload, as-is) |
| `urlenc` / `urlenc2x` / `urlenc3x` | single / double / triple URL-encoding |
| `hex` | every byte → `%XX` |
| `uniesc` | non-alnum → `\u00XX` |
| `case` | alternating upper/lower |
| `sqlcomment` | inject `/**/` into SQL keywords (`UN/**/ION`) |
| `ws` / `tab` / `newline` | replace spaces with `/**/` / `\t` / `%0a` |
| `html_dec` / `html_hex` | HTML entity encoding |
| `base64_wrap` | bare base64 (used by polyglot / deserialization classes) |

Each case has:

```jsonc
{
  "id":             "sqli-a4282461db",         // stable, hash-derived
  "class":          "sqli",
  "label":          "sqli · obf=urlenc",
  "method":         "GET",                     // GET/POST/PUT
  "path":           "/support",
  "query":          "u=1%27%20AND%20...",      // optional
  "body":           "{\"file\":\"...\"}",      // optional
  "headers":        { "user-agent": "...", "accept": "...", ... },
  "expected_action": "block",                  // or "allow" for clean
  "expected_rule":  "sqli",
  "obf":            "urlenc",
  "base_payload":   "1' AND extractvalue(..."  // pre-obfuscation, truncated
}
```

## How to drive it

The corpus is NDJSON so any consumer that reads line-by-line works.

### Replay via `curl` (one case at a time)

```bash
jq -c '.' tests/security/dataset/attacks_v4.ndjson | while read line; do
  method=$(echo "$line" | jq -r .method)
  path=$(echo "$line" | jq -r .path)
  query=$(echo "$line" | jq -r '.query // ""')
  url="http://localhost:8080${path}${query:+?${query}}"
  curl -sS -o /dev/null -w "%{http_code} ${url:0:100}\n" \
    -X "$method" "$url" \
    -H "$(echo "$line" | jq -r '.headers | to_entries[] | "\(.key): \(.value)"' | head -1)"
done | head -10
```

### Bulk replay with `xargs -P` for throughput

```bash
jq -c '.' tests/security/dataset/attacks_v4.ndjson | head -1000 | \
  xargs -P 16 -I {} bash -c '
    line={}
    # ... single-case curl as above
  '
```

### Scoring detector recall + FP rate

After replaying both files, compare:

- `attacks_v4.ndjson` → expect HTTP 403/429 (block/challenge) on
  ≥ 95% (target).  Each case has `expected_rule: "<class>"`; the
  WAF's `X-WAF-Rule-Id` response header should contain the class
  token.
- `clean_baselines_v4.ndjson` → expect 200/3xx/404 (NOT 403/429)
  on ≥ 99.5% (target).  Any 403/429 is a false positive.

A small Python scorer that consumes the WAF's response and tallies
per-class precision/recall is the right shape for CI integration.
Not yet shipped — extension hook.

## Reproducibility / versioning

The full corpus is checked into git despite its size (90 MB) so
the security regression battery is byte-stable between commits.
Re-generation with `--seed=42` overwrites identical output.

When extending:
- Add payloads to the matching `PAYLOADS_<CLASS>` list at the top
  of the script.
- Re-run the generator.  Bump the `_meta.version` if the schema
  changed.

If we ever need a leaner corpus that doesn't bloat git, compress:

```bash
gzip -9 tests/security/dataset/attacks_v4.ndjson
# Loader handles `.ndjson.gz` natively
```

## Limitations

- **Single-source IPs in headers** — `X-Forwarded-For` rotates
  through a 22-IP pool. For rate-limit / DDoS-gate testing, drive
  many distinct source IPs at the data plane layer instead.
- **No timing model** — the dataset doesn't carry inter-arrival
  delays. Replayers add their own (e.g. via `k6` scenarios or
  `--rate-limit`).
- **No upstream contract** — these cases assume the WAF blocks
  before they reach an upstream. If your upstream returns 200 on
  paths like `/.env`, that's an upstream config bug, not a WAF
  miss.
- **No mTLS / auth cases** — the corpus exercises the detector
  chain, not the auth gate. mTLS + JWT cases live in
  `contract_tests.json`.
