# MT-03 · Downstream enforcement — required/optional/SAN gate

**Covers:** mTLS — downstream client-cert verification at the data plane ·
**Severity:** **High** · **Expected duration:** ~10 min ·
**Prereq:** MT-02 green; client cert material available (see note); a TLS
data listener exposed.

> **Material needed.** Downstream mTLS verifies a **client** cert presented
> *to* the WAF, so this case needs (a) the WAF in `required`/`optional` mode
> with a `ca_bundle`, and (b) a client keypair that chains to that bundle,
> plus one that does NOT, plus one with a SAN outside `allowed_sans`. If the
> pre-prod doesn't ship test client certs, mark this case **BLOCKED**
> (needs certs) and file INFO — don't fail it. The browser/`fetch` path
> cannot present a client cert programmatically; this case is run with
> `curl --cert/--key` from a host that can reach the TLS data listener, or
> via a pre-provisioned browser client cert.

## Test

**Given** downstream `mode: required` (+ `ca_bundle`, optional `allowed_sans`).

**When** a client connects to the TLS data listener (1) with no cert,
(2) with a valid cert chaining to `ca_bundle` and a SAN in `allowed_sans`,
(3) with a valid-chain cert whose SAN is **not** in `allowed_sans`.

**Then** (1) and (3) are **rejected** at the TLS/identity gate; (2) is
**admitted**. In `optional` mode a certless client is admitted but flagged.
Each outcome produces an `/api/zero-trust/downstream/{connections,failures}` telemetry entry.

## Steps (curl from a host that reaches the TLS data listener)

```sh
TLS=https://<tls-data-host:port>   # the mTLS-enforced data listener
# 1. No client cert → expect TLS handshake refusal / 4xx identity reject
curl -ksi "$TLS/" ; echo "--- expect: rejected (no client cert)"
# 2. Valid cert + allowed SAN → expect admitted (200/502-upstream, NOT identity reject)
curl -ksi --cert client-ok.pem --key client-ok.key "$TLS/" ; echo "--- expect: admitted"
# 3. Valid chain, disallowed SAN → expect rejected (SAN gate)
curl -ksi --cert client-badsan.pem --key client-badsan.key "$TLS/" ; echo "--- expect: rejected (SAN)"
```

## Paste-to-Claude (telemetry verification)

> After the three curl attempts above, on admin tab N1 Zero Trust page:
>
> ```js
> (async () => {
>   const c = await (await fetch('/api/zero-trust/downstream/connections',{credentials:'include'})).json();
>   const f = await (await fetch('/api/zero-trust/downstream/failures',{credentials:'include'})).json();
>   return {connections:c, failures:f};
> })()
> ```
>
> Tell me: did the successful (case 2) connection appear in `connections`
> with its SAN, and did the no-cert (case 1) + bad-SAN (case 3) attempts
> appear in `failures` with a reason? Confirm the Zero Trust UI tables show
> the same.

## Pass criteria

- [ ] `required` + no cert → **rejected** (CRITICAL if a certless client is
      admitted in required mode).
- [ ] Valid cert + allowed SAN → **admitted**.
- [ ] Valid chain + disallowed SAN → **rejected** (SAN gate enforced).
- [ ] `optional` mode: certless admitted but flagged (spot-check).
- [ ] `/api/zero-trust/downstream/connections` logs the success (with SAN);
      `/api/zero-trust/downstream/failures` logs the two rejects with reasons; UI matches.
- [ ] (If no test certs) case marked BLOCKED + INFO, not failed.

## Findings template

- Per-case curl outcome (1/2/3).
- connections/failures entries + reasons; UI parity.
- Whether certs were available or case was blocked.
