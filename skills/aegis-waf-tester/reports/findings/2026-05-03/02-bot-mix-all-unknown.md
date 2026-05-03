---
id: 2026-05-03-bot-mix-all-unknown
date: 2026-05-03T16:10Z
severity: HIGH
area: control-plane
component: api/bots/mix + bot classifier
status: open
build_sha: cb95934
test_mode: smoke
---

# Bot classification mix is 100% "unknown" even with diverse curl traffic

## Summary

After driving 146 mixed requests (legit GETs, SQLi, XSS, recon,
ptrav) with three different XFF source IPs and standard `curl`
User-Agent, `/api/bots/mix?window=300` returns:

```jsonc
{ "categories": [{ "name": "unknown", "count": 136, "pct": 100.0 }] }
```

Not a single request classified as `verified`, `suspect`, or
`malicious`.  The Investigation page's "Bot classification mix"
card (folded in from Attack Analytics) reads as an empty
diagonal: 100% unknown, no actionable signal.

This is HIGH because (a) the SOC analyst gets no value from the
card today and (b) production traffic with real attackers WILL
have non-default UAs / JA4 fingerprints; failing-to-classify
silently means the dashboard hides bot signal that the WAF
otherwise has.

## Repro

```bash
make run-dev
DURATION=20 bash skills/aegis-waf-tester/scripts/drive-traffic.sh
sleep 2
curl -s -b /tmp/aegis-skill.jar \
  http://127.0.0.1:9443/api/bots/mix?window=300 | jq
```

## Expected

At least some classified buckets — `curl/X.Y.Z` is a known
non-browser UA the bot classifier should at minimum tag as
`unknown` with a non-zero confidence-other-class signal, or
ideally as `suspect` / `verified-bot`.  Real production
traffic has Googlebot / Bingbot / Cloudflare / scrapers — none
of those should land in `unknown` if the classifier is on.

## Actual

```jsonc
{ "categories": [{ "name": "unknown", "count": 136, "pct": 100.0 }] }
```

## Suggested fix

Two likely causes:

1. Classifier silently disabled in `make run-dev` profile (no
   threat-intel feeds, no JA4 baseline, no UA rules).  In that
   case the BotMix card needs an honest empty state ("no bot
   classifier configured — see docs/security/bot-classification")
   instead of pretending to classify and getting "unknown" on
   everything.
2. Classifier wired but its output isn't reaching the
   `/api/bots/mix` aggregator — same audit-bus consumer pattern
   as the detector hits aggregator that DOES light up.

Worth confirming: drive 30 s of traffic with a mix of
`-A "Mozilla/5.0 ..."` and `-A "Googlebot/2.1"` UAs and see
if the categories shift.  If they don't, the classifier never
fires; if they do, the test traffic is the issue and
`drive-traffic.sh` should be updated to spread UAs.

## Severity rationale

HIGH — this is a piece of signal the dashboard claims to provide
that's actually not provided.  Either fix the classifier or fix
the empty-state copy; the current shape is dishonest UX.

## Done-when

Either:
- The card shows non-zero counts in at least 2 categories under
  realistic traffic, OR
- The card displays an explicit "bot classifier not configured"
  empty state when no signal is producible.
