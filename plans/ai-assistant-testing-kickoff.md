# `E` — AI-Assistant Testing Kickoff

> **Status:** plan doc, ready to execute. Track ID prefix `SWEEP-T<n>`.
> Last revised 2026-05-03.
>
> Improves on the original "each person + their own AI tests, drop
> findings under `tests/`, then consolidate" idea by adding the three
> things that make consolidation tractable: **claim-based sharding**,
> a **fixed deliverable schema**, and a **scripted dedup pass**.

## 0 · One-line summary

Run a multi-tester sweep where every human pairs with an AI
assistant, claims one slice of the WAF surface, drops findings
into a sweep folder using a fixed schema, and a consolidation
script turns the union into a single ranked improvement plan.

## 1 · Why a process matters here

Three failure modes a naive "everyone tests, dump notes, we
collate" approach hits every time:

| Failure mode | Symptom | Process counter |
|---|---|---|
| **Trampling** | Two testers flip the same toggle, fail each other's runs | Claims file: `tests/sweeps/<sweep>/CLAIMS.md` lock-row before starting |
| **Free-form findings** | One tester writes a 3-line bug, another a 3-page essay; consolidation is exegesis | Fixed `findings.jsonl` schema per tester (see §3) |
| **Hallucinated bugs** | AI claims X is broken; reproducer doesn't exist; days lost | Every finding row REQUIRES a `repro` block that any teammate can paste |

These are real — we hit each at least once during the
hackathon-readiness sweeps (see `tests/results/run-cqa-*` runs).

## 2 · Three-layer model

```
SWEEP (one calendar event — "2026-05-10 SOC console sweep")
  ├── CLAIMS.md                       who is testing what slice
  ├── tester-<id>/                    one folder per human/AI pair
  │     ├── ENV.md                    versions, branch, config used
  │     ├── findings.jsonl            structured rows (one finding per line)
  │     ├── misses.md                 what the tester wanted to test but couldn't
  │     └── transcripts/              raw AI conversation logs (optional)
  └── consolidated/
        ├── findings-deduped.jsonl    output of consolidate.sh
        ├── README.md                 ranked summary
        └── improvement-plan.md       sprint proposal, file as SWEEP-T tasks
```

## 3 · Finding schema (`findings.jsonl`)

One JSON object per line. Required fields:

```json
{
  "id": "T-alice-001",
  "tester": "alice",
  "ai_model": "claude-sonnet-4.6",
  "ts": "2026-05-10T14:23:00Z",
  "area": "dashboard.soc",
  "severity": "high",
  "title": "Investigation page filter dropdown crashes when more than 50 sources are listed",
  "summary": "<1-3 sentences>",
  "repro": [
    "make run-dev",
    "open https://localhost:9443/console/soc/investigation",
    "click 'Source' filter, scroll past 50 — page goes blank"
  ],
  "expected": "list virtualises or paginates",
  "actual": "DOM crashes with 'too many children' console error",
  "evidence": ["screenshot.png", "console-trace.txt"],
  "blocked_by_docs": false,
  "tautology": false,
  "links": []
}
```

- `severity`: `critical | high | medium | low`. Critical = data loss /
  auth bypass / production-affecting; high = feature broken with no
  workaround; medium = workaround exists; low = polish.
- `area`: dot-notated path matching one of the claim slices (§4).
- `blocked_by_docs`: `true` if the finding is already documented in
  `Implement-Progress.md` or a `plans/*.md`. The tester must
  search before filing — saves the consolidation step from
  re-discovering known-knowns.
- `tautology`: `true` when the AI confirmed something the user
  already told it. Self-flagging; consolidation drops these.

Optional: `links` for related GitHub issues / PRs / Slack threads.

## 4 · Claim slices (initial 8)

The WAF surface partitions into eight roughly-independent slices.
Each slice has its own admin endpoints + dashboard pages + tests
that don't trample others. Testers claim by appending a row to
`CLAIMS.md`:

| Slice | Surface | Sample tests |
|---|---|---|
| `data-plane.security` | detector mask, rules, tier overrides | OWASP corpus, payload variants, tier promotion/demotion |
| `data-plane.routing` | upstream pools, health, failover | route table CRUD, draining, partial-pool failure |
| `data-plane.tls` | listener cert hot-swap, ACME, HTTP/3 | rotation under load, ACME order replay, alt-svc behaviour |
| `data-plane.mtls` | client auth, allowed SANs, CA bundle hot-swap | break-glass, mode flips, cert preview vs. live diff |
| `control.api` | REST + WebSocket admin endpoints | CSRF, rate limit, AuditedMutate replay |
| `control.dashboard.config` | Detectors/Rules/Routes/Upstreams pages | save flow, dirty-state, validation surfacing |
| `control.dashboard.soc` | Investigation/Compliance/Reports/Threat Intel/Incidents | data freshness, sort/filter sanity, empty states |
| `cluster.ha` | leader election, partition fallback, reconciliation | kill-the-leader, network partition, redis flap |

Slices are **non-overlapping by design**. A tester who finishes
their slice may claim a second; a slice with no claim by 24h
before the sweep gets rolled into a shared "unowned" pool.

## 5 · Per-tester pre-flight

Before opening their AI:

```sh
# Same starting state for everyone
git pull origin develop
git rev-parse HEAD > tests/sweeps/<sweep>/tester-<id>/ENV.md.head
make smoke                                # baseline check
docker compose -f deploy/docker-compose.dev.yml up -d
cargo run -p aegis-bin -- run --config config/dev.yaml &
```

Then:

1. Copy `tests/sweeps/template/` to `tests/sweeps/<sweep>/tester-<id>/`.
2. Read `tests/AI-ASSISTANT-RULES.md` (terse) AND prepend it to the
   AI's system prompt — this is the single most-impactful step for
   filtering hallucinated findings.
3. Edit `CLAIMS.md` to record their slice.
4. Test. File findings as JSON lines into `findings.jsonl` as they
   discover them — *not* at the end. Discovery order helps the
   consolidation step understand the tester's path.

## 6 · Consolidation pass

A single human (the **sweep lead**) runs:

```sh
./tests/sweeps/consolidate.sh <sweep-id>
```

The script:

1. Concatenates every tester's `findings.jsonl`.
2. Drops rows where `tautology: true` or `blocked_by_docs: true`.
3. Buckets by `area` then by `signature` — a hash of
   normalised `title + repro[0]` — and groups duplicates under
   the row with the most evidence.
4. Sorts by severity × number-of-testers-who-found-it × inverse fix
   cost (estimated; default = 1).
5. Writes `consolidated/findings-deduped.jsonl` plus a
   human-readable `consolidated/README.md`.

Then the sweep lead writes `consolidated/improvement-plan.md` —
the ranked top-N items become SWEEP-T tasks the team picks up
in the next sprint.

## 7 · Anti-patterns to call out in the kickoff prompt

Paste these into every tester's AI system prompt verbatim:

- **Don't infer "broken" from console warnings alone.** A
  `useEffect` warning isn't a bug; the missing screen behaviour
  is.
- **Reproducers must be paste-runnable.** "Click around in the
  Detectors page" is not a reproducer; the four specific clicks
  are.
- **If the docs say it's intentional, it's a doc finding, not a
  bug finding.** Files those under area `docs.<page>` so the
  consolidation can route them to the doc-updater track.
- **Don't auto-quarantine flaky tests.** File them with
  `severity: medium` and `area: tests.flake` so they get
  triaged, not buried.
- **Don't open issues yourself.** The sweep lead opens issues
  from the deduped list; per-tester issues fragment.

## 8 · Tooling to ship before the first sweep

Tracked as SWEEP-T1 .. SWEEP-T5:

- **SWEEP-T1** — `tests/sweeps/template/` skeleton (this commit).
- **SWEEP-T2** — `tests/sweeps/consolidate.sh` (next).
- **SWEEP-T3** — `tests/sweeps/template/findings.jsonl.schema.json`
  + a `make sweep-validate <sweep-id>` Makefile target that
  runs every tester's `findings.jsonl` through `jq -e` to catch
  malformed rows before consolidation.
- **SWEEP-T4** — `tests/sweeps/README.md` operator guide
  (this is the user-facing version of the sections above).
- **SWEEP-T5** — first actual sweep: 4–6 testers across 4–6
  slices, ~2h, write up under
  `tests/results/run-sweep-NN-YYYY-MM-DD-<theme>/`.

## 9 · Out of scope (queued for later)

- **Cross-tester live observation.** Watching another tester's
  session for cross-pollination findings — only worth it once
  we've run sweep #1 and know which slices benefit.
- **Per-tester isolated container stack.** Today everyone shares
  the same `docker-compose.dev.yml`; if state collisions become
  the dominant noise source we'll spin up
  `tests/sweeps/template/per-tester-compose.yml`.
- **AI-Assistant-as-consolidator.** The first run is human-led
  consolidation. Once we have ≥2 sweeps' worth of training
  examples, a Claude sub-agent reads the per-tester JSONL +
  emits the deduped output. Saved for after the human has a feel
  for what "good consolidation" looks like.
- **Tester reputation / scoring.** Rejected for cost / effort
  reasons; the JSONL itself is the record.

## 10 · Done-when

- A first sweep ran end-to-end: claims taken, findings filed,
  consolidate.sh succeeded, improvement-plan.md exists, ≥3
  SWEEP-T tasks landed in the regular plan queue.
- The sweep folder is reproducible: someone reading
  `tests/results/run-sweep-NN-*` 3 months later can rebuild the
  state, re-run any single repro, and understand why each
  finding ranked where it did.
- The schema validates: `make sweep-validate <sweep-id>` exits
  zero on every tester folder.
