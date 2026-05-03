# Aegis-Gate Tester — Claude Skill

A self-contained Claude Skill that drives the Aegis-Gate WAF as a
real QA engineer would: real browser, real curl, real findings.

## What it does

Walks four phases against a running `make run-dev` WAF and writes
structured findings under `reports/findings/`:

1. **Smoke** — boot, login, click every page, one curl. ~5 min.
2. **Functional** — every interactive control + every documented
   feature surface. ~20 min.
3. **UX (SOC analyst lens)** — pretend it's day 1, find friction. ~15 min.
4. **Performance + security regression** — throughput / latency /
   known-bad payloads. ~20 min.

Findings are graded `CRITICAL / HIGH / MEDIUM / LOW / INFO` and
written one per file to `reports/findings/YYYY-MM-DD/<slug>.md`
using the template at `reports/REPORT_TEMPLATE.md`.

## Install (Claude Desktop)

```bash
# from the aegis-gate repo root
mkdir -p ~/.claude/skills
cp -R skills/aegis-waf-tester ~/.claude/skills/
```

Then restart Claude Desktop. The skill is now available.

## Run it (two equivalent paths)

### Path 1 — connect the repo, let Claude do everything

In Claude Desktop:

1. **Mount the `aegis-gate` repo folder** into your workspace
   (Settings → Project / Folder Access). The skill reads its
   own scripts + writes findings into the repo without that.
2. Ask Claude:
   > Use the aegis-waf-tester skill in smoke mode.

If the WAF isn't running, Claude will detect it via pre-flight
and offer to boot it for you. The skill auto-runs:

```bash
bash skills/aegis-waf-tester/scripts/start-waf.sh
bash skills/aegis-waf-tester/scripts/verify-waf-up.sh
```

…then proceeds with the test mode you asked for.

### Path 2 — pre-boot yourself, no repo mounted

If you'd rather start the WAF manually (or your Claude Desktop
doesn't have repo access):

```bash
# In a terminal on your laptop:
make redis-up
make run-dev &      # leave this running
```

Then in Claude Desktop:

> Use the aegis-waf-tester skill in smoke mode against the WAF
> running on http://127.0.0.1:9443. No repo access — write
> findings as markdown into chat.

The skill falls back to **self-contained mode**: every check is
inlined into SKILL.md (no external script reads), and findings
land in the chat as copy-pasteable markdown blocks instead of
files in the repo. Test coverage is the same.

## Prerequisites — what each tool unlocks

| Tool / setup | Without it the skill… |
|---|---|
| `Bash` available to Claude | …can't do anything. `Bash` is the only hard requirement. |
| `Read` / `Write` / `Edit` | …writes findings into chat instead of files. Same content, less convenient archival. |
| Repo folder mounted | …loses access to checklists, can't run start-waf.sh / verify-waf-up.sh, falls back to inlined checks in SKILL.md. |
| WAF running on default ports | …pre-flight fails. Skill offers to boot via `start-waf.sh` or asks you to run `make run-dev`. |
| **Playwright MCP** plugin | …falls back to curl-only coverage and logs one INFO finding noting the gap. Most checks still pass. |
- `curl` and `jq` on PATH (every modern dev box has them).
- Optional but recommended: `wscat` (or `websocat`) for the
  WebSocket bridge tests.

## What you get back

A summary message at the end of each run:

```
Aegis-Gate test run complete · functional · 18m
Findings: 0 CRITICAL · 1 HIGH · 4 MEDIUM · 2 LOW · 6 INFO
Top blocker: HIGH — Live Feed renders no rows when SSE first connects (regression?)
Reports: skills/aegis-waf-tester/reports/findings/2026-05-03/*.md
Next suggested action: triage the SSE-first-connect HIGH; the rest can wait
```

Each finding file is self-contained: repro, expected, actual,
evidence, suggested fix, severity rationale, done-when. Drop
them into your issue tracker, attach to a PR, or paste into a
Slack thread — they read cleanly out of context.

## Folder layout

```
skills/aegis-waf-tester/
├── SKILL.md                # Main skill instructions Claude reads
├── README.md               # This file (operator-facing)
├── scripts/
│   ├── verify-waf-up.sh    # Pre-flight (data plane + admin + Redis); guidance per failure
│   ├── start-waf.sh        # Idempotent boot: redis-up + (build if needed) + WAF + wait for ready
│   ├── drive-traffic.sh    # 30 s of mixed legit + attack mix
│   └── reset-state.sh      # Clear access lists between runs
├── checklists/
│   ├── functional.md       # ~50 yes/no checks, audit-grade
│   ├── ux-soc.md           # 10 SOC-analyst scenarios, 1-5 ratings
│   ├── performance.md      # 8 perf measurements with targets
│   └── security.md         # Regression replay of known-bad payloads
└── reports/
    ├── REPORT_TEMPLATE.md  # Frontmatter + sections every finding has
    └── findings/           # Output: created/overwritten by the skill
        └── YYYY-MM-DD/
            └── <slug>.md
```

## Customising

Edit `checklists/*.md` to add product-specific checks (the
defaults cover everything documented in `Implement-Progress.md`
as of 2026-05-03). Edit `scripts/drive-traffic.sh` to change
the synthetic traffic mix. The Skill picks up changes
automatically — just re-run.

## Iterating with the dev team

After a run:

1. Read the generated findings. Reject any false-positives
   (see `SKILL.md` § anti-patterns) — delete the file.
2. Triage by severity. CRITICALs and HIGHs get fixed before
   release; MEDIUMs get scheduled; LOWs and INFOs feed the
   backlog.
3. Re-run after each fix lands. Findings that disappear are
   regressions caught and prevented; new findings catch
   second-order issues the fix introduced.

## Limits — what the Skill does NOT do

- It doesn't write code fixes. Findings include a "Suggested
  fix" pointer but the dev does the actual implementation.
- It doesn't run extended fuzzing or property-testing. Use
  `cargo test --workspace` and `tests/load/` for those.
- It doesn't replace `tests/security/nuclei` or the Round-1
  hackathon harness — it complements them as a fresh-eyes
  human-flow pass.
- It can't drive a multi-node HA cluster QA (single-node only).
  HA-cluster regression lives in `tests/cluster/`.

## Updating the Skill

Skills evolve with the product. Any time we ship a new feature
that should be QA'd:

1. Add a row to the right `checklists/*.md` file.
2. If the feature has a specific test script, add it under
   `scripts/` and reference it from the checklist.
3. Bump the date in `SKILL.md` if you're adding a phase.

The `Implement-Progress.md` "Last Completed" section is the
authoritative source for what's new in the product — when it
moves, the Skill should move with it.
