# `tests/sweeps/` — Multi-tester AI-assistant sweep workflow

> Operator guide for SWEEP-T track. The design rationale lives in
> [`plans/ai-assistant-testing-kickoff.md`](../../plans/ai-assistant-testing-kickoff.md);
> this file is the day-of running order.

## Layout

```
tests/sweeps/
├── README.md                              this file
├── template/                              copy this for each tester
│   ├── ENV.md
│   ├── findings.jsonl                     starts empty
│   ├── misses.md
│   └── transcripts/                       optional raw chat dumps
├── consolidate.sh                         dedup + rank pass
└── <sweep-id>/                            one folder per sweep
    ├── CLAIMS.md                          who is testing what slice
    ├── tester-<id>/                       one per human/AI pair
    └── consolidated/                      output of consolidate.sh
```

## Running a sweep

### 1. Sweep lead — kick off

```sh
SWEEP=run-sweep-01-2026-05-10-soc-console
mkdir -p tests/sweeps/$SWEEP
cp tests/sweeps/CLAIMS.template.md tests/sweeps/$SWEEP/CLAIMS.md
# Announce in chat: branch SHA, time-box, slice list
```

### 2. Each tester — claim a slice + run

```sh
SWEEP=run-sweep-01-2026-05-10-soc-console
TESTER=alice
mkdir -p tests/sweeps/$SWEEP/tester-$TESTER
cp -r tests/sweeps/template/* tests/sweeps/$SWEEP/tester-$TESTER/

# Edit CLAIMS.md to add a row: TESTER=alice, slice=control.dashboard.soc, started=...
# Edit tester-$TESTER/ENV.md with branch SHA, AI model, config used.

# Test. Append findings as JSON lines as you go:
cat >> tests/sweeps/$SWEEP/tester-$TESTER/findings.jsonl <<'EOF'
{"id":"T-alice-001","tester":"alice","ai_model":"claude-sonnet-4.6","ts":"2026-05-10T14:23:00Z","area":"control.dashboard.soc","severity":"high","title":"...","summary":"...","repro":["..."],"expected":"...","actual":"...","evidence":[],"blocked_by_docs":false,"tautology":false,"links":[]}
EOF

# Validate before submitting:
./tests/sweeps/consolidate.sh --validate $SWEEP/tester-$TESTER
```

### 3. Sweep lead — consolidate

```sh
./tests/sweeps/consolidate.sh $SWEEP
# → writes tests/sweeps/$SWEEP/consolidated/findings-deduped.jsonl
# → writes tests/sweeps/$SWEEP/consolidated/README.md
```

Then hand-write `consolidated/improvement-plan.md` ranking the top
items and turn the picks into `SWEEP-T<n>` plan tasks.

### 4. Archive

Move the consolidated folder under `tests/results/`:

```sh
mv tests/sweeps/$SWEEP tests/results/$SWEEP
```

`tests/sweeps/` is for in-flight work; `tests/results/` is the
durable history.

## Schema reminder

Every `findings.jsonl` row must have these fields. See
[`plans/ai-assistant-testing-kickoff.md`](../../plans/ai-assistant-testing-kickoff.md)
§3 for the full description.

| Field | Type | Required |
|---|---|---|
| `id` | string `T-<tester>-NNN` | yes |
| `tester` | string | yes |
| `ai_model` | string | yes |
| `ts` | RFC 3339 string | yes |
| `area` | dotted slice path | yes |
| `severity` | `critical \| high \| medium \| low` | yes |
| `title` | string | yes |
| `summary` | string | yes |
| `repro` | array of strings (paste-runnable) | yes |
| `expected` | string | yes |
| `actual` | string | yes |
| `evidence` | array of strings (filenames) | optional |
| `blocked_by_docs` | bool | yes |
| `tautology` | bool | yes |
| `links` | array of strings | optional |

## Slice catalogue

See `plans/ai-assistant-testing-kickoff.md` §4. Don't claim two
slices simultaneously; finish one, then claim the next.
