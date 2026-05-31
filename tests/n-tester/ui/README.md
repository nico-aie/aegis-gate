# n-tester UI playbooks (Claude Desktop + Chrome MCP)

Self-contained dashboard test cases QC walks through with **Claude
Desktop** driving **Chrome via the MCP extension**. Each `.md` is
designed to be opened, read top-to-bottom, and the **Paste-to-Claude**
block copied verbatim into the Claude Desktop chat.

## QC setup (one-time)

1. **Claude Desktop** with the **Chrome MCP** extension installed and
   active. Verify with `/mcp` in chat — you should see a Chrome-related
   server listed (`chrome-mcp`, `playwright-mcp`, or similar; any one
   that exposes `navigate`, `click`, `type`, `screenshot` tools).
2. **Cluster running** (in another terminal):
   ```sh
   # Brings up Redis + 2 WAF nodes from a clean state.
   tests/n-tester/_common.sh   # source it, then run `start_cluster`
   # — OR easier — let the shell tests bring it up; just run nt-01 once
   # and leave the cluster up by overriding the EXIT trap:
   AEGIS_KEEP_CLUSTER=1 tests/n-tester/nt-01-clu-config-plane-converge.sh
   ```
   (If `AEGIS_KEEP_CLUSTER` isn't supported, simpler: start both
   nodes manually per `deploy/CONFIG-PLANE-RUNBOOK.md`.)
3. **Chrome logged in** to `http://127.0.0.1:9443/` as
   `admin / aegis-test-1234` (accept the self-signed cert). Leave that
   tab open — every playbook references it.

## How to run one playbook

1. Open the `.md` file. Read **Given/When/Then** first to understand
   what's being verified.
2. Copy everything inside the **Paste-to-Claude** fenced block into
   Claude Desktop chat.
3. Claude operates Chrome and reports back what it saw.
4. Tick the **Pass criteria** checklist. Anything red → file under
   "Findings" in your run note.

## How to record a run

Create one file per QC session (NOT auto-generated — you write it):

```
tests/n-tester/reports/ui-2026-05-29-qc-session.md
```

Suggested skeleton:

```markdown
# UI run — 2026-05-29 — <your-name>
Cluster commit: <git rev-parse HEAD>
Browser: Chrome <version>
MCP server: <name + version>

## Results
| Playbook | Pass / Fail | Notes |
|---|---|---|
| NT-UI-01 |  ✅  |  |
| NT-UI-02 |  ✅  |  threshold input accepts decimals  |
| NT-UI-03 |  ❌  |  default label says "—" instead of 0.85, see screenshot |
| ...      |     |  |

## Findings
- NT-UI-03 — default label renders "—". Steps to reproduce: …
```

`reports/ui-*.md` is gitignored, but feel free to attach the run note
to whatever issue tracker you use.

## Playbook conventions

- Each playbook is one ~5-minute test.
- Severity is graded as **Critical / High / Medium** — failure of a
  Critical or High blocks the release; Medium is a quality-of-life
  finding QC files but doesn't block.
- Polling windows are noted ("≤ 10 s") so Claude knows when to stop
  waiting.
- When a playbook mentions a terminal sanity check ("now run `curl …`
  and compare"), QC opens a terminal alongside; Claude doesn't need to
  run shell commands — that's the human's role.

## When the dashboard is unreachable

If Claude reports "navigation failed" or "TLS handshake failed":

- The cluster is down — run `tests/n-tester/nt-01-clu-config-plane-converge.sh`
  to verify Redis + both nodes come up.
- The self-signed cert was never accepted in Chrome — manually visit
  `http://127.0.0.1:9443/`, accept the warning, then retry.
- The Chrome MCP server isn't running — `/mcp` in Claude Desktop should
  list it; if empty, restart Claude Desktop.

## Playbooks in this directory

| File | Covers | Severity |
|---|---|---|
| `nt-ui-01-scaling-page-two-nodes.md` | Scaling page shows 2 nodes + ConfigVersionCard tracks version | **High** |
| `nt-ui-02-ai-threshold-input.md`     | AI threshold input lives in the expanded AI row; Save updates live value | **Critical** |
| `nt-ui-03-default-vs-current.md`     | Input pre-filled with **live** value; label shows `default: <cfg>` | **High** |
| `nt-ui-04-validation-feedback.md`    | Invalid values (-0.5, 1.5, "abc") show a toast error and DO NOT PUT | **High** |
| `nt-ui-05-409-conflict-retry.md`     | Racing two tabs surfaces a 409 toast + auto-reloads on the loser | **Medium** |
| `nt-ui-06-feature-off-banner.md`     | When `feature_present: false`, the input is disabled with a clear hint | **Medium** |
| `nt-ui-07-keyboard-a11y.md`          | Tab order reaches the input + buttons; ARIA labels announce the field | **Medium** |
