# Phase 1 — HIGH (Run-4)

> **Branch:** all changes target `develop`.

---

## SEC-C001 (re-frame) · Hard-abort `make bench-dev` on `waf.yaml` drift

**Source:** Run-4 §SEC-C001 — same root cause as RUN3-NEW-1, observed again because Run-3's drift WARNING wasn't enforced.

### Verified state (2026-05-08, on `develop`)

After RUN3-NEW-1 shipped, `Makefile:bench-dev` does:

- Copy `config/dev.yaml → ./waf.yaml` when no local `waf.yaml`.
- `FORCE=1`: backup + overwrite.
- Else: print a drift WARNING when `dev.yaml` is newer than `waf.yaml`.

Run-4 confirms the warning isn't strong enough — the QA judging panel ran `./waf run --config waf.yaml` against a stale local file with `ai.enabled: true`, blocked 50 % of clean traffic, and tagged it CRITICAL. The fix in `dev.yaml` (Run-2 C002 follow-up) was never reflected in the bench artifact.

### Plan

Turn the drift detection into a hard ABORT. Operator chooses `FORCE=1` (refresh, with `.bak`) or `KEEP=1` (explicitly keep stale, accept consequences). No silent middle ground.

**Step 1 — replace WARNING with ABORT in `bench-dev` and `stage` targets.**

```makefile
bench-dev: build cert redis-up upstream-up
	@ln -sf target/release/waf ./waf
	@if [ ! -e ./waf.yaml ] || [ "$$FORCE" = "1" ]; then \
	  if [ -e ./waf.yaml ] && [ "$$FORCE" = "1" ]; then \
	    cp ./waf.yaml ./waf.yaml.bak ; \
	    echo "  FORCE=1: existing ./waf.yaml backed up to ./waf.yaml.bak" ; \
	  fi ; \
	  cp $(CONFIG_DEV) ./waf.yaml ; \
	  echo "  staged: ./waf.yaml (copied from $(CONFIG_DEV))" ; \
	elif [ "$(CONFIG_DEV)" -nt ./waf.yaml ] && [ "$$KEEP" != "1" ]; then \
	  echo "" ; \
	  echo "  ERROR: $(CONFIG_DEV) is newer than ./waf.yaml — drift detected." ; \
	  echo "" ; \
	  echo "  This used to be a silent warning, but stale waf.yaml has caused" ; \
	  echo "  benchmark regressions (Run-2 SEC-C001 / Run-3 NEW-1). Choose:" ; \
	  echo "" ; \
	  echo "    make bench-dev FORCE=1      # refresh waf.yaml from dev.yaml (with .bak)" ; \
	  echo "    make bench-dev KEEP=1       # acknowledge drift; keep your edits" ; \
	  echo "" ; \
	  echo "  To inspect the diff first:    diff ./waf.yaml $(CONFIG_DEV)" ; \
	  echo "" ; \
	  exit 1 ; \
	else \
	  if [ "$$KEEP" = "1" ] && [ "$(CONFIG_DEV)" -nt ./waf.yaml ]; then \
	    echo "  KEEP=1: drift acknowledged — booting with operator-edited waf.yaml" ; \
	  else \
	    echo "  ./waf.yaml already exists — left in place" ; \
	  fi ; \
	fi
	@echo "  staged: ./waf -> target/release/waf"
	...
```

**Step 2 — same treatment for `stage:` target** (compares to `config/profiles/prod-balanced.yaml`).

**Step 3 — when KEEP=1 + drift detected, also print the actual diff** (first 20 lines) so the operator sees exactly what they're keeping out:

```makefile
echo "  KEEP=1 acknowledged. Drift summary (first 20 lines of diff):" ; \
diff ./waf.yaml $(CONFIG_DEV) | head -20 | sed 's/^/    /' ; \
echo "" ;
```

**Step 4 — manual verification.**

```sh
# Fresh checkout — no waf.yaml
make bench-dev               # → "staged: ./waf.yaml (copied from config/dev.yaml)"

# Touch dev.yaml to create drift
touch config/dev.yaml
make bench-dev               # → ERROR + clear FORCE/KEEP recipe + exit 1

make bench-dev FORCE=1       # → backup + refresh
make bench-dev KEEP=1        # → acknowledge + boot with stale + show diff summary
```

**Step 5 — update the operator-facing doc.**

`deploy/STAGING-BENCHMARK.md` adds a "v2.3 submission workflow" section:

```
Before submitting to the judging panel:

1. Pull the latest develop branch.
2. Run: make bench-dev FORCE=1        # always refresh waf.yaml
3. Verify with curl probes per §<existing section>.
4. Tarball ./waf + ./waf.yaml + benchmark/ for submission.

Never ship a hand-edited waf.yaml unless every drift line is intentional.
The bench-dev target enforces this by aborting on drift; FORCE=1 syncs
from config/dev.yaml, KEEP=1 explicitly keeps your edits.
```

### Acceptance

- [ ] `make bench-dev` on fresh checkout still copies `dev.yaml` (no behavior change for the green path)
- [ ] `make bench-dev` with stale `waf.yaml` (drift detected) aborts with exit 1 + clear recipe
- [ ] `make bench-dev FORCE=1` overwrites + creates `.bak`
- [ ] `make bench-dev KEEP=1` boots with stale + prints diff summary
- [ ] Same treatment applied to `stage:` target
- [ ] `STAGING-BENCHMARK.md` documents the workflow
- [ ] Existing CI workflows pass (CI uses fresh checkouts → no drift → no abort)

**Effort:** ~30 min. Pure Makefile + doc edit.

---

## Sequencing

Single PR: `fix(makefile): hard-abort bench-dev on waf.yaml drift (SEC-C001 / RUN3-NEW-1 strengthening)`.
