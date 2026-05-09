# Phase 1 — HIGH (Run-3)

> **Branch:** all changes target `develop`.

---

## RUN3-NEW-1 · `make bench-dev` doesn't refresh `waf.yaml` from `config/dev.yaml`

**Source:** Run-3 §NEW-1.

### Verified state (2026-05-08, on `develop`)

`Makefile:140-151`:

```makefile
bench-dev: build cert redis-up upstream-up ## Boot dev with the v2.3 benchmark binary contract surfaced
	...
	@if [ ! -e ./waf.yaml ]; then \
	  cp $(CONFIG_DEV) ./waf.yaml ; \
	  echo "  staged: ./waf.yaml (copied from $(CONFIG_DEV))" ; \
	else \
	  echo "  ./waf.yaml already exists — left in place" ; \
	fi
```

The guard is intentional — it preserves operator-edited tunings between bench runs. But after a config-side fix lands in `config/dev.yaml`, the local `waf.yaml` (left over from a prior run) keeps the old values. In Run-3's case: `dev.yaml` had `ai.enabled: false` per Run-2's C002 follow-up, but `waf.yaml` still had `ai.enabled: true` + `confidence_threshold: 0.85` — the exact configuration that caused ~77 % FP rate.

This is a recurring footgun: every config-touching fix landed via `dev.yaml` is invisible to anyone running `make bench-dev` until they manually delete `waf.yaml`.

### Plan

Three approaches per the QA recommendation; ship A + B together for safety.

**Step 1 — add a `FORCE=1` opt-in flag** (Option A from the QA report).

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
	else \
	  ...drift check, see Step 2... \
	fi
```

**Step 2 — drift-check warning when `dev.yaml` is newer than `waf.yaml`.**

The natural signal: `config/dev.yaml`'s mtime is more recent than `./waf.yaml`'s. Fast (one stat per file), no parsing.

```makefile
	else \
	  if [ "$(CONFIG_DEV)" -nt ./waf.yaml ]; then \
	    echo "" ; \
	    echo "  WARNING: $(CONFIG_DEV) is newer than ./waf.yaml" ; \
	    echo "  Local waf.yaml may be missing recent fixes." ; \
	    echo "  To refresh:  make bench-dev FORCE=1" ; \
	    echo "  To inspect:  diff ./waf.yaml $(CONFIG_DEV)" ; \
	    echo "" ; \
	  else \
	    echo "  ./waf.yaml already exists — left in place" ; \
	  fi ; \
	fi
```

**Step 3 — same treatment for the `stage:` target** at `Makefile:111`. Same guard, same drift check (against `config/profiles/prod-balanced.yaml` instead of `config/dev.yaml`).

**Step 4 — document in `docs/operator/` or `deploy/STAGING-BENCHMARK.md`.** One-paragraph note explaining the `FORCE=1` flag and when to use it. Link from the bench-dev help output line.

**Step 5 — manual verification.**

```sh
# Fresh checkout — no waf.yaml
make bench-dev          # → "staged: ./waf.yaml (copied from config/dev.yaml)"

# Edit config/dev.yaml (touch the mtime)
touch config/dev.yaml
make bench-dev          # → WARNING: config/dev.yaml is newer than ./waf.yaml
                        #             To refresh: make bench-dev FORCE=1

# Force refresh
make bench-dev FORCE=1  # → FORCE=1: existing ./waf.yaml backed up to ./waf.yaml.bak
                        #   staged: ./waf.yaml (copied from config/dev.yaml)
```

### Acceptance

- [ ] `make bench-dev` without `FORCE` preserves operator's local edits (existing behavior)
- [ ] `make bench-dev FORCE=1` overwrites `waf.yaml` from `dev.yaml` after backing up to `.bak`
- [ ] When `config/dev.yaml` is newer than `waf.yaml`, the bench-dev banner prints the drift warning
- [ ] Same treatment applied to `stage:` target (production profile)
- [ ] `.bak` file is informational; doesn't change the boot path

**Effort:** ~30 min. Pure Makefile edit + 4-line doc note.

---

## Sequencing

Single PR: `fix(makefile): bench-dev waf.yaml drift warning + FORCE=1 (RUN3-NEW-1)`.

Test plan:
- [ ] `make bench-dev` on fresh checkout → copies dev.yaml
- [ ] `make bench-dev` on existing waf.yaml → leaves in place; no warning when timestamps match
- [ ] `touch config/dev.yaml && make bench-dev` → drift warning fires
- [ ] `make bench-dev FORCE=1` → backs up + overwrites
- [ ] CI doesn't break (existing CI runs use `make bench-dev` from a fresh checkout, so the guard stays harmless)
