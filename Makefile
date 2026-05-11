# Aegis-Gate — top-level operator targets.
#
# Run `make help` to see what's available. Common flow for a fresh
# clone:
#
#     make setup          # generate dev cert + release build
#     make run-dev        # first-light: dev profile (Redis auto-starts)
#     make smoke          # curl the data plane + admin health probe
#
# Profile picker (see docs/operator/profiles.md). Every run-* target
# auto-starts the dev Redis via the redis-up dep — first-light is
# one command.
#     make run-dev          → config/dev.yaml                       (dev/test)
#     make run              → config/profiles/prod-balanced.yaml    (default prod)
#     make run-strict       → config/profiles/prod-strict.yaml      (compliance)
#     make run-throughput   → config/profiles/prod-high-throughput.yaml
#
# Override defaults via env, e.g.:
#     CONFIG=config/prod.yaml make run
#     FEATURES="redis alerts geoip taxii http3" make build

# Make sure rustup's cargo is reachable when invoked from a non-login
# shell (CI, IDE run buttons, `make` from a fresh terminal). Operators
# who install Rust elsewhere can override CARGO directly.
SHELL := /bin/bash
export PATH := $(HOME)/.cargo/bin:$(PATH)
CARGO ?= cargo

# --- Tunables ---------------------------------------------------------------

# Default Cargo features for the release binary. Adjust to what your
# deployment actually needs; the dev-cert path doesn't depend on any of
# these. See config/README.md for the resolver / feature mapping.
#
# `geoip`, `alerts`, and `ai` are included by default. All three
# are no-ops when their respective config blocks are unset
# (`make geoip-link` not yet run; `alert_receivers: []`;
# `ai.enabled: false`), so non-users pay nothing at runtime —
# but the binary needs to be built with the feature so the
# config knob is honoured. Without `ai`, a config that sets
# `ai.enabled: true` (which `config/dev.yaml` does) fails boot.
# Including `alerts` matters because dispatch silently no-ops
# when the feature is missing — without it built in, an operator
# clicks "test alert receiver" and the dashboard reports success
# while nothing actually leaves the WAF. Override with
# FEATURES="redis" for slim builds.
FEATURES        ?= redis geoip alerts ai

# Default config to run against. The prod-balanced profile is the
# recommended starting point for production deployments — full detector
# mask, balanced risk thresholds, Redis state, 7-day audit retention.
# For first-light without Redis, use `make run-dev` (config/dev.yaml).
# See docs/operator/profiles.md for the full profile decision tree.
CONFIG          ?= config/profiles/prod-balanced.yaml

# Profile shortcuts — used by the run-* convenience targets below.
CONFIG_DEV        := config/dev.yaml
CONFIG_BALANCED   := config/profiles/prod-balanced.yaml
CONFIG_STRICT     := config/profiles/prod-strict.yaml
CONFIG_THROUGHPUT := config/profiles/prod-high-throughput.yaml

# Where the release binary lands.
WAF_BIN         := target/release/waf

# Self-signed cert paths (referenced by every profile under config/).
DEV_CRT         := config/certs/dev.crt
DEV_KEY         := config/certs/dev.key

# Endpoints used by `make smoke`.
SMOKE_DATA_HTTP  ?= http://localhost:8080/
SMOKE_DATA_HTTPS ?= https://localhost:8443/
SMOKE_ADMIN      ?= http://localhost:9443

# --- Phony targets ----------------------------------------------------------

.PHONY: help setup cert build build-debug run run-dev run-strict run-throughput \
        validate validate-all test test-fast clippy fmt smoke clean reset-cert \
        dashboard redis-up redis-down obs-up obs-down urls logs login-reset \
        upstream-build upstream-up upstream-down \
        mock-load mock-load-attacks mock-load-mix \
        stage bench-dev

help:
	@awk 'BEGIN { FS = ":.*##" } \
	      /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2 } \
	      /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ First-light

setup: cert build ## Generate dev cert + release build + (optional) build mock upstream
	@$(MAKE) --no-print-directory upstream-build 2>/dev/null || true
	@echo
	@echo "Setup done. Boot:"
	@echo "  make run-dev    # dev profile (Redis + mock upstream auto-start)"
	@echo "  make run        # prod-balanced (Redis auto-starts; you wire upstream)"

cert: $(DEV_CRT) ## Generate self-signed dev TLS cert (idempotent)

$(DEV_CRT) $(DEV_KEY):
	@bash config/gen-cert.sh

reset-cert: ## Delete + regenerate the dev cert
	@rm -f $(DEV_CRT) $(DEV_KEY)
	@$(MAKE) --no-print-directory cert

##@ Build

# Dashboard JSX sources — the bundler concatenates these in order.
# Order matches `crates/aegis-control/assets/dashboard/build.sh`.
DASHBOARD_DIR    := crates/aegis-control/assets/dashboard
DASHBOARD_SRCS   := \
  $(DASHBOARD_DIR)/src/widgets.jsx \
  $(DASHBOARD_DIR)/src/data.jsx \
  $(DASHBOARD_DIR)/src/pages.jsx \
  $(DASHBOARD_DIR)/src/help.jsx \
  $(DASHBOARD_DIR)/src/app.jsx
DASHBOARD_BUNDLE := $(DASHBOARD_DIR)/app.js

# 2026-05-11 — rebundle whenever any JSX source (or the bundler
# script itself) is newer than `app.js`. The bundle is embedded
# into the Rust binary via `include_bytes!`
# (`crates/aegis-control/src/dashboard/assets.rs:42`); cargo
# tracks that and rebuilds the binary automatically when the
# bundle changes, but it can't tell that the bundle itself is
# stale relative to the JSX sources — that's this rule's job.
$(DASHBOARD_BUNDLE): $(DASHBOARD_SRCS) $(DASHBOARD_DIR)/build.sh
	@bash $(DASHBOARD_DIR)/build.sh

build: $(DASHBOARD_BUNDLE) ## cargo build --release with $(FEATURES) — rebundles dashboard if JSX is newer
	@$(CARGO) build -p aegis-bin --release --features "$(FEATURES)"

stage: build ## v2.3 §8 binary contract — drop `./waf` + `./waf.yaml` in cwd (FORCE=1 to refresh, KEEP=1 to acknowledge drift)
	@ln -sf target/release/waf ./waf
	@if [ ! -e ./waf.yaml ] || [ "$$FORCE" = "1" ]; then \
	  if [ -e ./waf.yaml ] && [ "$$FORCE" = "1" ]; then \
	    cp ./waf.yaml ./waf.yaml.bak ; \
	    echo "  FORCE=1: existing ./waf.yaml backed up to ./waf.yaml.bak" ; \
	  fi ; \
	  cp config/profiles/prod-balanced.yaml ./waf.yaml ; \
	  echo "  staged: ./waf.yaml (copied from config/profiles/prod-balanced.yaml — edit before boot)" ; \
	elif [ "config/profiles/prod-balanced.yaml" -nt ./waf.yaml ] && [ "$$KEEP" != "1" ]; then \
	  echo "" ; \
	  echo "  ERROR: config/profiles/prod-balanced.yaml is newer than ./waf.yaml — drift detected." ; \
	  echo "" ; \
	  echo "  Stale waf.yaml has caused benchmark regressions" ; \
	  echo "  (Run-2 SEC-C001 / Run-3 NEW-1 / Run-4 SEC-C001). Pick one:" ; \
	  echo "" ; \
	  echo "    make stage FORCE=1      # refresh waf.yaml from prod-balanced.yaml (with .bak)" ; \
	  echo "    make stage KEEP=1       # acknowledge drift; keep your edits" ; \
	  echo "" ; \
	  echo "  To inspect the diff first:    diff ./waf.yaml config/profiles/prod-balanced.yaml" ; \
	  echo "" ; \
	  exit 1 ; \
	else \
	  if [ "$$KEEP" = "1" ] && [ "config/profiles/prod-balanced.yaml" -nt ./waf.yaml ]; then \
	    echo "  KEEP=1: drift acknowledged — booting with operator-edited waf.yaml" ; \
	    echo "  Drift summary (first 20 diff lines):" ; \
	    diff ./waf.yaml config/profiles/prod-balanced.yaml 2>/dev/null | head -20 | sed 's/^/    /' || true ; \
	    echo "" ; \
	  else \
	    echo "  ./waf.yaml already exists — left in place" ; \
	  fi ; \
	fi
	@echo "  staged: ./waf -> target/release/waf"
	@echo
	@echo "  Verify:"
	@echo "    ls -la ./waf ./waf.yaml"
	@echo "    ./waf validate --config ./waf.yaml"
	@echo "    ./waf run                     # picks up ./waf.yaml automatically"

build-debug: $(DASHBOARD_BUNDLE) ## cargo build (debug) for fast iteration — rebundles dashboard if JSX is newer
	@$(CARGO) build --workspace

# 2026-05-11 — `dashboard` is now an alias for the file-target
# rule above so the staleness check works the same way no matter
# which entry point the operator calls. Explicit re-bundling via
# `make dashboard` is still useful when you want to verify the
# bundle changed without triggering a full cargo build.
.PHONY: dashboard
dashboard: $(DASHBOARD_BUNDLE) ## Rebuild the dashboard JSX bundle if any src/*.jsx is newer

# Force a fresh rebundle even when nothing changed — useful for
# CI sanity checks and after toolchain bumps (esbuild version,
# Node version) where the bundle output might shift without any
# source-mtime change.
.PHONY: dashboard-force
dashboard-force: ## Force a fresh dashboard rebundle even if app.js is up-to-date
	@bash $(DASHBOARD_DIR)/build.sh

##@ Run

run: $(WAF_BIN) cert redis-up ## Boot against $(CONFIG) — default: prod-balanced
	@$(WAF_BIN) run --config $(CONFIG)

run-dev: $(WAF_BIN) cert redis-up upstream-up ## Boot dev profile (auto-starts Redis + mock upstream)
	@AEGIS_INSECURE_COOKIES=1 $(WAF_BIN) run --config $(CONFIG_DEV)

bench-dev: build cert redis-up upstream-up ## Boot dev with v2.3 benchmark binary contract (FORCE=1 to refresh waf.yaml, KEEP=1 to acknowledge drift)
	@# 1. Stage `./waf` + `./waf.yaml` per v2.3 §8 binary contract.
	@#    Uses dev.yaml content so the existing dev profile (loose
	@#    rate-limit + strikes disabled for shared loopback) is what
	@#    the OC harness sees — easier to drive 5k+ RPS through.
	@#
	@# Run-3 NEW-1 → Run-4 SEC-C001 (2026-05-08) — when ./waf.yaml
	@# exists and dev.yaml is newer, ABORT with a clear FORCE/KEEP
	@# choice. Earlier iterations only printed a WARNING; operators
	@# (and the QA judging panel) booted stale ./waf.yaml repeatedly,
	@# causing AI FP regressions across QA runs. Hard-abort makes
	@# the choice explicit.
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
	  echo "  Stale waf.yaml has caused benchmark regressions" ; \
	  echo "  (Run-2 SEC-C001 / Run-3 NEW-1 / Run-4 SEC-C001). Pick one:" ; \
	  echo "" ; \
	  echo "    make bench-dev FORCE=1      # refresh waf.yaml from $(CONFIG_DEV) (with .bak)" ; \
	  echo "    make bench-dev KEEP=1       # acknowledge drift; keep your edits" ; \
	  echo "" ; \
	  echo "  To inspect the diff first:    diff ./waf.yaml $(CONFIG_DEV)" ; \
	  echo "" ; \
	  exit 1 ; \
	else \
	  if [ "$$KEEP" = "1" ] && [ "$(CONFIG_DEV)" -nt ./waf.yaml ]; then \
	    echo "  KEEP=1: drift acknowledged — booting with operator-edited waf.yaml" ; \
	    echo "  Drift summary (first 20 diff lines):" ; \
	    diff ./waf.yaml $(CONFIG_DEV) 2>/dev/null | head -20 | sed 's/^/    /' || true ; \
	    echo "" ; \
	  else \
	    echo "  ./waf.yaml already exists — left in place" ; \
	  fi ; \
	fi
	@echo "  staged: ./waf -> target/release/waf"
	@echo
	@echo "v2.3 contract surface (data port + admin port both serve /__waf_control/*):"
	@echo "  GET    /__waf_control/capabilities"
	@echo "  GET    /__waf_control/healthz"
	@echo "  POST   /__waf_control/reset_state"
	@echo "  POST   /__waf_control/set_profile"
	@echo "  POST   /__waf_control/flush_cache"
	@echo "  POST   /__waf_control/challenge_verify"
	@echo "  Header: X-Benchmark-Secret: $${AEGIS_BENCHMARK_SECRET:-waf-hackathon-2026-ctrl}"
	@echo "  Audit:  ./waf_audit.log (created on first request)"
	@echo
	@if [ -z "$$AEGIS_BENCHMARK_SECRET" ]; then \
	  echo "  AEGIS_BENCHMARK_SECRET unset — falling back to contract default 'waf-hackathon-2026-ctrl'." ; \
	  echo "  For a real benchmark run, generate a fresh secret first:" ; \
	  echo "    export AEGIS_BENCHMARK_SECRET=\$$(openssl rand -base64 32 | tr -d '=+/' | head -c 40)" ; \
	  echo ; \
	fi
	@AEGIS_INSECURE_COOKIES=1 \
	  AEGIS_BENCHMARK_SECRET=$${AEGIS_BENCHMARK_SECRET:-waf-hackathon-2026-ctrl} \
	  ./waf run --config ./waf.yaml

run-strict: $(WAF_BIN) cert redis-up ## Boot against prod-strict profile — compliance-tightened
	@$(WAF_BIN) run --config $(CONFIG_STRICT)

run-throughput: $(WAF_BIN) cert redis-up ## Boot against prod-high-throughput profile — CDN front-door tuning
	@$(WAF_BIN) run --config $(CONFIG_THROUGHPUT)

validate: $(WAF_BIN) ## Validate $(CONFIG) without booting
	@$(WAF_BIN) validate --config $(CONFIG)

validate-all: $(WAF_BIN) ## Validate dev + all three production profiles
	@for cfg in $(CONFIG_DEV) $(CONFIG_BALANCED) $(CONFIG_STRICT) $(CONFIG_THROUGHPUT); do \
	    printf "validate %-44s " "$$cfg"; \
	    $(WAF_BIN) validate --config $$cfg >/dev/null 2>&1 && echo OK || { echo FAIL; $(WAF_BIN) validate --config $$cfg; exit 1; }; \
	done

redis-up: ## Start the local dev Redis (idempotent — auto-invoked by all run-* targets)
	@if docker ps --filter "name=^aegis-redis$$" --format '{{.Status}}' | grep -q "^Up"; then \
	    : ;\
	elif docker ps -a --filter "name=^aegis-redis$$" --format '{{.Names}}' | grep -q .; then \
	    docker start aegis-redis >/dev/null; \
	else \
	    docker compose -f deploy/docker-compose.dev.yml up -d redis; \
	fi

redis-down: ## Stop the local dev Redis
	@docker stop aegis-redis 2>/dev/null || true

# Mock upstream — Go-based, handles 50k+ RPS, used by run-dev so the
# data plane has something to forward to. Production profiles wire
# their own upstreams via config; this target is dev-only.
UPSTREAM_BIN_DEV := /tmp/aegis-fast-upstream

upstream-build: ## Build the bundled Go mock upstream (one-time, ~5s)
	@command -v go >/dev/null || { echo "FAIL: go not installed; brew install go (or skip — run-dev still boots, smoke test will 502 on data-plane)"; exit 1; }
	@go build -o $(UPSTREAM_BIN_DEV) tests/hackathon/upstream/fast-upstream.go
	@echo "built $(UPSTREAM_BIN_DEV)"

upstream-up: ## Start the dev mock upstream on :9999 (idempotent — auto-invoked by run-dev)
	@if lsof -nP -iTCP:9999 -sTCP:LISTEN >/dev/null 2>&1; then \
	    : ;\
	elif [ -x "$(UPSTREAM_BIN_DEV)" ]; then \
	    nohup $(UPSTREAM_BIN_DEV) >/tmp/aegis-fast-upstream.log 2>&1 & \
	    sleep 0.3; \
	    echo "upstream up (logs: /tmp/aegis-fast-upstream.log)"; \
	else \
	    echo "Note: $(UPSTREAM_BIN_DEV) not built. Run 'make upstream-build' first to enable a mock upstream — without it, the data-plane smoke check will return 502 (which is also valid: the WAF is healthy, the upstream is just absent)."; \
	fi

upstream-down: ## Stop the dev mock upstream
	@pkill -f $(UPSTREAM_BIN_DEV) 2>/dev/null || true
	@echo "upstream stopped"

##@ Demo / observability traffic
# Generate live traffic against the local WAF so the dashboard +
# Grafana have something to display. All three targets assume
# `make run-dev` is already running in another terminal.

# Default duration; override with DURATION=2m make mock-load-mix
DURATION ?= 60s

mock-load: ## Generate legit + crawler + attacker mix at modest rate (~50 RPS, $(DURATION))
	@command -v k6 >/dev/null || { echo "FAIL: k6 not installed; brew install k6"; exit 1; }
	@echo "==> driving WAF on $(SMOKE_DATA_HTTP) for $(DURATION)"
	@WAF_TARGET=$(SMOKE_DATA_HTTP) \
	    DURATION=$(DURATION) \
	    LEGIT_RPS=40 CRAWLER_RPS=5 ATTACKER_RPS=8 \
	    k6 run --no-summary tests/hackathon/k6/prod-balanced-5k-v2.js \
	    || true
	@echo
	@echo "==> dashboard now has data: http://localhost:9443/  (Tracking → Live Activity)"
	@echo "==> Grafana (if 'make obs-up' was run): http://localhost:3000/"

mock-load-attacks: ## Attack-only flood — drives detector hits + audit chain ($(DURATION))
	@command -v k6 >/dev/null || { echo "FAIL: k6 not installed; brew install k6"; exit 1; }
	@echo "==> attack-only flood on $(SMOKE_DATA_HTTP) for $(DURATION)"
	@WAF_TARGET=$(SMOKE_DATA_HTTP) \
	    DURATION=$(DURATION) \
	    LEGIT_RPS=0 CRAWLER_RPS=0 ATTACKER_RPS=30 \
	    k6 run --no-summary tests/hackathon/k6/prod-balanced-5k-v2.js \
	    || true
	@echo
	@echo "==> dashboard: http://localhost:9443/  (Attacks Distribution / Audit Trail)"

mock-load-mix: ## High-volume mix (~5 k RPS) — see how the dashboard looks under stress
	@command -v k6 >/dev/null || { echo "FAIL: k6 not installed; brew install k6"; exit 1; }
	@echo "==> high-volume mix on $(SMOKE_DATA_HTTP) for $(DURATION) (~5k RPS)"
	@WAF_TARGET=$(SMOKE_DATA_HTTP) \
	    DURATION=$(DURATION) \
	    LEGIT_RPS=4000 CRAWLER_RPS=300 ATTACKER_RPS=1000 \
	    k6 run --no-summary tests/hackathon/k6/prod-balanced-5k-v2.js \
	    || true
	@echo
	@echo "==> dashboard: http://localhost:9443/"

obs-up: redis-up ## Start the full observability stack (Redis + Prometheus + Grafana + Jaeger)
	@docker compose -f deploy/docker-compose.dev.yml up -d prometheus grafana jaeger 2>&1 | grep -v "Network\|orphan" || true
	@echo
	@$(MAKE) --no-print-directory urls

obs-down: ## Stop the observability stack (keeps Redis)
	@docker compose -f deploy/docker-compose.dev.yml stop prometheus grafana jaeger 2>/dev/null || true

urls: ## Print where to find every UI / endpoint / log file
	@echo "== Aegis-Gate URLs =="
	@echo "  Data plane (HTTP)        http://localhost:8080/"
	@echo "  Data plane (HTTPS)       https://localhost:8443/   (-k for self-signed cert)"
	@echo "  Admin / dashboard        http://localhost:9443/"
	@echo "  Admin healthz            http://localhost:9443/healthz/ready"
	@echo "  Admin Prometheus scrape  http://localhost:9443/metrics"
	@echo "  Runtime sizing           http://localhost:9443/api/runtime"
	@echo
	@echo "== Observability stack (after 'make obs-up') =="
	@echo "  Prometheus UI            http://localhost:9090/"
	@echo "  Grafana UI               http://localhost:3000/    (admin/admin on first login)"
	@echo "    └─ pre-loaded boards   Aegis WAF Overview · Runtime · Redis"
	@echo "  Jaeger UI (traces)       http://localhost:16686/"
	@echo "  redis-exporter           http://localhost:9121/metrics"
	@echo
	@echo "== Logs / state =="
	@echo "  WAF stdout (foreground)  the terminal where 'make run' is running"
	@echo "  Audit chain (jsonl)      /tmp/aegis-dev-audit.jsonl"
	@echo "  Interop audit            ./waf_audit.log"
	@echo "  Redis container logs     docker logs -f aegis-redis"
	@echo "  Prometheus logs          docker logs -f aegis-prometheus"
	@echo "  Grafana logs             docker logs -f aegis-grafana"

logs: ## Tail the WAF audit chain + redis container logs
	@echo "(Ctrl-C to stop)"; \
	tail -F /tmp/aegis-dev-audit.jsonl ./waf_audit.log 2>/dev/null &
	@docker logs -f aegis-redis 2>&1 | sed 's/^/[redis] /'

$(WAF_BIN):
	@$(MAKE) --no-print-directory build

##@ Test

test: ## cargo test --workspace
	@$(CARGO) test --workspace

test-fast: ## cargo test for changed crates only (skips clippy)
	@$(CARGO) test --workspace --no-fail-fast

clippy: ## cargo clippy --workspace -- -D warnings
	@$(CARGO) clippy --workspace -- -D warnings

fmt: ## cargo fmt --all
	@$(CARGO) fmt --all

login-reset: ## Force-clear stale browser session — call /admin/logout + print clear-cookie advice
	@echo "==> calling /admin/logout"
	@curl -sS -X POST $(SMOKE_ADMIN)/admin/logout -o /dev/null -w "  status=%{http_code}\n" || true
	@echo
	@echo "If the dashboard still says 'missing aegis_csrf cookie', clear browser"
	@echo "cookies for $(SMOKE_ADMIN):"
	@echo "  Chrome:   DevTools → Application → Cookies → 127.0.0.1:9443 → trash"
	@echo "  Firefox:  Settings → Privacy → Manage Data → 127.0.0.1 → Remove"
	@echo "  Safari:   Develop → Empty Caches; Storage → 127.0.0.1 → Delete"
	@echo
	@echo "Then refresh the dashboard and log in again. The new session will"
	@echo "issue cookies without the Secure flag (since AEGIS_INSECURE_COOKIES=1"
	@echo "is set by 'make run-dev'), and the browser will accept them on HTTP."

smoke: ## curl the data plane + admin health (assumes `make run-dev` is up)
	@printf "HTTPS  %-32s " "$(SMOKE_DATA_HTTPS)"
	@code=$$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 $(SMOKE_DATA_HTTPS) 2>/dev/null); \
	    if [ "$$code" = "200" ]; then echo "$$code  ✓"; \
	    elif [ "$$code" = "502" ]; then echo "$$code  (no upstream wired — run 'make upstream-up' or boot 'make run-dev')"; \
	    elif [ "$$code" = "000" ] || [ -z "$$code" ]; then echo "DOWN  (TLS listener not bound — dev.yaml + cert needed; run 'make cert')"; \
	    else echo "$$code"; fi
	@printf "HTTP   %-32s " "$(SMOKE_DATA_HTTP)"
	@code=$$(curl -s  -o /dev/null -w "%{http_code}" --max-time 3 $(SMOKE_DATA_HTTP) 2>/dev/null); \
	    if [ "$$code" = "200" ]; then echo "$$code  ✓"; \
	    elif [ "$$code" = "502" ]; then echo "$$code  (no upstream wired — run 'make upstream-up' or boot 'make run-dev')"; \
	    elif [ "$$code" = "000" ] || [ -z "$$code" ]; then echo "DOWN  (WAF not running — start with 'make run-dev')"; \
	    else echo "$$code"; fi
	@printf "Admin  %-32s " "$(SMOKE_ADMIN)/healthz/ready"
	@code=$$(curl -s  -o /dev/null -w "%{http_code}" --max-time 3 $(SMOKE_ADMIN)/healthz/ready 2>/dev/null); \
	    if [ "$$code" = "200" ]; then echo "$$code  ✓"; \
	    else echo "$${code:-DOWN}"; fi

openapi-test: ## OpenAPI shape contract test (assumes `make run` is up)
	@AEGIS_ADMIN=$(SMOKE_ADMIN) bash tests/api/openapi-shape.sh

openapi-lint: ## Lint docs/control-plane/api.openapi.yaml via redocly
	@npx --yes -p '@redocly/cli@latest' redocly lint docs/control-plane/api.openapi.yaml

protocols-test: ## Multi-protocol smoke — h1/h2/h3/WS/gRPC (assumes `make run` is up)
	@bash tests/protocols/run-all.sh

ci-local: ## Run the same lint + test + smoke suite GitHub Actions runs
	@$(CARGO) fmt --all -- --check
	@$(CARGO) clippy --workspace -- -D warnings
	@$(CARGO) test --workspace
	@bash tests/api/openapi-shape.sh   # requires `make run` already up
	@bash tests/protocols/run-all.sh   # requires `make run` already up

helm-lint: ## helm lint + kube-linter on deploy/helm/aegis-gate
	@helm lint deploy/helm/aegis-gate
	@docker run --rm -v "$(PWD)/deploy/helm/aegis-gate:/chart" \
	    stackrox/kube-linter:latest lint /chart

helm-render: ## Render the chart with placeholder values (no install)
	@helm template aegis deploy/helm/aegis-gate \
	    --set admin.password.hash='$$argon2id$$placeholder' \
	    --set admin.csrf.secret='deadbeef'

##@ GeoIP databases

# Override either side via env, e.g.:
#   make geoip-link COUNTRY_DB=/path/to/Country.mmdb ASN_DB=/path/to/ASN.mmdb
COUNTRY_DB ?=
ASN_DB     ?=
GEOIP_DIR  := data/geoip

# Auto-discover the most-recent MaxMind extract in ~/Downloads when
# COUNTRY_DB / ASN_DB aren't passed explicitly. The default zip layout
# is `GeoLite2-{Country,ASN}_<YYYYMMDD>/GeoLite2-*.mmdb`.
geoip-link: ## Symlink MaxMind .mmdb files into data/geoip/ (override with COUNTRY_DB=, ASN_DB=)
	@mkdir -p $(GEOIP_DIR)
	@if [ -n "$(COUNTRY_DB)" ]; then \
	    src="$(COUNTRY_DB)"; \
	else \
	    src=$$(ls -t $$HOME/Downloads/GeoLite2-Country_*/GeoLite2-Country.mmdb 2>/dev/null | head -1); \
	fi; \
	if [ -z "$$src" ] || [ ! -f "$$src" ]; then \
	    echo "geoip-link: no Country DB found"; \
	    echo "  Pass COUNTRY_DB=/path/to/GeoLite2-Country.mmdb"; \
	    echo "  or drop the MaxMind extract into ~/Downloads/GeoLite2-Country_<date>/"; \
	    exit 1; \
	fi; \
	ln -sfn "$$src" $(GEOIP_DIR)/GeoLite2-Country.mmdb; \
	echo "geoip-link: Country -> $$src"
	@if [ -n "$(ASN_DB)" ]; then \
	    src="$(ASN_DB)"; \
	else \
	    src=$$(ls -t $$HOME/Downloads/GeoLite2-ASN_*/GeoLite2-ASN.mmdb 2>/dev/null | head -1); \
	fi; \
	if [ -z "$$src" ] || [ ! -f "$$src" ]; then \
	    echo "geoip-link: no ASN DB found (optional — skipping)"; \
	else \
	    ln -sfn "$$src" $(GEOIP_DIR)/GeoLite2-ASN.mmdb; \
	    echo "geoip-link: ASN     -> $$src"; \
	fi
	@ls -la $(GEOIP_DIR)/*.mmdb 2>/dev/null || true

geoip-status: ## Show current GeoIP DB symlinks + their resolved targets
	@echo "GeoIP DB layout:"
	@for f in $(GEOIP_DIR)/GeoLite2-Country.mmdb $(GEOIP_DIR)/GeoLite2-ASN.mmdb; do \
	    if [ -e "$$f" ]; then \
	        target=$$(readlink "$$f" || echo "(plain file)"); \
	        size=$$(ls -la "$$f" | awk '{print $$5}'); \
	        echo "  $$f -> $$target ($$size bytes)"; \
	    else \
	        echo "  $$f -> MISSING"; \
	    fi; \
	done

geoip-unlink: ## Remove the data/geoip/ symlinks (does NOT touch the source files)
	@rm -f $(GEOIP_DIR)/*.mmdb
	@echo "geoip-unlink: cleared $(GEOIP_DIR)/*.mmdb"

##@ AI detector

# Override the model path:  make ai-link MODEL=/abs/path/to/waf_model.onnx
# Defaults to data/ai_model/waf_model.onnx (already-present dev model).
MODEL    ?=
AI_DIR   := data/ai_model

ai-link: ## Symlink an .onnx model into data/ai_model/waf_model.onnx (override with MODEL=)
	@mkdir -p $(AI_DIR)
	@if [ -n "$(MODEL)" ]; then \
	    src="$(MODEL)"; \
	else \
	    src=$$(ls -t $$HOME/Downloads/waf_model*.onnx 2>/dev/null | head -1); \
	fi; \
	if [ -z "$$src" ] || [ ! -f "$$src" ]; then \
	    echo "ai-link: no .onnx found"; \
	    echo "  Pass MODEL=/abs/path/to/waf_model.onnx"; \
	    echo "  or drop your model at ~/Downloads/waf_model*.onnx"; \
	    exit 1; \
	fi; \
	dst_abs=$$(cd "$(AI_DIR)" 2>/dev/null && pwd)/waf_model.onnx; \
	src_abs=$$(cd "$$(dirname "$$src")" 2>/dev/null && pwd)/$$(basename "$$src"); \
	if [ "$$src_abs" = "$$dst_abs" ]; then \
	    echo "ai-link: source and destination resolve to the same path"; \
	    echo "  $$src_abs"; \
	    echo "  Already in place — no symlink needed."; \
	    exit 0; \
	fi; \
	ln -sfn "$$src" $(AI_DIR)/waf_model.onnx; \
	echo "ai-link: $(AI_DIR)/waf_model.onnx -> $$src"
	@ls -la $(AI_DIR)/waf_model.onnx 2>/dev/null || true

ai-status: ## Show the current AI model symlink + size
	@echo "AI model layout:"
	@if [ -e "$(AI_DIR)/waf_model.onnx" ]; then \
	    target=$$(readlink "$(AI_DIR)/waf_model.onnx" || echo "(plain file)"); \
	    size=$$(stat -f '%z' "$(AI_DIR)/waf_model.onnx" 2>/dev/null || stat -c '%s' "$(AI_DIR)/waf_model.onnx" 2>/dev/null); \
	    echo "  $(AI_DIR)/waf_model.onnx -> $$target ($$size bytes)"; \
	else \
	    echo "  $(AI_DIR)/waf_model.onnx -> MISSING (run make ai-link)"; \
	fi
	@if [ -e "$(AI_DIR)/label_map.json" ]; then \
	    echo "  $(AI_DIR)/label_map.json -> present"; \
	fi

ai-unlink: ## Remove the AI model symlink (does NOT touch the source file)
	@rm -f $(AI_DIR)/waf_model.onnx
	@echo "ai-unlink: cleared $(AI_DIR)/waf_model.onnx"

##@ Multi-tester sweeps

sweep-validate: ## Validate one tester's findings.jsonl — usage: make sweep-validate TESTER=path/to/folder-or-jsonl
	@if [ -z "$(TESTER)" ]; then \
	    echo "usage: make sweep-validate TESTER=tests/sweeps/<sweep-id>/tester-<id>"; \
	    exit 2; \
	fi
	@./tests/sweeps/consolidate.sh --validate "$(TESTER)"

sweep-consolidate: ## Run consolidate pass for a sweep — usage: make sweep-consolidate SWEEP=run-sweep-NN-...
	@if [ -z "$(SWEEP)" ]; then \
	    echo "usage: make sweep-consolidate SWEEP=run-sweep-NN-YYYY-MM-DD-<theme>"; \
	    exit 2; \
	fi
	@./tests/sweeps/consolidate.sh "$(SWEEP)"

##@ Cleanup

clean: ## cargo clean (does NOT delete dev certs)
	@$(CARGO) clean
