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
# `geoip` and `alerts` are included by default. Both are no-ops
# when their respective config blocks are unset (`make geoip-link`
# not yet run; `alert_receivers: []`), so non-users pay nothing.
# Including `alerts` matters because dispatch silently no-ops
# when the feature is missing — without it built in, an operator
# clicks "test alert receiver" and the dashboard reports success
# while nothing actually leaves the WAF. Override with
# FEATURES="redis" for slim builds.
FEATURES        ?= redis geoip alerts

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
        mock-load mock-load-attacks mock-load-mix

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

build: ## cargo build --release with $(FEATURES)
	@$(CARGO) build -p aegis-bin --release --features "$(FEATURES)"

build-debug: ## cargo build (debug) for fast iteration
	@$(CARGO) build --workspace

dashboard: ## Rebuild the dashboard JSX bundle (run after editing src/*.jsx)
	@bash crates/aegis-control/assets/dashboard/build.sh

##@ Run

run: $(WAF_BIN) cert redis-up ## Boot against $(CONFIG) — default: prod-balanced
	@$(WAF_BIN) run --config $(CONFIG)

run-dev: $(WAF_BIN) cert redis-up upstream-up ## Boot dev profile (auto-starts Redis + mock upstream)
	@AEGIS_INSECURE_COOKIES=1 $(WAF_BIN) run --config $(CONFIG_DEV)

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
