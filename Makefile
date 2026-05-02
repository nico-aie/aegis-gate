# Aegis-Gate — top-level operator targets.
#
# Run `make help` to see what's available. Common flow for a fresh
# clone:
#
#     make setup          # generate dev cert + release build
#     make run-dev        # first-light: in-memory, no Redis required
#     make run            # production default: prod-balanced profile
#                         #   (requires Redis — `make redis-up` first)
#     make smoke          # curl the data plane + admin health probe
#
# Profile picker (see docs/operator/profiles.md):
#     make run-dev          → config/dev.yaml                       (in-memory)
#     make run              → config/profiles/prod-balanced.yaml    (default)
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
FEATURES        ?= redis

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
        dashboard redis-up redis-down

help:
	@awk 'BEGIN { FS = ":.*##" } \
	      /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2 } \
	      /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ First-light

setup: cert build ## Generate dev cert + release build (one-shot fresh clone)
	@echo
	@echo "Setup done. First-light (no Redis):"
	@echo "  make run-dev"
	@echo
	@echo "Production default (prod-balanced — needs Redis):"
	@echo "  make redis-up && make run"

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

run: $(WAF_BIN) cert ## Boot against $(CONFIG) — default: prod-balanced (Redis required)
	@$(WAF_BIN) run --config $(CONFIG)

run-dev: $(WAF_BIN) cert ## Boot against config/dev.yaml — in-memory, no Redis
	@$(WAF_BIN) run --config $(CONFIG_DEV)

run-strict: $(WAF_BIN) cert ## Boot against prod-strict profile — compliance-tightened
	@$(WAF_BIN) run --config $(CONFIG_STRICT)

run-throughput: $(WAF_BIN) cert ## Boot against prod-high-throughput profile — CDN front-door tuning
	@$(WAF_BIN) run --config $(CONFIG_THROUGHPUT)

validate: $(WAF_BIN) ## Validate $(CONFIG) without booting
	@$(WAF_BIN) validate --config $(CONFIG)

validate-all: $(WAF_BIN) ## Validate dev + all three production profiles
	@for cfg in $(CONFIG_DEV) $(CONFIG_BALANCED) $(CONFIG_STRICT) $(CONFIG_THROUGHPUT); do \
	    printf "validate %-44s " "$$cfg"; \
	    $(WAF_BIN) validate --config $$cfg >/dev/null 2>&1 && echo OK || { echo FAIL; $(WAF_BIN) validate --config $$cfg; exit 1; }; \
	done

redis-up: ## Start the local dev Redis (required by prod-balanced/strict/throughput)
	@docker compose -f deploy/docker-compose.dev.yml up -d redis

redis-down: ## Stop the local dev Redis
	@docker compose -f deploy/docker-compose.dev.yml stop redis

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

smoke: ## curl the data plane + admin health (assumes `make run` is up)
	@printf "HTTPS  %-32s " "$(SMOKE_DATA_HTTPS)"
	@curl -sk -o /dev/null -w "%{http_code}\n" $(SMOKE_DATA_HTTPS) || echo "DOWN"
	@printf "HTTP   %-32s " "$(SMOKE_DATA_HTTP)"
	@curl -s  -o /dev/null -w "%{http_code}\n" $(SMOKE_DATA_HTTP) || echo "DOWN"
	@printf "Admin  %-32s " "$(SMOKE_ADMIN)/healthz/ready"
	@curl -s  -o /dev/null -w "%{http_code}\n" $(SMOKE_ADMIN)/healthz/ready || echo "DOWN"

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

##@ Cleanup

clean: ## cargo clean (does NOT delete dev certs)
	@$(CARGO) clean
