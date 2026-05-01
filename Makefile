# Aegis-Gate — top-level operator targets.
#
# Run `make help` to see what's available. Common flow for a fresh
# clone:
#
#     make setup          # generate dev cert + release build
#     make run            # boot the WAF against config/prod.yaml
#     make smoke          # curl the data plane + admin health probe
#
# Override defaults via env, e.g.:
#     CONFIG=config/dev.yaml make run
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

# Default config to run against.
CONFIG          ?= config/prod.yaml

# Where the release binary lands.
WAF_BIN         := target/release/waf

# Self-signed cert paths (must match config/prod.yaml).
DEV_CRT         := config/certs/dev.crt
DEV_KEY         := config/certs/dev.key

# Endpoints used by `make smoke`.
SMOKE_DATA_HTTP  ?= http://localhost:8080/
SMOKE_DATA_HTTPS ?= https://localhost:8443/
SMOKE_ADMIN      ?= http://localhost:9443

# --- Phony targets ----------------------------------------------------------

.PHONY: help setup cert build build-debug run validate test test-fast \
        clippy fmt smoke clean reset-cert dashboard

help:
	@awk 'BEGIN { FS = ":.*##" } \
	      /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2 } \
	      /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ First-light

setup: cert build ## Generate dev cert + release build (one-shot fresh clone)
	@echo
	@echo "Setup done. Boot with:"
	@echo "  make run"

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

run: $(WAF_BIN) cert ## Boot the WAF against $(CONFIG) (default: config/prod.yaml)
	@$(WAF_BIN) run --config $(CONFIG)

validate: $(WAF_BIN) ## Validate $(CONFIG) without booting
	@$(WAF_BIN) validate --config $(CONFIG)

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
