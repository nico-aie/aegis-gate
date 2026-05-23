# Aegis Inference Server — build & test shortcuts
# Requires: Rust/Cargo, protoc (brew install protobuf)

.PHONY: build release run-mock run bench test clean help

## Build (debug)
build:
	cargo build

## Build (optimised release)
release:
	cargo build --release

## Start server in mock mode (no ONNX model needed)
run-mock:
	cargo run --bin aegis-infer -- \
		--mock \
		--max-batch 256 \
		--delay-ms 2 \
		--workers 2 \
		--log-level info

## Start server in mock mode + UDS socket
run-mock-uds:
	cargo run --bin aegis-infer -- \
		--mock \
		--bind-uds /tmp/aegis-infer.sock \
		--log-level debug

## Start server with real ONNX model (set MODEL_PATH env var)
run-onnx:
	cargo run --release --bin aegis-infer -- \
		--model-path $(MODEL_PATH) \
		--workers 4 \
		--max-batch 256 \
		--delay-ms 2 \
		--bind-uds /tmp/aegis-infer.sock

## Quick smoke test (1 000 requests, 50 concurrent)
bench-quick:
	cargo run --bin infer-bench -- \
		--requests 1000 \
		--concurrency 50 \
		--payload mixed

## Full throughput benchmark (10 000 requests, 200 concurrent)
bench:
	cargo run --release --bin infer-bench -- \
		--requests 10000 \
		--concurrency 200 \
		--payload mixed \
		--warmup 500

## Benchmark via UDS
bench-uds:
	cargo run --release --bin infer-bench -- \
		--endpoint unix:///tmp/aegis-infer.sock \
		--requests 10000 \
		--concurrency 500 \
		--payload mixed

## Unit tests
test:
	cargo test

## Clean build artefacts
clean:
	cargo clean

help:
	@grep -E '^##' Makefile | sed 's/## //'
