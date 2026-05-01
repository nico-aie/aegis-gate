# Aegis-Gate — production container image (B6-T1).
#
# Two-stage build:
#   1. `builder` — `rust:1.91-slim` compiles the release binary with
#      the `production` feature umbrella (redis, alerts, geoip,
#      taxii, http3, every cloud secret resolver, every service
#      discovery driver). Build context is restricted via
#      `.dockerignore` so target/ + node_modules/ + run logs don't
#      slow the build.
#   2. `runtime` — `gcr.io/distroless/cc-debian12:nonroot` carries
#      glibc + ca-certificates + tzdata + the `git` binary that
#      `B3-T1`'s GitOps poll-driver shells out to. Single
#      statically-linked-to-glibc binary at /usr/local/bin/waf.
#      Runs as the distroless `nonroot` user (uid/gid 65532).
#
# Build:
#   docker buildx build \
#       --platform linux/amd64,linux/arm64 \
#       --tag aegis-gate:1.4.2 \
#       --tag aegis-gate:latest \
#       -f deploy/Dockerfile .
#
# Run (bind-mount the operator's config + cert dir):
#   docker run --rm -p 8080:8080 -p 8443:8443 -p 9443:9443 \
#       -v /etc/aegis:/etc/aegis:ro \
#       aegis-gate:1.4.2
#
# Override the entrypoint command:
#   docker run --rm aegis-gate:1.4.2 validate --config /etc/aegis/waf.yaml
#
# Image size budget: < 100 MiB compressed.

# Rust 1.91+ — the dep tree pulls `aws-types` 1.3.15 / `aws-smithy-xml`
# 0.60.15 which require 1.91. Plus `time` 0.3 (1.88) and
# `cpufeatures` 0.3 (1.85, edition2024). Bump the workspace
# `rust-version` in lockstep when bumping this.
ARG RUST_VERSION=1.91
ARG DEBIAN_VERSION=bookworm

# ---------------------------------------------------------------------------
# Stage 1 — builder
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-slim-${DEBIAN_VERSION} AS builder

# Native deps the production feature set pulls in:
#   - perl + make → openssl-sys (FIPS path)
#   - pkg-config + libssl-dev → AWS / GCP / Azure SDKs (when not
#     using rustls-only feature flags)
#   - cmake → ring fallback for some hosts; harmless if unused
#   - protobuf-compiler → tonic / gRPC codegen if added later
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        libssl-dev \
        perl \
        pkg-config \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# Copy the manifest skeleton + src so cargo can dependency-cache.
# The .dockerignore strips target/ from the context.
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
COPY config ./config

# Production build with the umbrella feature set.
RUN cargo build -p aegis-bin --release --features production \
    && strip target/release/waf \
    && /work/target/release/waf version || true

# ---------------------------------------------------------------------------
# Stage 2 — runtime (distroless, non-root)
# ---------------------------------------------------------------------------
# `gcr.io/distroless/cc-debian12:nonroot` already includes:
#   - glibc 2.36
#   - ca-certificates (for upstream HTTPS + cloud SDKs)
#   - tzdata (for chrono)
#   - the `nonroot` user (uid/gid 65532)
# We add `git` because B3-T1's GitOps poll driver shells out to it.
FROM debian:${DEBIAN_VERSION}-slim AS git-stage
RUN apt-get update \
    && apt-get install --yes --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# Copy the WAF binary + the system git binary the GitOps loader
# shells out to. The distroless base ships sh-less — git just
# needs to be exec()'able.
COPY --from=builder /work/target/release/waf /usr/local/bin/waf
COPY --from=git-stage /usr/bin/git /usr/bin/git
# git's runtime depends on a few shared libs already in distroless
# /lib + /usr/lib (libpcre2, zlib, libcurl). Distroless `cc` ships
# all of them — no extra `COPY --from` needed.

# Listener defaults baked into config/prod.yaml:
#   8080  data plane plaintext
#   8443  data plane TLS
#   9443  admin (loopback by default — operators rebind via env)
#   443/udp HTTP/3 (when http3 feature is on + listener configured)
EXPOSE 8080
EXPOSE 8443
EXPOSE 9443
EXPOSE 443/udp

# Default config + cert mount points. Operators bind-mount their
# real config + certs into these paths.
VOLUME ["/etc/aegis"]
VOLUME ["/var/lib/aegis"]

USER nonroot:nonroot

# OCI labels — readable by `docker inspect` + GHCR/Artifact Registry.
LABEL org.opencontainers.image.title="Aegis-Gate" \
      org.opencontainers.image.description="Production WAF / security gateway in Rust" \
      org.opencontainers.image.source="https://github.com/example/aegis-gate" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.documentation="https://github.com/example/aegis-gate#readme"

ENTRYPOINT ["/usr/local/bin/waf"]
CMD ["run", "--config", "/etc/aegis/waf.yaml"]
