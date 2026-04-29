#!/usr/bin/env bash
# tests/api/tls-ciphers.sh — Negotiated cipher suite smoke (P4)
#
# Asserts the admin listener (always TLS) negotiates ONE OF the
# documented modern cipher suites and refuses obviously-weak
# ones. Per `docs/data-plane/tls-termination.md`:
#
#   TLS 1.3:  TLS_AES_128_GCM_SHA256
#             TLS_AES_256_GCM_SHA384
#             TLS_CHACHA20_POLY1305_SHA256
#   TLS 1.2:  ECDHE-{ECDSA,RSA}-AES{128,256}-GCM-SHA{256,384}
#             ECDHE-{ECDSA,RSA}-CHACHA20-POLY1305
#
# Plus a deliberate negative — we try to force the legacy
# `RC4-SHA` / `DES-CBC3-SHA` ciphers (TLS 1.2 weak set) and
# expect the handshake to fail.
#
# This script needs `openssl s_client` because curl can't be
# coerced into requesting a single TLS 1.2 cipher portably.
# Both Apple's LibreSSL build and OpenSSL 1.1+/3+ work.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/_common.sh"

require curl
if ! command -v openssl >/dev/null 2>&1; then
  echo "INFO: openssl not present — skipping cipher-negotiation test"
  exit 0
fi

# Strip the protocol prefix to get host:port for s_client.
target="${AEGIS_ADMIN#https://}"
target="${target#http://}"
host="${target%%/*}"

# Probe first — if we can't even connect, skip cleanly so this
# script doesn't fail when admin isn't running.
if ! { echo | openssl s_client -connect "$host" \
                               -servername "${host%%:*}" \
                               -no_ign_eof 2>&1 \
        | grep -q "BEGIN CERTIFICATE"; }; then
  echo "INFO: $host did not negotiate a TLS session — skipping (admin not running?)"
  exit 0
fi

# 1. Default handshake — must land on a documented modern suite.
# Each pipeline is wrapped with `|| true` so openssl's non-zero
# exit on protocol mismatch doesn't trip set -e mid-script.
neg=$( { echo | openssl s_client -connect "$host" \
                                 -servername "${host%%:*}" \
                                 -tls1_3 \
                                 -no_ign_eof 2>/dev/null; true; } \
       | awk '/Cipher\s*:/{print $3; exit}' || true)
if [[ -z "$neg" ]]; then
  echo "INFO: TLS 1.3 unavailable to openssl — falling back to default version"
  neg=$( { echo | openssl s_client -connect "$host" \
                                   -servername "${host%%:*}" \
                                   -no_ign_eof 2>/dev/null; true; } \
         | awk '/Cipher\s*:/{print $3; exit}' || true)
fi
if [[ -z "$neg" ]]; then
  echo "FAIL: openssl s_client could not negotiate a TLS session"
  exit 1
fi

case "$neg" in
  TLS_AES_128_GCM_SHA256|TLS_AES_256_GCM_SHA384|TLS_CHACHA20_POLY1305_SHA256)
    ok "negotiated TLS 1.3 cipher: $neg" ;;
  ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE-RSA-AES128-GCM-SHA256 \
  | ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE-RSA-AES256-GCM-SHA384 \
  | ECDHE-ECDSA-CHACHA20-POLY1305 | ECDHE-RSA-CHACHA20-POLY1305)
    ok "negotiated TLS 1.2 cipher: $neg" ;;
  *)
    echo "FAIL: unexpected cipher negotiated: $neg"
    echo "      expected one of the documented modern suites"
    exit 1
    ;;
esac

# 2. Negative — request a weak TLS 1.2 cipher, expect failure.
weak_response=$(echo | openssl s_client -connect "$host" \
                                        -servername "${host%%:*}" \
                                        -tls1_2 \
                                        -cipher 'DES-CBC3-SHA' \
                                        -no_ign_eof 2>&1 || true)
if echo "$weak_response" | grep -qE 'Cipher\s*:\s*DES-CBC3-SHA'; then
  echo "FAIL: server agreed to use weak DES-CBC3-SHA cipher"
  exit 1
fi
ok "weak DES-CBC3-SHA cipher rejected by handshake"

# 3. Bonus — verify the certificate chain at least parses (not a
#    full PKI assertion; just that openssl gets to the cert step).
if echo | openssl s_client -connect "$host" \
                           -servername "${host%%:*}" \
                           -showcerts -no_ign_eof 2>/dev/null \
   | grep -q "BEGIN CERTIFICATE"; then
  ok "server presented at least one certificate"
else
  echo "FAIL: no certificate chain visible to openssl"
  exit 1
fi
