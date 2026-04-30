#!/usr/bin/env bash
# Generate a self-signed TLS cert for local development / first-light
# testing. Drops the cert + key into config/certs/ where prod.yaml
# expects them by default.
#
# Usage:
#   bash config/gen-cert.sh                       # default 1-year cert
#   bash config/gen-cert.sh --days 90             # custom validity
#   bash config/gen-cert.sh --cn waf.local        # custom common name
#
# DO NOT use the resulting cert in production. It's self-signed,
# not chained to any CA, and the key is on disk in plaintext. Replace
# with a real cert (or wire the `tls.acme:` block in prod.yaml) before
# exposing the WAF to the internet.

set -euo pipefail

DAYS=365
CN="aegis-gate.local"
OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --days) DAYS="$2"; shift 2 ;;
    --cn)   CN="$2";   shift 2 ;;
    --out)  OUT_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,15p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) echo "unknown flag: $1" >&2; exit 1 ;;
  esac
done

command -v openssl >/dev/null \
  || { echo "openssl not in PATH — install it first" >&2; exit 1; }

mkdir -p "$OUT_DIR"
CRT="$OUT_DIR/dev.crt"
KEY="$OUT_DIR/dev.key"

if [[ -f "$CRT" && -f "$KEY" ]]; then
  echo "Cert already exists: $CRT"
  echo "Delete it first if you want to regenerate."
  openssl x509 -in "$CRT" -noout -subject -dates
  exit 0
fi

# Inline OpenSSL config — keeps the command self-contained.
CONF="$(mktemp)"
trap 'rm -f "$CONF"' EXIT
cat > "$CONF" <<EOF
[req]
distinguished_name = dn
prompt             = no
x509_extensions    = v3_ext

[dn]
CN = $CN
O  = Aegis-Gate (self-signed dev)

[v3_ext]
basicConstraints     = CA:FALSE
keyUsage             = digitalSignature, keyEncipherment
extendedKeyUsage     = serverAuth
subjectAltName       = @sans

[sans]
DNS.1 = $CN
DNS.2 = localhost
IP.1  = 127.0.0.1
IP.2  = ::1
EOF

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$KEY" -out "$CRT" \
  -days "$DAYS" -config "$CONF" >/dev/null 2>&1

chmod 600 "$KEY"

echo "wrote $CRT"
echo "wrote $KEY"
echo
openssl x509 -in "$CRT" -noout -subject -issuer -dates
echo
echo "Boot the WAF with TLS:"
echo "  target/release/waf run --config config/prod.yaml"
echo
echo "Smoke test:"
echo "  curl -k https://localhost:8443/"
