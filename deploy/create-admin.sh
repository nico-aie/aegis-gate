#!/usr/bin/env bash
# create-admin.sh — mint an admin account and append it to the config's
# `admin.dashboard_auth.accounts:` block in one step.
#
#   Usage:   ./deploy/create-admin.sh <username> [config-file]
#            ./deploy/create-admin.sh <username> --print   # fragment only, no file edit
#
#   The password is prompted silently (never echoed, never in shell
#   history / `ps`). Config defaults to config/dev.yaml.
#
# What it does:
#   1. `waf admin create-account` → argon2id hash + ready-to-paste fragment
#   2. inserts the new entry under the existing `accounts:` list
#   3. `waf validate` — on failure the config is restored from backup
#
# No TOTP secret is minted here on purpose: with `require_totp: true`
# the account's FIRST web login lands on the QR setup page, so each
# admin enrolls Google Authenticator on their own phone and the secret
# never passes through the operator's terminal. (Want to pre-enroll
# anyway? Run `waf admin create-account --username <u> --with-totp`
# manually and paste the printed fragment yourself.)
#
# Restart the WAF afterwards — the account set is read at boot.

set -euo pipefail

WAF_BIN="${WAF_BIN:-target/release/waf}"

usage() { grep '^#' "$0" | sed -n '2,12p' | sed 's/^# \{0,3\}//'; exit 1; }

USERNAME="${1:-}"
[ -n "$USERNAME" ] || usage
case "$USERNAME" in
  -*) usage ;;
esac

PRINT_ONLY=0
CONFIG="config/dev.yaml"
if [ "${2:-}" = "--print" ]; then
  PRINT_ONLY=1
elif [ -n "${2:-}" ]; then
  CONFIG="$2"
fi

[ -x "$WAF_BIN" ] || { echo "error: $WAF_BIN not found — run 'make build' first (or set WAF_BIN=)"; exit 1; }

# Refuse a duplicate before prompting for a password.
if [ "$PRINT_ONLY" -eq 0 ]; then
  [ -f "$CONFIG" ] || { echo "error: config file not found: $CONFIG"; exit 1; }
  if grep -qE "^\s*-\s*username:\s*[\"']?${USERNAME}[\"']?\s*$" "$CONFIG"; then
    echo "error: account '$USERNAME' already exists in $CONFIG"
    exit 1
  fi
fi

# Silent password prompt (read -s: no echo, not in argv).
printf 'Password for %s: ' "$USERNAME"
read -rs PASSWORD; echo
printf 'Confirm password: '
read -rs PASSWORD2; echo
[ "$PASSWORD" = "$PASSWORD2" ] || { echo "error: passwords do not match"; exit 1; }
[ -n "$PASSWORD" ] || { echo "error: password cannot be empty"; exit 1; }

# The CLI reads the password from stdin (its prompt warns about echo —
# irrelevant here since we pipe). Capture just the fragment lines.
FRAGMENT=$(printf '%s\n' "$PASSWORD" \
  | "$WAF_BIN" admin create-account --username "$USERNAME" \
  | grep -E '^\s+(- username:|password_hash_ref:)')
unset PASSWORD PASSWORD2

[ -n "$FRAGMENT" ] || { echo "error: waf admin create-account produced no fragment"; exit 1; }

if [ "$PRINT_ONLY" -eq 1 ]; then
  echo
  echo "Paste under admin.dashboard_auth.accounts:"
  printf '%s\n' "$FRAGMENT"
  exit 0
fi

grep -qE '^\s*accounts:\s*$' "$CONFIG" || {
  echo "error: no 'accounts:' block in $CONFIG — add one under admin.dashboard_auth first"
  echo "Fragment for manual paste:"; printf '%s\n' "$FRAGMENT"
  exit 1
}

BACKUP=$(mktemp "${TMPDIR:-/tmp}/$(basename "$CONFIG").XXXXXX.bak")
cp "$CONFIG" "$BACKUP"

# Insert the fragment right after the `accounts:` line, RE-INDENTED to
# match the target file (the CLI prints a top-level example; the real
# block sits deeper under admin.dashboard_auth).
FRAG="$FRAGMENT" python3 - "$CONFIG" <<'EOF'
import os, re, sys
path = sys.argv[1]
frag_lines = [l.strip() for l in os.environ["FRAG"].split("\n") if l.strip()]
lines = open(path).read().split("\n")
for i, l in enumerate(lines):
    m = re.match(r"^(\s*)accounts:\s*$", l)
    if m:
        base = m.group(1)
        indented = [
            (base + "  " + fl) if fl.startswith("- ") else (base + "    " + fl)
            for fl in frag_lines
        ]
        lines[i+1:i+1] = indented
        break
open(path, "w").write("\n".join(lines))
EOF

if "$WAF_BIN" validate --config "$CONFIG" >/dev/null 2>&1; then
  rm -f "$BACKUP"
  echo
  echo "✔ account '$USERNAME' added to $CONFIG (config validates)"
  echo "  → restart the WAF (make run-dev) to load it"
  echo "  → first web login shows the Google Authenticator QR setup"
else
  cp "$BACKUP" "$CONFIG"; rm -f "$BACKUP"
  echo "error: $CONFIG failed validation after insert — restored original."
  echo "Run manually to see why:  $WAF_BIN validate --config $CONFIG"
  echo "Fragment for manual paste:"; printf '%s\n' "$FRAGMENT"
  exit 1
fi
