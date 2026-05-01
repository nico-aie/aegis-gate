#!/usr/bin/env bash
# Pre-compile the dashboard JSX → JS (DD-T1).
#
# Concatenates the source modules in dependency order, then runs
# esbuild as a JSX transform (not a bundler — the design uses the
# Object.assign(window, ...) pattern for cross-module wiring).
# Output is a single `app.js` next to `index.html`. React + ReactDOM
# come from the local UMD bundles loaded earlier in `index.html`.
#
# Run from anywhere; resolves paths from this script's location.
# Re-run after editing any file in src/.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

# Order matters: widgets first (defines I, Sparkline, …),
# data next (defines RULES, useTicking, …), then pages and help
# which consume widgets+data, finally app which mounts.
SOURCES=(
  "src/widgets.jsx"
  "src/data.jsx"
  "src/pages.jsx"
  "src/help.jsx"
  "src/app.jsx"
)

# Concatenate to a temp file with separator comments for readable
# stack traces.
TMP=$(mktemp -t aegis-dashboard.XXXXXX).jsx
{
  printf '/* Aegis WAF Console — bundled by build.sh from:\n'
  printf '   %s\n' "${SOURCES[@]}"
  printf '*/\n\n'
  for src in "${SOURCES[@]}"; do
    printf '\n/* ===== %s ===== */\n' "$src"
    # Wrap each file in its own IIFE so per-file `const { useState }
    # = React;` destructures don't collide across modules. Globals
    # ride out via the `Object.assign(window, ...)` calls in each
    # file.
    printf ';(function() {\n'
    cat "$src"
    printf '\n})();\n'
  done
} > "$TMP"

# esbuild via npx — JSX transform only, no bundling.
# - target=es2020: matches React 18's runtime baseline.
# - jsx=transform + jsx-factory: classic React.createElement (we have
#   React loaded as a UMD global, so we need the classic transform).
# - --minify-whitespace + --minify-syntax: safe minification that
#   drops comments / whitespace and rewrites obviously-shorter syntax
#   (`!0` for `true`, etc.). Identifier minification is intentionally
#   OFF because the design uses `Object.assign(window, { PageX, ... })`
#   to hand functions to the router — renaming `PageX` would break
#   the router lookup.
npx --yes esbuild "$TMP" \
  --loader:.jsx=jsx \
  --target=es2020 \
  --jsx=transform \
  --jsx-factory=React.createElement \
  --jsx-fragment=React.Fragment \
  --minify-whitespace \
  --minify-syntax \
  --outfile="$HERE/app.js" \
  --log-level=warning

rm -f "$TMP"

echo "built $HERE/app.js ($(wc -c < "$HERE/app.js") bytes)"
