#!/usr/bin/env bash
# Consolidate per-tester findings.jsonl into a deduped, ranked
# summary. Companion to plans/ai-assistant-testing-kickoff.md
# (SWEEP-T2).
#
# Usage:
#   ./tests/sweeps/consolidate.sh <sweep-id>
#       Run the full pass: validate → concat → drop tautology /
#       blocked_by_docs → dedup by signature → rank → write
#       consolidated/.
#
#   ./tests/sweeps/consolidate.sh --validate <path>
#       Validate a single tester folder's findings.jsonl. Exits
#       non-zero if any row is malformed. Use this before
#       submitting your findings.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SWEEPS_ROOT="$SCRIPT_DIR"

require_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "consolidate: jq is required (install via 'brew install jq' or apt)" >&2
    exit 2
  fi
}

# Per-row validation. Reads JSONL on stdin; prints offending rows
# to stderr and exits non-zero on first failure.
validate_jsonl() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "validate: $file not found" >&2
    return 1
  fi
  local lineno=0 status=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    [[ -z "$line" ]] && continue
    if ! echo "$line" | jq -e . >/dev/null 2>&1; then
      echo "validate: $file:$lineno — not valid JSON" >&2
      status=1
      continue
    fi
    # Required-field check.
    local missing
    missing=$(echo "$line" | jq -r '
      [
        if has("id") then empty else "id" end,
        if has("tester") then empty else "tester" end,
        if has("ai_model") then empty else "ai_model" end,
        if has("ts") then empty else "ts" end,
        if has("area") then empty else "area" end,
        if has("severity") then empty else "severity" end,
        if has("title") then empty else "title" end,
        if has("summary") then empty else "summary" end,
        if has("repro") then empty else "repro" end,
        if has("expected") then empty else "expected" end,
        if has("actual") then empty else "actual" end,
        if has("blocked_by_docs") then empty else "blocked_by_docs" end,
        if has("tautology") then empty else "tautology" end
      ] | join(",")
    ')
    if [[ -n "$missing" ]]; then
      echo "validate: $file:$lineno — missing fields: $missing" >&2
      status=1
    fi
    # Severity vocabulary.
    local sev
    sev=$(echo "$line" | jq -r '.severity // ""')
    case "$sev" in
      critical|high|medium|low) ;;
      *)
        echo "validate: $file:$lineno — severity must be one of critical|high|medium|low (got '$sev')" >&2
        status=1
        ;;
    esac
    # Repro must be a non-empty array.
    local repro_n
    repro_n=$(echo "$line" | jq -r '(.repro // []) | length')
    if [[ "$repro_n" -lt 1 ]]; then
      echo "validate: $file:$lineno — repro must be a non-empty array" >&2
      status=1
    fi
  done < "$file"
  return $status
}

# Stable signature per finding: lower-cased title + first repro
# step, whitespace-normalised. Used as a grouping key — works as
# well as a hash for our scale (tens of findings per sweep) and
# avoids depending on a non-portable jq filter (no built-in sha
# in older jq).
emit_with_signature() {
  jq -c '
    . + {
      _sig: (((.title // "") + "|" + ((.repro // [])[0] // ""))
        | ascii_downcase
        | gsub("\\s+"; " "))
    }
  '
}

# Severity → numeric weight for ranking.
severity_weight() {
  jq -c '
    . + {
      _sev_weight: (
        if .severity == "critical" then 1000
        elif .severity == "high"   then 100
        elif .severity == "medium" then 10
        else 1 end
      )
    }
  '
}

# Group rows by signature, keeping the first row's metadata and
# the merged tester list + max severity.
collapse_duplicates() {
  jq -s '
    group_by(._sig)
    | map({
        signature: .[0]._sig,
        title: (.[0].title),
        area: (.[0].area),
        severity: (
          map(.severity) as $sevs
          | if   ($sevs | index("critical")) then "critical"
            elif ($sevs | index("high"))     then "high"
            elif ($sevs | index("medium"))   then "medium"
            else "low" end
        ),
        testers: (map(.tester) | unique),
        ai_models: (map(.ai_model) | unique),
        finding_count: length,
        first_seen: (map(.ts) | min),
        repro: (.[0].repro),
        summary: (.[0].summary),
        expected: (.[0].expected),
        actual: (.[0].actual),
        evidence: (map(.evidence // []) | add | unique),
        links: (map(.links // []) | add | unique),
        all_ids: (map(.id))
      })
  '
}

# Score = severity × tester_count (more independent confirmations →
# more signal). Sort descending.
rank() {
  jq '
    map(. + {
      _score: ((
        if .severity == "critical" then 1000
        elif .severity == "high"   then 100
        elif .severity == "medium" then 10
        else 1 end
      ) * (.testers | length))
    })
    | sort_by(-._score)
    | map(del(._score))
  '
}

# Build the human-readable README.
write_readme() {
  local sweep_id="$1"
  local deduped="$2"
  local out="$3"

  local total
  total=$(jq 'length' < "$deduped")
  local crit hi med lo
  crit=$(jq '[.[] | select(.severity == "critical")] | length' < "$deduped")
  hi=$(jq   '[.[] | select(.severity == "high")] | length'     < "$deduped")
  med=$(jq  '[.[] | select(.severity == "medium")] | length'   < "$deduped")
  lo=$(jq   '[.[] | select(.severity == "low")] | length'      < "$deduped")

  {
    echo "# Sweep $sweep_id — consolidated findings"
    echo
    echo "_Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ) by \`tests/sweeps/consolidate.sh\`._"
    echo
    echo "## Summary"
    echo
    echo "- Total deduped findings: **$total**"
    echo "- Critical: $crit · High: $hi · Medium: $med · Low: $lo"
    echo
    echo "Rows are sorted by severity × distinct-tester count."
    echo "Findings flagged \`tautology: true\` or \`blocked_by_docs: true\`"
    echo "in the per-tester JSONL were dropped before consolidation."
    echo
    echo "## Findings"
    echo
    echo "| # | Severity | Area | Title | Testers | First seen |"
    echo "|---|----------|------|-------|---------|------------|"
    jq -r '
      to_entries[] |
      "| \(.key + 1) | \(.value.severity) | \(.value.area) | \(.value.title) | \(.value.testers | join(", ")) | \(.value.first_seen) |"
    ' < "$deduped"
    echo
    echo "## Repro details"
    echo
    jq -r '
      to_entries[] |
      "### \(.key + 1). \(.value.title)\n\n" +
      "- **Severity:** \(.value.severity)\n" +
      "- **Area:** `\(.value.area)`\n" +
      "- **Reported by:** \(.value.testers | join(", "))\n" +
      "- **AI models:** \(.value.ai_models | join(", "))\n" +
      "- **Finding IDs:** \(.value.all_ids | join(", "))\n\n" +
      "**Summary.** \(.value.summary)\n\n" +
      "**Repro:**\n```\n" + (.value.repro | join("\n")) + "\n```\n\n" +
      "**Expected:** \(.value.expected)\n\n" +
      "**Actual:** \(.value.actual)\n"
    ' < "$deduped"
  } > "$out"
}

main() {
  require_jq

  if [[ "${1:-}" == "--validate" ]]; then
    local target="${2:-}"
    if [[ -z "$target" ]]; then
      echo "usage: $0 --validate <tester-folder-or-jsonl>" >&2
      exit 2
    fi
    if [[ -d "$target" ]]; then
      target="$target/findings.jsonl"
    fi
    if validate_jsonl "$target"; then
      echo "validate: $target — OK"
      return 0
    else
      echo "validate: $target — FAILED" >&2
      return 1
    fi
  fi

  local sweep_id="${1:-}"
  if [[ -z "$sweep_id" ]]; then
    echo "usage: $0 <sweep-id>" >&2
    echo "       $0 --validate <path>" >&2
    exit 2
  fi

  local sweep_dir="$SWEEPS_ROOT/$sweep_id"
  if [[ ! -d "$sweep_dir" ]]; then
    echo "consolidate: sweep folder not found: $sweep_dir" >&2
    exit 2
  fi

  local out_dir="$sweep_dir/consolidated"
  mkdir -p "$out_dir"
  local deduped="$out_dir/findings-deduped.jsonl"
  local readme="$out_dir/README.md"

  # Validate every tester's JSONL up front so we fail fast.
  local fail=0
  while IFS= read -r -d '' f; do
    if ! validate_jsonl "$f"; then
      fail=1
    fi
  done < <(find "$sweep_dir" -mindepth 2 -name 'findings.jsonl' -print0)
  if [[ $fail -ne 0 ]]; then
    echo "consolidate: aborting — fix validation errors above" >&2
    exit 2
  fi

  # Concatenate, drop tautology / blocked_by_docs, signature,
  # collapse, rank.
  find "$sweep_dir" -mindepth 2 -name 'findings.jsonl' -print0 |
    xargs -0 cat |
    grep -v '^$' |
    jq -c 'select((.tautology // false) == false and (.blocked_by_docs // false) == false)' |
    emit_with_signature |
    collapse_duplicates |
    rank > "$deduped"

  write_readme "$sweep_id" "$deduped" "$readme"

  echo "consolidate: wrote $deduped"
  echo "consolidate: wrote $readme"
  echo
  echo "Next step: hand-write $out_dir/improvement-plan.md ranking the"
  echo "top-N items, file each as a SWEEP-T<n> task in plans/, and move"
  echo "the whole sweep folder under tests/results/ when archiving."
}

main "$@"
