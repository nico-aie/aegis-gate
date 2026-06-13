#!/usr/bin/env bash
# =============================================================================
# run.sh — Aegis-Gate round-2 regression runner (bash + curl + jq)
#
# Sends every JSON case under cases/<class>/cases.json to the WAF, reads the
# verdict from the X-Aegis-Decision response header (status code as fallback),
# compares it to the case's expected verdict, and writes:
#   - a live console report (per-class table + totals, FP/FN highlighted)
#   - reports/run-<ts>.jsonl       per-case records (id,class,method,path,rule,…)
#   - reports/run-<ts>.summary.json machine summary
#   - reports/run-<ts>.md + reports/latest.md   human-readable analysis report
#       (FP/FN cases listed inline, per-class detection rate, bypass-by-evasion)
#
#   ./run.sh                     # whole suite
#   ./run.sh injection-sqli      # one class (folder name)
#   ./run.sh websocket xss       # several classes
#   ./run.sh --file cases/xss/cases.json
#   ./run.sh --all --verbose
#   ./run.sh --list              # list classes + case counts, run nothing
#   WAF_BASE_URL=http://127.0.0.1:8080 ./run.sh injection-cmdi
#
# Verdict is taken from (in order):
#   1. X-Aegis-Decision response header  (allow | block | challenge)
#   2. HTTP status fallback: 403->block, 429->challenge, 413->block,
#      101->allow, everything else (2xx/3xx/401/404)->allow (passed through)
#
# Exit code: 0 if no false-negatives AND no false-positives, else 1.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CASES_DIR="$HERE/cases"
REPORT_DIR="$HERE/reports"

BASE_URL="${WAF_BASE_URL:-http://localhost:8080}"
SID="${AEGIS_SID:-regression-dummy-sid}"     # local stub issues no real session; shape is what the WAF judges
DECISION_HDR="x-aegis-decision"
RULE_HDR="x-aegis-rule-id"
TIMEOUT="${AEGIS_TIMEOUT:-7}"
MAX_REPEAT="${AEGIS_MAX_REPEAT:-40}"         # cap burst sends for rate-limit cases (non-DoS courtesy)
VERBOSE=0; LISTONLY=0; ONLY_FP=0; LOGIN=0
declare -a TARGETS=()
EXPLICIT_FILE=""

if [ -t 1 ]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[34m'; DIM=$'\e[2m'; N=$'\e[0m'; else R=; G=; Y=; B=; DIM=; N=; fi
usage(){ sed -n '2,34p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage;;
    --all) :;;
    --list) LISTONLY=1;;
    --verbose|-v) VERBOSE=1;;
    --only-fp) ONLY_FP=1;;
    --login) LOGIN=1;;
    --base-url) BASE_URL="$2"; shift;;
    --file) EXPLICIT_FILE="$2"; shift;;
    --sid) SID="$2"; shift;;
    -*) echo "unknown flag $1" >&2; exit 2;;
    *) TARGETS+=("$1");;
  esac
  shift
done

command -v jq   >/dev/null || { echo "${R}jq is required${N}" >&2; exit 2; }
command -v curl >/dev/null || { echo "${R}curl is required${N}" >&2; exit 2; }

declare -a FILES=()
if [ -n "$EXPLICIT_FILE" ]; then
  FILES+=("$EXPLICIT_FILE")
elif [ ${#TARGETS[@]} -gt 0 ]; then
  for t in "${TARGETS[@]}"; do
    if [ -f "$CASES_DIR/$t/cases.json" ]; then FILES+=("$CASES_DIR/$t/cases.json")
    elif [ -f "$t" ]; then FILES+=("$t")
    else echo "${Y}no such class/file: $t${N}" >&2; fi
  done
else
  while IFS= read -r f; do FILES+=("$f"); done < <(find "$CASES_DIR" -name cases.json | sort)
fi

if [ "$LISTONLY" = 1 ]; then
  printf "%-22s %6s %7s %7s\n" CLASS TOTAL ATTACK BENIGN
  for f in "${FILES[@]}"; do
    cls=$(basename "$(dirname "$f")")
    printf "%-22s %6s %7s %7s\n" "$cls" "$(jq 'length' "$f")" \
      "$(jq '[.[]|select(.expect.verdict!="allow")]|length' "$f")" \
      "$(jq '[.[]|select(.expect.verdict=="allow")]|length' "$f")"
  done
  exit 0
fi

if [ "$LOGIN" = 1 ]; then
  lt=$(curl -sS -m "$TIMEOUT" -X POST "$BASE_URL/login" -H 'Content-Type: application/json' \
        -d '{"username":"alice","password":"P@ssw0rd1"}' 2>/dev/null | jq -r '.login_token // empty')
  if [ -n "$lt" ]; then
    sc=$(curl -sS -m "$TIMEOUT" -i -X POST "$BASE_URL/otp" -H 'Content-Type: application/json' \
          -d "{\"login_token\":\"$lt\",\"otp_code\":\"123456\"}" 2>/dev/null \
          | grep -i '^set-cookie: *sid=' | head -1 | sed -E 's/.*sid=([^;]+).*/\1/')
    [ -n "$sc" ] && SID="$sc" && echo "${DIM}got live session cookie${N}"
  else echo "${DIM}live login unavailable (stub) — using dummy sid${N}"; fi
fi

mkdir -p "$REPORT_DIR" 2>/dev/null || true
TS=$(date +%Y%m%d-%H%M%S)
JSONL="$REPORT_DIR/run-$TS.jsonl"
SUMMARY="$REPORT_DIR/run-$TS.summary.json"
MD="$REPORT_DIR/run-$TS.md"
: > "$JSONL" 2>/dev/null || JSONL=$(mktemp)

WS_PROBE="$HERE/lib/ws_probe.py"; HAVE_WS=0
if command -v python3 >/dev/null && [ -f "$WS_PROBE" ]; then python3 -c 'import websocket' 2>/dev/null && HAVE_WS=1; fi

# ---------- verdict helpers ----------
norm_decision(){ local d; d=$(grep -i "^$DECISION_HDR:" "$1" 2>/dev/null | head -1 | cut -d: -f2- | tr -d ' \r\n' | tr 'A-Z' 'a-z')
  case "$d" in allow|pass|allowed) echo allow;; block|deny|denied|blocked) echo block;; challenge|challenged) echo challenge;; *) echo "";; esac; }
verdict_from_code(){ case "$1" in 403|413) echo block;; 429) echo challenge;;
  101|200|201|204|301|302|304|400|401|404|409|422) echo allow;; 000) echo error;; *) echo allow;; esac; }
matches(){ local e="$1" a="$2"; KIND=ok
  if [ "$a" = error ]; then KIND=error; return 1; fi
  case "$e" in
    allow)     [ "$a" = allow ] && return 0; KIND=false_positive; return 1;;
    block)     { [ "$a" = block ] || [ "$a" = challenge ]; } && return 0; KIND=false_negative; return 1;;
    challenge) { [ "$a" = challenge ] || [ "$a" = block ]; } && return 0; KIND=false_negative; return 1;;
  esac; return 1; }

declare -A C_TOTAL C_PASS C_FAIL C_FP C_FN C_SKIP C_ERR
G_TOTAL=0; G_PASS=0; G_FAIL=0; G_FP=0; G_FN=0; G_SKIP=0; G_ERR=0

emit(){ # $1 result $2 kind ; uses META_* globals
  jq -nc --arg id "$M_ID" --arg cls "$M_CLS" --arg name "$M_NAME" --arg e "$M_EXP" \
     --arg a "$M_ACT" --arg r "$1" --arg k "$2" --arg rule "$M_RULE" --arg method "$M_METHOD" \
     --arg path "$M_PATH" --arg sev "$M_SEV" --arg src "$M_SRC" --argjson tags "${M_TAGS:-[]}" \
     '{id:$id,class:$cls,result:$r,kind:$k,expected:$e,actual:$a,rule_id:$rule,method:$method,path:$path,severity:$sev,source:$src,tags:$tags,name:$name}' >> "$JSONL"; }

record(){ # decide pass/fail from M_EXP vs M_ACT, tally, print, emit
  if matches "$M_EXP" "$M_ACT"; then
    C_PASS[$M_CLS]=$(( ${C_PASS[$M_CLS]:-0}+1 )); G_PASS=$((G_PASS+1))
    [ "$VERBOSE" = 1 ] && [ "$ONLY_FP" = 0 ] && printf "  ${G}PASS${N} %-12s exp=%-9s got=%-9s %s\n" "$M_ID" "$M_EXP" "$M_ACT" "$M_NAME"
    emit pass ok
  else
    C_FAIL[$M_CLS]=$(( ${C_FAIL[$M_CLS]:-0}+1 )); G_FAIL=$((G_FAIL+1))
    case "$KIND" in
      false_positive) C_FP[$M_CLS]=$(( ${C_FP[$M_CLS]:-0}+1 )); G_FP=$((G_FP+1));;
      false_negative) C_FN[$M_CLS]=$(( ${C_FN[$M_CLS]:-0}+1 )); G_FN=$((G_FN+1));;
      error)          C_ERR[$M_CLS]=$(( ${C_ERR[$M_CLS]:-0}+1 )); G_ERR=$((G_ERR+1));;
    esac
    printf "  ${R}FAIL${N} %-12s exp=%-9s got=%-9s ${Y}[%s]${N} %s\n" "$M_ID" "$M_EXP" "$M_ACT" "$KIND" "$M_NAME"
    emit fail "$KIND"
  fi; }

send_case(){
  local c="$1"
  M_CLS="$2"
  M_ID=$(jq -r '.id' <<<"$c");          M_NAME=$(jq -r '.name' <<<"$c")
  M_METHOD=$(jq -r '.request.method' <<<"$c"); M_PATH=$(jq -r '.request.path' <<<"$c")
  M_EXP=$(jq -r '.expect.verdict' <<<"$c"); M_SEV=$(jq -r '.severity // "medium"' <<<"$c")
  M_SRC=$(jq -r '.source // "generated"' <<<"$c"); M_TAGS=$(jq -c '.tags // []' <<<"$c")
  M_RULE=""; M_ACT=""
  local auth body_b64 execute repeat is_ws ws_only ws_frames
  auth=$(jq -r '.request.auth // "none"' <<<"$c"); body_b64=$(jq -r '.request.body_b64 // false' <<<"$c")
  execute=$(jq -r '.request.execute // true' <<<"$c")
  repeat=$(jq -r '[.tags[]?|select(startswith("repeat:"))]|.[0]//"" | sub("repeat:";"")' <<<"$c")
  is_ws=$(jq -r 'if .ws then "1" else "0" end' <<<"$c")
  ws_only=$(jq -r '.ws.handshake_only // true' <<<"$c")
  ws_frames=$(jq -r '.ws.frames | length // 0' <<<"$c" 2>/dev/null); ws_frames=${ws_frames:-0}

  C_TOTAL[$M_CLS]=$(( ${C_TOTAL[$M_CLS]:-0}+1 )); G_TOTAL=$((G_TOTAL+1))

  if [ "$execute" = "false" ]; then
    C_SKIP[$M_CLS]=$(( ${C_SKIP[$M_CLS]:-0}+1 )); G_SKIP=$((G_SKIP+1)); M_ACT=skip
    [ "$VERBOSE" = 1 ] && printf "  ${DIM}SKIP${N} %-12s %s (informational)\n" "$M_ID" "$M_NAME"
    emit skip informational; return; fi

  if [ "$is_ws" = 1 ] && [ "$ws_only" != "true" ] && [ "$ws_frames" -gt 0 ]; then
    if [ "$HAVE_WS" = 0 ]; then
      C_SKIP[$M_CLS]=$(( ${C_SKIP[$M_CLS]:-0}+1 )); G_SKIP=$((G_SKIP+1)); M_ACT=skip
      [ "$VERBOSE" = 1 ] && printf "  ${Y}SKIP${N} %-12s %s (needs lib/ws_probe.py + websocket-client)\n" "$M_ID" "$M_NAME"
      emit skip no_ws_helper; return; fi
    M_ACT=$(jq -c '{base_url:env.WB,sid:env.WS_SID,case:.}' <<<"$c" | WB="$BASE_URL" WS_SID="$SID" python3 "$WS_PROBE" 2>/dev/null); M_ACT=${M_ACT:-error}
    record; return; fi

  local hdr_tmp body_tmp code; hdr_tmp=$(mktemp); body_tmp=$(mktemp)
  declare -a CURL=(curl -sS -m "$TIMEOUT" --path-as-is -g -o "$body_tmp" -D "$hdr_tmp" -w '%{http_code}' -X "$M_METHOD")
  while IFS= read -r b64; do [ -z "$b64" ] && continue
    CURL+=(-H "$(printf '%s' "$b64" | base64 -d 2>/dev/null)"); done \
    < <(jq -r '.request.headers // {} | to_entries[] | "\(.key): \(.value)" | @base64' <<<"$c")
  [ "$auth" = session ] && CURL+=(-H "Cookie: sid=$SID")
  if [ "$(jq -r 'if .request.body==null then 1 else 0 end' <<<"$c")" = 0 ]; then
    if [ "$body_b64" = true ]; then jq -r '.request.body' <<<"$c" | base64 -d > "$body_tmp.req" 2>/dev/null
    else jq -r '.request.body' <<<"$c" > "$body_tmp.req"; fi
    CURL+=(--data-binary "@$body_tmp.req"); fi
  CURL+=("$BASE_URL$M_PATH")

  local n=1; [ -n "$repeat" ] && n=$repeat; [ "$n" -gt "$MAX_REPEAT" ] && n=$MAX_REPEAT
  if [ "$n" -le 1 ]; then
    code=$("${CURL[@]}" 2>/dev/null); code=${code:-000}
    M_ACT=$(norm_decision "$hdr_tmp"); [ -z "$M_ACT" ] && M_ACT=$(verdict_from_code "$code")
  else
    local i a c2 hit=""
    for ((i=0;i<n;i++)); do c2=$("${CURL[@]}" 2>/dev/null); c2=${c2:-000}
      a=$(norm_decision "$hdr_tmp"); [ -z "$a" ] && a=$(verdict_from_code "$c2")
      { [ "$a" = challenge ] || [ "$a" = block ]; } && hit=$a; done
    M_ACT=${hit:-allow}; fi
  M_RULE=$(grep -i "^$RULE_HDR:" "$hdr_tmp" 2>/dev/null | head -1 | cut -d: -f2- | tr -d '\r\n' | sed 's/^ *//')
  rm -f "$hdr_tmp" "$body_tmp" "$body_tmp.req" 2>/dev/null
  record; }

# ---------- run ----------
echo "${B}Aegis-Gate r2 regression${N}  base=$BASE_URL  sid=${SID:0:8}…  ($(date +%H:%M:%S))"; echo
for f in "${FILES[@]}"; do
  [ -f "$f" ] || continue
  cls=$(basename "$(dirname "$f")"); [ "$cls" = cases ] && cls=$(basename "$f" .json)
  echo "${B}▸ $cls${N} ${DIM}($(jq 'length' "$f") cases)${N}"
  while IFS= read -r case_json; do send_case "$case_json" "$cls"; done < <(jq -c '.[]' "$f")
done

# ---------- console summary ----------
echo; echo "${B}── per-class ──${N}"
printf "%-22s %6s %6s %6s %6s %6s %6s\n" CLASS TOTAL PASS FAIL FP FN SKIP
for cls in $(printf '%s\n' "${!C_TOTAL[@]}" | sort); do
  col=$G; [ "${C_FAIL[$cls]:-0}" -gt 0 ] && col=$R
  printf "${col}%-22s${N} %6s %6s %6s %6s %6s %6s\n" "$cls" \
    "${C_TOTAL[$cls]:-0}" "${C_PASS[$cls]:-0}" "${C_FAIL[$cls]:-0}" "${C_FP[$cls]:-0}" "${C_FN[$cls]:-0}" "${C_SKIP[$cls]:-0}"
done
echo "${B}── totals ──${N}"
printf "%-22s %6s %6s %6s ${R}%6s${N} ${R}%6s${N} %6s\n" TOTAL "$G_TOTAL" "$G_PASS" "$G_FAIL" "$G_FP" "$G_FN" "$G_SKIP"
echo; echo "  ${R}false negatives (attacks that slipped through): $G_FN${N}"
echo "  ${Y}false positives (benign traffic blocked):       $G_FP${N}"
[ "$G_ERR" -gt 0 ] && echo "  ${R}errors (no/!verdict — WAF down?):              $G_ERR${N}"
[ "$G_SKIP" -gt 0 ] && echo "  ${DIM}skipped (informational / no ws helper):        $G_SKIP${N}"

# ---------- machine summary ----------
jq -n --arg ts "$TS" --arg base "$BASE_URL" --argjson t "$G_TOTAL" --argjson p "$G_PASS" \
  --argjson f "$G_FAIL" --argjson fp "$G_FP" --argjson fn "$G_FN" --argjson er "$G_ERR" --argjson sk "$G_SKIP" \
  '{ts:$ts,base_url:$base,total:$t,pass:$p,fail:$f,false_positives:$fp,false_negatives:$fn,errors:$er,skipped:$sk,
    detection_rate:(if ($t-$sk)>0 then (($p)/($t-$sk)*1000|round/10) else 0 end)}' > "$SUMMARY" 2>/dev/null || true

# ---------- markdown analysis report ----------
{
  det=0; den=$((G_TOTAL-G_SKIP)); [ "$den" -gt 0 ] && det=$(awk "BEGIN{printf \"%.1f\",$G_PASS/$den*100}")
  echo "# Aegis-Gate r2 regression — run report"
  echo
  echo "- **When:** $TS    **Target:** \`$BASE_URL\`"
  echo "- **Total:** $G_TOTAL  ·  **Pass:** $G_PASS  ·  **Fail:** $G_FAIL  ·  **Skipped:** $G_SKIP"
  echo "- **False negatives (attacks allowed):** $G_FN  ·  **False positives (benign blocked):** $G_FP  ·  **Errors:** $G_ERR"
  echo "- **Detection rate (pass / executed):** ${det}%"
  [ "$G_ERR" -gt 0 ] && echo && echo "> ⚠️ $G_ERR cases returned no verdict — is the WAF up at \`$BASE_URL\`? Treat this run's numbers with care."
  echo
  echo "## Per-class"
  echo
  echo "| Class | Total | Pass | Fail | FP | FN | Skip | Detect% |"
  echo "|---|--:|--:|--:|--:|--:|--:|--:|"
  for cls in $(printf '%s\n' "${!C_TOTAL[@]}" | sort); do
    tot=${C_TOTAL[$cls]:-0}; sk=${C_SKIP[$cls]:-0}; pa=${C_PASS[$cls]:-0}; exq=$((tot-sk)); dr="-"
    [ "$exq" -gt 0 ] && dr=$(awk "BEGIN{printf \"%.0f\",$pa/$exq*100}")
    echo "| $cls | $tot | $pa | ${C_FAIL[$cls]:-0} | ${C_FP[$cls]:-0} | ${C_FN[$cls]:-0} | $sk | ${dr} |"
  done
  echo
  if [ "$G_FN" -gt 0 ]; then
    echo "## ❌ False negatives — attacks that slipped through ($G_FN)"
    echo "_Top priority: these are detector gaps. Grouped to show what to harden._"
    echo
    echo "| id | class | method | path | rule fired |"
    echo "|---|---|---|---|---|"
    jq -r 'select(.kind=="false_negative") | "| \(.id) | \(.class) | \(.method) | `\((.path|gsub("\n";" ")|.[0:70]))` | \(if (.rule_id//"")=="" then "—" else .rule_id end) |"' "$JSONL"
    echo
    echo "**Slipped-through by evasion technique:**"
    echo
    fns_ev=$(jq -r 'select(.kind=="false_negative") | .tags[]? | select(startswith("evasion:"))' "$JSONL" | sort | uniq -c | sort -rn)
    if [ -n "$fns_ev" ]; then echo '```'; echo "$fns_ev"; echo '```'; else echo "_(no evasion-tagged cases among the misses)_"; fi
    echo
  fi
  if [ "$G_FP" -gt 0 ]; then
    echo "## ⚠️ False positives — benign traffic blocked ($G_FP)"
    echo "_These hurt the legitimate-traffic score. Tune the firing rule down for these shapes._"
    echo
    echo "| id | class | method | path | rule fired |"
    echo "|---|---|---|---|---|"
    jq -r 'select(.kind=="false_positive") | "| \(.id) | \(.class) | \(.method) | `\((.path|gsub("\n";" ")|.[0:70]))` | \(if (.rule_id//"")=="" then "—" else .rule_id end) |"' "$JSONL"
    echo
  fi
  if [ "$G_ERR" -gt 0 ]; then
    echo "## 🔌 Errors — no verdict captured ($G_ERR)"
    echo
    jq -r 'select(.actual=="error") | "- \(.id) (\(.class)) \(.method) \(.path[0:60])"' "$JSONL"
    echo
  fi
  echo "## What's working — rules that fired on caught attacks"
  echo
  rb=$(jq -r 'select(.result=="pass" and .expected!="allow" and (.rule_id//"")!="") | .rule_id' "$JSONL" | sort | uniq -c | sort -rn | head -20)
  if [ -n "$rb" ]; then echo '```'; echo "$rb"; echo '```'; else echo "_(no X-Aegis-Rule-Id headers seen — relying on status/decision only)_"; fi
  echo
  echo "---"
  echo "_Raw per-case log: \`$(basename "$JSONL")\`  ·  machine summary: \`$(basename "$SUMMARY")\`_"
  echo "_Filter misses:_ \`jq 'select(.kind==\"false_negative\")' reports/$(basename "$JSONL")\`"
} > "$MD" 2>/dev/null
cp -f "$MD" "$REPORT_DIR/latest.md" 2>/dev/null || true

echo; echo "${DIM}per-case log:  $JSONL${N}"
echo "${DIM}summary json:  $SUMMARY${N}"
echo "${B}analysis report: $MD${N}  ${DIM}(also reports/latest.md)${N}"

[ "$G_FN" -eq 0 ] && [ "$G_FP" -eq 0 ] && [ "$G_ERR" -eq 0 ] && exit 0 || exit 1
