//! AI rule generation (2026-06-21) — turn a natural-language intent
//! ("block requests to /admin from outside the office IP range") into a valid
//! WAF rule DSL body the operator can review + save.
//!
//! Pure prompt-building + output-cleaning here; the guarded LLM call goes
//! through [`super::summary::complete_guarded`] (redact → cost-admit →
//! provider → record-usage) so the egress gate + budget can never be bypassed.
//! The generated body is NOT auto-applied — it prefills the New-rule editor and
//! is validated by `api::rules::validate_rule_body` like any hand-written body.

use super::{summary::complete_guarded, CostGuard, LlmError, LlmProvider, LlmRequest};

/// Output cap — a rule body is small; bounds cost + runaway generations.
const MAX_OUTPUT_TOKENS: u32 = 600;

/// System prompt: pins the model to emit ONLY the DSL (no prose, no fences) and
/// teaches it the exact grammar the engine accepts (mirrors the New-rule
/// modal's syntax help so the model and the validator agree).
const RULEGEN_SYSTEM: &str = "\
You are a WAF rule author. Output ONLY a single YAML list item for the Aegis \
rule DSL — no prose, no markdown, no code fences, no comments.

Grammar (one rule, a YAML list item):
- id: <string>        # 1-64 chars, lowercase, hyphens/underscores; MUST match the requested id
  priority: <int>     # higher wins; default 100
  when: <condition>   # one of: path_matches:{contains|regex: ...} | ip_in: [..] |
                      #   header_matches:{name:.., contains:..} | method: [..] |
                      #   host_matches:{contains|regex:..} | body_matches:{contains|regex:..} |
                      #   all:[..] | any:[..] | not: <cond> | true
  then: <action>      # one of: allow | log_only | block:{status:403} |
                      #   challenge:{level: js} | rate_limit:{key:ip, limit:N, window:Ns} |
                      #   raise_risk: <int>
  scope: global       # or { route: \"<route-id>\" }

Rules:
- Emit exactly ONE rule and nothing else.
- Use the EXACT id the operator gives; if none is given, invent a short
  kebab-case id that DESCRIBES THE INTENT (e.g. block-ip-1-2-3-4), never a
  generic template name.
- The `then` action MUST match the intent's verb — do not default to allow:
    block / deny / forbid / reject  -> block: { status: 403 }
    allow / permit / whitelist / trust -> allow
    log / monitor / observe / shadow   -> log_only
    challenge / captcha                 -> challenge: { level: js }
    rate limit / throttle / slow down   -> rate_limit: { key: ip, limit: N, window: Ns }
  A 'block ...' request must produce block, NOT allow.
- Prefer the narrowest `when` that satisfies the intent.

FORMAT IS STRICT — `when:` and `then:` are nested maps, NEVER one line. Copy the
exact indentation of these valid examples:

Block specific IPs:
- id: block-bad-ips
  priority: 100
  when:
    ip_in:
      - \"203.0.113.10\"
      - \"198.51.100.42\"
  then:
    block:
      status: 403
  scope: global

Block a path:
- id: block-admin
  priority: 100
  when:
    path_matches:
      contains: \"/admin\"
  then:
    block:
      status: 403
  scope: global

Allow a trusted IP:
- id: allow-office
  priority: 200
  when:
    ip_in:
      - \"192.0.2.1\"
  then: allow
  scope: global

NEVER write `when: ip_in: [...]` on one line — it is invalid.";

/// Build the (un-redacted) generation prompt. Pure. `id` is the operator's
/// requested rule id (the model is told to use it verbatim so the body id and
/// the form id agree — see the rule-id-divergence fix).
pub fn render_rule_prompt(intent: &str, id: &str) -> LlmRequest {
    let id = id.trim();
    let id_line = if id.is_empty() {
        "No id given — invent a short kebab-case id.".to_string()
    } else {
        format!("Required rule id (use verbatim as `id:`): {id}")
    };
    LlmRequest {
        system: Some(RULEGEN_SYSTEM.to_string()),
        prompt: format!("{id_line}\n\nIntent: {intent}\n\nOutput the single YAML rule now:"),
        max_tokens: MAX_OUTPUT_TOKENS,
    }
}

/// Strip a leading/trailing markdown code fence (```` ```yaml ```` / ```` ``` ````)
/// the model may wrap the body in despite the instruction, returning the inner
/// DSL trimmed. Idempotent on already-clean input.
pub fn strip_code_fences(s: &str) -> String {
    let t = s.trim();
    if !t.starts_with("```") {
        return t.to_string();
    }
    // Drop the first line (``` or ```yaml) and a trailing fence line.
    let mut lines: Vec<&str> = t.lines().collect();
    if !lines.is_empty() {
        lines.remove(0);
    }
    if lines.last().map(|l| l.trim_start().starts_with("```")) == Some(true) {
        lines.pop();
    }
    lines.join("\n").trim().to_string()
}

/// Build a repair prompt: hand the model its own invalid draft + the validator
/// errors and ask for a corrected single rule. Used by the one-shot self-repair
/// retry when the first draft fails `validate_rule_body`.
pub fn render_repair_prompt(intent: &str, id: &str, bad_body: &str, errors: &str) -> LlmRequest {
    let id = id.trim();
    let id_line = if id.is_empty() {
        String::new()
    } else {
        format!("Rule id (use verbatim as `id:`): {id}\n")
    };
    LlmRequest {
        system: Some(RULEGEN_SYSTEM.to_string()),
        prompt: format!(
            "{id_line}Intent: {intent}\n\nYour previous draft FAILED validation:\n\
             ----- draft -----\n{bad_body}\n-----------------\n\
             Validator errors:\n{errors}\n\n\
             Fix ONLY what the errors flag, keep the same intent, and output the \
             corrected single YAML rule now (no prose, no fences):"
        ),
        max_tokens: MAX_OUTPUT_TOKENS,
    }
}

/// Generate a rule body from an intent via the guarded LLM pipeline. Returns
/// the cleaned DSL text (fences stripped). If the first draft fails the rule-DSL
/// validator, retry ONCE with the errors fed back (self-repair); return the
/// better of the two. The caller re-validates and the operator reviews.
pub(crate) async fn generate(
    provider: &dyn LlmProvider,
    guard: &CostGuard,
    intent: &str,
    id: &str,
) -> Result<String, LlmError> {
    let first = strip_code_fences(
        &complete_guarded(provider, guard, render_rule_prompt(intent, id)).await?.text,
    );
    let v = crate::api::rules::validate_rule_body(&first);
    if v.ok {
        return Ok(first);
    }
    // One-shot self-repair: feed the validator errors back to the model.
    let errors = v
        .errors
        .iter()
        .map(|e| format!("- line {}: {}", e.line, e.message))
        .collect::<Vec<_>>()
        .join("\n");
    let repaired = strip_code_fences(
        &complete_guarded(provider, guard, render_repair_prompt(intent, id, &first, &errors))
            .await?
            .text,
    );
    // Return the repaired draft only if it actually validates; otherwise keep
    // the first so the UI shows the original errors (don't trade one bad draft
    // for another). Either way the caller re-validates + the operator reviews.
    if crate::api::rules::validate_rule_body(&repaired).ok {
        Ok(repaired)
    } else {
        Ok(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_carries_grammar_intent_and_id() {
        let req = render_rule_prompt("block /admin from outside office", "custom-admin-block");
        assert!(req.system.as_deref().unwrap().contains("when:"));
        assert!(req.prompt.contains("block /admin from outside office"));
        assert!(req.prompt.contains("custom-admin-block"));
    }

    #[test]
    fn system_prompt_steers_block_intent_to_block_action() {
        let sys = render_rule_prompt("block ip 1.2.3.4", "x").system.unwrap();
        // The verb→action mapping must be present so a block intent can't
        // produce `allow` (the reported mis-generation).
        assert!(sys.contains("block: { status: 403 }"));
        assert!(sys.contains("must produce block, NOT allow"));
    }

    #[test]
    fn prompt_handles_missing_id() {
        let req = render_rule_prompt("block path /x", "");
        assert!(req.prompt.contains("invent a short kebab-case id"));
    }

    #[test]
    fn repair_prompt_includes_bad_draft_and_errors() {
        let req = render_repair_prompt(
            "block ip 1.2.3.4",
            "block-ip",
            "- id: block-ip\n  when: ip_in: [1.2.3.4]",
            "- line 2: unknown string condition: ip_in",
        );
        assert!(req.prompt.contains("FAILED validation"));
        assert!(req.prompt.contains("unknown string condition: ip_in"));
        assert!(req.prompt.contains("when: ip_in: [1.2.3.4]"));
        assert!(req.prompt.contains("block ip 1.2.3.4"));
    }

    #[test]
    fn strip_fences_unwraps_yaml_block() {
        let raw = "```yaml\n- id: x\n  then: { block: { status: 403 } }\n```";
        let out = strip_code_fences(raw);
        assert!(out.starts_with("- id: x"));
        assert!(!out.contains("```"));
    }

    #[test]
    fn strip_fences_passes_clean_input_through() {
        let raw = "- id: x\n  then: { allow }";
        assert_eq!(strip_code_fences(raw), raw);
    }
}
