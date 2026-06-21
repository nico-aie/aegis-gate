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
- Use the EXACT id the operator gives; if none is given, invent a short kebab-case id.
- Prefer the narrowest `when` that satisfies the intent; default `then` to block:{status:403} for deny intents.";

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

/// Generate a rule body from an intent via the guarded LLM pipeline. Returns
/// the cleaned DSL text (fences stripped). The caller validates it.
pub(crate) async fn generate(
    provider: &dyn LlmProvider,
    guard: &CostGuard,
    intent: &str,
    id: &str,
) -> Result<String, LlmError> {
    let req = render_rule_prompt(intent, id);
    let resp = complete_guarded(provider, guard, req).await?;
    Ok(strip_code_fences(&resp.text))
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
    fn prompt_handles_missing_id() {
        let req = render_rule_prompt("block path /x", "");
        assert!(req.prompt.contains("invent a short kebab-case id"));
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
