use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

/// A single WAF rule.
#[derive(Clone, Debug, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub priority: u32,
    #[serde(default)]
    pub scope: Scope,
    #[serde(rename = "when")]
    pub condition: Condition,
    #[serde(rename = "then")]
    pub action: RuleAction,
}

/// Where the rule applies.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Scope {
    #[default]
    Global,
    Route(String),
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ScopeVisitor;
        impl<'de> Visitor<'de> for ScopeVisitor {
            type Value = Scope;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("\"global\" or {route: \"name\"}")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Scope, E> {
                if v == "global" { Ok(Scope::Global) } else { Err(E::custom("expected \"global\"")) }
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Scope, A::Error> {
                let key: String = map.next_key()?.ok_or_else(|| de::Error::custom("empty map"))?;
                if key == "route" {
                    let val: String = map.next_value()?;
                    Ok(Scope::Route(val))
                } else {
                    Err(de::Error::custom(format!("unknown scope key: {key}")))
                }
            }
        }
        deserializer.deserialize_any(ScopeVisitor)
    }
}

/// Match operation for string comparisons.
#[derive(Clone, Debug)]
pub enum MatchOp {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Contains(String),
    Regex(String),
}

impl<'de> Deserialize<'de> for MatchOp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MatchOpVisitor;
        impl<'de> Visitor<'de> for MatchOpVisitor {
            type Value = MatchOp;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a map with one key: exact|prefix|suffix|contains|regex")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<MatchOp, A::Error> {
                let key: String = map.next_key()?.ok_or_else(|| de::Error::custom("empty map"))?;
                let val: String = map.next_value()?;
                match key.as_str() {
                    "exact" => Ok(MatchOp::Exact(val)),
                    "prefix" => Ok(MatchOp::Prefix(val)),
                    "suffix" => Ok(MatchOp::Suffix(val)),
                    "contains" => Ok(MatchOp::Contains(val)),
                    "regex" => Ok(MatchOp::Regex(val)),
                    _ => Err(de::Error::custom(format!("unknown match op: {key}"))),
                }
            }
        }
        deserializer.deserialize_map(MatchOpVisitor)
    }
}

/// Condition tree.
#[derive(Clone, Debug)]
pub enum Condition {
    All(Vec<Condition>),
    Any(Vec<Condition>),
    Not(Box<Condition>),
    IpIn(Vec<String>),
    PathMatches(MatchOp),
    HostMatches(MatchOp),
    Method(Vec<String>),
    HeaderMatches { name: String, op: MatchOp },
    QueryMatches { name: String, op: MatchOp },
    BodyMatches(MatchOp),
    CookieMatches { name: String, op: MatchOp },
    JwtClaim { path: String, op: MatchOp },
    BotClass(Vec<String>),
    ThreatFeed { id: String, min_confidence: u32 },
    SchemaViolation,
    True,
}

impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CondVisitor;
        impl<'de> Visitor<'de> for CondVisitor {
            type Value = Condition;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a condition: bool true, or a map with one key")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Condition, E> {
                if v { Ok(Condition::True) } else { Err(E::custom("false not supported")) }
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Condition, E> {
                if v == "true" || v == "schema_violation" {
                    match v {
                        "true" => Ok(Condition::True),
                        "schema_violation" => Ok(Condition::SchemaViolation),
                        _ => Err(E::custom(format!("unknown string condition: {v}"))),
                    }
                } else {
                    Err(E::custom(format!("unknown string condition: {v}")))
                }
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Condition, A::Error> {
                let key: String = map.next_key()?.ok_or_else(|| de::Error::custom("empty map"))?;
                match key.as_str() {
                    "all" => Ok(Condition::All(map.next_value()?)),
                    "any" => Ok(Condition::Any(map.next_value()?)),
                    "not" => Ok(Condition::Not(Box::new(map.next_value()?))),
                    "ip_in" => Ok(Condition::IpIn(map.next_value()?)),
                    "path_matches" => Ok(Condition::PathMatches(map.next_value()?)),
                    "host_matches" => Ok(Condition::HostMatches(map.next_value()?)),
                    "method" => Ok(Condition::Method(map.next_value()?)),
                    "body_matches" => Ok(Condition::BodyMatches(map.next_value()?)),
                    "bot_class" => Ok(Condition::BotClass(map.next_value()?)),
                    "header_matches" => {
                        #[derive(Deserialize)]
                        struct HM { name: String, op: MatchOp }
                        let hm: HM = map.next_value()?;
                        Ok(Condition::HeaderMatches { name: hm.name, op: hm.op })
                    }
                    "query_matches" => {
                        #[derive(Deserialize)]
                        struct QM { name: String, op: MatchOp }
                        let qm: QM = map.next_value()?;
                        Ok(Condition::QueryMatches { name: qm.name, op: qm.op })
                    }
                    "cookie_matches" => {
                        #[derive(Deserialize)]
                        struct CM { name: String, op: MatchOp }
                        let cm: CM = map.next_value()?;
                        Ok(Condition::CookieMatches { name: cm.name, op: cm.op })
                    }
                    "jwt_claim" => {
                        #[derive(Deserialize)]
                        struct JC { path: String, op: MatchOp }
                        let jc: JC = map.next_value()?;
                        Ok(Condition::JwtClaim { path: jc.path, op: jc.op })
                    }
                    "threat_feed" => {
                        #[derive(Deserialize)]
                        struct TF { id: String, min_confidence: u32 }
                        let tf: TF = map.next_value()?;
                        Ok(Condition::ThreatFeed { id: tf.id, min_confidence: tf.min_confidence })
                    }
                    _ => Err(de::Error::custom(format!("unknown condition: {key}"))),
                }
            }
        }
        deserializer.deserialize_any(CondVisitor)
    }
}

/// What the rule does when it matches.
#[derive(Clone, Debug)]
pub enum RuleAction {
    Allow,
    Block { status: u16 },
    Challenge { level: String },
    RateLimit { key: String, limit: u64, window_s: u32 },
    RaiseRisk(u32),
    LogOnly,
}

impl<'de> Deserialize<'de> for RuleAction {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ActionVisitor;
        impl<'de> Visitor<'de> for ActionVisitor {
            type Value = RuleAction;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("\"allow\", \"log_only\", or a map with one key")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<RuleAction, E> {
                match v {
                    "allow" => Ok(RuleAction::Allow),
                    "log_only" => Ok(RuleAction::LogOnly),
                    _ => Err(E::custom(format!("unknown action string: {v}"))),
                }
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<RuleAction, A::Error> {
                let key: String = map.next_key()?.ok_or_else(|| de::Error::custom("empty map"))?;
                match key.as_str() {
                    "allow" => { let _: serde::de::IgnoredAny = map.next_value()?; Ok(RuleAction::Allow) }
                    "log_only" => { let _: serde::de::IgnoredAny = map.next_value()?; Ok(RuleAction::LogOnly) }
                    "block" => {
                        #[derive(Deserialize)]
                        struct B { #[serde(default = "default_block_status")] status: u16 }
                        let b: B = map.next_value()?;
                        Ok(RuleAction::Block { status: b.status })
                    }
                    "challenge" => {
                        #[derive(Deserialize)]
                        struct C { level: String }
                        let c: C = map.next_value()?;
                        Ok(RuleAction::Challenge { level: c.level })
                    }
                    "rate_limit" => {
                        #[derive(Deserialize)]
                        struct RL { key: String, limit: u64, window_s: u32 }
                        let rl: RL = map.next_value()?;
                        Ok(RuleAction::RateLimit { key: rl.key, limit: rl.limit, window_s: rl.window_s })
                    }
                    "raise_risk" => {
                        let val: u32 = map.next_value()?;
                        Ok(RuleAction::RaiseRisk(val))
                    }
                    _ => Err(de::Error::custom(format!("unknown action: {key}"))),
                }
            }
        }
        deserializer.deserialize_any(ActionVisitor)
    }
}

fn default_block_status() -> u16 {
    403
}

impl RuleAction {
    /// Whether this action terminates rule evaluation.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            RuleAction::Allow
                | RuleAction::Block { .. }
                | RuleAction::Challenge { .. }
                | RuleAction::RateLimit { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_default_is_global() {
        assert_eq!(Scope::default(), Scope::Global);
    }

    #[test]
    fn terminal_actions() {
        assert!(RuleAction::Allow.is_terminal());
        assert!(RuleAction::Block { status: 403 }.is_terminal());
        assert!(RuleAction::Challenge { level: "js".into() }.is_terminal());
        assert!(
            RuleAction::RateLimit {
                key: "ip".into(),
                limit: 100,
                window_s: 60
            }
            .is_terminal()
        );
    }

    #[test]
    fn non_terminal_actions() {
        assert!(!RuleAction::RaiseRisk(10).is_terminal());
        assert!(!RuleAction::LogOnly.is_terminal());
    }

    #[test]
    fn match_op_variants() {
        let _exact = MatchOp::Exact("foo".into());
        let _prefix = MatchOp::Prefix("/api".into());
        let _suffix = MatchOp::Suffix(".php".into());
        let _contains = MatchOp::Contains("admin".into());
        let _regex = MatchOp::Regex(r"\d+".into());
    }
}
