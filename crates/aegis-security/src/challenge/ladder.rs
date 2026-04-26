use aegis_core::decision::ChallengeLevel;
use aegis_core::tier::Tier;

/// Bot class for ladder decisions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BotClass {
    Human,
    Verified,      // known good bot (Googlebot, etc.)
    Unverified,    // claims to be a bot, not verified
    Automated,     // detected automation
    Unknown,
}

/// Determine the next challenge level given risk, human confidence, bot class, and tier.
///
/// Escalation: None → Js → PoW → Captcha → Block (returned as None = block).
///
/// - `risk`: current risk score (0–100)
/// - `human_conf`: human confidence score (0–100, higher = more likely human)
/// - `bot`: bot classification
/// - `tier`: route/request tier
///
/// Returns `Some(level)` for a challenge, or `None` if the request should be blocked.
pub fn next_level(
    risk: u32,
    human_conf: u32,
    bot: &BotClass,
    tier: &Tier,
) -> Option<ChallengeLevel> {
    // Verified bots get a pass unless very high risk.
    if *bot == BotClass::Verified && risk < 80 {
        return Some(ChallengeLevel::Js);
    }

    // Known automated + high risk → block.
    if *bot == BotClass::Automated && risk > 60 {
        return None; // block
    }

    // High human confidence → lighter challenge.
    if human_conf > 80 && risk < 60 {
        return Some(ChallengeLevel::Js);
    }

    // Tier-based escalation.
    match tier {
        Tier::Critical => escalate_critical(risk),
        Tier::High => escalate_high(risk),
        Tier::Medium => escalate_medium(risk),
        Tier::CatchAll => escalate_catchall(risk),
    }
}

fn escalate_critical(risk: u32) -> Option<ChallengeLevel> {
    match risk {
        0..=29 => Some(ChallengeLevel::Js),
        30..=49 => Some(ChallengeLevel::Pow),
        50..=69 => Some(ChallengeLevel::Captcha),
        _ => None, // block
    }
}

fn escalate_high(risk: u32) -> Option<ChallengeLevel> {
    match risk {
        0..=39 => Some(ChallengeLevel::Js),
        40..=59 => Some(ChallengeLevel::Pow),
        60..=79 => Some(ChallengeLevel::Captcha),
        _ => None,
    }
}

fn escalate_medium(risk: u32) -> Option<ChallengeLevel> {
    match risk {
        0..=49 => Some(ChallengeLevel::Js),
        50..=69 => Some(ChallengeLevel::Pow),
        70..=89 => Some(ChallengeLevel::Captcha),
        _ => None,
    }
}

fn escalate_catchall(risk: u32) -> Option<ChallengeLevel> {
    match risk {
        0..=59 => Some(ChallengeLevel::Js),
        60..=79 => Some(ChallengeLevel::Pow),
        80..=94 => Some(ChallengeLevel::Captcha),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_risk_human_gets_js() {
        let level = next_level(10, 90, &BotClass::Human, &Tier::Medium);
        assert!(matches!(level, Some(ChallengeLevel::Js)));
    }

    #[test]
    fn medium_risk_medium_tier_gets_pow() {
        let level = next_level(55, 50, &BotClass::Unknown, &Tier::Medium);
        assert!(matches!(level, Some(ChallengeLevel::Pow)));
    }

    #[test]
    fn high_risk_medium_tier_gets_captcha() {
        let level = next_level(75, 30, &BotClass::Unknown, &Tier::Medium);
        assert!(matches!(level, Some(ChallengeLevel::Captcha)));
    }

    #[test]
    fn very_high_risk_medium_tier_blocks() {
        let level = next_level(95, 10, &BotClass::Unknown, &Tier::Medium);
        assert!(level.is_none());
    }

    #[test]
    fn critical_tier_escalates_faster() {
        // At risk 35 critical already at PoW, medium would be Js.
        let critical = next_level(35, 50, &BotClass::Unknown, &Tier::Critical);
        let medium = next_level(35, 50, &BotClass::Unknown, &Tier::Medium);
        assert!(matches!(critical, Some(ChallengeLevel::Pow)));
        assert!(matches!(medium, Some(ChallengeLevel::Js)));
    }

    #[test]
    fn catchall_tier_more_lenient() {
        // At risk 65 catchall still Pow, high would be Captcha.
        let catchall = next_level(65, 50, &BotClass::Unknown, &Tier::CatchAll);
        let high = next_level(65, 50, &BotClass::Unknown, &Tier::High);
        assert!(matches!(catchall, Some(ChallengeLevel::Pow)));
        assert!(matches!(high, Some(ChallengeLevel::Captcha)));
    }

    #[test]
    fn verified_bot_lenient() {
        let level = next_level(50, 0, &BotClass::Verified, &Tier::Critical);
        assert!(matches!(level, Some(ChallengeLevel::Js)));
    }

    #[test]
    fn verified_bot_very_high_risk_follows_tier() {
        let level = next_level(85, 0, &BotClass::Verified, &Tier::Critical);
        assert!(level.is_none()); // falls through to tier-based, blocked
    }

    #[test]
    fn automated_bot_high_risk_blocks() {
        let level = next_level(65, 10, &BotClass::Automated, &Tier::Medium);
        assert!(level.is_none());
    }

    #[test]
    fn automated_bot_low_risk_gets_challenge() {
        let level = next_level(30, 10, &BotClass::Automated, &Tier::Medium);
        assert!(matches!(level, Some(ChallengeLevel::Js)));
    }

    #[test]
    fn high_confidence_low_risk_gets_js() {
        let level = next_level(40, 85, &BotClass::Unknown, &Tier::Critical);
        assert!(matches!(level, Some(ChallengeLevel::Js)));
    }
}
