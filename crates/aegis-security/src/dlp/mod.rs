pub mod fpe;

use regex::Regex;
use std::sync::LazyLock;

/// DLP action to take on a match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DlpAction {
    Redact,
    Mask,
    Block,
    Monitor,
}

/// A DLP pattern match.
#[derive(Clone, Debug)]
pub struct DlpMatch {
    pub pattern_name: String,
    pub matched_value: String,
    pub action: DlpAction,
}

/// DLP pattern definition.
struct DlpPattern {
    name: &'static str,
    regex: Regex,
    validator: Option<fn(&str) -> bool>,
}

static DLP_PATTERNS: LazyLock<Vec<DlpPattern>> = LazyLock::new(|| {
    vec![
        DlpPattern {
            name: "credit_card",
            regex: Regex::new(r"\b(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})\b").unwrap(),
            validator: Some(luhn_check),
        },
        DlpPattern {
            name: "ssn",
            regex: Regex::new(r"\b(\d{3}-\d{2}-\d{4})\b").unwrap(),
            validator: Some(ssn_validate),
        },
        DlpPattern {
            name: "iban",
            regex: Regex::new(r"\b([A-Z]{2}\d{2}[A-Z0-9]{4,30})\b").unwrap(),
            validator: Some(iban_mod97),
        },
        DlpPattern {
            name: "email",
            regex: Regex::new(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b").unwrap(),
            validator: None,
        },
        DlpPattern {
            name: "phone",
            regex: Regex::new(r"\b(\+?\d{1,3}[\s-]?\(?\d{1,4}\)?[\s-]?\d{3,4}[\s-]?\d{4})\b").unwrap(),
            validator: None,
        },
        DlpPattern {
            name: "aws_key",
            regex: Regex::new(r"\b(AKIA[0-9A-Z]{16})\b").unwrap(),
            validator: None,
        },
        DlpPattern {
            name: "aws_secret",
            regex: Regex::new(r"(?i)(?:aws_secret_access_key|secret_key)\s*[=:]\s*([A-Za-z0-9/+=]{40})").unwrap(),
            validator: None,
        },
        DlpPattern {
            name: "github_token",
            regex: Regex::new(r"\b(gh[ps]_[A-Za-z0-9_]{36,})\b").unwrap(),
            validator: None,
        },
        DlpPattern {
            name: "stripe_key",
            regex: Regex::new(r"\b(sk_(?:live|test)_[A-Za-z0-9]{24,})\b").unwrap(),
            validator: None,
        },
        DlpPattern {
            name: "slack_token",
            regex: Regex::new(r"\b(xox[bpars]-[A-Za-z0-9-]+)\b").unwrap(),
            validator: None,
        },
        DlpPattern {
            name: "pem_private_key",
            regex: Regex::new(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----").unwrap(),
            validator: None,
        },
        DlpPattern {
            name: "jwt",
            regex: Regex::new(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)\b").unwrap(),
            validator: None,
        },
    ]
});

/// Scan text for DLP-sensitive data.
pub fn scan(text: &str) -> Vec<DlpMatch> {
    let mut matches = Vec::new();
    for pat in DLP_PATTERNS.iter() {
        for cap in pat.regex.captures_iter(text) {
            let value = cap.get(1).map_or(cap.get(0).unwrap().as_str(), |m| m.as_str());
            if let Some(validator) = pat.validator {
                if !validator(value) {
                    continue;
                }
            }
            matches.push(DlpMatch {
                pattern_name: pat.name.into(),
                matched_value: value.into(),
                action: DlpAction::Mask,
            });
        }
    }
    matches
}

/// Mask a credit card: `****-****-****-1234`.
pub fn mask_credit_card(cc: &str) -> String {
    let digits: String = cc.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 4 {
        return "****".to_string();
    }
    let last4 = &digits[digits.len() - 4..];
    format!("****-****-****-{last4}")
}

/// Mask an SSN: `***-**-1234`.
pub fn mask_ssn(ssn: &str) -> String {
    let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 4 {
        return "***-**-****".to_string();
    }
    let last4 = &digits[digits.len() - 4..];
    format!("***-**-{last4}")
}

/// Mask an email: `j***@example.com`.
pub fn mask_email(email: &str) -> String {
    if let Some(at) = email.find('@') {
        let local = &email[..at];
        let domain = &email[at..];
        if local.len() <= 1 {
            format!("*{domain}")
        } else {
            let first = &local[..1];
            format!("{first}***{domain}")
        }
    } else {
        "***".to_string()
    }
}

/// Redact text by replacing all DLP matches with `[REDACTED]`.
pub fn redact(text: &str) -> String {
    let mut result = text.to_string();
    for pat in DLP_PATTERNS.iter() {
        result = pat.regex.replace_all(&result, "[REDACTED]").to_string();
    }
    result
}

/// Luhn check for credit card numbers.
fn luhn_check(cc: &str) -> bool {
    let digits: Vec<u32> = cc
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

fn ssn_validate(ssn: &str) -> bool {
    let parts: Vec<&str> = ssn.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let area: u32 = parts[0].parse().unwrap_or(0);
    let group: u32 = parts[1].parse().unwrap_or(0);
    let serial: u32 = parts[2].parse().unwrap_or(0);
    area > 0 && area != 666 && area < 900 && group > 0 && serial > 0
}

fn iban_mod97(iban: &str) -> bool {
    if iban.len() < 5 {
        return false;
    }
    // Move first 4 chars to end.
    let rearranged = format!("{}{}", &iban[4..], &iban[..4]);
    // Convert letters to numbers (A=10, B=11, etc.).
    let mut numeric = String::new();
    for ch in rearranged.chars() {
        if ch.is_ascii_digit() {
            numeric.push(ch);
        } else if ch.is_ascii_uppercase() {
            let n = (ch as u32) - ('A' as u32) + 10;
            numeric.push_str(&n.to_string());
        } else {
            return false;
        }
    }
    // Mod 97 check.
    let mut remainder = 0u64;
    for ch in numeric.chars() {
        remainder = (remainder * 10 + ch.to_digit(10).unwrap_or(0) as u64) % 97;
    }
    remainder == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    // Credit card tests.
    #[test]
    fn detect_visa() {
        let matches = scan("Card: 4111-1111-1111-1111");
        assert!(matches.iter().any(|m| m.pattern_name == "credit_card"));
    }

    #[test]
    fn detect_mastercard() {
        let matches = scan("Card: 5500 0000 0000 0004");
        assert!(matches.iter().any(|m| m.pattern_name == "credit_card"));
    }

    #[test]
    fn reject_invalid_luhn() {
        let matches = scan("Card: 4111-1111-1111-1112");
        assert!(!matches.iter().any(|m| m.pattern_name == "credit_card"));
    }

    #[test]
    fn mask_cc() {
        assert_eq!(mask_credit_card("4111-1111-1111-1111"), "****-****-****-1111");
        assert_eq!(mask_credit_card("4111111111111111"), "****-****-****-1111");
    }

    // SSN tests.
    #[test]
    fn detect_ssn() {
        let matches = scan("SSN: 123-45-6789");
        assert!(matches.iter().any(|m| m.pattern_name == "ssn"));
    }

    #[test]
    fn reject_invalid_ssn() {
        let matches = scan("SSN: 000-45-6789");
        assert!(!matches.iter().any(|m| m.pattern_name == "ssn"));
    }

    #[test]
    fn mask_ssn_test() {
        assert_eq!(mask_ssn("123-45-6789"), "***-**-6789");
    }

    // IBAN tests.
    #[test]
    fn detect_iban_gb() {
        let matches = scan("IBAN: GB29NWBK60161331926819");
        assert!(matches.iter().any(|m| m.pattern_name == "iban"));
    }

    #[test]
    fn detect_iban_de() {
        let matches = scan("IBAN: DE89370400440532013000");
        assert!(matches.iter().any(|m| m.pattern_name == "iban"));
    }

    // Email tests.
    #[test]
    fn detect_email() {
        let matches = scan("Email: john@example.com");
        assert!(matches.iter().any(|m| m.pattern_name == "email"));
    }

    #[test]
    fn mask_email_test() {
        assert_eq!(mask_email("john@example.com"), "j***@example.com");
        assert_eq!(mask_email("a@b.com"), "*@b.com");
    }

    // API key tests.
    #[test]
    fn detect_aws_key() {
        let matches = scan("Key: AKIAIOSFODNN7EXAMPLE");
        assert!(matches.iter().any(|m| m.pattern_name == "aws_key"));
    }

    #[test]
    fn detect_github_token() {
        let matches = scan("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        assert!(matches.iter().any(|m| m.pattern_name == "github_token"));
    }

    #[test]
    fn detect_stripe_key() {
        let matches = scan("Key: sk_live_ABCDEFGHIJKLMNOPQRSTUVWx");
        assert!(matches.iter().any(|m| m.pattern_name == "stripe_key"));
    }

    #[test]
    fn detect_slack_token() {
        let matches = scan("Token: xoxb-123456789012-ABCDEFGHIJKL");
        assert!(matches.iter().any(|m| m.pattern_name == "slack_token"));
    }

    #[test]
    fn detect_pem_key() {
        let matches = scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----");
        assert!(matches.iter().any(|m| m.pattern_name == "pem_private_key"));
    }

    #[test]
    fn detect_jwt() {
        let matches = scan("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456");
        assert!(matches.iter().any(|m| m.pattern_name == "jwt"));
    }

    // Redact test.
    #[test]
    fn redact_credit_card() {
        let text = "Card: 4111-1111-1111-1111 was charged";
        let redacted = redact(text);
        assert!(!redacted.contains("4111"));
        assert!(redacted.contains("[REDACTED]"));
    }

    // Clean text.
    #[test]
    fn clean_text_no_matches() {
        let matches = scan("Hello world, nothing sensitive here.");
        assert!(matches.is_empty());
    }

    #[test]
    fn luhn_valid() {
        assert!(luhn_check("4111111111111111"));
        assert!(luhn_check("5500000000000004"));
    }

    #[test]
    fn luhn_invalid() {
        assert!(!luhn_check("4111111111111112"));
        assert!(!luhn_check("1234"));
    }

    #[test]
    fn iban_valid() {
        assert!(iban_mod97("GB29NWBK60161331926819"));
        assert!(iban_mod97("DE89370400440532013000"));
    }

    #[test]
    fn iban_invalid() {
        assert!(!iban_mod97("GB00NWBK60161331926819"));
        assert!(!iban_mod97("XX"));
    }
}
