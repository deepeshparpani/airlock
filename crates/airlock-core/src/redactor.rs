use regex::Regex;
use std::sync::LazyLock;

struct SecretPattern {
    pattern: Regex,
    replacement: &'static str,
}

static SECRET_PATTERNS: LazyLock<Vec<SecretPattern>> = LazyLock::new(|| {
    vec![
        SecretPattern {
            pattern: Regex::new(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b").unwrap(),
            replacement: "[REDACTED_AWS_KEY]",
        },
        SecretPattern {
            pattern: Regex::new(r"\bAWS_SECRET_ACCESS_KEY=[A-Za-z0-9/+=]{40}\b").unwrap(),
            replacement: "AWS_SECRET_ACCESS_KEY=[REDACTED_AWS_SECRET]",
        },
        SecretPattern {
            pattern: Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b").unwrap(),
            replacement: "[REDACTED_GITHUB_TOKEN]",
        },
        SecretPattern {
            pattern: Regex::new(r"\bgithub_pat_[A-Za-z0-9_]{82}\b").unwrap(),
            replacement: "[REDACTED_GITHUB_PAT]",
        },
        SecretPattern {
            pattern: Regex::new(r"\bxox[baprs]-[0-9A-Za-z]{10,48}\b").unwrap(),
            replacement: "[REDACTED_SLACK_TOKEN]",
        },
        SecretPattern {
            pattern: Regex::new(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b").unwrap(),
            replacement: "Bearer [REDACTED_BEARER_TOKEN]",
        },
        SecretPattern {
            pattern: Regex::new(r"(?s)-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----.*?-----END (?:[A-Z ]+)?PRIVATE KEY-----").unwrap(),
            replacement: "[REDACTED_PRIVATE_KEY]",
        },
    ]
});

pub fn redact_secrets(cmd: &str) -> (String, bool) {
    let mut had_secrets = false;
    let mut redacted = cmd.to_string();

    for sp in SECRET_PATTERNS.iter() {
        if sp.pattern.is_match(&redacted) {
            had_secrets = true;
            redacted = sp.pattern.replace_all(&redacted, sp.replacement).into_owned();
        }
    }

    (redacted, had_secrets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_key_redaction() {
        let (out, had) = redact_secrets("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
        assert!(had);
        assert!(out.contains("[REDACTED_AWS_KEY]"));
    }

    #[test]
    fn test_github_token_redaction() {
        let (out, had) = redact_secrets("curl -H 'Authorization: token ghp_123456789012345678901234567890123456'");
        assert!(had);
        assert!(out.contains("[REDACTED_GITHUB_TOKEN]"));
    }
}
