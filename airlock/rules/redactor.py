import re

SECRET_PATTERNS = [
    (re.compile(r'\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b'), '[REDACTED_AWS_KEY]'),
    (re.compile(r'\bAWS_SECRET_ACCESS_KEY=[A-Za-z0-9/+=]{40}\b'), 'AWS_SECRET_ACCESS_KEY=[REDACTED_AWS_SECRET]'),
    (re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b'), '[REDACTED_GITHUB_TOKEN]'),
    (re.compile(r'\bgithub_pat_[A-Za-z0-9_]{82}\b'), '[REDACTED_GITHUB_PAT]'),
    (re.compile(r'\bxox[baprs]-[0-9A-Za-z]{10,48}\b'), '[REDACTED_SLACK_TOKEN]'),
    (re.compile(r'\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b'), 'Bearer [REDACTED_BEARER_TOKEN]'),
    (re.compile(r'-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z ]+)?PRIVATE KEY-----'), '[REDACTED_PRIVATE_KEY]'),
]

def redact_secrets(cmd: str) -> tuple[str, bool]:
    """Redacts known high-entropy secrets and authentication tokens before model evaluation."""
    had_secrets = False
    redacted = cmd
    for pattern, replacement in SECRET_PATTERNS:
        if pattern.search(redacted):
            had_secrets = True
            redacted = pattern.sub(replacement, redacted)
    return redacted, had_secrets
