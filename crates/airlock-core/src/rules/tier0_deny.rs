use crate::config::SAFE_BUILD_ARTIFACT_NAMES;
use regex::Regex;
use std::path::{Path, Component};
use std::sync::LazyLock;

pub fn is_safe_build_artifact_path(p: &str) -> bool {
    let p = p.trim_matches(|c| c == '\'' || c == '"').trim();
    if p.is_empty() {
        return false;
    }
    if p.contains('*') || p.contains('?') || p.contains('[') || p.contains(']')
        || p.contains('~') || p.contains('$') || p.contains('`') {
        return false;
    }
    if p.starts_with('/') || p.starts_with('\\') {
        return false;
    }

    let path = Path::new(p);
    let mut last_part = "";
    for comp in path.components() {
        match comp {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return false,
            Component::CurDir => continue,
            Component::Normal(os_str) => {
                if let Some(s) = os_str.to_str() {
                    last_part = s;
                } else {
                    return false;
                }
            }
        }
    }

    if last_part.is_empty() {
        return false;
    }

    SAFE_BUILD_ARTIFACT_NAMES.contains(&last_part)
}

pub fn check_recursive_rm_violations(cmd: &str) -> Option<String> {
    let subcmd_delims = Regex::new(r"(?:&&|\|\||[;\n|])").unwrap();
    for sub in subcmd_delims.split(cmd) {
        let sub = sub.trim();
        if sub.is_empty() {
            continue;
        }

        let tokens: Vec<String> = shlex::split(sub).unwrap_or_else(|| {
            sub.split_whitespace().map(|s| s.to_string()).collect()
        });

        if tokens.is_empty() {
            continue;
        }

        let mut idx = 0;
        let env_prefix_re = Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*=.*").unwrap();
        while idx < tokens.len() && env_prefix_re.is_match(&tokens[idx]) {
            idx += 1;
        }
        if idx >= tokens.len() {
            continue;
        }

        let base_cmd = Path::new(&tokens[idx])
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("");

        if base_cmd == "rm" || base_cmd == "unlink" {
            idx += 1;
            let mut has_recursive = false;
            let mut targets = Vec::new();

            while idx < tokens.len() {
                let tok = &tokens[idx];
                if tok.starts_with('-') && tok != "-" {
                    if tok == "--recursive" || (tok.contains('r') || tok.contains('R')) {
                        has_recursive = true;
                    }
                } else {
                    targets.push(tok.clone());
                }
                idx += 1;
            }

            if has_recursive {
                if targets.is_empty() {
                    return Some("Tier 0 Hard Deny: Recursive rm invocation with no explicit target".to_string());
                }
                for target in targets {
                    if !is_safe_build_artifact_path(&target) {
                        return Some(format!(
                            "Tier 0 Hard Deny: rm -rf is strictly restricted to safe build/cache directories \
                            (e.g. dist, build, node_modules, target, __pycache__). Denied for target: '{}'",
                            target
                        ));
                    }
                }
            }
        }
    }

    None
}

static PROTECTED_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    let protected_paths = [
        // Cloud & Auth Tokens
        r"~/\.gemini/antigravity-oauth-token",
        r"~/\.ssh(?:/[a-zA-Z0-9_\-\.]+)?",
        r"~/\.aws(?:/[a-zA-Z0-9_\-\.]+)?",
        r"~/\.azure",
        r"~/\.config/gcloud",
        r"~/\.gnupg",
        r"~/\.kube",
        r"~/\.netrc",
        r"~/\.git-credentials",
        r"~/\.dockercfg",
        r"~/\.docker/config\.json",
        r"~/\.npmrc",
        r"~/\.pypirc",
        r"~/\.password-store",
        r"\.env(?:\.[a-zA-Z0-9_\-]+)?",
        r"\bid_rsa\b",
        r"\bid_ed25519\b",
        r"\bid_ecdsa\b",

        // System Credentials & Keychains
        r"/etc/shadow",
        r"/etc/sudoers",
        r"~/Library/Keychains",
        r"/Library/Keychains",
        r"\.keychain(?:-db)?",
        r"~/\.local/share/keyrings",

        // Shell History
        r"~/\.bash_history",
        r"~/\.zsh_history",
        r"~/\.sh_history",
        r"~/\.history",

        // Browser Artifacts
        r"~/Library/Application(?:\s+|\\ )+Support/Google/Chrome",
        r"~/\.config/google-chrome",
        r"~/Library/Application(?:\s+|\\ )+Support/BraveSoftware",
        r"~/\.config/BraveSoftware",
        r"~/Library/Application(?:\s+|\\ )+Support/Microsoft(?:\s+|\\ )+Edge",
        r"~/\.config/microsoft-edge",
        r"~/Library/Application(?:\s+|\\ )+Support/Arc",
        r"~/Library/Application(?:\s+|\\ )+Support/Firefox",
        r"~/\.mozilla/firefox",
        r"~/Library/Cookies",
        r"Cookies\.binarycookies",
        r"Login(?:\s+|\\ )+Data",
        r"\bcookies\.sqlite\b",
        r"\blogins\.json\b",
        r"\bkey4\.db\b",
        r"~/Library/Safari",

        // Personal Messaging & Email Databases
        r"~/Library/Messages",
        r"\bchat\.db\b",
        r"Telegram(?:\s+|\\ )+Desktop",
        r"~/\.local/share/TelegramDesktop",
        r"~/Library/Application(?:\s+|\\ )+Support/Signal",
        r"~/\.config/Signal",
        r"~/Library/Application(?:\s+|\\ )+Support/WhatsApp",
        r"~/Library/Containers/desktop\.WhatsApp",
        r"~/Library/Application(?:\s+|\\ )+Support/Slack",
        r"~/\.config/Slack",
        r"~/Library/Application(?:\s+|\\ )+Support/discord",
        r"~/\.config/discord",
        r"~/Library/Mail",
        r"~/Library/Thunderbird",
        r"~/\.thunderbird",
    ];

    let pattern = format!("(?:{})", protected_paths.join("|"));
    Regex::new(&pattern).unwrap()
});

static ROOT_RM_RE1: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\brm\s+.*-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)\s+(?:--no-preserve-root\s+)?/(?:\s|\*|$)").unwrap()
});
static ROOT_RM_RE2: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\brm\s+.*-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)\s+.*--no-preserve-root\b").unwrap()
});
static CRITICAL_DIRS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\brm\s+.*-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)\s+.*(?:/system|/data|/etc|/boot|/usr|/bin|/sbin|/var|/root|/Users|/home)(?:\s|$|\*)").unwrap()
});
static DD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bdd\s+.*of=/dev/(?:sd[a-z]|nvme[0-9]|block/|disk|rdisk)").unwrap()
});
static MKFS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bmkfs(?:\.[a-z0-9]+)?\s+/dev/").unwrap()
});
static PASSWD_OVERWRITE_RE1: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r">\s*(?:/etc/passwd|/etc/shadow|/etc/sudoers)\b").unwrap()
});
static PASSWD_OVERWRITE_RE2: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\btee\s+(?:-a\s+)?(?:/etc/passwd|/etc/shadow|/etc/sudoers)\b").unwrap()
});
static FIND_DESTRUCT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bfind\s+.*\s+(?:-delete|-exec\s+rm|-execdir\s+rm)\b").unwrap()
});
static ENV_RM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\benv\s+.*rm\s+-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)\b").unwrap()
});
static REVERSE_SHELL_RE1: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:nc|ncat|netcat|socat)\s+.*-(?:e|c)\s+/bin/(?:sh|bash)\b").unwrap()
});
static REVERSE_SHELL_RE2: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/dev/tcp/[0-9a-zA-Z\.\-]+/[0-9]+").unwrap()
});
static TUNNEL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:ngrok|localtunnel|cloudflared(?:\s+tunnel)?|bore\s+local|frpc)\b").unwrap()
});
static CURL_SH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:curl|wget)\b.*\|\s*(?:sh|bash|zsh|python[0-9.]*|perl|ruby)\b").unwrap()
});
static BROWSER_DEBUG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:google-chrome|chromium|brave|chrome|msedge|firefox|safari)\b.*--(?:remote-debugging-port|remote-debugging-pipe)").unwrap()
});
static CRED_ECHO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:echo|printf)\s+.*\$[A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE)").unwrap()
});
static CRED_PRINTENV_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:printenv|env)\s+.*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE)").unwrap()
});
static NETWORK_TOOLS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:curl|wget|nc|ncat|netcat|socat|scp|rsync|sftp)\b").unwrap()
});
static READ_TOOLS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:cat|head|tail|grep|more|less|strings|xxd|hexdump|od|awk|sed|cp|mv|tar|zip)\s+").unwrap()
});
static SQLITE_ABUSE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bsqlite3\b.*\.output\s+/(?:etc|bin|usr|var|system)").unwrap()
});
static BASE64_PIPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bbase64\s+-(?:d|-decode)\s*\|\s*(?:sh|bash|zsh)\b").unwrap()
});
static PYTHON_DESTRUCT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bpython[0-9.]*\s+.*(?:__import__\(|posix|system|unlink|rmdir|rmtree)").unwrap()
});

pub fn check_tier0_hard_deny(cmd: &str) -> Option<String> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return Some("Empty command".to_string());
    }

    if let Some(rm_viol) = check_recursive_rm_violations(trimmed) {
        return Some(rm_viol);
    }

    if ROOT_RM_RE1.is_match(trimmed) || ROOT_RM_RE2.is_match(trimmed) {
        return Some("Tier 0 Hard Deny: Destructive root filesystem deletion detected".to_string());
    }

    if CRITICAL_DIRS_RE.is_match(trimmed) {
        return Some("Tier 0 Hard Deny: Critical system path deletion detected".to_string());
    }

    if DD_RE.is_match(trimmed) {
        return Some("Tier 0 Hard Deny: Direct partition/disk overwrite operation".to_string());
    }
    if MKFS_RE.is_match(trimmed) {
        return Some("Tier 0 Hard Deny: Partition format operation".to_string());
    }

    if PASSWD_OVERWRITE_RE1.is_match(trimmed) || PASSWD_OVERWRITE_RE2.is_match(trimmed) {
        return Some("Tier 0 Hard Deny: Attempt to overwrite system authentication files".to_string());
    }

    if FIND_DESTRUCT_RE.is_match(trimmed) {
        return Some("Tier 0 Hard Deny: Destructive find operation".to_string());
    }

    if ENV_RM_RE.is_match(trimmed) {
        return Some("Tier 0 Hard Deny: Destructive command execution via env".to_string());
    }

    if trimmed.contains(":(){ :|:& };:") || trimmed.contains(":(){ :|:&};:") {
        return Some("Tier 0 Hard Deny: Fork bomb detected".to_string());
    }

    if REVERSE_SHELL_RE1.is_match(trimmed) || REVERSE_SHELL_RE2.is_match(trimmed) {
        return Some("Tier 0 Hard Deny: Reverse shell invocation detected".to_string());
    }

    if TUNNEL_RE.is_match(trimmed) {
        return Some("Tier 0 Hard Deny: Unauthorized tunneling or port proxying utility detected".to_string());
    }

    if CURL_SH_RE.is_match(trimmed) {
        return Some("Tier 0 Hard Deny: Unverified remote script execution pipe (curl|sh) detected".to_string());
    }

    if BROWSER_DEBUG_RE.is_match(trimmed) {
        return Some("Tier 0 Hard Deny: Browser session debugging / remote profile takeover attempt detected".to_string());
    }

    if CRED_ECHO_RE.is_match(trimmed) || CRED_PRINTENV_RE.is_match(trimmed) {
        return Some("Tier 0 Hard Deny: Credential materialization from environment variable detected".to_string());
    }

    let has_protected = PROTECTED_REGEX.is_match(trimmed);

    // Network exfiltration
    if NETWORK_TOOLS_RE.is_match(trimmed) {
        if has_protected || trimmed.contains("AWS_SECRET_ACCESS_KEY") {
            return Some("Tier 0 Hard Deny: Exfiltration of credentials, personal data, or protected paths".to_string());
        }
        let lower = trimmed.to_lowercase();
        if lower.contains("token=") || lower.contains("secret=") || lower.contains("password=")
            || lower.contains("credential=") || lower.contains("bearer=") {
            return Some("Tier 0 Hard Deny: Exfiltration of credentials, personal data, or protected paths".to_string());
        }
    }

    // Direct read / inspection
    if READ_TOOLS_RE.is_match(trimmed) && has_protected {
        return Some("Tier 0 Hard Deny: Direct access to protected credentials, browser sessions, or personal communication data".to_string());
    }

    if SQLITE_ABUSE_RE.is_match(trimmed) {
        return Some("Tier 0 Hard Deny: Sqlite file write to system directory".to_string());
    }

    if PYTHON_DESTRUCT_RE.is_match(trimmed) && (trimmed.contains("rm ") || trimmed.contains("system")) {
        return Some("Tier 0 Hard Deny: Obfuscated system execution via Python".to_string());
    }

    if BASE64_PIPE_RE.is_match(trimmed) {
        return Some("Tier 0 Hard Deny: Encoded payload execution pipe".to_string());
    }

    None
}
