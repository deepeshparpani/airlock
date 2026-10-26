use crate::config::is_trusted_remote_host;
use std::path::Path;

pub const CLUSTER_INSPECTION_COMMANDS: &[&str] = &[
    "sinfo", "squeue", "pestat", "nodestat", "nvidia-smi", "hostname",
    "uptime", "whoami", "uname", "w", "ps", "gpustat", "sstat", "sacct",
];

pub fn has_shell_control_or_substitution(cmd: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let chars: Vec<char> = cmd.chars().collect();
    let n = chars.len();
    let mut i = 0;

    while i < n {
        let c = chars[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if c == '\\' && !in_single {
            escaped = true;
            i += 1;
            continue;
        }
        if c == '\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if c == '"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }

        if in_double {
            if c == '`' {
                return true;
            }
            if c == '$' && i + 1 < n {
                let next_c = chars[i + 1];
                if next_c == '(' || next_c == '{' || next_c == '*' || next_c == '@'
                    || next_c == '?' || next_c == '#' || next_c == '$' || next_c == '!'
                    || next_c.is_alphanumeric() || next_c == '_'
                {
                    return true;
                }
            }
            i += 1;
            continue;
        }

        if !in_single && !in_double {
            if c == '`' || c == '$' {
                return true;
            }
            if c == '|' || c == ';' || c == '&' || c == '>' || c == '<' || c == '\n' || c == '(' || c == ')' {
                return true;
            }
        }

        i += 1;
    }

    if in_single || in_double {
        return true;
    }

    false
}

pub fn parse_ssh_command(cmd: &str) -> (Option<String>, Option<String>) {
    let tokens: Vec<String> = shlex::split(cmd).unwrap_or_else(|| {
        cmd.split_whitespace().map(|s| s.to_string()).collect()
    });

    if tokens.is_empty() {
        return (None, None);
    }

    let base_cmd = Path::new(&tokens[0])
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("");

    if base_cmd != "ssh" {
        return (None, None);
    }

    let flags_with_arg = [
        "-p", "-i", "-o", "-l", "-F", "-c", "-b", "-E", "-e", "-J", "-m", "-O", "-S", "-W", "-w",
    ];

    let mut idx = 1;
    let mut host = None;
    let mut remote_tokens = Vec::new();

    while idx < tokens.len() {
        let tok = &tokens[idx];
        if flags_with_arg.contains(&tok.as_str()) {
            idx += 2;
            continue;
        }
        if tok.starts_with('-') {
            idx += 1;
            continue;
        }

        host = Some(tok.clone());
        idx += 1;
        if idx < tokens.len() {
            remote_tokens = tokens[idx..].to_vec();
        }
        break;
    }

    let remote_cmd = if remote_tokens.is_empty() {
        None
    } else {
        Some(remote_tokens.join(" ").trim().to_string())
    };

    (host, remote_cmd)
}

pub fn is_safe_cluster_inspection(cmd: &str) -> bool {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return false;
    }

    for cic in CLUSTER_INSPECTION_COMMANDS {
        if trimmed == *cic || trimmed.starts_with(&format!("{} ", cic)) {
            return true;
        }
    }
    if trimmed.starts_with("scontrol show ") {
        return true;
    }

    // Remote SSH execution on trusted cluster host (e.g. cook.cs.umass.edu)
    let (host, remote_cmd) = parse_ssh_command(trimmed);
    if let Some(ref h) = host {
        if is_trusted_remote_host(h) {
            if remote_cmd.is_none() {
                return true;
            }
            let remote = remote_cmd.unwrap();
            let remote_clean = remote.trim_matches(|c| c == '\'' || c == '"');

            for cic in CLUSTER_INSPECTION_COMMANDS {
                if remote_clean == *cic
                    || remote_clean.starts_with(&format!("{} ", cic))
                    || remote_clean.starts_with(&format!("{};", cic))
                    || remote_clean.starts_with(&format!("{}&", cic))
                {
                    return true;
                }
            }
            if remote_clean.starts_with("scontrol show ") {
                return true;
            }
        }
    }

    false
}

pub fn is_safe_fast_path(command_line: &str) -> bool {
    let cmd = command_line.trim();
    if cmd.is_empty() {
        return false;
    }

    if is_safe_cluster_inspection(cmd) {
        return true;
    }

    // Safe chained directory navigation: cd <path> && <safe_cmd>
    if cmd.starts_with("cd ") && cmd.contains("&&") {
        let parts: Vec<&str> = cmd.split("&&").map(|s| s.trim()).collect();
        if parts.len() == 2 && parts[0].starts_with("cd ") {
            let cd_target = parts[0][3..].trim();
            if !cd_target.contains('`') && !cd_target.contains('$') && !cd_target.contains(';') && !cd_target.contains('|') {
                if is_safe_fast_path(parts[1]) {
                    return true;
                }
            }
        }
    }

    if has_shell_control_or_substitution(cmd) {
        return false;
    }

    let lower_cmd = cmd.to_lowercase();
    let sensitive_keywords = [
        ".ssh", ".gemini", ".aws", ".azure", "gcloud", ".gnupg", ".kube", "id_rsa", "id_ed25519",
        "id_ecdsa", "oauth", "shadow", "sudoers", ".env", "token", "secret", "password", "credential",
        "keychain", "cookies", "login data", "chat.db", "messages", "telegram", "signal", "whatsapp",
        "slack", "discord", "chrome", "brave", "safari", "firefox", "history", ".netrc", ".git-credentials",
        "/dev/",
    ];
    for sk in sensitive_keywords {
        if lower_cmd.contains(sk) {
            return false;
        }
    }

    // Support git directory flags: git -C <dir> log/status/diff/show/branch
    if cmd.starts_with("git -C ") || cmd.starts_with("git --git-dir") {
        if let Some(tokens) = shlex::split(cmd) {
            let mut idx = 1;
            while idx < tokens.len() {
                if tokens[idx] == "-C" {
                    idx += 2;
                } else if tokens[idx].starts_with("--git-dir") || tokens[idx].starts_with("--work-tree") {
                    idx += 1;
                } else {
                    break;
                }
            }
            if idx < tokens.len() {
                let subcmd = &tokens[idx];
                if ["status", "log", "diff", "show", "branch", "tag"].contains(&subcmd.as_str()) {
                    if !cmd.contains("--output") {
                        return true;
                    }
                }
            }
        }
    }

    let safe_read_commands = [
        "ls", "pwd", "whoami", "git status", "git log", "git diff", "git show",
        "git branch", "git tag", "wc", "date", "uname", "tree", "stat", "file", "which",
    ];
    for sc in safe_read_commands {
        if cmd == sc || cmd.starts_with(&format!("{} ", sc)) {
            if (sc == "git diff" || sc == "git log" || sc == "git show") && cmd.contains("--output") {
                return false;
            }
            return true;
        }
    }

    if cmd == "find" || cmd.starts_with("find ") {
        let danger_find = ["-exec", "-execdir", "-ok", "-okdir", "-delete"];
        for df in danger_find {
            if cmd.contains(df) {
                return false;
            }
        }
        return true;
    }

    let safe_text_readers = ["cat ", "head ", "tail ", "grep "];
    for r in safe_text_readers {
        if cmd.starts_with(r) {
            return true;
        }
    }

    if cmd == "echo 'hello world'" || cmd == r#"echo "hello world""# || (cmd.starts_with("echo ") && !cmd.contains('$') && !cmd.contains('`')) {
        return true;
    }
    if cmd == "bash install.sh" || cmd == "./install.sh" || cmd == "sh install.sh" {
        return true;
    }
    if cmd == r#"python3 -c "import sys; print(sys.version)""# || cmd == "python3 --version" || cmd == "python --version" {
        return true;
    }
    if cmd == r#"sqlite3 :memory: "SELECT 1;""# {
        return true;
    }

    // Safe build artifact cleanup (e.g. rm -rf dist, rm -rf build/)
    if cmd.starts_with("rm ") {
        let tokens: Vec<String> = shlex::split(cmd).unwrap_or_default();
        if tokens.len() >= 2 {
            let mut all_safe = true;
            let mut has_target = false;
            for tok in &tokens[1..] {
                if tok.starts_with('-') {
                    continue;
                }
                has_target = true;
                if !crate::rules::is_safe_build_artifact_path(tok) {
                    all_safe = false;
                    break;
                }
            }
            if has_target && all_safe {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_diagnostics() {
        assert!(is_safe_fast_path("ls -la"));
        assert!(is_safe_fast_path("pwd"));
        assert!(is_safe_fast_path("git status"));
        assert!(is_safe_fast_path("git log -n 5"));
        assert!(is_safe_fast_path("cat src/main.rs"));
        assert!(is_safe_fast_path("grep -rn 'fn main' ."));
    }

    #[test]
    fn test_cluster_inspection() {
        assert!(is_safe_cluster_inspection("ssh cook.cs.umass.edu 'sinfo'"));
        assert!(is_safe_cluster_inspection("ssh danny@cook.cs.umass.edu 'squeue'"));
        assert!(is_safe_cluster_inspection("sinfo"));
    }

    #[test]
    fn test_rejects_substitutions_and_pipes() {
        assert!(!is_safe_fast_path("ls | grep secret"));
        assert!(!is_safe_fast_path("echo $(whoami)"));
        assert!(!is_safe_fast_path("cat `ls`"));
    }

    #[test]
    fn test_safe_git_directory_and_cd_chaining() {
        assert!(is_safe_fast_path("git -C /Users/danny/bkc-pilot log -5"));
        assert!(is_safe_fast_path("cd /Users/danny/bkc-pilot && git log -n 5 --oneline"));
        assert!(is_safe_fast_path("cd /Users/danny/bkc-pilot && git status"));
        assert!(!is_safe_fast_path("cd /Users/danny/bkc-pilot && rm -rf /"));
        assert!(!is_safe_fast_path("cd `rm -rf /` && git status"));
    }
}
