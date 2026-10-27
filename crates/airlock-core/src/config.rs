use std::collections::HashSet;

pub const SAFE_BUILD_ARTIFACT_NAMES: &[&str] = &[
    "dist", "build", "node_modules", "target", "__pycache__",
    ".pytest_cache", ".turbo", ".next", ".nuxt", ".cache",
    ".parcel-cache", "coverage", ".coverage", "out", ".venv", "venv",
];

pub const DEFAULT_TRUSTED_REMOTE_HOSTS: &[&str] = &[
    "cook.cs.umass.edu",
    "*.cs.umass.edu",
    "*.umass.edu",
    "localhost",
    "127.0.0.1",
];

pub fn get_safe_build_artifacts() -> HashSet<&'static str> {
    SAFE_BUILD_ARTIFACT_NAMES.iter().copied().collect()
}

pub fn is_trusted_remote_host(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    let host_lower = host.to_lowercase();
    let mut clean_host = host_lower.trim();

    if let Some((_, after_at)) = clean_host.split_once('@') {
        clean_host = after_at;
    }
    if !clean_host.starts_with('[') {
        if let Some((before_colon, _)) = clean_host.split_once(':') {
            clean_host = before_colon;
        }
    }

    for pattern in DEFAULT_TRUSTED_REMOTE_HOSTS {
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..]; // e.g. .cs.umass.edu
            if clean_host.ends_with(suffix) && clean_host.len() > suffix.len() {
                return true;
            }
        } else if clean_host == *pattern {
            return true;
        }
    }

    false
}

pub const TERMINAL_VAR_PREFIXES: &[&str] = &[
    "ITERM_",
    "KITTY_",
    "ALACRITTY_",
    "GHOSTTY_",
    "WEZTERM_",
    "WARP_",
    "VSCODE_",
    "KONSOLE_",
    "TERM_",
    "LC_TERMINAL",
    "TMUX",
    "ZELLIJ",
    "VTE_",
];

pub const TERMINAL_VAR_EXACT: &[&str] = &[
    "COLORTERM",
    "TERMINAL_EMULATOR",
    "WINDOWID",
    "STY",
    "WINDOW",
    "HYPER_CLI",
    "TABBY_CONFIG_DIRECTORY",
    "TILIX_ID",
    "TERMINATOR_UUID",
    "TERMINATOR_DBUS_NAME",
    "TERMINATOR_DBUS_PATH",
    "FOOT_SERVER_SOCKET",
];

pub const HEADLESS_ENVS_TO_SET: &[(&str, &str)] = &[
    ("TERM", "dumb"),
    ("CI", "1"),
    ("NO_COLOR", "1"),
    ("DEBIAN_FRONTEND", "noninteractive"),
    ("PYTHONUNBUFFERED", "1"),
    ("MPLBACKEND", "Agg"),
    ("QT_QPA_PLATFORM", "offscreen"),
    ("ELECTRON_RUN_AS_NODE", "1"),
    ("AGY_HOOK_BYPASS", "1"),
    ("AIRLOCK_HOOK_BYPASS", "1"),
];

pub fn should_strip_env_var(key: &str) -> bool {
    let key_upper = key.to_ascii_uppercase();
    if TERMINAL_VAR_EXACT.contains(&key_upper.as_str()) {
        return true;
    }
    for prefix in TERMINAL_VAR_PREFIXES {
        if key_upper.starts_with(prefix) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trusted_remote_hosts() {
        assert!(is_trusted_remote_host("cook.cs.umass.edu"));
        assert!(is_trusted_remote_host("danny@cook.cs.umass.edu"));
        assert!(is_trusted_remote_host("node12.cs.umass.edu:22"));
        assert!(is_trusted_remote_host("localhost"));
        assert!(!is_trusted_remote_host("evil.com"));
        assert!(!is_trusted_remote_host("fakeumass.edu"));
    }

    #[test]
    fn test_terminal_env_stripping() {
        // iTerm2
        assert!(should_strip_env_var("ITERM_SESSION_ID"));
        assert!(should_strip_env_var("iterm_profile"));
        // Apple Terminal
        assert!(should_strip_env_var("TERM_PROGRAM"));
        assert!(should_strip_env_var("TERM_SESSION_ID"));
        // Kitty
        assert!(should_strip_env_var("KITTY_WINDOW_ID"));
        assert!(should_strip_env_var("KITTY_LISTEN_ON"));
        // Alacritty
        assert!(should_strip_env_var("ALACRITTY_LOG"));
        assert!(should_strip_env_var("ALACRITTY_SOCKET"));
        // Ghostty
        assert!(should_strip_env_var("GHOSTTY_RESOURCES_DIR"));
        // WezTerm
        assert!(should_strip_env_var("WEZTERM_UNIX_SOCKET"));
        assert!(should_strip_env_var("WEZTERM_PANE"));
        // Warp
        assert!(should_strip_env_var("WARP_SESSION_ID"));
        // VS Code
        assert!(should_strip_env_var("VSCODE_INJECTION"));
        assert!(should_strip_env_var("VSCODE_PID"));
        // tmux & screen
        assert!(should_strip_env_var("TMUX"));
        assert!(should_strip_env_var("TMUX_PANE"));
        assert!(should_strip_env_var("STY"));
        assert!(should_strip_env_var("WINDOW"));
        // VTE & Konsole
        assert!(should_strip_env_var("VTE_VERSION"));
        assert!(should_strip_env_var("KONSOLE_VERSION"));
        // Safe vars should NOT be stripped
        assert!(!should_strip_env_var("PATH"));
        assert!(!should_strip_env_var("HOME"));
        assert!(!should_strip_env_var("USER"));
        assert!(!should_strip_env_var("CARGO_HOME"));
    }
}
