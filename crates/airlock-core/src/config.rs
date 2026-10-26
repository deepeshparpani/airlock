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
}
