pub mod config;
pub mod daemon;
pub mod redactor;
pub mod rules;

pub use config::{
    is_trusted_remote_host, should_strip_env_var, HEADLESS_ENVS_TO_SET, SAFE_BUILD_ARTIFACT_NAMES,
};
pub use daemon::{get_port_file_path, get_socket_path, CircuitBreaker, PortManifest, SingletonLock};
pub use redactor::redact_secrets;
pub use rules::{
    check_recursive_rm_violations, check_tier0_hard_deny, is_safe_build_artifact_path,
    is_safe_cluster_inspection, is_safe_fast_path,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    Escalate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier0Verdict {
    pub decision: Decision,
    pub reason: String,
}

pub fn evaluate_tier0(cmd: &str) -> Tier0Verdict {
    // 1. Check Hard Deny
    if let Some(deny_reason) = check_tier0_hard_deny(cmd) {
        return Tier0Verdict {
            decision: Decision::Deny,
            reason: deny_reason,
        };
    }

    // 2. Check Fast Allow
    if is_safe_fast_path(cmd) {
        return Tier0Verdict {
            decision: Decision::Allow,
            reason: "Tier 0 Fast-path: Verified safe read command".to_string(),
        };
    }

    // 3. Needs Escalation (Stage 1 / Stage 2)
    Tier0Verdict {
        decision: Decision::Escalate,
        reason: "Unresolved by Tier 0: requires semantic classifier evaluation".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier0_fast_path_allow() {
        let verdict = evaluate_tier0("ls -la");
        assert_eq!(verdict.decision, Decision::Allow);
    }

    #[test]
    fn test_tier0_hard_deny_root_rm() {
        let verdict = evaluate_tier0("rm -rf /");
        assert_eq!(verdict.decision, Decision::Deny);
    }

    #[test]
    fn test_tier0_escalate() {
        let verdict = evaluate_tier0("npm run build");
        assert_eq!(verdict.decision, Decision::Escalate);
    }
}
