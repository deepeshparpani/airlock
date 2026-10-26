use airlock_core::{evaluate_tier0, redact_secrets, Decision};
use serde::Serialize;
use serde_json::Value;
use std::env;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Serialize)]
struct HookOutput {
    decision: &'static str,
    reason: String,
}

fn format_latency(micros: u128) -> String {
    if micros < 1000 {
        format!("{:.2}ms", micros as f64 / 1000.0)
    } else {
        format!("{:.2}s", micros as f64 / 1_000_000.0)
    }
}

fn print_verdict(decision: Decision, reason: &str, elapsed_micros: u128) {
    let latency_str = format_latency(elapsed_micros);
    match decision {
        Decision::Allow => {
            let prefix = format!("allowed by Danny's custom classifier ({})", latency_str);
            eprintln!("\x1b[92m✔ {}\x1b[0m", prefix);
            let out = HookOutput {
                decision: "allow",
                reason: format!("{}: {}", prefix, reason),
            };
            println!("{}", serde_json::to_string(&out).unwrap());
        }
        Decision::Deny => {
            let prefix = format!("denied by Danny's custom classifier ({})", latency_str);
            eprintln!("\x1b[91m✖ {}: {}\x1b[0m", prefix, reason);
            let out = HookOutput {
                decision: "deny",
                reason: format!("{}: {}", prefix, reason),
            };
            println!("{}", serde_json::to_string(&out).unwrap());
        }
        Decision::Escalate => {
            let prefix = format!("denied by Danny's custom classifier ({})", latency_str);
            eprintln!("\x1b[91m✖ {}: {}\x1b[0m", prefix, reason);
            let out = HookOutput {
                decision: "deny",
                reason: format!("{}: {}", prefix, reason),
            };
            println!("{}", serde_json::to_string(&out).unwrap());
        }
    }
}

fn extract_command_from_payload(raw: &str) -> Option<String> {
    if let Ok(val) = serde_json::from_str::<Value>(raw) {
        // 1. Antigravity format: toolCall.args.CommandLine / command
        if let Some(cmd) = val.pointer("/toolCall/args/CommandLine").and_then(|v| v.as_str()) {
            return Some(cmd.to_string());
        }
        if let Some(cmd) = val.pointer("/toolCall/args/command").and_then(|v| v.as_str()) {
            return Some(cmd.to_string());
        }
        // 2. Snake case: tool_call.args.CommandLine
        if let Some(cmd) = val.pointer("/tool_call/args/CommandLine").and_then(|v| v.as_str()) {
            return Some(cmd.to_string());
        }
        if let Some(cmd) = val.pointer("/tool_call/args/command").and_then(|v| v.as_str()) {
            return Some(cmd.to_string());
        }
        // 3. tool_input.CommandLine / command
        if let Some(cmd) = val.pointer("/tool_input/CommandLine").and_then(|v| v.as_str()) {
            return Some(cmd.to_string());
        }
        if let Some(cmd) = val.pointer("/tool_input/command").and_then(|v| v.as_str()) {
            return Some(cmd.to_string());
        }
        // 4. Top-level command
        if let Some(cmd) = val.get("command").and_then(|v| v.as_str()) {
            return Some(cmd.to_string());
        }
    }
    None
}

fn delegate_to_python_hook(raw_input: &str) -> bool {
    let home = env::var("HOME").unwrap_or_default();
    let script_paths = [
        format!("{}/.gemini/config/scripts/airlock_hook.py", home),
        format!("{}/.gemini/config/scripts/lgtm_hook.py", home),
        "scripts/airlock_hook.py".to_string(),
    ];

    let mut target_script = None;
    for sp in &script_paths {
        if PathBuf::from(sp).exists() {
            target_script = Some(sp.clone());
            break;
        }
    }

    let script = match target_script {
        Some(s) => s,
        None => return false,
    };

    let mut child = match Command::new("python3")
        .arg(&script)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(raw_input.as_bytes());
    }

    match child.wait() {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

fn main() {
    let start = Instant::now();

    // Check bypass
    if env::var("AGY_HOOK_BYPASS").as_deref() == Ok("1")
        || env::var("AIRLOCK_HOOK_BYPASS").as_deref() == Ok("1")
    {
        println!(r#"{{"decision":"allow","reason":"Bypass loop explicitly allowed"}}"#);
        return;
    }

    let args: Vec<String> = env::args().collect();
    let mut command: Option<String> = None;
    let mut raw_stdin = String::new();

    if args.len() > 2 && args[1] == "--cmd" {
        command = Some(args[2].clone());
    } else if args.len() > 1 && !args[1].starts_with('-') {
        command = Some(args[1..].join(" "));
    } else {
        if let Ok(_) = io::stdin().read_to_string(&mut raw_stdin) {
            let trimmed = raw_stdin.trim();
            if !trimmed.is_empty() {
                if let Some(extracted) = extract_command_from_payload(trimmed) {
                    command = Some(extracted);
                } else {
                    command = Some(trimmed.to_string());
                }
            }
        }
    }

    let cmd = match command {
        Some(c) => c,
        None => {
            print_verdict(Decision::Deny, "Empty command", start.elapsed().as_micros());
            return;
        }
    };

    let (redacted_cmd, _) = redact_secrets(&cmd);
    let verdict = evaluate_tier0(&redacted_cmd);
    let elapsed = start.elapsed().as_micros();

    match verdict.decision {
        Decision::Allow => {
            print_verdict(Decision::Allow, &verdict.reason, elapsed);
        }
        Decision::Deny => {
            print_verdict(Decision::Deny, &verdict.reason, elapsed);
        }
        Decision::Escalate => {
            // Forward to Stage 1 / Stage 2 Python daemon fallback if unresolved by Tier 0
            let forwarded_payload = if raw_stdin.is_empty() {
                serde_json::json!({
                    "toolCall": {
                        "name": "run_command",
                        "args": {
                            "CommandLine": cmd
                        }
                    }
                }).to_string()
            } else {
                raw_stdin
            };

            if !delegate_to_python_hook(&forwarded_payload) {
                print_verdict(Decision::Deny, &verdict.reason, elapsed);
            }
        }
    }
}
