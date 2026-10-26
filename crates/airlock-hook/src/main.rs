use airlock_core::{evaluate_tier0, redact_secrets, Decision};
use serde::{Deserialize, Serialize};
use std::env;
use std::io::{self, Read};
use std::time::Instant;

#[derive(Deserialize)]
struct HookPayload {
    command: Option<String>,
    tool_input: Option<ToolInput>,
}

#[derive(Deserialize)]
struct ToolInput {
    command: Option<String>,
    #[serde(rename = "CommandLine")]
    command_line: Option<String>,
}

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
            // For Phase 1 & 2 before daemon IPC is wired, default safe fail-closed or notify
            let prefix = format!("denied by Danny's custom classifier ({})", latency_str);
            eprintln!("\x1b[93m⚠ {}: Escalation required\x1b[0m", prefix);
            let out = HookOutput {
                decision: "deny",
                reason: format!("{}: Command requires Stage 1 daemon escalation", prefix),
            };
            println!("{}", serde_json::to_string(&out).unwrap());
        }
    }
}

fn extract_command_from_payload(raw: &str) -> Option<String> {
    if let Ok(payload) = serde_json::from_str::<HookPayload>(raw) {
        if let Some(cmd) = payload.command {
            return Some(cmd);
        }
        if let Some(ti) = payload.tool_input {
            if let Some(cmd) = ti.command {
                return Some(cmd);
            }
            if let Some(cmd) = ti.command_line {
                return Some(cmd);
            }
        }
    }
    None
}

fn main() {
    let start = Instant::now();
    let args: Vec<String> = env::args().collect();
    let mut command: Option<String> = None;

    if args.len() > 2 && args[1] == "--cmd" {
        command = Some(args[2].clone());
    } else if args.len() > 1 && !args[1].starts_with('-') {
        command = Some(args[1..].join(" "));
    } else {
        let mut buffer = String::new();
        if let Ok(_) = io::stdin().read_to_string(&mut buffer) {
            let trimmed = buffer.trim();
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

    print_verdict(verdict.decision, &verdict.reason, elapsed);
}
