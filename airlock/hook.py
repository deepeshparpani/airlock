import sys
import os
import json
import time

from airlock.terminal import format_latency, print_to_terminal
from airlock.rules import check_tier0_hard_deny, is_safe_fast_path, redact_secrets
from airlock.classifier import evaluate_command

def emit_verdict(decision: str, reason: str, start_time: float):
    elapsed = time.perf_counter() - start_time
    is_allowed = decision.lower() == "allow"
    latency_str = format_latency(elapsed)
    if is_allowed:
        prefix = f"allowed by Danny's custom classifier ({latency_str})"
        print_to_terminal(f"\033[92m✔ {prefix}\033[0m")
        print(json.dumps({
            "decision": "allow",
            "reason": f"{prefix}: {reason}"
        }))
    else:
        prefix = f"denied by Danny's custom classifier ({latency_str})"
        print_to_terminal(f"\033[91m✖ {prefix}: {reason}\033[0m")
        print(json.dumps({
            "decision": "deny",
            "reason": f"{prefix}: {reason}"
        }))

def run_hook(command_line: str, start_time: float, daemon_script: str | None = None):
    # Tier 0 Hard Deny
    tier0_deny_reason = check_tier0_hard_deny(command_line)
    if tier0_deny_reason:
        emit_verdict("deny", tier0_deny_reason, start_time)
        return

    # Tier 0 Fast Allow
    if is_safe_fast_path(command_line):
        emit_verdict("allow", "Tier 0 Fast-path: Verified safe read command", start_time)
        return

    # Secret Redaction
    redacted_cmd, _ = redact_secrets(command_line)

    # Stage 1 + Stage 2 Evaluation
    decision, reason = evaluate_command(redacted_cmd, daemon_script=daemon_script)
    emit_verdict(decision, reason, start_time)

def main(daemon_script: str | None = None):
    start_time = time.perf_counter()
    try:
        input_data = sys.stdin.read()
        if not input_data:
            emit_verdict("deny", "No input provided", start_time)
            return

        payload = json.loads(input_data)
        command_line = payload.get("toolCall", {}).get("args", {}).get("CommandLine", "")

        if os.environ.get("AGY_HOOK_BYPASS") == "1":
            print(json.dumps({
                "decision": "allow",
                "reason": "Bypass loop explicitly allowed"
            }))
            return

        run_hook(command_line, start_time, daemon_script=daemon_script)

    except Exception as e:
        emit_verdict("deny", f"Hook exception: {str(e)}", start_time)

if __name__ == "__main__":
    main()
