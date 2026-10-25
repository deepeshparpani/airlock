from airlock.classifier.stage1 import (
    build_stage1_prompt,
    query_stage1_daemon,
    query_stage1_fallback,
    get_daemon_conn,
    spawn_daemon,
)
from airlock.classifier.stage2 import escalate_to_stage2

def evaluate_command(redacted_cmd: str, daemon_script: str | None = None) -> tuple[str, str]:
    """
    Evaluates a command using the two-stage classifier architecture.
    Returns (decision, reason).
    """
    stage1_prompt = build_stage1_prompt(redacted_cmd)
    stage1_res = query_stage1_daemon(stage1_prompt, daemon_script=daemon_script)
    if not stage1_res:
        stage1_res = query_stage1_fallback(stage1_prompt)

    if not stage1_res:
        return "deny", "Security Classifier Error: Daemon and fallback unavailable"

    confidence = stage1_res.get("confidence", "high").lower()
    decision = stage1_res.get("decision", "deny").lower()
    reason = stage1_res.get("reason", "")
    thinking = stage1_res.get("thinking", "")

    # Stage 1 High Confidence
    if confidence == "high":
        return decision, reason

    # Low Confidence -> Escalate to Stage 2 Deep Review
    stage2_res = escalate_to_stage2(redacted_cmd, thinking, reason)
    s2_decision = stage2_res.get("decision", "deny").lower()
    s2_risk = stage2_res.get("risk_category", "suspicious")
    s2_reason = stage2_res.get("reason", reason)

    return s2_decision, f"Stage 2 [{s2_risk}]: {s2_reason}"

__all__ = [
    "evaluate_command",
    "build_stage1_prompt",
    "query_stage1_daemon",
    "query_stage1_fallback",
    "escalate_to_stage2",
    "get_daemon_conn",
    "spawn_daemon",
]
