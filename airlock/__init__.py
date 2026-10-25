"""
Airlock - AI Command Security Classifier for Autonomous Coding Agents
"""

__version__ = "1.0.0"

from airlock.rules import check_tier0_hard_deny, is_safe_fast_path, redact_secrets
from airlock.classifier import evaluate_command
from airlock.hook import run_hook, emit_verdict

__all__ = [
    "__version__",
    "check_tier0_hard_deny",
    "is_safe_fast_path",
    "redact_secrets",
    "evaluate_command",
    "run_hook",
    "emit_verdict",
]
