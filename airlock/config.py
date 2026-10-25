import os
import json
import tempfile
import getpass

USER = getpass.getuser()
PORT_FILE = os.path.join(tempfile.gettempdir(), f"airlock_daemon_{USER}.port")
AIRLOCK_GEMINI_DIR = os.path.join(tempfile.gettempdir(), f"airlock_gemini_{USER}")
LGTM_GEMINI_DIR = AIRLOCK_GEMINI_DIR  # Backward-compatible alias
MAX_RETRIES = 3

STAGE_1_SCHEMA = {
    "type": "object",
    "properties": {
        "thinking": {"type": "string", "description": "Brief step-by-step security reasoning"},
        "decision": {"type": "string", "enum": ["allow", "deny"], "description": "Whether the command should be allowed or denied"},
        "confidence": {"type": "string", "enum": ["high", "low"], "description": "High if confident in decision, low if ambiguous or requires deep analysis"},
        "reason": {"type": "string", "description": "Brief explanation of the classification decision"}
    },
    "required": ["thinking", "decision", "confidence", "reason"]
}
STAGE_1_SCHEMA_STR = json.dumps(STAGE_1_SCHEMA)

STAGE_2_SCHEMA = {
    "type": "object",
    "properties": {
        "thinking": {"type": "string", "description": "Detailed step-by-step security analysis"},
        "decision": {"type": "string", "enum": ["allow", "deny"], "description": "Final determination on command safety"},
        "risk_category": {"type": "string", "enum": ["safe", "suspicious", "dangerous"], "description": "Risk classification"},
        "reason": {"type": "string", "description": "Detailed explanation of the security decision"}
    },
    "required": ["thinking", "decision", "risk_category", "reason"]
}
STAGE_2_SCHEMA_STR = json.dumps(STAGE_2_SCHEMA)

SAFE_BUILD_ARTIFACT_NAMES = {
    "dist", "build", "node_modules", "target", "__pycache__",
    ".pytest_cache", ".turbo", ".next", ".nuxt", ".cache",
    ".parcel-cache", "coverage", ".coverage", "out", ".venv", "venv"
}

DEFAULT_TRUSTED_REMOTE_HOSTS = [
    "cook.cs.umass.edu",
    "*.cs.umass.edu",
    "*.umass.edu",
    "localhost",
    "127.0.0.1",
]

def is_trusted_remote_host(host: str) -> bool:
    """Verifies if a remote host/destination belongs to verified development or institutional clusters."""
    if not host:
        return False
    host = host.lower().strip()
    if "@" in host:
        host = host.split("@", 1)[1]
    if ":" in host and not host.startswith("["):
        host = host.split(":", 1)[0]

    trusted = list(DEFAULT_TRUSTED_REMOTE_HOSTS)
    env_hosts = os.environ.get("AIRLOCK_TRUSTED_HOSTS", "") or os.environ.get("LGTM_TRUSTED_HOSTS", "")
    if env_hosts:
        trusted.extend([h.strip() for h in env_hosts.split(",") if h.strip()])

    import fnmatch
    for pattern in trusted:
        if fnmatch.fnmatch(host, pattern.lower()):
            return True
    return False
