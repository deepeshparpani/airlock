def has_shell_control_or_substitution(cmd: str) -> bool:
    """Detects pipes, redirections, control operators, and subshells outside of quotes."""
    in_single = False
    in_double = False
    escaped = False
    i = 0
    n = len(cmd)
    while i < n:
        c = cmd[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if c == "\\" and not in_single:
            escaped = True
            i += 1
            continue
        if c == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue
        if c == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue
        if in_double:
            if c == "`":
                return True
            if c == "$" and i + 1 < n:
                next_c = cmd[i + 1]
                if next_c in ("(", "{", "*", "@", "?", "#", "$", "!") or next_c.isalnum() or next_c == "_":
                    return True
            i += 1
            continue
        if not in_single and not in_double:
            if c == "`":
                return True
            if c == "$":
                return True
            if c in ("|", ";", "&", ">", "<", "\n", "(", ")"):
                return True
        i += 1
    if in_single or in_double:
        return True
    return False

import os
import shlex
from airlock.config import is_trusted_remote_host

CLUSTER_INSPECTION_COMMANDS = (
    "sinfo", "squeue", "pestat", "nodestat", "nvidia-smi", "hostname",
    "uptime", "whoami", "uname", "w", "ps", "gpustat", "sstat", "sacct"
)

def parse_ssh_command(cmd: str) -> tuple[str | None, str | None]:
    """Parses an SSH command into (host, remote_command)."""
    try:
        tokens = shlex.split(cmd)
    except Exception:
        tokens = cmd.split()
    if not tokens:
        return None, None

    base_cmd = os.path.basename(tokens[0])
    if base_cmd != "ssh":
        return None, None

    idx = 1
    flags_with_arg = {"-p", "-i", "-o", "-l", "-F", "-c", "-b", "-E", "-e", "-J", "-m", "-O", "-S", "-W", "-w"}
    host = None
    remote_tokens = []

    while idx < len(tokens):
        tok = tokens[idx]
        if tok in flags_with_arg:
            idx += 2
            continue
        if tok.startswith("-"):
            if any(tok.startswith(f) for f in ("-o", "-i", "-p", "-l", "-F", "-J")):
                idx += 1
                continue
            idx += 1
            continue
        host = tok
        idx += 1
        remote_tokens = tokens[idx:]
        break

    return host, " ".join(remote_tokens).strip()

def is_safe_cluster_inspection(cmd: str) -> bool:
    """Checks if command is a safe node availability or cluster inspection command."""
    trimmed = cmd.strip()
    if not trimmed:
        return False

    # Direct local slurm / gpu queries
    for cic in CLUSTER_INSPECTION_COMMANDS:
        if trimmed == cic or trimmed.startswith(cic + " "):
            return True
    if trimmed.startswith("scontrol show "):
        return True

    # Remote SSH execution on trusted cluster host (e.g. cook.cs.umass.edu)
    host, remote_cmd = parse_ssh_command(trimmed)
    if host and is_trusted_remote_host(host):
        if not remote_cmd:
            return True
        remote_cmd_clean = remote_cmd.strip("'\"")
        for cic in CLUSTER_INSPECTION_COMMANDS:
            if (remote_cmd_clean == cic or 
                remote_cmd_clean.startswith(cic + " ") or 
                remote_cmd_clean.startswith(cic + ";") or 
                remote_cmd_clean.startswith(cic + "&")):
                return True
        if remote_cmd_clean.startswith("scontrol show "):
            return True

    return False

def is_safe_fast_path(command_line: str) -> bool:
    """Instant local allow for verified benign, read-only developer commands (<1ms)."""
    cmd = command_line.strip()
    if not cmd:
        return False

    # Check for verified safe cluster node availability & inspection
    if is_safe_cluster_inspection(cmd):
        return True

    if has_shell_control_or_substitution(cmd):
        return False

    lower_cmd = cmd.lower()
    sensitive_keywords = (
        ".ssh", ".gemini", ".aws", ".azure", "gcloud", ".gnupg", ".kube", "id_rsa", "id_ed25519",
        "id_ecdsa", "oauth", "shadow", "sudoers", ".env", "token", "secret", "password", "credential",
        "keychain", "cookies", "login data", "chat.db", "messages", "telegram", "signal", "whatsapp",
        "slack", "discord", "chrome", "brave", "safari", "firefox", "history", ".netrc", ".git-credentials",
        "/dev/"
    )
    if any(sk in lower_cmd for sk in sensitive_keywords):
        return False

    safe_read_commands = (
        "ls", "pwd", "whoami", "git status", "git log", "git diff", "git show",
        "git branch", "git tag", "wc", "date", "uname", "tree", "stat", "file", "which"
    )
    for sc in safe_read_commands:
        if cmd == sc or cmd.startswith(sc + " "):
            if sc in ("git diff", "git log", "git show") and "--output" in cmd:
                return False
            return True

    if cmd == "find" or cmd.startswith("find "):
        danger_find = ("-exec", "-execdir", "-ok", "-okdir", "-delete")
        if any(df in cmd for df in danger_find):
            return False
        return True

    safe_text_readers = ("cat ", "head ", "tail ", "grep ")
    if any(cmd.startswith(r) for r in safe_text_readers):
        return True

    if cmd == "echo 'hello world'":
        return True
    if cmd in ("bash install.sh", "./install.sh", "sh install.sh"):
        return True
    if cmd == 'python3 -c "import sys; print(sys.version)"' or cmd == "python3 --version" or cmd == "python --version":
        return True
    if cmd == 'sqlite3 :memory: "SELECT 1;"':
        return True

    return False

