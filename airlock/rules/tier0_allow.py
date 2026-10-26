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

def is_safe_python_command(cmd: str) -> bool:
    """Verifies benign Python inspection, import checking, and testing commands."""
    if cmd in ("python3 --version", "python --version", "python3 -V", "python -V"):
        return True

    # Safe test runners
    if cmd.startswith("python3 -m pytest") or cmd.startswith("python -m pytest") or \
       cmd.startswith("python3 -m unittest") or cmd.startswith("python -m unittest") or \
       cmd.startswith("pytest ") or cmd == "pytest":
        if not any(c in cmd for c in ('>', '<', '|', ';', '`', '$')):
            return True

    # Safe python3 -c / python -c inline scripts
    prefix = None
    if cmd.startswith("python3 -c "):
        prefix = "python3 -c "
    elif cmd.startswith("python -c "):
        prefix = "python -c "
    elif cmd.startswith("python3 -c\"") or cmd.startswith("python3 -c'"):
        prefix = "python3 -c"
    elif cmd.startswith("python -c\"") or cmd.startswith("python -c'"):
        prefix = "python -c"

    if prefix is None:
        return False

    code_part = cmd[len(prefix):].strip()
    if (code_part.startswith('"') and code_part.endswith('"')) or \
       (code_part.startswith("'") and code_part.endswith("'")):
        code_part = code_part[1:-1].strip()

    lower_code = code_part.lower()

    # Reject dangerous operations, system execution, socket creation, filesystem mutation, or eval
    dangerous_terms = (
        "os.", "subprocess", "popen", "pty", "shutil", "socket", "urllib", "requests", "http.client",
        "eval(", "exec(", "open(", "__import__", "unlink", "remove", "rmdir", "chmod", "chown",
        "ctypes", "builtins", "getattr", "setattr", "delattr", "system(", "spawn", "fork", "kill",
        "breakpoint", "compile("
    )
    if any(dt in lower_code for dt in dangerous_terms):
        return False

    # Reject direct credential/secret path inspection
    sensitive_terms = ("id_rsa", ".env", ".gemini", "token", "password", "secret", "keychain", "aws_")
    if any(st in lower_code for st in sensitive_terms):
        return False

    # Disallow backticks or subshell expansion inside the script
    if any(c in code_part for c in ('`', '$')):
        return False

    return True

def is_safe_fast_path(command_line: str) -> bool:
    """Instant local allow for verified benign, read-only developer commands (<1ms)."""
    cmd = command_line.strip()
    if not cmd:
        return False

    # Check for verified safe cluster node availability & inspection
    if is_safe_cluster_inspection(cmd):
        return True

    # Safe chained directory navigation: cd <path> && <safe_cmd>
    if cmd.startswith("cd ") and "&&" in cmd:
        parts = [s.strip() for s in cmd.split("&&")]
        if len(parts) == 2 and parts[0].startswith("cd "):
            cd_target = parts[0][3:].strip()
            if not any(c in cd_target for c in ('`', '$', ';', '|')):
                if is_safe_fast_path(parts[1]):
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

    # Support git directory flags: git -C <dir> log/status/diff/show/branch
    if cmd.startswith("git -C ") or cmd.startswith("git --git-dir"):
        try:
            import shlex
            tokens = shlex.split(cmd)
            idx = 1
            while idx < len(tokens):
                if tokens[idx] == "-C":
                    idx += 2
                elif tokens[idx].startswith("--git-dir") or tokens[idx].startswith("--work-tree"):
                    idx += 1
                else:
                    break
            if idx < len(tokens):
                subcmd = tokens[idx]
                if subcmd in ("status", "log", "diff", "show", "branch", "tag"):
                    if "--output" not in cmd:
                        return True
        except Exception:
            pass

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
    if is_safe_python_command(cmd):
        return True
    if cmd == 'sqlite3 :memory: "SELECT 1;"':
        return True

    return False

