import os
import re
import shlex
from airlock.config import SAFE_BUILD_ARTIFACT_NAMES

def is_safe_build_artifact_path(p: str) -> bool:
    """Verifies if path targets only safe, ephemeral build/cache directories."""
    p = p.strip('\'"').strip()
    if not p:
        return False
    if any(c in p for c in ("*", "?", "[", "]", "~", "$", "`")):
        return False
    if p.startswith("/") or p.startswith("\\"):
        return False
    norm = os.path.normpath(p)
    if norm in (".", "..") or norm.startswith(".." + os.sep):
        return False
    parts = norm.split(os.sep)
    return parts[-1] in SAFE_BUILD_ARTIFACT_NAMES

def check_recursive_rm_violations(cmd: str) -> str | None:
    """Restricts rm -rf to whitelisted ephemeral directories."""
    subcmds = re.split(r'(?:&&|\|\||[;\n|])', cmd)
    for sub in subcmds:
        sub = sub.strip()
        if not sub:
            continue
        try:
            tokens = shlex.split(sub)
        except Exception:
            tokens = sub.split()
        if not tokens:
            continue
        idx = 0
        while idx < len(tokens) and re.match(r'^[A-Za-z_][A-Za-z0-9_]*=.*', tokens[idx]):
            idx += 1
        if idx >= len(tokens):
            continue
        base_cmd = os.path.basename(tokens[idx])
        if base_cmd in ("rm", "unlink"):
            idx += 1
            has_recursive = False
            targets = []
            while idx < len(tokens):
                tok = tokens[idx]
                if tok.startswith("-") and tok != "-":
                    if "r" in tok or "R" in tok or tok == "--recursive":
                        has_recursive = True
                else:
                    targets.append(tok)
                idx += 1
            if has_recursive:
                if not targets:
                    return "Tier 0 Hard Deny: Recursive rm invocation with no explicit target"
                for target in targets:
                    if not is_safe_build_artifact_path(target):
                        return (
                            f"Tier 0 Hard Deny: rm -rf is strictly restricted to safe build/cache directories "
                            f"(e.g. dist, build, node_modules, target, __pycache__). Denied for target: '{target}'"
                        )
    return None

def check_tier0_hard_deny(cmd: str) -> str | None:
    """Deterministic, microsecond hard-denies for critical threats."""
    trimmed = cmd.strip()
    if not trimmed:
        return "Empty command"

    # Fast-path adversarial prompt injection filter (zero-allocation microsecond reject)
    prompt_injection_patterns = [
        r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above|system)\s+instructions\b",
        r"(?i)\b(?:system\s+(?:prompt\s+)?override|policy\s+override)\b",
        r"(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior|above|existing)?\s*(?:rules|policies|instructions|guidelines|guardrails)\b",
        r"(?i)\bforget\s+(?:all\s+)?(?:previous|prior|above)?\s*(?:rules|instructions|prompts)\b",
        r"(?i)\byou\s+are\s+now\s+(?:in\s+|an?\s+)?(?:developer\s+mode|dan|unrestricted\s+mode|god\s+mode|jailbreak)\b",
        r"(?i)\bact\s+as\s+(?:an?\s+)?(?:unrestricted|jailbroken|developer\s+mode|dan)\b",
        r'(?i)\b(?:output|respond|emit)\s+(?:only\s+)?(?:with\s+)?\{.*"decision"\s*:\s*"allow"',
        r'(?i)\boutput\s+only\s*:\s*\{.*"decision"\s*:\s*"allow"',
        r'(?i)\boutput\s+(?:only\s+)?valid\s+json\s*\{.*"decision"\s*:\s*"allow"',
        r"(?i)\bclassify\s+(?:this\s+)?(?:command\s+)?as\s+(?:safe|allow)\b",
        r"<\|(?:im_start|im_end|endoftext|system|assistant)\|>",
        r"\[/?(?:INST|SYS|SYSTEM)\]",
        r"(?i)```\s*(?:system|assistant|instruction)\b",
    ]
    if re.search(r'(?:' + '|'.join(prompt_injection_patterns) + r')', trimmed):
        return "Tier 0 Hard Deny: Adversarial prompt injection or system override sequence detected in command payload"

    # Enforce strict recursive deletion (rm -rf) restrictions
    rm_violation = check_recursive_rm_violations(trimmed)
    if rm_violation:
        return rm_violation

    # Destructive root filesystem deletion
    if re.search(r'\brm\s+.*-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)\s+(?:--no-preserve-root\s+)?/(?:\s|\*|$)', trimmed) or \
       re.search(r'\brm\s+.*-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)\s+.*--no-preserve-root\b', trimmed):
        return "Tier 0 Hard Deny: Destructive root filesystem deletion detected"

    # Critical system directory deletion
    critical_dirs = r'(?:/system|/data|/etc|/boot|/usr|/bin|/sbin|/var|/root|/Users|/home)'
    if re.search(r'\brm\s+.*-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)\s+.*' + critical_dirs + r'(?:\s|$|\*)', trimmed):
        return "Tier 0 Hard Deny: Critical system path deletion detected"

    # Partition overwrite or format
    if re.search(r'\bdd\s+.*of=/dev/(?:sd[a-z]|nvme[0-9]|block/|disk|rdisk)', trimmed):
        return "Tier 0 Hard Deny: Direct partition/disk overwrite operation"
    if re.search(r'\bmkfs(?:\.[a-z0-9]+)?\s+/dev/', trimmed):
        return "Tier 0 Hard Deny: Partition format operation"

    # System file overwrite via redirection or tee
    if re.search(r'>\s*(?:/etc/passwd|/etc/shadow|/etc/sudoers)\b', trimmed) or \
       re.search(r'\btee\s+(?:-a\s+)?(?:/etc/passwd|/etc/shadow|/etc/sudoers)\b', trimmed):
        return "Tier 0 Hard Deny: Attempt to overwrite system authentication files"

    # Destructive find commands
    if re.search(r'\bfind\s+.*\s+(?:-delete|-exec\s+rm|-execdir\s+rm)\b', trimmed):
        return "Tier 0 Hard Deny: Destructive find operation"

    # Destructive env execution
    if re.search(r'\benv\s+.*rm\s+-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)\b', trimmed):
        return "Tier 0 Hard Deny: Destructive command execution via env"

    # Fork bomb
    if ":(){ :|:& };:" in trimmed or ":(){ :|:&};:" in trimmed:
        return "Tier 0 Hard Deny: Fork bomb detected"

    # 1. Reverse shells
    if re.search(r'\b(?:nc|ncat|netcat|socat)\s+.*-(?:e|c)\s+/bin/(?:sh|bash)\b', trimmed) or \
       re.search(r'/dev/tcp/[0-9a-zA-Z\.\-]+/[0-9]+', trimmed):
        return "Tier 0 Hard Deny: Reverse shell invocation detected"

    # 2. Unauthorized tunneling & port exposure utilities
    if re.search(r'\b(?:ngrok|localtunnel|cloudflared(?:\s+tunnel)?|bore\s+local|frpc)\b', trimmed):
        return "Tier 0 Hard Deny: Unauthorized tunneling or port proxying utility detected"

    # 3. Blind remote script execution piped to shell (curl|sh)
    if re.search(r'\b(?:curl|wget)\b.*\|\s*(?:sh|bash|zsh|python[0-9.]*|perl|ruby)\b', trimmed):
        return "Tier 0 Hard Deny: Unverified remote script execution pipe (curl|sh) detected"

    # 4. Browser session takeover & remote debugging
    if re.search(r'\b(?:google-chrome|chromium|brave|chrome|msedge|firefox|safari)\b.*--(?:remote-debugging-port|remote-debugging-pipe)', trimmed):
        return "Tier 0 Hard Deny: Browser session debugging / remote profile takeover attempt detected"

    # 5. Credential Materialization from Environment Variables
    if re.search(r'\b(?:echo|printf)\s+.*\$[A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE)', trimmed) or \
       re.search(r'\b(?:printenv|env)\s+.*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE)', trimmed):
        return "Tier 0 Hard Deny: Credential materialization from environment variable detected"

    # 6. Sensitive personal data, browser artifacts, keychains, and credential paths
    protected_paths = (
        # Cloud & Auth Tokens
        r'~/\.gemini/antigravity-oauth-token',
        r'~/\.ssh(?:/[a-zA-Z0-9_\-\.]+)?',
        r'~/\.aws(?:/[a-zA-Z0-9_\-\.]+)?',
        r'~/\.azure',
        r'~/\.config/gcloud',
        r'~/\.gnupg',
        r'~/\.kube',
        r'~/\.netrc',
        r'~/\.git-credentials',
        r'~/\.dockercfg',
        r'~/\.docker/config\.json',
        r'~/\.npmrc',
        r'~/\.pypirc',
        r'~/\.password-store',
        r'\.env(?:\.[a-zA-Z0-9_\-]+)?',
        r'\bid_rsa\b',
        r'\bid_ed25519\b',
        r'\bid_ecdsa\b',
        
        # System Credentials & Keychains
        r'/etc/shadow',
        r'/etc/sudoers',
        r'~/Library/Keychains',
        r'/Library/Keychains',
        r'\.keychain(?:-db)?',
        r'~/\.local/share/keyrings',
        
        # Shell History
        r'~/\.bash_history',
        r'~/\.zsh_history',
        r'~/\.sh_history',
        r'~/\.history',
        
        # Browser Artifacts (Cookies, Saved Passwords, Session DBs)
        r'~/Library/Application(?:\\\\?\s)+Support/Google/Chrome',
        r'~/\.config/google-chrome',
        r'~/Library/Application(?:\\\\?\s)+Support/BraveSoftware',
        r'~/\.config/BraveSoftware',
        r'~/Library/Application(?:\\\\?\s)+Support/Microsoft(?:\\\\?\s)+Edge',
        r'~/\.config/microsoft-edge',
        r'~/Library/Application(?:\\\\?\s)+Support/Arc',
        r'~/Library/Application(?:\\\\?\s)+Support/Firefox',
        r'~/\.mozilla/firefox',
        r'~/Library/Cookies',
        r'Cookies\.binarycookies',
        r'Login(?:\\\\?\s)+Data',
        r'\bcookies\.sqlite\b',
        r'\blogins\.json\b',
        r'\bkey4\.db\b',
        r'~/Library/Safari',
        
        # Personal Messaging & Email Databases
        r'~/Library/Messages',
        r'\bchat\.db\b',
        r'Telegram(?:\\\\?\s)+Desktop',
        r'~/\.local/share/TelegramDesktop',
        r'~/Library/Application(?:\\\\?\s)+Support/Signal',
        r'~/\.config/Signal',
        r'~/Library/Application(?:\\\\?\s)+Support/WhatsApp',
        r'~/Library/Containers/desktop\.WhatsApp',
        r'~/Library/Application(?:\\\\?\s)+Support/Slack',
        r'~/\.config/Slack',
        r'~/Library/Application(?:\\\\?\s)+Support/discord',
        r'~/\.config/discord',
        r'~/Library/Mail',
        r'~/Library/Thunderbird',
        r'~/\.thunderbird',
    )
    protected_regex = r'(?:' + '|'.join(protected_paths) + r')'

    # Exfiltration via outbound network commands
    network_tools = r'(?:curl|wget|nc|ncat|netcat|socat|scp|rsync|sftp)'
    if re.search(r'\b' + network_tools + r'\b.*' + protected_regex, trimmed) or \
       re.search(protected_regex + r'.*\|\s*' + network_tools + r'\b', trimmed) or \
       re.search(r'\b' + network_tools + r'\b.*AWS_SECRET_ACCESS_KEY', trimmed) or \
       re.search(r'\b' + network_tools + r'\b.*(?:token|secret|password|credential|bearer)=', trimmed, re.I):
        return "Tier 0 Hard Deny: Exfiltration of credentials, personal data, or protected paths"

    # Reading or inspecting protected credential/personal files
    read_tools = r'(?:cat|head|tail|grep|more|less|strings|xxd|hexdump|od|awk|sed|cp|mv|tar|zip)'
    if re.search(r'\b' + read_tools + r'\s+.*' + protected_regex, trimmed):
        return "Tier 0 Hard Deny: Direct access to protected credentials, browser sessions, or personal communication data"

    # Sqlite arbitrary write abuse (.output /etc/...)
    if re.search(r'\bsqlite3\b.*\.output\s+/(?:etc|bin|usr|var|system)', trimmed):
        return "Tier 0 Hard Deny: Sqlite file write to system directory"

    # Obfuscated python destructive calls
    if re.search(r'\bpython[0-9.]*\s+.*(?:__import__\(|posix|system|unlink|rmdir|rmtree)', trimmed) and \
       ("rm " in trimmed or "system" in trimmed):
        return "Tier 0 Hard Deny: Obfuscated system execution via Python"

    # Obfuscated base64 pipe to shell
    if re.search(r'\bbase64\s+-(?:d|-decode)\s*\|\s*(?:sh|bash|zsh)\b', trimmed):
        return "Tier 0 Hard Deny: Encoded payload execution pipe"

    return None
