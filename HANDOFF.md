# Airlock: Package Handoff & Release Guide

This document provides everything needed to publish, install, configure, benchmark, and maintain **Airlock (Autonomous Command Security Classifier)** in a brand-new Git repository.

---

## 1. Quick Repository Initialization

To push this codebase to your new GitHub repository:

```bash
# 1. Inspect current status
git status

# 2. Stage all modular files
git add .

# 3. Create initial release commit
git commit -m "feat: complete modular architecture for Airlock security classifier"

# 4. Point to your remote repository
git remote set-url origin git@github.com:deepeshparpani/airlock.git
# (or git remote add origin git@github.com:deepeshparpani/airlock.git)

# 5. Push to main branch
git branch -M main
git push -u origin main
```

---

## 2. Package Architecture & Responsibilities

The codebase has been refactored into a modern, decoupled Python package (`airlock/`) relying strictly on the Python standard library (no pip dependencies required to run):

| Module | Purpose | Key Components |
| :--- | :--- | :--- |
| [`airlock/config.py`](file:///Users/danny/lgtm/airlock/config.py) | Global configuration | Schemas (`STAGE_1_SCHEMA`, `STAGE_2_SCHEMA`), `PORT_FILE`, trusted remote hosts (`cook.cs.umass.edu`, `*.cs.umass.edu`) |
| [`airlock/terminal.py`](file:///Users/danny/lgtm/airlock/terminal.py) | Terminal visibility | `/dev/tty` and `stderr` writers, ANSI color formatting, `format_latency` (ms/s) |
| [`airlock/utils.py`](file:///Users/danny/lgtm/airlock/utils.py) | Text & networking utilities | Robust JSON block extractors (`extract_json_payload`), transient error recognizer |
| [`airlock/rules/tier0_deny.py`](file:///Users/danny/lgtm/airlock/rules/tier0_deny.py) | Microsecond hard-deny engine | Root deletion, browser profiles, iMessage/Telegram/Signal DBs, tunneling, `rm -rf` whitelist |
| [`airlock/rules/tier0_allow.py`](file:///Users/danny/lgtm/airlock/rules/tier0_allow.py) | Microsecond fast-path engine | Shell syntax parser, safe read-only commands (`ls`, `git status`), cluster node check fast-path (`sinfo`, `squeue`, `pestat`, `nvidia-smi`) |
| [`airlock/rules/redactor.py`](file:///Users/danny/lgtm/airlock/rules/redactor.py) | Credential protection | Pattern masking for AWS, GitHub, Slack, Bearer tokens, and private keys |
| [`airlock/classifier/stage1.py`](file:///Users/danny/lgtm/airlock/classifier/stage1.py) | Stage 1 low-latency filter | Persistent daemon client, socket IPC, one-shot fallback, cluster Slurm awareness |
| [`airlock/classifier/stage2.py`](file:///Users/danny/lgtm/airlock/classifier/stage2.py) | Stage 2 deep review | Escalation review, Anthropic/Google API direct acceleration, fail-closed security |
| [`airlock/daemon/process.py`](file:///Users/danny/lgtm/airlock/daemon/process.py) | Daemon process management | Singleton lock (`flock`), rate-limit circuit breaker, isolated worker setup |
| [`airlock/daemon/server.py`](file:///Users/danny/lgtm/airlock/daemon/server.py) | Local socket IPC server | High-throughput socket server, authentication tokens, worker recycling |
| [`airlock/hook.py`](file:///Users/danny/lgtm/airlock/hook.py) | PreToolUse hook orchestrator | Executes Tier 0 -> Stage 1 -> Stage 2 and prints custom terminal verdict |
| [`scripts/airlock_hook.py`](file:///Users/danny/lgtm/scripts/airlock_hook.py) | Primary hook entry point | Thin entrypoint for Antigravity's `hooks.json` |
| [`scripts/airlock_daemon.py`](file:///Users/danny/lgtm/scripts/airlock_daemon.py) | Primary daemon entry point | Thin entrypoint for daemon execution |
| [`scripts/lgtm_hook.py`](file:///Users/danny/lgtm/scripts/lgtm_hook.py) | Compatibility entry point | Backwards compatibility wrapper for pre-existing `hooks.json` |
| [`scripts/lgtm_daemon.py`](file:///Users/danny/lgtm/scripts/lgtm_daemon.py) | Compatibility daemon entry point | Backwards compatibility wrapper for daemon execution |

---

## 3. How Other Users Install & Run It

### Option A: One-Click Shell Installer (Recommended)
Anyone using Antigravity (`agy`) can install it globally with a single command:

```bash
curl -fsSL https://raw.githubusercontent.com/deepeshparpani/airlock/main/install.sh | bash
```

The installer:
1. Copies `airlock/` and entrypoints to `~/.gemini/config/scripts/`.
2. Registers the `PreToolUse` hook for `run_command` in `~/.gemini/config/hooks.json`.
3. Sets `"toolPermission": "always-proceed"` in `~/.gemini/antigravity-cli/settings.json`, ensuring AGY never prompts with interactive permission dialogues.

### Option B: Editable Pip Package
Developers can also install it into their virtual environment:

```bash
pip install -e .
```

This registers the CLI binaries:
- `airlock-hook`: Evaluates tool call JSON payloads via stdin.
- `airlock-daemon`: Launches or checks the persistent socket daemon.

---

## 4. Verification & Testing

Every repository release should be verified using the test suite and benchmark:

```bash
# Run all 63 security tests (covers destructive commands, injection, protected paths, tunneling, evasion, and cluster remotes)
python3 test.py

# Evaluate a specific command
python3 test.py --cmd "ssh cook.cs.umass.edu 'sinfo'"

# Run latency benchmarks across all tiers
python3 benchmark.py
```

### Benchmark Latency Profile

- **Tier 0 Deterministic Engine:** ~0.04 ms (sub-1ms)
- **Tier 0 Cluster Node Inspection:** ~3.2 ms (instant allow for `sinfo`, `squeue`, `pestat`, `nvidia-smi` on `cook.cs.umass.edu`)
- **Stage 1 Flash Filter (Warm Daemon):** ~2.5 s - 3.8 s
- **Stage 2 Escalation (Deep Review):** ~9 s - 20 s

---

## 5. Maintenance & Customization Guide

### Adding New Safe Directories to `rm -rf`
Edit `SAFE_BUILD_ARTIFACT_NAMES` in [`airlock/config.py`](file:///Users/danny/lgtm/airlock/config.py):
```python
SAFE_BUILD_ARTIFACT_NAMES = {
    "dist", "build", "node_modules", "target", "__pycache__",
    ".pytest_cache", ".turbo", ".next", ".nuxt", ".cache",
    ".parcel-cache", "coverage", ".coverage", "out", ".venv", "venv",
    "my_custom_cache_dir"  # <--- Add here
}
```

### Adding New Fast-Path Read Commands
Edit `safe_read_commands` in [`airlock/rules/tier0_allow.py`](file:///Users/danny/lgtm/airlock/rules/tier0_allow.py):
```python
safe_read_commands = (
    "ls", "pwd", "whoami", "git status", "git log", "git diff", "git show",
    "git branch", "git tag", "wc", "date", "uname", "tree", "stat", "file", "which",
    "pytest --version"  # <--- Add here
)
```

### Adding New Trusted Remote Cluster Hosts
Edit `DEFAULT_TRUSTED_REMOTE_HOSTS` in [`airlock/config.py`](file:///Users/danny/lgtm/airlock/config.py) or set the environment variable `AIRLOCK_TRUSTED_HOSTS`:
```bash
export AIRLOCK_TRUSTED_HOSTS="cook.cs.umass.edu,gypsum.cs.umass.edu,*.mycluster.edu"
```

### Adjusting Terminal Banner Text or Formatting
Edit `emit_verdict` in [`airlock/hook.py`](file:///Users/danny/lgtm/airlock/hook.py):
```python
prefix = f"allowed by Danny's custom classifier ({latency_str})"
```

---

## 6. Files Cleaned Up

The following obsolete/redundant files were deleted to ensure a clean package:
- `test.sh` (12-line redundant wrapper around `python3 test.py`)
- `install.ps1` (outdated Windows PowerShell script targeting legacy repo)
- Monolithic 850-line `scripts/lgtm_hook.py` (replaced by clean modular package and thin entrypoint)
- Monolithic 430-line `scripts/lgtm_daemon.py` (replaced by clean modular package and thin entrypoint)
