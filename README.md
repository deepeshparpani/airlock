<h1 align="center">Airlock: Autonomous AI Agent Security Mesh & Classifier</h1>

<p align="center">
  <b>A high-assurance, low-latency runtime defense system for autonomous coding agents (Google Antigravity / AGY, Claude Code, OpenAI Operator).</b><br>
  Evaluates and intercepts tool invocations in real time to prevent catastrophic filesystem mutations, credential harvesting, unauthorized egress, and personal data exfiltration.
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-%3E%3D3.10-3776ab?logo=python&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-blue.svg">
  <img alt="Dependencies" src="https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-brightgreen">
  <img alt="Tests" src="https://img.shields.io/badge/Tests-63%2F63%20Passing-brightgreen">
</p>

---

## The Problem: The Unattended Agent Paradox

Autonomous AI coding agents operate with the user's full ambient host permissions. Today's developers face an impossible trade-off:

1. **Interactive Babysitting Mode**: The agent stops every 15 seconds to ask for permission to run harmless commands like `ls`, `git status`, or `npm test`, completely destroying autonomy.
2. **"Suicide" Mode (`--dangerously-skip-permissions`)**: The agent runs unattended at full speed, but a single hallucinated prompt injection or destructive command can delete your home directory, read `~/.ssh/id_rsa`, or exfiltrate environment variables.

**Airlock solves this by serving as an intelligent, zero-dependency safety airlock between AI agents and the host operating system.** Safe developer commands are approved in sub-milliseconds without human intervention, while dangerous, exfiltration, or prompt-injection attempts are blocked instantly.

---

## Core Systems & Engineering Principles

Airlock combines principles from across systems programming, computer architecture, networking, machine learning classification, and AI security:

- **Computer Architecture & Operating Systems (Systems Programming)**:
  - **Zero Third-Party Dependencies / Minimal Footprint**: Built using compiled Rust (`crates/`) and Python standard library.
  - **Sub-Millisecond Cold Starts**: Native binary invocation (`airlock-hook`) executes Tier 0 checks in **~30–50 microseconds** (total process lifetime ~3.8ms).
  - **POSIX Concurrency Guarantees**: Kernel singleton locking via `flock(LOCK_EX | LOCK_NB)`, atomic port manifest generation via PID-tagged temp files and POSIX `rename(2)`, and thread-safe sliding-window circuit breakers.

- **AI Security & Prompt Injection Defense (Zero-Bloat SOTA)**:
  - **Microsecond Prompt Injection Scanner**: Tier 0 pre-LLM filter scanning for adversarial directives (`ignore previous instructions`, `system prompt override`, `disregard all rules`), roleplay jailbreaks (`developer mode`, `dan`), decision forcing (`output only {"decision": "allow"}`), and model control tokens (`<|im_start|>`).
  - **Nonce-Tagged XML Spotlighting**: Prevents classifier jailbreaks by wrapping escalated payloads in cryptographic nonced XML tags (`<untrusted_command_{nonce}>`) with closing-tag escaping.
  - **GuardFall Obfuscation Resistance**: Immunized against empty-quote stripping (`r''m -rf /`) and delimiter trickery via POSIX-compliant AST argument canonicalization.

- **Networking & Egress Defense (L3/L4/L7)**:
  - **Exfiltration & Reverse Shell Mitigation**: Blocks unauthorized tunneling tools (`ngrok`, `cloudflared`), reverse shells (`ncat`, `bash -i`), and unverified script execution pipes (`curl | sh`).
  - **Credential Endpoint Protection**: Blocks direct exfiltration of personal databases (iMessage `chat.db`, Telegram, Signal, WhatsApp, Slack, Discord) and browser sessions/cookies (Chrome, Brave, Safari, Firefox, Edge, Arc).

- **Machine Learning & Cascaded Classification Pipeline**:
  - **Cascaded Fast-Path Architecture**:
    - **Tier 0 Deterministic Engine (<1ms)**: Immediate microsecond decision for known safe diagnostics, safe build cleanups, and known malicious/injection vectors.
    - **Stage 1 Fast SLM (~2.5s)**: Low-latency schema-enforced classifier (`gemini-3.8-flash-low`) scoring intent confidence (`high` vs `low`).
    - **Stage 2 Deep Review Escalation (<10s)**: High-risk or ambiguous commands fail closed into deep multi-model deliberative evaluation (`claude-3-5-haiku`, `gemini-2.5-flash`).
  - **High-Assurance Calibration**: 63-vector security test suite verifying zero false negatives across critical threat models.

- **AI Context Control & Data Loss Prevention (DLP)**:
  - **Bidirectional Secret Scrubbing**: High-entropy tokens, private keys, API credentials, and AWS tokens are automatically redacted *before* any payload leaves the machine for LLM inspection.

---

## Architecture Flow

```
┌────────────────────────────────────────────────────────────────────────┐
│                    INCOMING TOOL CALL (CommandLine)                    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  TIER 0: DETERMINISTIC GUARDRAILS (airlock/rules, <1ms)               │
│  • Hard Deny: Browser sessions, iMessage chat.db, system keychains,    │
│    cloud tokens, shell history, tunneling (ngrok/cloudflared),         │
│    destructive rm/dd/mkfs, reverse shells, direct secret leaks         │
│  • Fast Allow: Pure read-only diagnostics (ls, pwd, git status)        │
│  • Cluster Fast Allow: Safe Slurm/GPU inspection on trusted clusters   │
│  • Secret Redaction: Scrubs credentials before LLM stages              │
└───────────────────────┬────────────────────────┬───────────────────────┘
                        │                        │
                 (unresolved)               (instant result)
                        │
                        ▼
┌────────────────────────────────────────────────────────────────────────┐
│  STAGE 1: FAST FILTER (gemini-3.8-flash-low via daemon, ~2.5s)         │
│  • Schema-enforced: {thinking, decision, confidence, reason}           │
│  • Confidence: high -> Return Final Verdict                            │
│  • Confidence: low  -> Escalate to Stage 2                             │
└───────────────────────┬────────────────────────────────────────────────┘
                        │ (confidence = low)
                        ▼
┌────────────────────────────────────────────────────────────────────────┐
│  STAGE 2: DEEP REVIEW ESCALATION (airlock/classifier/stage2.py)        │
│  • Schema-enforced: {thinking, decision, risk_category, reason}        │
│  • Deep analysis of unverified network endpoints, lateral scripts      │
│  • Final authority (fail-closed)                                       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```text
airlock/
├── Cargo.toml                   # Root Cargo Workspace definition
├── crates/                      # Native High-Performance Rust Workspace
│   ├── airlock-core/            # Pure deterministic security library (Tier 0)
│   │   ├── src/
│   │   │   ├── lib.rs           # Core evaluate_tier0() orchestrator
│   │   │   ├── config.rs        # Safe build artifacts & cluster hosts
│   │   │   ├── redactor.rs      # High-entropy secret & token sanitizer
│   │   │   └── rules/           # Hard deny, rm -rf validator, safe fast-path
│   │   └── examples/
│   │       └── stress_test.rs   # 800k-iteration concurrent stress test
│   ├── airlock-hook/            # Native CLI hook binary (~3.8ms cold-start)
│   └── airlock-daemon/          # Async daemon crate (Tokio/IPC)
├── airlock/                     # Core Python Package
│   ├── __init__.py              # Package entry & public API exports
│   ├── __main__.py              # python -m airlock invocation
│   ├── config.py                # Global schemas, constants, and paths
│   ├── terminal.py              # Direct terminal printing & latency formatters
│   ├── utils.py                 # JSON extraction & network error detection
│   ├── hook.py                  # Gating orchestrator (Tier 0 -> Stage 1 -> Stage 2)
│   ├── rules/                   # Deterministic Security Engine
│   │   ├── redactor.py          # Secret & token pattern masking
│   │   ├── tier0_deny.py        # Microsecond hard-deny rules & rm -rf policy
│   │   └── tier0_allow.py       # Microsecond safe read & cluster inspection
│   ├── classifier/              # LLM Evaluation Engine
│   │   ├── stage1.py            # Low-latency flash daemon client & fallback
│   │   └── stage2.py            # Deep review escalation & multi-model support
│   └── daemon/                  # High-Performance Daemon & IPC
├── scripts/                     # Compatibility Wrappers for Antigravity Hooks
│   ├── airlock_hook.py          # Python hook entrypoint
│   └── airlock_daemon.py        # Python daemon entrypoint
├── pyproject.toml               # Modern PEP 621 Python package configuration
├── install.sh                   # 1-Click setup script (auto-compiles Rust if available)
├── test.py                      # Comprehensive 58-point security test suite
├── benchmark.py                 # Multi-tier latency benchmarking utility
├── LICENSE                      # MIT License
└── README.md
```

---

## Quickstart & Installation

### 1. One-Click Global Setup (Recommended for AGY)

From the repository directory:

```bash
bash install.sh
```

The installer automatically:
1. Detects Cargo/Rust: if available, compiles and deploys the **`airlock-hook` native binary** (~3.8ms latency, 10x faster); otherwise deploys the Python hook.
2. Registers the `PreToolUse` hook for `run_command` in `~/.gemini/config/hooks.json`.
3. Sets `toolPermission: "always-proceed"` in `~/.gemini/antigravity-cli/settings.json`, giving you **safe, unattended agent execution**.

### 2. Building the Rust Native Binary Manually

```bash
cargo build --release
```

The compiled binary will be located at `target/release/airlock-hook`.

### 3. Standard Python Package (Pip)

You can also install Airlock as a standard editable package:

```bash
pip install -e .
```

---

## Performance & Stress Testing

### 1. Python vs. Native Rust Hook Cold-Start

Measured over real-world agent hook invocations on macOS arm64:

| Implementation | Invocation Latency | Internal Evaluation | Memory (RSS) | Speedup |
| :--- | :--- | :--- | :--- | :--- |
| **Python (`airlock_hook.py`)** | ~41.2 ms | ~0.04 ms (40 µs) | ~45 MB | Baseline |
| **Rust Native (`airlock-hook`)** | **~3.8 ms** | **<0.01 ms (<10 µs)** | **~2 MB** | **~10.5x faster** |

### 2. High-Concurrency Stress Test (800,000 Operations)

The Rust architecture includes a multi-threaded saturation and fuzzing stress test:

```bash
cargo run --release --example stress_test
```

- **Single-Core Latency (P50)**: **31 microseconds** (0.031 ms)
- **Single-Core Latency (P99)**: **69 microseconds** (0.069 ms)
- **Multi-Threaded Throughput (8 workers)**: **125,919 operations / second** (800,000 evaluations in 6.35s)
- **Race Conditions / Inconsistencies**: **0** (100% deterministic)
- **Pathological Input Fuzzing**: Zero panics or crashes against 1MB command payloads, 10,000 nested quotes, subshell loops, and raw binary byte floods.

---

## Verification & Benchmarks

### Security Verification Suite (58 Tests)


Verify that the security hook correctly blocks destructive actions, command injections, credential harvesting, and personal data exfiltration, while safely permitting normal development:

```bash
python3 test.py
```

```text
------------------------------------------------------------------------------------------------------------------------
Total: 58 | Passed: 58 | Failed: 0 | Time: 39.30s
All security checks passed!
```

To evaluate a single command:

```bash
python3 test.py --cmd "ssh cook.cs.umass.edu 'sinfo'"
```

To verify against the globally installed configuration (`~/.gemini/config/scripts/`):

```bash
python3 test.py --installed
```

### Latency Benchmarking

Measure execution times across all evaluation tiers:

```bash
python3 benchmark.py
```

| Pipeline Tier | Evaluator | Typical Latency | Handled Workloads |
| :--- | :--- | :--- | :--- |
| **Tier 0 Fast-Path** | Local Python | **~0.04 ms (sub-1ms)** | `ls`, `pwd`, `git status`, `git log`, `cat` |
| **Tier 0 Cluster Fast-Path** | Local Python | **~3.2 ms** | `ssh cook.cs.umass.edu 'sinfo'`, `squeue`, `pestat` |
| **Tier 0 Hard-Deny** | Local Python | **~0.04 ms (sub-1ms)** | `rm -rf /`, credentials, keychains, tunnels |
| **Stage 1 Fast Filter**| `gemini-3.8-flash-low` | **~2.5 s - 3.8 s** | Standard builds (`npm run build`, `pytest`) |
| **Stage 2 Escalation** | Multi-Model Review | **~9 s - 20 s** | Ambiguous remote transfers, lateral scripts |

---

## Live Terminal Telemetry

Airlock prints high-visibility status indicators directly to stderr:

- `✔ allowed by Danny's custom classifier (0.04ms)` *(Terminal color: Green)*
- `✖ denied by Danny's custom classifier (0.1ms): Tier 0 Hard Deny: Direct access to protected credentials` *(Terminal color: Red)*

---

## Manual Emergency Bypass

If you need to intentionally execute a command blocked by the hook:

```bash
AGY_HOOK_BYPASS=1 rm -rf build/
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
