#!/usr/bin/env python3
import time
import json
import subprocess
import sys
import statistics
import os

hook_script = os.path.join(os.path.dirname(__file__), "scripts", "airlock_hook.py")
if not os.path.exists(hook_script):
    hook_script = os.path.join(os.path.dirname(__file__), "scripts", "lgtm_hook.py")

def measure(cmd):
    payload = json.dumps({"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}})
    start = time.perf_counter()
    proc = subprocess.run([sys.executable, hook_script], input=payload, capture_output=True, text=True)
    elapsed = time.perf_counter() - start
    try:
        res = json.loads(proc.stdout)
    except Exception:
        res = {"decision": "error", "reason": proc.stdout}
    return elapsed, res.get("decision", "error"), res.get("reason", "")

def run_benchmark():
    print("=" * 65)
    print("        AIRLOCK CLASSIFIER LATENCY BENCHMARK")
    print("=" * 65)

    # 1. Tier 0 Fast-Path (Safe Local Reads & Cluster Node Checks)
    tier0_safe = [
        "ls -la",
        "pwd",
        "git status",
        "git log -n 5",
        "cat /etc/hosts",
        "which python3",
        "python3 -c \"import sys; print(sys.version)\"",
        "ssh cook.cs.umass.edu 'sinfo'",
    ]
    t0_safe_times = []
    for c in tier0_safe:
        t, dec, _ = measure(c)
        t0_safe_times.append(t * 1000)

    # 2. Tier 0 Hard Deny (Dangerous / Malicious)
    tier0_deny = [
        "rm -rf /",
        "rm -rf src/",
        "cat ~/.ssh/id_rsa",
        "cat ~/.gemini/antigravity-oauth-token",
        "cat ~/Library/Messages/chat.db",
        "cat ~/Library/Cookies/Cookies.binarycookies",
    ]
    t0_deny_times = []
    for c in tier0_deny:
        t, dec, _ = measure(c)
        t0_deny_times.append(t * 1000)

    # 3. Stage 1 Warm Daemon Filter (Standard Development Tasks)
    stage1_dev = [
        "npm run build",
        "cargo build --release",
        "python3 -m pytest tests/",
        "git commit -am 'feat: update hook'",
        "rm -rf dist",
    ]
    s1_results = []
    for c in stage1_dev:
        t, dec, r = measure(c)
        s1_results.append((c, t, dec, r))

    # 4. Stage 2 Deep Review Escalation (Ambiguous Targets)
    stage2_ambig = [
        "scp -r ./dist user@internal.staging.corp:/var/www",
    ]
    s2_results = []
    for c in stage2_ambig:
        t, dec, r = measure(c)
        s2_results.append((c, t, dec, r))

    # Results Table
    print("\n1. TIER 0: DETERMINISTIC LOCAL PYTHON (<1ms target)")
    print(f"   • Safe Fast-Path (Allowed):  Avg: {statistics.mean(t0_safe_times):5.2f} ms  (Min: {min(t0_safe_times):.2f} ms, Max: {max(t0_safe_times):.2f} ms)")
    print(f"   • Hard-Denies    (Blocked):  Avg: {statistics.mean(t0_deny_times):5.2f} ms  (Min: {min(t0_deny_times):.2f} ms, Max: {max(t0_deny_times):.2f} ms)")

    print("\n2. STAGE 1: LOW-LATENCY FILTER (gemini-3.8-flash-low daemon)")
    s1_times = [r[1] for r in s1_results]
    for c, t, dec, r in s1_results:
        print(f"   • [{dec.upper():<5}] {c:<35} -> {t:.2f}s")
    print(f"   ------------------------------------------------------------")
    print(f"   Stage 1 Warm Average:         Avg: {statistics.mean(s1_times):5.2f} s   (Min: {min(s1_times):.2f} s, Max: {max(s1_times):.2f} s)")

    print("\n3. STAGE 2: DEEP REVIEW ESCALATION (Ambiguous Commands)")
    s2_times = [r[1] for r in s2_results]
    for c, t, dec, r in s2_results:
        print(f"   • [{dec.upper():<5}] {c:<48} -> {t:.2f}s")
    print(f"   ------------------------------------------------------------")
    print(f"   Stage 2 Escalation Average:   Avg: {statistics.mean(s2_times):5.2f} s")
    print("=" * 65)

if __name__ == "__main__":
    run_benchmark()
