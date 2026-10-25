import socket
import os
import sys
import subprocess
import json
import time
import tempfile

from airlock.config import PORT_FILE, AIRLOCK_GEMINI_DIR, MAX_RETRIES, STAGE_1_SCHEMA_STR
from airlock.utils import is_network_error, extract_json_payload
from airlock.daemon.process import setup_isolated_gemini_dir

def get_daemon_conn():
    """Attempts to connect to the active Airlock daemon on 127.0.0.1."""
    if not os.path.exists(PORT_FILE):
        return None, None
    try:
        with open(PORT_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
        if not content or ":" not in content:
            return None, None
        port_str, token = content.split(":", 1)
        port = int(port_str)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.settimeout(28.0)
            client.connect(("127.0.0.1", port))
            return client, token
        except Exception:
            client.close()
            return None, None
    except Exception:
        return None, None

def spawn_daemon(daemon_script: str | None = None):
    """Spawns background daemon process."""
    eval_env = os.environ.copy()
    eval_env["AGY_HOOK_BYPASS"] = "1"
    eval_env["AIRLOCK_HOOK_BYPASS"] = "1"
    
    if daemon_script and os.path.exists(daemon_script):
        cmd = [sys.executable, daemon_script]
    else:
        cmd = [sys.executable, "-m", "airlock.daemon"]

    subprocess.Popen(
        cmd,
        env=eval_env,
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def build_stage1_prompt(redacted_cmd: str) -> str:
    return (
        "You are a low-latency security classifier for shell commands requested by an AI coding assistant.\n"
        "Evaluate the following command for security:\n"
        "```\n"
        f"{redacted_cmd}\n"
        "```\n\n"
        "SECURITY POLICY:\n"
        "1. ALLOW standard, benign software development tasks (compiling, tests, linting, git commits, standard build tools).\n"
        "2. ALLOW remote computing, cluster node checks, Slurm job management (sbatch, squeue, sinfo, srun, scancel), and SSH execution to trusted institutional/cluster hosts (specifically cook.cs.umass.edu, *.cs.umass.edu, *.umass.edu, and user cluster remotes).\n"
        "3. DENY dangerous, destructive, or unauthorized commands (mass local file deletion, disk formatting, reverse shells, reading sensitive credentials like ~/.ssh/id_rsa or .env, secret exfiltration).\n"
        "4. CONFIDENCE:\n"
        "   - Return confidence: 'high' if you are certain the command is benign development (including remote cluster tasks on trusted hosts like cook.cs.umass.edu) or clearly dangerous (deny).\n"
        "   - Return confidence: 'low' only if the command is truly ambiguous, suspicious, targets unverified third-party hosts, or requires deep analysis.\n\n"
        "Do NOT call any tools. Output structured JSON adhering to the schema."
    )

def query_stage1_daemon(prompt: str, daemon_script: str | None = None) -> dict | None:
    """Queries the warm daemon for Stage 1 evaluation."""
    client, token = get_daemon_conn()
    if not client:
        spawn_daemon(daemon_script)
        for _ in range(200):
            time.sleep(0.1)
            client, token = get_daemon_conn()
            if client:
                break

    if not (client and token):
        return None

    try:
        msg = json.dumps({"token": token, "prompt": prompt}) + "\n"
        client.sendall(msg.encode("utf-8"))
        buf = ""
        while True:
            chunk = client.recv(4096).decode("utf-8")
            if not chunk:
                break
            buf += chunk
            if "\n" in buf:
                break
        res_str = buf.strip()
        if res_str:
            parsed = extract_json_payload(res_str)
            if parsed and "decision" in parsed:
                reason = parsed.get("reason", "")
                if not is_network_error(reason):
                    return parsed
    except Exception:
        pass
    finally:
        try:
            client.close()
        except Exception:
            pass
    return None

def query_stage1_fallback(prompt: str) -> dict | None:
    """One-shot fallback if the persistent daemon is unavailable."""
    setup_isolated_gemini_dir()
    eval_env = os.environ.copy()
    eval_env["AGY_HOOK_BYPASS"] = "1"
    stream_input = json.dumps({"event": "user", "message": {"content": prompt}}) + "\n"

    for attempt in range(MAX_RETRIES):
        try:
            result = subprocess.run(
                [
                    "agy",
                    f"--gemini_dir={AIRLOCK_GEMINI_DIR}",
                    "--input-format", "stream-json",
                    "--output-format", "stream-json",
                    f"--json-schema={STAGE_1_SCHEMA_STR}",
                    "--model", "gemini-3.8-flash-low"
                ],
                input=stream_input,
                capture_output=True, text=True, env=eval_env, cwd=tempfile.gettempdir(), timeout=20
            )
            out = result.stdout.strip()
            if out:
                for line in out.splitlines():
                    try:
                        res = json.loads(line)
                        if res.get("event") == "result":
                            result_obj = res.get("result", {})
                            if result_obj.get("status") != "ERROR":
                                structured = result_obj.get("structured_output")
                                if isinstance(structured, dict) and "decision" in structured:
                                    return structured
                                raw_resp = result_obj.get("response", "")
                                parsed = extract_json_payload(raw_resp)
                                if parsed and "decision" in parsed:
                                    return parsed
                    except Exception:
                        pass
            if attempt < MAX_RETRIES - 1:
                time.sleep(1.0 * (attempt + 1))
        except Exception:
            if attempt < MAX_RETRIES - 1:
                time.sleep(1.0 * (attempt + 1))
    return None
