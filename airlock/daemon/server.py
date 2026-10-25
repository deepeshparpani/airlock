import socket
import os
import sys
import json
import time
import secrets
import atexit
import shutil

from airlock.config import PORT_FILE, AIRLOCK_GEMINI_DIR, MAX_RETRIES
from airlock.utils import is_network_error, extract_json_payload
from airlock.daemon.process import (
    LOCK_FILE,
    is_circuit_open,
    record_rate_limit,
    acquire_singleton_lock,
    safely_terminate_proc,
    kill_stale_workers,
    kill_other_daemons,
    spawn_agy,
)

def read_json_message(conn):
    buf = ""
    while True:
        chunk = conn.recv(4096).decode("utf-8")
        if not chunk:
            break
        buf += chunk
        if "\n" in buf:
            break
    line = buf.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except Exception:
        return None

def start_daemon_server():
    if os.path.exists(PORT_FILE):
        try:
            with open(PORT_FILE, "r", encoding="utf-8") as f:
                port_str, _ = f.read().strip().split(":", 1)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_sock:
                test_sock.settimeout(1.0)
                test_sock.connect(("127.0.0.1", int(port_str)))
            # If socket connects successfully, daemon is already alive and running
            return
        except Exception:
            try:
                os.remove(PORT_FILE)
            except OSError:
                pass

    lock_fd = acquire_singleton_lock()
    if lock_fd is None:
        # Another daemon is currently booting or running
        return

    kill_other_daemons()
    kill_stale_workers()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.listen(16)

    auth_token = secrets.token_hex(16)
    
    # Atomic write of PORT_FILE to prevent race conditions during reads
    tmp_port_file = f"{PORT_FILE}.{os.getpid()}.tmp"
    with open(tmp_port_file, "w", encoding="utf-8") as f:
        f.write(f"{port}:{auth_token}\n")
    try:
        os.chmod(tmp_port_file, 0o600)
    except OSError:
        pass
    os.replace(tmp_port_file, PORT_FILE)

    proc = spawn_agy()
    count = 0

    def cleanup():
        safely_terminate_proc(proc)
        kill_stale_workers()
        if os.path.exists(PORT_FILE):
            try:
                os.remove(PORT_FILE)
            except OSError:
                pass
        shutil.rmtree(AIRLOCK_GEMINI_DIR, ignore_errors=True)
        try:
            os.close(lock_fd)
            if os.path.exists(LOCK_FILE):
                os.remove(LOCK_FILE)
        except Exception:
            pass

    atexit.register(cleanup)

    while True:
        conn = None
        try:
            conn, _ = server.accept()
            conn.settimeout(35.0)

            req = read_json_message(conn)
            if not req:
                continue

            if req.get("token") != auth_token:
                conn.sendall(b'{"decision": "deny", "confidence": "high", "reason": "unauthorized"}\n')
                continue

            if is_circuit_open():
                conn.sendall(json.dumps({
                    "decision": "deny",
                    "confidence": "low",
                    "reason": "Circuit breaker active: 3+ consecutive rate-limit errors in 60s"
                }).encode("utf-8") + b"\n")
                continue

            prompt = req.get("prompt", "")
            payload = {"event": "user", "message": {"content": prompt}}

            response = ""
            for attempt in range(MAX_RETRIES):
                if proc.poll() is not None:
                    proc = spawn_agy()

                try:
                    proc.stdin.write(json.dumps(payload) + "\n")
                    proc.stdin.flush()
                except (BrokenPipeError, OSError):
                    proc = spawn_agy()
                    try:
                        proc.stdin.write(json.dumps(payload) + "\n")
                        proc.stdin.flush()
                    except Exception:
                        pass

                raw_response = ""
                err_msg = ""
                is_error = False
                structured_output = None

                while True:
                    line = proc.stdout.readline()
                    if not line:
                        is_error = True
                        err_msg = "EOF reading from agy stream"
                        break
                    try:
                        res = json.loads(line)
                        if res.get("event") == "result":
                            result_obj = res.get("result", {})
                            if result_obj.get("status") == "ERROR":
                                is_error = True
                                err_msg = result_obj.get("error", "Unknown error")
                            else:
                                structured = result_obj.get("structured_output")
                                if isinstance(structured, dict) and "decision" in structured:
                                    structured_output = structured
                                else:
                                    raw_response = result_obj.get("response", "")
                            break
                    except Exception:
                        pass

                if is_error and is_network_error(err_msg):
                    record_rate_limit()
                    if attempt < MAX_RETRIES - 1:
                        safely_terminate_proc(proc)
                        kill_stale_workers()
                        time.sleep(1.0 * (attempt + 1))
                        proc = spawn_agy()
                        continue
                    else:
                        response = json.dumps({"decision": "deny", "confidence": "low", "reason": f"API Error: {err_msg}"})
                        break
                elif is_error:
                    response = json.dumps({"decision": "deny", "confidence": "low", "reason": f"API Error: {err_msg}"})
                    break
                else:
                    if structured_output is not None:
                        response = json.dumps(structured_output)
                    else:
                        parsed_obj = extract_json_payload(raw_response)
                        if parsed_obj is not None:
                            response = json.dumps(parsed_obj)
                        else:
                            response = raw_response
                    break

            conn.sendall(response.encode("utf-8") + b"\n")

            count += 1
            if count >= 20:
                safely_terminate_proc(proc)
                kill_stale_workers()
                shutil.rmtree(AIRLOCK_GEMINI_DIR, ignore_errors=True)
                proc = spawn_agy()
                count = 0

        except Exception as e:
            try:
                if conn:
                    conn.sendall(json.dumps({"decision": "deny", "confidence": "low", "reason": f"daemon error: {str(e)}"}).encode("utf-8") + b"\n")
            except Exception:
                pass
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

def main():
    start_daemon_server()

if __name__ == "__main__":
    main()
