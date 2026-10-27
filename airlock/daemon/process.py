import os
import subprocess
import time
import tempfile
import shutil
from airlock.config import USER, AIRLOCK_GEMINI_DIR, STAGE_1_SCHEMA_STR

LOCK_FILE = os.path.join(tempfile.gettempdir(), f"airlock_daemon_{USER}.lock")

rate_limit_errors = []

def record_rate_limit():
    now = time.time()
    rate_limit_errors.append(now)
    while rate_limit_errors and rate_limit_errors[0] < now - 60:
        rate_limit_errors.pop(0)

def is_circuit_open() -> bool:
    now = time.time()
    while rate_limit_errors and rate_limit_errors[0] < now - 60:
        rate_limit_errors.pop(0)
    return len(rate_limit_errors) >= 3

def acquire_singleton_lock():
    lock_fd = os.open(LOCK_FILE, os.O_CREAT | os.O_RDWR, 0o600)
    if os.name != "nt":
        import fcntl
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError):
            os.close(lock_fd)
            return None
    else:
        import msvcrt
        try:
            msvcrt.locking(lock_fd, msvcrt.LK_NBLCK, 1)
        except (OSError, IOError):
            os.close(lock_fd)
            return None
    return lock_fd

def safely_terminate_proc(p):
    if not p or p.poll() is not None:
        return
    try:
        p.terminate()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.wait(timeout=2)
            except Exception:
                pass
    except Exception:
        pass

def setup_isolated_gemini_dir():
    cli_dir = os.path.join(AIRLOCK_GEMINI_DIR, "antigravity-cli")
    os.makedirs(cli_dir, exist_ok=True)
    os.makedirs(AIRLOCK_GEMINI_DIR, exist_ok=True)

    root_gemini = os.path.expanduser("~/.gemini")
    real_cli = os.path.join(root_gemini, "antigravity-cli")

    def _link_item(src: str, dst: str):
        if os.path.exists(src):
            if os.path.islink(dst) or os.path.exists(dst):
                try:
                    os.remove(dst)
                except OSError:
                    pass
            try:
                os.symlink(src, dst)
            except (OSError, NotImplementedError, AttributeError):
                try:
                    shutil.copy2(src, dst)
                except OSError:
                    pass

    # Link auth credentials and configuration files
    for fname in ("oauth_creds.json", "google_accounts.json", "installation_id", "settings.json"):
        src = os.path.join(root_gemini, fname)
        _link_item(src, os.path.join(AIRLOCK_GEMINI_DIR, fname))
        _link_item(src, os.path.join(cli_dir, fname))

    for fname in ("settings.json", "installation_id", "antigravity-oauth-token"):
        src = os.path.join(real_cli, fname)
        _link_item(src, os.path.join(cli_dir, fname))

def kill_stale_workers():
    if os.name != "nt":
        try:
            subprocess.run(["pkill", "-9", "-f", f"agy.*--gemini_dir={AIRLOCK_GEMINI_DIR}"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

def kill_other_daemons():
    if os.name != "nt":
        my_pid = str(os.getpid())
        try:
            out = subprocess.check_output(["pgrep", "-f", "airlock_daemon|lgtm_daemon"], text=True)
            for pid_str in out.strip().split():
                if pid_str != my_pid:
                    try:
                        os.kill(int(pid_str), 9)
                    except OSError:
                        pass
        except Exception:
            pass

def spawn_agy():
    from airlock.utils import get_headless_env
    setup_isolated_gemini_dir()
    kill_stale_workers()
    env = get_headless_env()
    proc = subprocess.Popen(
        [
            "agy",
            f"--gemini_dir={AIRLOCK_GEMINI_DIR}",
            "--input-format", "stream-json",
            "--output-format", "stream-json",
            f"--json-schema={STAGE_1_SCHEMA_STR}",
            "--model", "gemini-3.8-flash-low"
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        env=env,
        cwd=tempfile.gettempdir(),
        start_new_session=True,
    )
    while True:
        line = proc.stdout.readline()
        if not line or "init" in line:
            break
    return proc
