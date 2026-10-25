import sys

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def format_latency(elapsed: float) -> str:
    """Format elapsed time gracefully, displaying ms for sub-10ms and s for larger intervals."""
    if elapsed < 0.01:
        return f"{elapsed * 1000:.1f}ms"
    return f"{elapsed:.2f}s"

def print_to_terminal(text: str) -> None:
    """
    Print text directly to the user's terminal.
    1. If sys.stderr is a TTY, write to sys.stderr.
    2. If sys.stderr is piped (e.g. captured by Antigravity or a runner),
       attempt to write directly to /dev/tty so the interactive terminal
       sees the banner.
    3. Always write to sys.stderr so non-interactive runners/loggers capture it.
    """
    if sys.stderr.isatty():
        try:
            sys.stderr.write(text + "\n")
            sys.stderr.flush()
            return
        except Exception:
            pass

    # Try /dev/tty for direct interactive terminal visibility
    try:
        with open("/dev/tty", "w") as tty:
            tty.write(text + "\n")
            tty.flush()
    except Exception:
        pass

    # Always write to sys.stderr for any runner reading stderr
    try:
        sys.stderr.write(text + "\n")
        sys.stderr.flush()
    except Exception:
        pass
