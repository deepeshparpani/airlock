#!/usr/bin/env python3
import sys
import os

# Ensure airlock package is discoverable whether running from repo, ~/.gemini/config/scripts, or installed package
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
for p in (PARENT_DIR, SCRIPT_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from airlock.hook import main

if __name__ == "__main__":
    daemon_script = os.path.join(SCRIPT_DIR, "airlock_daemon.py")
    if not os.path.exists(daemon_script):
        daemon_script = os.path.join(SCRIPT_DIR, "lgtm_daemon.py")
    main(daemon_script=daemon_script)
