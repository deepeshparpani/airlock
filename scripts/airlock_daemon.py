#!/usr/bin/env python3
import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
for p in (PARENT_DIR, SCRIPT_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from airlock.daemon.server import main

if __name__ == "__main__":
    main()
