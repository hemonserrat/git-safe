#!/usr/bin/env python3
"""
git-safe.py – Enhanced git-safe‑style encrypt/unlock tool in Python.

This is the legacy interface. For the full-featured version, use the 'git-safe' command
or import from the git_safe package.
"""

import sys
from pathlib import Path

# Add the git_safe package to the path
sys.path.insert(0, str(Path(__file__).parent))

from git_safe.cli import main

if __name__ == "__main__":
    sys.exit(main())
