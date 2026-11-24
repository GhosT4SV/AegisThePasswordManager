"""Shared location for portable Aegis data and configuration files."""

import sys
from pathlib import Path


if getattr(sys, "frozen", False):
    # For the onedir build, keep user data beside Aegis.exe, not in _MEIPASS.
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent
