"""
hibp.py — Have I Been Pwned password checker.

Uses the Pwned Passwords API with k-anonymity:
  - Only the first 5 chars of SHA-1 are sent to the server
  - The full hash never leaves the machine
  - No API key required for the password range endpoint

Docs: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

import hashlib
import urllib.request
import urllib.error
from typing import Optional


HIBP_API = "https://api.pwnedpasswords.com/range/"
TIMEOUT  = 5   # seconds


# ── Core check ─────────────────────────────────────────────────────────────

def _sha1(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_password(password: str) -> tuple[bool, int, Optional[str]]:
    """
    Check if a password has appeared in known data breaches.

    Returns:
        (pwned: bool, count: int, error: Optional[str])

        pwned  — True if the password was found in breaches
        count  — number of times it appeared (0 if not found)
        error  — human-readable error string, or None on success
    """
    if not password:
        return False, 0, "Empty password"

    sha1   = _sha1(password)
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        req = urllib.request.Request(
            HIBP_API + prefix,
            headers={
                "User-Agent":       "Aegis/2.0",
                "Add-Padding":      "true",   # prevents traffic analysis
            }
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.URLError as e:
        return False, 0, f"Network error: {e.reason}"
    except Exception as e:
        return False, 0, f"Request failed: {e}"

    # Response is lines of  SUFFIX:COUNT
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(":")
        if len(parts) != 2:
            continue
        resp_suffix, count_str = parts
        # padding entries have count 0 — skip them
        if resp_suffix == suffix:
            try:
                count = int(count_str)
            except ValueError:
                count = 0
            if count > 0:
                return True, count, None

    return False, 0, None


def breach_summary(count: int) -> str:
    """Return a human-readable severity label."""
    if count == 0:
        return "Not found in any known breach ✓"
    if count < 10:
        return f"Found in {count} breach(es) — low exposure"
    if count < 1_000:
        return f"Found in {count:,} breaches — moderate risk"
    if count < 100_000:
        return f"Found in {count:,} breaches — high risk"
    return f"Found in {count:,} breaches — extremely common, change immediately"
