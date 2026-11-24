"""
security.py — anti-tamper, fail2ban, VM/debug detection, logging.

Fail2ban state is protected with HMAC-SHA256 so the JSON file
cannot be edited to reset the attempt counter without knowing
the machine-specific secret key.
"""

import os
import sys
import json
import hmac
import hashlib
import logging
import ctypes
import subprocess
import time
from pathlib import Path
from paths import BASE_DIR

# ── Paths ──────────────────────────────────────────────────────────────────
_BASE        = BASE_DIR
LOG_FILE     = _BASE / "Aegis.log"
STATE_FILE   = _BASE / "Aegis_state.bin"   # now binary, not plain JSON
SECRET_FILE  = _BASE / "Aegis_secret.key"  # machine-local HMAC key

# ── Logger ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("Aegis")


def _log(level: str, msg: str):
    getattr(log, level)(msg)


# ══════════════════════════════════════════════════════════════════════════
#  HMAC-protected state storage
#
#  File format: [HMAC-SHA256 32 bytes][JSON payload bytes]
#
#  The HMAC key is generated once per machine and stored in
#  Aegis_secret.key  (should be kept alongside the DB).
#  Without the key, an attacker cannot produce a valid HMAC for
#  a tampered payload — any modification is detected and the
#  state is treated as corrupted (attempts reset to MAX to be safe).
# ══════════════════════════════════════════════════════════════════════════

def _get_or_create_secret() -> bytes:
    """Return the machine-local HMAC key, generating it on first run."""
    if SECRET_FILE.exists():
        raw = SECRET_FILE.read_bytes()
        if len(raw) == 32:
            return raw
    key = os.urandom(32)
    SECRET_FILE.write_bytes(key)
    # Restrict permissions on non-Windows as best effort
    try:
        os.chmod(SECRET_FILE, 0o600)
    except Exception:
        pass
    _log("info", "FAIL2BAN: new HMAC secret generated.")
    return key


def _sign(payload: bytes, key: bytes) -> bytes:
    return hmac.new(key, payload, hashlib.sha256).digest()


def _load_state() -> dict:
    """
    Load and verify the fail2ban state.
    If missing, returns clean state.
    If tampered or unreadable, returns POISONED state (max attempts)
    so the attacker gains nothing from editing the file.
    """
    if not STATE_FILE.exists():
        return {"attempts": 0, "banned_until": None, "stage": 0}

    raw = STATE_FILE.read_bytes()
    if len(raw) < 33:
        _log("critical", "FAIL2BAN: state file too short — treating as tampered.")
        return _poisoned_state()

    stored_mac = raw[:32]
    payload    = raw[32:]
    key        = _get_or_create_secret()

    expected_mac = _sign(payload, key)
    if not hmac.compare_digest(stored_mac, expected_mac):
        _log("critical",
             "FAIL2BAN: HMAC mismatch — state file was tampered with! "
             "Treating attempt counter as maximum.")
        return _poisoned_state()

    try:
        return json.loads(payload.decode("utf-8"))
    except Exception:
        _log("critical", "FAIL2BAN: state file corrupt.")
        return _poisoned_state()


def _poisoned_state() -> dict:
    """
    Return a state that will immediately trigger a ban.
    Used when tampering is detected — the attacker gets locked out
    instead of a clean slate.
    """
    return {
        "attempts":    999,
        "banned_until": time.time() + 24 * 60 * 60,   # 24h ban
        "stage":       3,
        "_tampered":   True,
    }


def _save_state(state: dict) -> None:
    key     = _get_or_create_secret()
    payload = json.dumps(state, ensure_ascii=False).encode("utf-8")
    mac     = _sign(payload, key)
    STATE_FILE.write_bytes(mac + payload)


# ══════════════════════════════════════════════════════════════════════════
#  1. Self-integrity check
# ══════════════════════════════════════════════════════════════════════════
_HASH_FILE = _BASE / "Aegis_hashes.json"


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_hashes():
    """
    Write the reference hash manifest.
    Run once after any legitimate code change:
      python -c "from security import build_hashes; build_hashes()"
    """
    targets = ["main.py", "crypto.py", "styles.py",
               "security.py", "vault_window.py", "hibp.py"]
    hashes  = {}
    for name in targets:
        p = _BASE / name
        if p.exists():
            hashes[name] = _file_sha256(p)
    with open(_HASH_FILE, "w") as f:
        json.dump(hashes, f, indent=2)
    _log("info", "Hash manifest written.")
    return hashes


def verify_integrity() -> bool:
    if not _HASH_FILE.exists():
        _log("warning", "Hash manifest missing — skipping integrity check.")
        return True

    with open(_HASH_FILE) as f:
        stored = json.load(f)

    ok = True
    for name, expected in stored.items():
        p = _BASE / name
        if not p.exists():
            _log("critical", f"INTEGRITY: file missing — {name}")
            ok = False
            continue
        actual = _file_sha256(p)
        if actual != expected:
            _log("critical",
                 f"INTEGRITY: hash mismatch — {name} "
                 f"expected={expected[:12]}… got={actual[:12]}…")
            ok = False

    if ok:
        _log("info", "Integrity check passed.")
    return ok


# ══════════════════════════════════════════════════════════════════════════
#  2. VM / debugger detection
# ══════════════════════════════════════════════════════════════════════════
_VM_REGISTRY_KEYS = [
    r"SYSTEM\CurrentControlSet\Services\VBoxGuest",
    r"SYSTEM\CurrentControlSet\Services\vmhgfs",
    r"SYSTEM\CurrentControlSet\Services\vmmouse",
    r"SOFTWARE\VMware, Inc.\VMware Tools",
    r"SOFTWARE\Oracle\VirtualBox Guest Additions",
]

_VM_PROCESSES = {
    "vboxservice.exe", "vboxtray.exe",
    "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
    "vmsrvc.exe", "vmusrvc.exe",
}


def _check_registry_vm() -> bool:
    try:
        import winreg
        for key in _VM_REGISTRY_KEYS:
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key)
                return True
            except FileNotFoundError:
                pass
    except Exception:
        pass
    return False


def _check_process_vm() -> bool:
    try:
        out = subprocess.check_output(
            ["tasklist", "/FO", "CSV", "/NH"],
            stderr=subprocess.DEVNULL, timeout=3
        ).decode(errors="ignore").lower()
        return any(p in out for p in _VM_PROCESSES)
    except Exception:
        return False


def _check_debugger() -> bool:
    try:
        return bool(ctypes.windll.kernel32.IsDebuggerPresent())
    except Exception:
        return False


def _check_remote_debugger() -> bool:
    try:
        result = ctypes.c_bool(False)
        ctypes.windll.kernel32.CheckRemoteDebuggerPresent(
            ctypes.windll.kernel32.GetCurrentProcess(),
            ctypes.byref(result)
        )
        return result.value
    except Exception:
        return False


def security_scan() -> dict:
    results = {
        "debugger":        _check_debugger(),
        "remote_debugger": _check_remote_debugger(),
        "vm_registry":     _check_registry_vm(),
        "vm_process":      _check_process_vm(),
    }
    results["any_threat"] = any(results.values())

    if results["debugger"]:        _log("critical", "SECURITY: local debugger detected.")
    if results["remote_debugger"]: _log("critical", "SECURITY: remote debugger detected.")
    if results["vm_registry"]:     _log("warning",  "SECURITY: VM registry keys found.")
    if results["vm_process"]:      _log("warning",  "SECURITY: VM guest process found.")
    if not results["any_threat"]:  _log("info",     "Security scan clean.")

    return results


# ══════════════════════════════════════════════════════════════════════════
#  3. Fail2ban
# ══════════════════════════════════════════════════════════════════════════
_LOCK_SCREEN_AT = 2     # default — overridden by per-user settings


def _win_lock():
    try:
        ctypes.windll.user32.LockWorkStation()
        _log("warning", "FAIL2BAN: workstation locked.")
    except Exception:
        pass


def get_ban_status() -> tuple[bool, int]:
    """Returns (is_banned, seconds_remaining)."""
    state = _load_state()

    if state.get("_tampered"):
        _log("critical", "FAIL2BAN: tampered state detected on get_ban_status.")
        return True, int(state.get("banned_until", time.time() + 86400) - time.time())

    bu = state.get("banned_until")
    if bu:
        remaining = bu - time.time()
        if remaining > 0:
            return True, int(remaining)
        # ban expired — reset
        _save_state({"attempts": 0, "banned_until": None, "stage": 0})
        _log("info", "FAIL2BAN: ban expired, counter reset.")
    return False, 0


def record_failed_attempt(settings: dict | None = None) -> dict:
    """
    Record a failed login attempt.
    All thresholds are read from the per-user security profile.
    State is HMAC-signed — tampering triggers an automatic 24h ban.
    """
    s        = settings or {}
    lock_at  = int(s.get("fail2ban_lockscreen_attempts", _LOCK_SCREEN_AT))
    ban_at   = int(s.get("fail2ban_ban_attempts",        5))
    ban_mins = int(s.get("fail2ban_timeout_minutes",     10))
    do_lock  = bool(s.get("fail2ban_lock_screen",        True))

    ban_stages = [
        (ban_at,      ban_mins * 60),
        (ban_at * 2,  ban_mins * 3 * 60),
        (ban_at * 3,  24 * 60 * 60),
    ]

    state = _load_state()

    # If state was tampered, apply ban immediately
    if state.get("_tampered"):
        _log("critical", "FAIL2BAN: tampered state — applying immediate 24h ban.")
        _save_state({
            "attempts":    999,
            "banned_until": time.time() + 86400,
            "stage":       3,
        })
        return {"lock_screen": False, "banned": True,
                "ban_seconds": 86400, "attempts": 999}

    state["attempts"] = state.get("attempts", 0) + 1
    n     = state["attempts"]
    stage = state.get("stage", 0)
    action = {"lock_screen": False, "banned": False,
              "ban_seconds": 0,    "attempts": n}

    _log("warning", f"FAIL2BAN: failed attempt #{n}.")

    if n == lock_at and do_lock:
        action["lock_screen"] = True
        _win_lock()

    for idx, (threshold, seconds) in enumerate(ban_stages):
        if n >= threshold and stage < idx + 1:
            stage = idx + 1
            state["stage"]        = stage
            state["banned_until"] = time.time() + seconds
            action["banned"]      = True
            action["ban_seconds"] = seconds
            _log("critical",
                 f"FAIL2BAN: ban stage {stage} — {seconds//60} min "
                 f"(attempt {n}).")
            break

    _save_state(state)
    return action


def record_success():
    """Reset fail2ban counter on successful login."""
    state = _load_state()
    prev  = state.get("attempts", 0)
    _save_state({"attempts": 0, "banned_until": None, "stage": 0})
    if prev:
        _log("info",
             f"FAIL2BAN: login OK after {prev} failed attempt(s). "
             "Counter reset.")
    else:
        _log("info", "Login successful.")


# ══════════════════════════════════════════════════════════════════════════
#  4. Startup routine
# ══════════════════════════════════════════════════════════════════════════
def startup_checks() -> dict:
    _log("info", f"--- Aegis starting (pid={os.getpid()}) ---")
    integrity       = verify_integrity()
    scan            = security_scan()
    banned, remaining = get_ban_status()
    return {
        "integrity_ok":  integrity,
        "scan":          scan,
        "banned":        banned,
        "ban_remaining": remaining,
    }
