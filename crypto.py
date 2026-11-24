import os
import tempfile
import json
import hashlib
import struct
from pathlib import Path
from typing import Optional
from paths import BASE_DIR

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_FILE = BASE_DIR / "Aegis.db"
LEGACY_DB_FILE = DB_FILE
VAULTS_DIR = BASE_DIR / "vaults"

# ── Argon2id parameters ────────────────────────────────────────────────────
ARGON2_MEMORY  = 64 * 1024   # 64 MB
ARGON2_TIME    = 3
ARGON2_PARALLEL= 4
ARGON2_KEYLEN  = 32          # AES-256

SALT_LEN  = 16
NONCE_LEN = 12
FORMAT_MAGIC = b"AEGISVLT"
FORMAT_VERSION = 1
HEADER = struct.Struct(">8sBIII16s12s")
MIN_MEMORY_KIB, MAX_MEMORY_KIB = 8 * 1024, 256 * 1024
MIN_TIME_COST, MAX_TIME_COST = 1, 10
MIN_PARALLELISM, MAX_PARALLELISM = 1, 8


# ── Default security profile ───────────────────────────────────────────────
DEFAULT_SETTINGS = {
    "security_level": "medium",

    # Session and clipboard
    "clipboard_autoclear_seconds":   10,
    "auto_lock_minutes": 5,

    # Self-destruct
    "self_destruct_password": "",   # stored as SHA-256 hash if set

    # Environment checks
    "anti_debug":        True,
    "anti_vm":           True,

    # Fail2ban
    "fail2ban_enabled":            True,
    "fail2ban_lock_screen":        True,
    "fail2ban_lockscreen_attempts": 2,
    "fail2ban_ban_attempts":        5,
    "fail2ban_timeout_minutes":    10,
    "hibp_enabled":                False,

}


# ── Key derivation ─────────────────────────────────────────────────────────
def _derive_key(password: str, salt: bytes, memory_cost: int = ARGON2_MEMORY,
                time_cost: int = ARGON2_TIME,
                parallelism: int = ARGON2_PARALLEL) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=ARGON2_KEYLEN,
        type=Type.ID,
    )


# ── Encrypt / decrypt ──────────────────────────────────────────────────────
def _encrypt(data: bytes, key: bytes, nonce: bytes,
             associated_data: bytes | None = None) -> bytes:
    return AESGCM(key).encrypt(nonce, data, associated_data)


def _decrypt(ciphertext: bytes, key: bytes, nonce: bytes,
             associated_data: bytes | None = None) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)


# ── DB read / write ────────────────────────────────────────────────────────
def load_db(password: str, path: Path | str = DB_FILE) -> Optional[dict]:
    path = Path(path)
    if not path.exists():
        return None

    raw = path.read_bytes()
    try:
        if raw.startswith(FORMAT_MAGIC):
            if len(raw) < HEADER.size + 16:
                return None
            magic, version, memory_cost, time_cost, parallelism, salt, nonce = \
                HEADER.unpack(raw[:HEADER.size])
            if magic != FORMAT_MAGIC or version != FORMAT_VERSION:
                return None
            if not (MIN_MEMORY_KIB <= memory_cost <= MAX_MEMORY_KIB and
                    MIN_TIME_COST <= time_cost <= MAX_TIME_COST and
                    MIN_PARALLELISM <= parallelism <= MAX_PARALLELISM and
                    memory_cost >= 8 * parallelism):
                return None
            associated_data = raw[:HEADER.size]
            ciphertext = raw[HEADER.size:]
        else:
            # Legacy files used [salt][nonce][ciphertext] with fixed parameters.
            if len(raw) < SALT_LEN + NONCE_LEN + 16:
                return None
            salt = raw[:SALT_LEN]
            nonce = raw[SALT_LEN:SALT_LEN + NONCE_LEN]
            ciphertext = raw[SALT_LEN + NONCE_LEN:]
            memory_cost, time_cost, parallelism = (
                ARGON2_MEMORY, ARGON2_TIME, ARGON2_PARALLEL)
            associated_data = None

        key = _derive_key(password, salt, memory_cost, time_cost, parallelism)
        plaintext = _decrypt(ciphertext, key, nonce, associated_data)
        return json.loads(plaintext.decode("utf-8"))
    except Exception:
        return None


def save_db(db: dict, password: str, path: Path | str = DB_FILE) -> None:
    path = Path(path)
    salt  = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    header = HEADER.pack(FORMAT_MAGIC, FORMAT_VERSION, ARGON2_MEMORY,
                         ARGON2_TIME, ARGON2_PARALLEL, salt, nonce)
    key   = _derive_key(password, salt)
    plaintext  = json.dumps(db, ensure_ascii=False).encode("utf-8")
    ciphertext = _encrypt(plaintext, key, nonce, header)
    # Replace atomically so a crash or power loss cannot leave a half-written vault.
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".aegis-", suffix=".tmp",
                                     dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(header + ciphertext)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def vault_path_for(username: str) -> Path:
    """Return a filesystem-safe path for one account's encrypted vault."""
    if not username or not username.strip():
        raise ValueError("Username cannot be empty")
    account_id = hashlib.sha256(username.encode("utf-8")).hexdigest()
    return VAULTS_DIR / f"{account_id}.aegis"


def save_account_db(db: dict, username: str, password: str) -> None:
    """Persist exactly one account in its independently encrypted vault."""
    save_db(extract_account_db(db, username), password, vault_path_for(username))


def extract_account_db(db: dict, username: str) -> dict:
    """Return an isolated database containing only the requested account."""
    users = db.get("users")
    if not isinstance(users, dict) or username not in users:
        raise ValueError("Account is missing from vault data")
    return {"users": {username: users[username]}}


def load_account_db(username: str, password: str) -> tuple[Optional[dict], bool]:
    """Load one account; migrate only that account from the legacy shared DB.

    Returns (database, migrated_from_legacy). The legacy source is preserved
    until the owner verifies every account migration and archives/removes it.
    """
    account_path = vault_path_for(username)
    if account_path.exists():
        db = load_db(password, account_path)
        if db is None or username not in db.get("users", {}):
            return None, False
        # A per-account file must never grant access to another account.
        if set(db.get("users", {})) != {username}:
            return None, False
        return db, False

    legacy = load_db(password, LEGACY_DB_FILE)
    legacy_user = legacy.get("users", {}).get(username) if legacy else None
    if legacy_user is None:
        return None, False

    # Successful decryption proves the legacy file password. Older builds may
    # have left other account verifiers stale after a password change.
    migrated_user = json.loads(json.dumps(legacy_user))
    migrated_user["master"] = hash_pw(password)
    migrated_user.setdefault("settings", {})["hibp_enabled"] = False
    migrated = {"users": {username: migrated_user}}
    save_account_db(migrated, username, password)
    verified = load_db(password, account_path)
    if verified is None or set(verified.get("users", {})) != {username}:
        try:
            account_path.unlink()
        except OSError:
            pass
        raise OSError("Could not verify migrated account vault")
    return verified, True


def db_exists(path: Path | str = DB_FILE) -> bool:
    return Path(path).exists()


# ── Password utilities ─────────────────────────────────────────────────────
def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def hash_destruct(password: str) -> str:
    return hashlib.sha256(
        ("__destruct__" + password).encode("utf-8")
    ).hexdigest()


def set_master_password(db: dict, username: str, password: str) -> dict:
    """Update only the verifier for the independently encrypted account."""
    user = db.get("users", {}).get(username)
    if user is None:
        raise ValueError("Account is missing from vault data")
    user["master"] = hash_pw(password)
    return db


# ── User management ────────────────────────────────────────────────────────
def get_user(db: dict, username: str) -> Optional[dict]:
    return db.get("users", {}).get(username)


def create_user(db: dict, username: str,
                master_password: str) -> dict:
    db.setdefault("users", {})
    db["users"][username] = {
        "master":   hash_pw(master_password),
        "entries":  [],
        "settings": dict(DEFAULT_SETTINGS),
    }
    return db


def verify_master(db: dict, username: str,
                  password: str) -> bool:
    user = get_user(db, username)
    if not user:
        return False
    return user.get("master") == hash_pw(password)


def is_self_destruct(db: dict, username: str,
                     password: str) -> bool:
    user = get_user(db, username)
    if not user:
        return False
    stored = user.get("settings", {}).get("self_destruct_password", "")
    if not stored:
        return False
    return stored == hash_destruct(password)


def get_settings(db: dict, username: str) -> dict:
    user = get_user(db, username)
    if not user:
        return dict(DEFAULT_SETTINGS)
    # Merge with defaults so new keys are always present
    merged = dict(DEFAULT_SETTINGS)
    merged.update(user.get("settings", {}))
    return merged


def save_settings(db: dict, username: str,
                  settings: dict) -> dict:
    db["users"][username]["settings"] = settings
    return db


def add_entry(db: dict, username: str, entry: dict) -> dict:
    db["users"][username]["entries"].append(entry)
    return db


def delete_entry(db: dict, username: str, idx: int) -> dict:
    db["users"][username]["entries"].pop(idx)
    return db


def get_entries(db: dict, username: str) -> list:
    return db.get("users", {}).get(username, {}).get("entries", [])


def update_entry(db: dict, username: str, idx: int, entry: dict) -> dict:
    db["users"][username]["entries"][idx] = entry
    return db
