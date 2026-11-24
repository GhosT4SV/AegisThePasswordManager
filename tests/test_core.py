import tempfile
import unittest
import json
import os
from pathlib import Path
from unittest.mock import patch

from crypto import (ARGON2_MEMORY, ARGON2_PARALLEL, ARGON2_TIME, NONCE_LEN,
                    SALT_LEN, _derive_key, _encrypt, add_entry, create_user,
                    extract_account_db, get_entries, hash_pw, load_account_db, load_db,
                    save_account_db, save_db, set_master_password,
                    update_entry, vault_path_for)
from vault_io import export_csv, import_csv
from instance_lock import AlreadyRunningError, SingleInstanceLock


class CryptoStorageTests(unittest.TestCase):
    def test_encrypted_database_round_trip_and_wrong_password(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder) / "vault.bin"
            db = create_user({"users": {}}, "test", "correct horse battery staple")
            add_entry(db, "test", {"service": "example", "login": "alice",
                                    "password": "secret"})
            save_db(db, "correct horse battery staple", path)

            self.assertEqual(load_db("correct horse battery staple", path), db)
            self.assertIsNone(load_db("wrong password", path))
            self.assertNotIn(b"secret", path.read_bytes())
            self.assertEqual(list(Path(folder).glob(".aegis-*.tmp")), [])

    def test_failed_atomic_replace_preserves_previous_vault(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder) / "vault.bin"
            password = "correct horse battery staple"
            original = create_user({"users": {}}, "test", password)
            save_db(original, password, path)
            changed = create_user({"users": {}}, "test", password)
            add_entry(changed, "test", {"service": "new", "login": "u",
                                          "password": "p"})

            with patch("crypto.os.replace", side_effect=OSError("simulated disk error")):
                with self.assertRaises(OSError):
                    save_db(changed, password, path)

            self.assertEqual(load_db(password, path), original)
            self.assertEqual(list(Path(folder).glob(".aegis-*.tmp")), [])

    def test_kdf_header_is_authenticated(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder) / "vault.bin"
            db = create_user({"users": {}}, "test", "correct horse battery staple")
            save_db(db, "correct horse battery staple", path)
            raw = bytearray(path.read_bytes())
            raw[12] ^= 1  # alter a valid KDF memory parameter in the header
            path.write_bytes(raw)
            self.assertIsNone(load_db("correct horse battery staple", path))

    def test_reads_legacy_salt_nonce_ciphertext_format(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder) / "legacy.bin"
            password = "legacy master password"
            db = {"users": {"legacy": {"entries": []}}}
            salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
            key = _derive_key(password, salt, ARGON2_MEMORY,
                              ARGON2_TIME, ARGON2_PARALLEL)
            payload = json.dumps(db).encode("utf-8")
            path.write_bytes(salt + nonce + _encrypt(payload, key, nonce))
            self.assertEqual(load_db(password, path), db)

    def test_entry_update_preserves_database_shape(self):
        db = create_user({"users": {}}, "test", "a-long-test-password")
        add_entry(db, "test", {"service": "old", "login": "u", "password": "p"})
        update_entry(db, "test", 0, {"service": "new", "login": "u", "password": "p"})
        self.assertEqual(db["users"]["test"]["entries"][0]["service"], "new")

    def test_entries_are_read_from_account_namespace(self):
        db = create_user({"users": {}}, "test", "a-long-test-password")
        entry = {"service": "Example", "login": "alice", "password": "secret"}
        add_entry(db, "test", entry)
        self.assertEqual(get_entries(db, "test"), [entry])
        self.assertEqual(get_entries(db, "missing"), [])

    def test_extract_account_removes_other_profiles_from_session_db(self):
        db = create_user({"users": {}}, "alice", "alice-master-password")
        create_user(db, "bob", "bobby-master-password")
        isolated = extract_account_db(db, "alice")
        self.assertEqual(set(isolated["users"]), {"alice"})
        with self.assertRaises(ValueError):
            extract_account_db(db, "missing")

    def test_master_password_rekey_updates_only_selected_account(self):
        db = create_user({"users": {}}, "first", "old-password")
        create_user(db, "second", "old-password")
        set_master_password(db, "first", "new-password")
        self.assertEqual(db["users"]["first"]["master"], hash_pw("new-password"))
        self.assertEqual(db["users"]["second"]["master"], hash_pw("old-password"))

    def test_accounts_have_separate_encrypted_files_and_keys(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root = Path(folder)
            with patch("crypto.VAULTS_DIR", root / "vaults"), \
                    patch("crypto.LEGACY_DB_FILE", root / "missing-legacy.db"):
                alice = create_user({"users": {}}, "alice", "alice-master-password")
                bob = create_user({"users": {}}, "bob", "bobby-master-password")
                save_account_db(alice, "alice", "alice-master-password")
                save_account_db(bob, "bob", "bobby-master-password")

                self.assertNotEqual(vault_path_for("alice"), vault_path_for("bob"))
                self.assertIsNotNone(load_account_db("alice", "alice-master-password")[0])
                self.assertIsNone(load_account_db("alice", "bobby-master-password")[0])
                self.assertIsNone(load_account_db("bob", "alice-master-password")[0])

    def test_legacy_login_migrates_only_that_account_and_preserves_source(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root = Path(folder)
            legacy_path = root / "Aegis.db"
            legacy = create_user({"users": {}}, "alice", "legacy-password")
            create_user(legacy, "bob", "legacy-password")
            legacy["users"]["alice"]["settings"]["hibp_enabled"] = True
            save_db(legacy, "legacy-password", legacy_path)
            with patch("crypto.VAULTS_DIR", root / "vaults"), \
                    patch("crypto.LEGACY_DB_FILE", legacy_path):
                alice, migrated = load_account_db("alice", "legacy-password")
                self.assertTrue(migrated)
                self.assertEqual(set(alice["users"]), {"alice"})
                self.assertFalse(alice["users"]["alice"]["settings"]["hibp_enabled"])
                self.assertTrue(legacy_path.exists())
                self.assertFalse(vault_path_for("bob").exists())
                bob, migrated_bob = load_account_db("bob", "legacy-password")
                self.assertTrue(migrated_bob)
                self.assertEqual(set(bob["users"]), {"bob"})


class CsvTests(unittest.TestCase):
    def test_csv_round_trip_includes_extended_fields(self):
        entry = {"service": "Example", "login": "alice", "password": "secret",
                 "url": "https://example.test", "category": "Work", "notes": "note"}
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder) / "export.csv"
            export_csv([entry], path)
            self.assertEqual(import_csv(path), [entry])

    def test_csv_rejects_missing_required_columns(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder) / "bad.csv"
            path.write_text("service,password\nExample,secret\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                import_csv(path)


class InstanceLockTests(unittest.TestCase):
    def test_lock_blocks_second_writer_and_releases_cleanly(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder) / "instance.lock"
            first = SingleInstanceLock(path)
            second = SingleInstanceLock(path)
            first.acquire()
            try:
                with self.assertRaises(AlreadyRunningError):
                    second.acquire()
            finally:
                first.release()
            second.acquire()
            second.release()


if __name__ == "__main__":
    unittest.main()
