"""Import/export helpers for the local Aegis vault."""

import csv
import shutil
from pathlib import Path


CSV_FIELDS = ("service", "login", "password", "url", "category", "notes")


def export_csv(entries: list[dict], path: str | Path) -> None:
    """Export selected entries as plaintext CSV (caller must warn the user)."""
    with open(path, "w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS,
                                extrasaction="ignore")
        writer.writeheader()
        for entry in entries:
            writer.writerow({field: entry.get(field, "")
                             for field in CSV_FIELDS})


def import_csv(path: str | Path) -> list[dict]:
    """Read a CSV export and validate required fields before merging."""
    result = []
    with open(path, "r", newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or not {"service", "login", "password"}.issubset(
                set(reader.fieldnames)):
            raise ValueError("CSV must contain service, login and password columns")
        for line, row in enumerate(reader, start=2):
            service = (row.get("service") or "").strip()
            password = row.get("password") or ""
            if not service or not password:
                raise ValueError(f"Row {line} is missing a service or password")
            result.append({
                "service": service,
                "login": (row.get("login") or "").strip(),
                "password": password,
                "url": (row.get("url") or "").strip(),
                "category": (row.get("category") or "").strip(),
                "notes": row.get("notes") or "",
            })
    return result


def create_encrypted_backup(source: str | Path, destination: str | Path) -> None:
    """Copy the already-encrypted vault file; never decrypt it for backup."""
    shutil.copyfile(source, destination)
