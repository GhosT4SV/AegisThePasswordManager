"""
vault_window.py — main app window after login.
Layout: sidebar (left) + content area (right).
"""

import csv
import copy
import threading
from tkinter import filedialog, messagebox
import customtkinter as ctk
from crypto import (
    extract_account_db, load_db, save_account_db, vault_path_for,
    get_entries, add_entry, delete_entry, update_entry,
    get_settings, save_settings, hash_pw, hash_destruct, set_master_password,
    verify_master, DEFAULT_SETTINGS
)
from styles import theme, apply_theme, PALETTES, FONT, PRESETS_FILE
from hibp import check_password, breach_summary
from vault_io import create_encrypted_backup, export_csv, import_csv


def t(key: str) -> str:
    return theme[key]


# ── Tab helper (imported from main to avoid circular) ─────────────────────
def _tab_chain(widgets: list):
    def _focus(w):
        inner = getattr(w, "_entry", None)
        if inner:
            inner.focus_set()
        else:
            w.focus_set()

    def _invoke(w):
        cmd = w.cget("command") if hasattr(w, "cget") else None
        if cmd:
            cmd()

    n = len(widgets)
    for i, w in enumerate(widgets):
        nxt = widgets[(i + 1) % n]
        prv = widgets[(i - 1) % n]
        target = getattr(w, "_entry", w)
        target.bind("<Tab>",
                    lambda e, nx=nxt: (_focus(nx), "break")[1], add="+")
        target.bind("<Shift-Tab>",
                    lambda e, pv=prv: (_focus(pv), "break")[1], add="+")
        if isinstance(w, ctk.CTkButton):
            target.bind("<space>",  lambda e, bw=w: _invoke(bw), add="+")
            target.bind("<Return>", lambda e, bw=w: _invoke(bw), add="+")


# ══════════════════════════════════════════════════════════════════════════
#  Content panels
# ══════════════════════════════════════════════════════════════════════════

class VaultPanel(ctk.CTkFrame):
    """Password entries list + add/delete."""

    def __init__(self, master, username: str, db: dict,
                 master_pw: str, on_db_update=None, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self._user        = username
        self._db          = db
        self._master_pw   = master_pw
        self._on_db_update= on_db_update
        self._selected    = None
        self._editing     = None
        self._build()

    def _build(self):
        # Header
        hdr = ctk.CTkLabel(self, text="🔐  Vault",
                           font=ctk.CTkFont(FONT, 22, "bold"),
                           text_color=t("ACCENT"), anchor="w")
        hdr.pack(fill="x", padx=4, pady=(4, 16))

        # Add-entry row
        add_card = ctk.CTkFrame(self, fg_color=t("SURFACE2"),
                                corner_radius=14)
        add_card.pack(fill="x", pady=(0, 12))

        fields_row = ctk.CTkFrame(add_card, fg_color="transparent")
        fields_row.pack(fill="x", padx=12, pady=(12, 8))

        self._e_svc = ctk.CTkEntry(
            fields_row, placeholder_text="Service",
            corner_radius=10, fg_color=t("SURFACE"),
            border_color=t("BORDER"), text_color=t("TEXT"),
            font=ctk.CTkFont(FONT, 13))
        self._e_log = ctk.CTkEntry(
            fields_row, placeholder_text="Login",
            corner_radius=10, fg_color=t("SURFACE"),
            border_color=t("BORDER"), text_color=t("TEXT"),
            font=ctk.CTkFont(FONT, 13))
        self._e_pw = ctk.CTkEntry(
            fields_row, placeholder_text="Password",
            show="•", corner_radius=10, fg_color=t("SURFACE"),
            border_color=t("BORDER"), text_color=t("TEXT"),
            font=ctk.CTkFont(FONT, 13))

        for w in (self._e_svc, self._e_log, self._e_pw):
            w.pack(side="left", expand=True, fill="x", padx=(0, 8))

        detail_row = ctk.CTkFrame(add_card, fg_color="transparent")
        detail_row.pack(fill="x", padx=12, pady=(0, 8))
        self._e_url = ctk.CTkEntry(detail_row, placeholder_text="Website URL",
            corner_radius=10, fg_color=t("SURFACE"), border_color=t("BORDER"),
            text_color=t("TEXT"), font=ctk.CTkFont(FONT, 13))
        self._e_category = ctk.CTkEntry(detail_row, placeholder_text="Category",
            corner_radius=10, fg_color=t("SURFACE"), border_color=t("BORDER"),
            text_color=t("TEXT"), font=ctk.CTkFont(FONT, 13))
        self._e_notes = ctk.CTkEntry(detail_row, placeholder_text="Notes",
            corner_radius=10, fg_color=t("SURFACE"), border_color=t("BORDER"),
            text_color=t("TEXT"), font=ctk.CTkFont(FONT, 13))
        for w in (self._e_url, self._e_category, self._e_notes):
            w.pack(side="left", expand=True, fill="x", padx=(0, 8))

        add_btn = ctk.CTkButton(
            add_card, text="＋ Add",
            height=38, width=100, corner_radius=10,
            fg_color=t("ACCENT"), hover_color=t("ACCENT_HOV"),
            text_color="#000000", font=ctk.CTkFont(FONT, 13, "bold"),
            command=self._submit_entry)
        add_btn.pack(anchor="e", padx=12, pady=(0, 12))

        self._search_var = ctk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._refresh())
        ctk.CTkEntry(self, textvariable=self._search_var,
            placeholder_text="Search service, login, URL, category or notes…",
            height=36, corner_radius=10, fg_color=t("SURFACE"),
            border_color=t("BORDER"), text_color=t("TEXT"),
            font=ctk.CTkFont(FONT, 12)).pack(fill="x", pady=(0, 8))

        # Column headers
        col_hdr = ctk.CTkFrame(self, fg_color="transparent")
        col_hdr.pack(fill="x", padx=4)
        for text, w in [("Service", 180), ("Login", 180), ("Password", 140)]:
            ctk.CTkLabel(col_hdr, text=text, width=w, anchor="w",
                         font=ctk.CTkFont(FONT, 11),
                         text_color=t("SUBTEXT")).pack(side="left", padx=8)

        ctk.CTkFrame(self, fg_color=t("BORDER"),
                     height=1, corner_radius=0).pack(fill="x", pady=(4, 0))

        # Scrollable list
        self._box = ctk.CTkScrollableFrame(
            self, fg_color="transparent", corner_radius=0)
        self._box.pack(fill="both", expand=True, pady=(4, 12))

        # Delete button
        action_row = ctk.CTkFrame(self, fg_color="transparent")
        action_row.pack(fill="x")
        ctk.CTkButton(action_row, text="Edit selected", height=36,
            command=self._edit_selected).pack(side="left", padx=(0, 6))
        del_btn = ctk.CTkButton(action_row, text="Delete selected",
            height=36, fg_color=t("DANGER"), hover_color=t("DANGER_HOV"),
            command=self._delete)
        del_btn.pack(side="left", padx=6)
        ctk.CTkButton(action_row, text="Encrypted backup", height=36,
            command=self._backup).pack(side="right", padx=(6, 0))
        ctk.CTkButton(action_row, text="Restore backup", height=36,
            command=self._restore_backup).pack(side="right", padx=6)
        ctk.CTkButton(action_row, text="Export CSV", height=36,
            command=self._export_csv).pack(side="right", padx=6)
        ctk.CTkButton(action_row, text="Import CSV", height=36,
            command=self._import_csv).pack(side="right", padx=6)

        # HIBP check row
        hibp_row = ctk.CTkFrame(self, fg_color="transparent")
        hibp_row.pack(fill="x", pady=(12, 0))

        self._hibp_lbl = ctk.CTkLabel(
            hibp_row, text="",
            font=ctk.CTkFont(FONT, 12),
            text_color=t("SUBTEXT"), anchor="w")
        self._hibp_lbl.pack(side="left", fill="x", expand=True)

        self._hibp_btn = ctk.CTkButton(
            hibp_row, text="🔍  Check selected",
            height=38, width=180, corner_radius=10,
            fg_color=t("SURFACE2"), hover_color=t("BORDER"),
            border_color=t("BORDER"), border_width=1,
            text_color=t("TEXT"),
            font=ctk.CTkFont(FONT, 12, "bold"),
            command=self._hibp_check)
        self._hibp_btn.pack(side="right")

        _tab_chain([self._e_svc, self._e_log, self._e_pw,
                    self._e_url, self._e_category, self._e_notes, add_btn,
                    del_btn, self._hibp_btn])
        self._refresh()
        if get_settings(self._db, self._user).get("hibp_enabled", True):
            self.after(1500, self._auto_hibp_scan)

    def _refresh(self):
        for w in self._box.winfo_children():
            w.destroy()
        self._selected = None
        entries = get_entries(self._db, self._user)
        query = self._search_var.get().strip().casefold()
        for i, e in enumerate(entries):
            searchable = " ".join(str(e.get(k, "")) for k in
                ("service", "login", "url", "category", "notes")).casefold()
            if query and query not in searchable:
                continue
            row = ctk.CTkFrame(self._box, fg_color=t("SURFACE2"),
                               corner_radius=10, height=44)
            row.pack(fill="x", pady=3)
            row.pack_propagate(False)

            for text, width in [
                (f"{e.get('service', '')} · {e.get('category', '')}".rstrip(" · "), 180),
                (e.get("login", ""),    180),
            ]:
                ctk.CTkLabel(row, text=text, width=width, anchor="w",
                             font=ctk.CTkFont(FONT, 13),
                             text_color=t("TEXT")).pack(side="left", padx=8)

            # Password field with eye toggle
            password = e.get("password", "")
            pw_var = ctk.StringVar(value="•" * len(password))
            pw_lbl = ctk.CTkLabel(row, textvariable=pw_var, width=140,
                                  anchor="w", font=ctk.CTkFont(FONT, 13),
                                  text_color=t("TEXT"))
            pw_lbl.pack(side="left", padx=8)

            pw_val = password   # capture

            def _press_eye(ev, lbl=pw_lbl, var=pw_var, p=pw_val):
                var.set(p)
            def _release_eye(ev, lbl=pw_lbl, var=pw_var, p=pw_val):
                var.set("•" * len(p))

            eye_btn = ctk.CTkButton(
                row, text="👁", width=32, height=28,
                corner_radius=8,
                fg_color="transparent", hover_color=t("BORDER"),
                text_color=t("SUBTEXT"), font=ctk.CTkFont(FONT, 14))
            eye_btn.pack(side="left", padx=(0, 2))
            eye_btn.bind("<ButtonPress-1>",   _press_eye)
            eye_btn.bind("<ButtonRelease-1>", _release_eye)

            copy_btn = ctk.CTkButton(
                row, text="📋", width=32, height=28,
                corner_radius=8,
                fg_color="transparent", hover_color=t("BORDER"),
                text_color=t("SUBTEXT"), font=ctk.CTkFont(FONT, 14),
                command=lambda p=pw_val: self._copy_pw(p))
            copy_btn.pack(side="left", padx=(0, 4))

            # select row on click (but not on eye/copy buttons)
            for widget in (row, pw_lbl):
                widget.bind("<Button-1>",
                            lambda ev, r=row, n=i: self._select(r, n))

    def _select(self, row_widget, idx):
        for w in self._box.winfo_children():
            w.configure(fg_color=t("SURFACE2"))
        row_widget.configure(fg_color=t("BORDER"))
        self._selected = idx

    def _submit_entry(self):
        s = self._e_svc.get().strip()
        l = self._e_log.get().strip()
        p = self._e_pw.get()
        if not all([s, l, p]):
            return
        entry = {"service": s, "login": l, "password": p,
                 "url": self._e_url.get().strip(),
                 "category": self._e_category.get().strip(),
                 "notes": self._e_notes.get().strip()}
        candidate = copy.deepcopy(self._db)
        if self._editing is None:
            add_entry(candidate, self._user, entry)
        else:
            update_entry(candidate, self._user, self._editing, entry)
        if not self._persist_candidate(candidate):
            return
        self._editing = None
        if self._editing is None:
            for child in self.winfo_children():
                if isinstance(child, ctk.CTkFrame):
                    for button in child.winfo_children():
                        if isinstance(button, ctk.CTkButton) and "Save changes" in button.cget("text"):
                            button.configure(text="＋ Add")
        for w in (self._e_svc, self._e_log, self._e_pw,
                  self._e_url, self._e_category, self._e_notes):
            w.delete(0, "end")
        self._refresh()

    def _edit_selected(self):
        if self._selected is None:
            return
        entry = get_entries(self._db, self._user)[self._selected]
        for widget, key in ((self._e_svc, "service"), (self._e_log, "login"),
                            (self._e_pw, "password"), (self._e_url, "url"),
                            (self._e_category, "category"), (self._e_notes, "notes")):
            widget.delete(0, "end")
            widget.insert(0, entry.get(key, ""))
        self._editing = self._selected
        for child in self.winfo_children():
            if isinstance(child, ctk.CTkFrame):
                for button in child.winfo_children():
                    if isinstance(button, ctk.CTkButton) and "Add" in button.cget("text"):
                        button.configure(text="Save changes")

    def _delete(self):
        if self._selected is None:
            return
        if not messagebox.askyesno("Delete entry", "Delete the selected vault entry?",
                                   parent=self):
            return
        candidate = copy.deepcopy(self._db)
        delete_entry(candidate, self._user, self._selected)
        if not self._persist_candidate(candidate):
            return
        self._refresh()

    def _persist_candidate(self, candidate: dict, password: str | None = None) -> bool:
        """Persist a proposed vault state before replacing the live session state."""
        try:
            save_account_db(candidate, self._user, password or self._master_pw)
        except Exception as exc:
            messagebox.showerror("Save failed", f"The vault was not changed.\n{exc}",
                                 parent=self)
            return False
        self._db = candidate
        if self._on_db_update:
            self._on_db_update(candidate)
        return True

    def _backup(self):
        target = filedialog.asksaveasfilename(parent=self,
            title="Save encrypted Aegis backup", defaultextension=".aegis",
            filetypes=[("Encrypted Aegis backup", "*.aegis"), ("All files", "*.*")])
        if target:
            try:
                create_encrypted_backup(vault_path_for(self._user), target)
                messagebox.showinfo("Backup created", "Encrypted backup saved.", parent=self)
            except OSError as exc:
                messagebox.showerror("Backup failed", str(exc), parent=self)

    def _restore_backup(self):
        source = filedialog.askopenfilename(parent=self,
            title="Choose encrypted Aegis backup",
            filetypes=[("Aegis backup", "*.aegis *.db"), ("All files", "*.*")])
        if not source:
            return
        if not messagebox.askyesno("Restore backup",
            "Restoring replaces the current vault with this backup. Continue?", parent=self):
            return
        try:
            restored = load_db(self._master_pw, source)
        except OSError as exc:
            messagebox.showerror("Restore failed", str(exc), parent=self)
            return
        if restored is None or self._user not in restored.get("users", {}):
            messagebox.showerror("Restore failed",
                "The backup is invalid, uses a different master password, or lacks this account.", parent=self)
            return
        restored = extract_account_db(restored, self._user)
        if not self._persist_candidate(restored):
            return
        self._refresh()
        messagebox.showinfo("Restore complete", "Vault restored successfully.", parent=self)
        self.after(500, self.winfo_toplevel()._logout)

    def _export_csv(self):
        if not messagebox.askyesno("Plaintext export",
            "CSV files are not encrypted and expose every exported password. Continue?", parent=self):
            return
        target = filedialog.asksaveasfilename(parent=self,
            title="Export vault entries", defaultextension=".csv",
            filetypes=[("CSV", "*.csv")])
        if target:
            try:
                export_csv(get_entries(self._db, self._user), target)
                messagebox.showinfo("Export complete", "CSV exported. Store it securely and delete it when no longer needed.", parent=self)
            except (OSError, csv.Error) as exc:
                messagebox.showerror("Export failed", str(exc), parent=self)

    def _import_csv(self):
        source = filedialog.askopenfilename(parent=self,
            title="Import CSV", filetypes=[("CSV", "*.csv")])
        if not source:
            return
        try:
            entries = import_csv(source)
        except (OSError, ValueError, csv.Error) as exc:
            messagebox.showerror("Import failed", str(exc), parent=self)
            return
        if not entries:
            messagebox.showinfo("Import", "No entries found in CSV.", parent=self)
            return
        if not messagebox.askyesno("Import entries",
            f"Add {len(entries)} entries to this vault?", parent=self):
            return
        candidate = copy.deepcopy(self._db)
        for entry in entries:
            add_entry(candidate, self._user, entry)
        if not self._persist_candidate(candidate):
            return
        self._refresh()
        messagebox.showinfo("Import complete", f"Imported {len(entries)} entries.", parent=self)

    def _hibp_check(self):
        if self._selected is None:
            self._hibp_set("Select an entry first.", t("SUBTEXT"))
            return
        entries = get_entries(self._db, self._user)
        if self._selected >= len(entries):
            return
        pw = entries[self._selected]["password"]
        svc = entries[self._selected]["service"]

        self._hibp_btn.configure(state="disabled", text="Checking…")
        self._hibp_set("Contacting HaveIBeenPwned…", t("SUBTEXT"))

        def _worker():
            pwned, count, error = check_password(pw)
            if error:
                msg   = f"⚠  {error}"
                color = t("SUBTEXT")
            elif pwned:
                msg   = f"⚠  {svc}: {breach_summary(count)}"
                color = t("DANGER")
            else:
                msg   = f"✓  {svc}: Not found in any known breach"
                color = t("ACCENT")
            self.after(0, lambda: self._hibp_set(msg, color))
            self.after(0, lambda: self._hibp_btn.configure(
                state="normal", text="🔍  Check selected"))

        threading.Thread(target=_worker, daemon=True).start()

    def _hibp_set(self, msg: str, color: str):
        self._hibp_lbl.configure(text=msg, text_color=color)

    def _auto_hibp_scan(self):
        """Scan all vault entries against HIBP on login, show popup summary."""
        if not get_settings(self._db, self._user).get("hibp_enabled", True):
            return
        entries = get_entries(self._db, self._user)
        if not entries:
            return

        def _worker():
            results = []
            for e in entries:
                pwned, count, error = check_password(e["password"])
                if error:
                    continue
                if pwned:
                    results.append((e["service"], e["login"], count))
            self.after(0, lambda r=results: self._show_hibp_popup(r))

        threading.Thread(target=_worker, daemon=True).start()

    def _show_hibp_popup(self, results: list):
        """Show popup summarising HIBP scan results."""
        popup = ctk.CTkToplevel(self)
        popup.title("Breach Report")
        popup.configure(fg_color=t("BG"))
        popup.resizable(False, False)
        popup.grab_set()

        ctk.CTkLabel(popup, text="🔍  Breach Scan Complete",
                     font=ctk.CTkFont(FONT, 16, "bold"),
                     text_color=t("ACCENT")).pack(pady=(20, 8))

        if not results:
            ctk.CTkLabel(popup,
                         text="✓  No passwords found in known breaches.",
                         font=ctk.CTkFont(FONT, 13),
                         text_color=t("ACCENT")).pack(padx=24, pady=(0, 20))
        else:
            ctk.CTkLabel(popup,
                         text=f"⚠  {len(results)} password(s) found in breaches:",
                         font=ctk.CTkFont(FONT, 13),
                         text_color=t("DANGER")).pack(padx=24, pady=(0, 8))

            box = ctk.CTkScrollableFrame(popup, fg_color=t("SURFACE"),
                                          corner_radius=12, height=200)
            box.pack(fill="x", padx=20, pady=(0, 12))
            for svc, login, count in results:
                row = ctk.CTkFrame(box, fg_color=t("SURFACE2"),
                                   corner_radius=8, height=40)
                row.pack(fill="x", pady=3)
                row.pack_propagate(False)
                ctk.CTkLabel(row,
                             text=f"  {svc} ({login})",
                             font=ctk.CTkFont(FONT, 12, "bold"),
                             text_color=t("TEXT"), anchor="w").pack(
                    side="left", padx=8)
                ctk.CTkLabel(row,
                             text=f"{count:,}×  ",
                             font=ctk.CTkFont(FONT, 12),
                             text_color=t("DANGER"), anchor="e").pack(
                    side="right", padx=8)

        ctk.CTkButton(popup, text="Close",
                      height=40, corner_radius=10,
                      fg_color=t("SURFACE2"), hover_color=t("BORDER"),
                      text_color=t("SUBTEXT"),
                      command=popup.destroy).pack(padx=20, pady=(0, 20),
                                                   fill="x")
        popup.update_idletasks()
        w = 420
        h = popup.winfo_reqheight()
        # Center over vault window
        try:
            vx = self.winfo_toplevel().winfo_x()
            vy = self.winfo_toplevel().winfo_y()
            vw = self.winfo_toplevel().winfo_width()
            vh = self.winfo_toplevel().winfo_height()
            popup.geometry(f"{w}x{h}+{vx+(vw-w)//2}+{vy+(vh-h)//2}")
        except Exception:
            popup.geometry(f"{w}x{h}")

    def _copy_pw(self, password: str):
        self.clipboard_clear()
        self.clipboard_append(password)
        # Flash the HIBP label as "copied" feedback
        old = self._hibp_lbl.cget("text")
        self._hibp_lbl.configure(text="✓  Copied to clipboard",
                                  text_color=t("ACCENT"))
        settings = get_settings(self._db, self._user)
        clear_sec = settings.get("clipboard_autoclear_seconds", 10)
        top = self.winfo_toplevel()
        top._clipboard_generation += 1
        top._clipboard_value = password
        generation = top._clipboard_generation
        self.after(clear_sec * 1000, lambda g=generation, p=password:
                   top._clear_clipboard_if_matches(p, g))
        self.after(2000, lambda: self._hibp_lbl.configure(
            text=old, text_color=t("SUBTEXT")))


# ── Generator panel ────────────────────────────────────────────────────────
class GeneratorPanel(ctk.CTkFrame):
    """Simple password generator."""

    def __init__(self, master, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self._build()

    def _build(self):
        ctk.CTkLabel(self, text="🎲  Generator",
                     font=ctk.CTkFont(FONT, 22, "bold"),
                     text_color=t("ACCENT"), anchor="w").pack(
            fill="x", padx=4, pady=(4, 20))

        card = ctk.CTkFrame(self, fg_color=t("SURFACE2"), corner_radius=16)
        card.pack(fill="x")

        # Length slider
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(20, 8))
        ctk.CTkLabel(row, text="Length",
                     font=ctk.CTkFont(FONT, 13),
                     text_color=t("TEXT")).pack(side="left")
        self._len_lbl = ctk.CTkLabel(row, text="16",
                                     font=ctk.CTkFont(FONT, 13, "bold"),
                                     text_color=t("ACCENT"))
        self._len_lbl.pack(side="right")
        self._slider = ctk.CTkSlider(
            card, from_=8, to=64, number_of_steps=56,
            button_color=t("ACCENT"), button_hover_color=t("ACCENT_HOV"),
            progress_color=t("ACCENT"),
            command=self._update_len)
        self._slider.set(16)
        self._slider.pack(fill="x", padx=20, pady=(0, 16))

        # Checkboxes
        self._vars = {}
        for label, key, default in [
            ("Uppercase  (A-Z)", "upper", True),
            ("Lowercase  (a-z)", "lower", True),
            ("Digits       (0-9)", "digits", True),
            ("Symbols   (!@#…)", "symbols", False),
        ]:
            var = ctk.BooleanVar(value=default)
            self._vars[key] = var
            ctk.CTkCheckBox(card, text=label, variable=var,
                            font=ctk.CTkFont(FONT, 13),
                            text_color=t("TEXT"),
                            checkmark_color=t("BG"),
                            fg_color=t("ACCENT"),
                            hover_color=t("ACCENT_HOV")).pack(
                anchor="w", padx=20, pady=4)

        # Output
        out_row = ctk.CTkFrame(card, fg_color="transparent")
        out_row.pack(fill="x", padx=20, pady=(16, 20))
        self._output = ctk.CTkEntry(
            out_row, height=46, corner_radius=12,
            fg_color=t("SURFACE"), border_color=t("BORDER"),
            text_color=t("TEXT"), font=ctk.CTkFont(FONT, 15))
        self._output.pack(side="left", expand=True, fill="x", padx=(0, 8))

        ctk.CTkButton(out_row, text="Generate",
                      width=110, height=46, corner_radius=12,
                      fg_color=t("ACCENT"), hover_color=t("ACCENT_HOV"),
                      text_color="#000000",
                      font=ctk.CTkFont(FONT, 13, "bold"),
                      command=self._generate).pack(side="left")

        ctk.CTkButton(card, text="📋  Copy",
                      height=38, corner_radius=10, width=120,
                      fg_color=t("SURFACE"), hover_color=t("BORDER"),
                      border_color=t("BORDER"), border_width=1,
                      text_color=t("TEXT"),
                      font=ctk.CTkFont(FONT, 13),
                      command=self._copy).pack(anchor="e",
                                               padx=20, pady=(0, 20))

    def _update_len(self, val):
        self._len_lbl.configure(text=str(int(val)))

    def _generate(self):
        import random, secrets, string
        groups = []
        if self._vars["upper"].get():   groups.append(string.ascii_uppercase)
        if self._vars["lower"].get():   groups.append(string.ascii_lowercase)
        if self._vars["digits"].get():  groups.append(string.digits)
        if self._vars["symbols"].get(): groups.append("!@#$%^&*()-_=+[]{}|;:,.<>?")
        if not groups:
            groups = [string.ascii_letters]
        pool = "".join(groups)
        length = int(self._slider.get())
        chars = [secrets.choice(group) for group in groups]
        chars.extend(secrets.choice(pool) for _ in range(length - len(chars)))
        random.SystemRandom().shuffle(chars)
        pw = "".join(chars)
        self._output.delete(0, "end")
        self._output.insert(0, pw)

    def _copy(self):
        pw = self._output.get()
        if pw:
            self.clipboard_clear()
            self.clipboard_append(pw)
            top = self.winfo_toplevel()
            top._clipboard_generation += 1
            top._clipboard_value = pw
            generation = top._clipboard_generation
            seconds = get_settings(top._db, top._user).get(
                "clipboard_autoclear_seconds", 10)
            self.after(seconds * 1000, lambda g=generation, p=pw:
                top._clear_clipboard_if_matches(p, g))


# ── Settings panel ─────────────────────────────────────────────────────────
class SettingsPanel(ctk.CTkFrame):
    """Inline theme settings (same logic as old SettingsWindow)."""

    def __init__(self, master, app_root, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self._app   = app_root
        self._draft = dict(theme)
        self._entries: dict[str, ctk.CTkEntry] = {}
        self._build()

    def _build(self):
        ctk.CTkLabel(self, text="⚙  Settings",
                     font=ctk.CTkFont(FONT, 22, "bold"),
                     text_color=t("ACCENT"), anchor="w").pack(
            fill="x", padx=4, pady=(4, 16))

        # Presets
        pf = ctk.CTkFrame(self, fg_color=t("SURFACE2"), corner_radius=14)
        pf.pack(fill="x", pady=(0, 16))
        ctk.CTkLabel(pf, text="Presets",
                     font=ctk.CTkFont(FONT, 12),
                     text_color=t("SUBTEXT")).pack(
            anchor="w", padx=14, pady=(10, 4))

        btn_row = ctk.CTkFrame(pf, fg_color="transparent")
        btn_row.pack(fill="x", padx=10, pady=(0, 8))
        for name, palette in PALETTES.items():
            if not palette:
                continue
            ctk.CTkButton(
                btn_row, text=name, height=32, corner_radius=8,
                fg_color=palette["SURFACE"],
                hover_color=palette["SURFACE2"],
                border_color=palette["ACCENT"], border_width=2,
                text_color=palette["ACCENT"],
                font=ctk.CTkFont(FONT, 11, "bold"),
                command=lambda p=palette: self._load_preset(p)
            ).pack(side="left", padx=4)

        save_row = ctk.CTkFrame(pf, fg_color="transparent")
        save_row.pack(fill="x", padx=10, pady=(0, 10))
        self._preset_name = ctk.CTkEntry(
            save_row, placeholder_text="New preset name…",
            width=200, height=30, corner_radius=8,
            fg_color=t("SURFACE"), border_color=t("BORDER"),
            text_color=t("TEXT"), font=ctk.CTkFont(FONT, 12))
        self._preset_name.pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            save_row, text="＋ Save preset",
            height=30, corner_radius=8, width=130,
            fg_color=t("ACCENT"), hover_color=t("ACCENT_HOV"),
            text_color="#000000",
            font=ctk.CTkFont(FONT, 12, "bold"),
            command=self._save_preset
        ).pack(side="left")

        # Colour editor
        editor = ctk.CTkScrollableFrame(self, fg_color=t("SURFACE"),
                                         corner_radius=12)
        editor.pack(fill="both", expand=True, pady=(0, 16))

        LABELS = {
            "BG": "Background", "SURFACE": "Surface (cards)",
            "SURFACE2": "Surface 2 (inputs)", "ACCENT": "Accent colour",
            "ACCENT_HOV": "Accent hover", "DANGER": "Danger / error",
            "DANGER_HOV": "Danger hover", "TEXT": "Primary text",
            "SUBTEXT": "Secondary text", "BORDER": "Border",
        }
        for key, label in LABELS.items():
            row = ctk.CTkFrame(editor, fg_color="transparent")
            row.pack(fill="x", pady=4, padx=8)
            swatch = ctk.CTkFrame(row, width=28, height=28,
                                  corner_radius=6,
                                  fg_color=self._draft.get(key, "#888"))
            swatch.pack(side="left", padx=(0, 8))
            ctk.CTkLabel(row, text=label, width=140, anchor="w",
                         font=ctk.CTkFont(FONT, 13),
                         text_color=t("TEXT")).pack(side="left")
            ent = ctk.CTkEntry(row, width=110, height=32, corner_radius=8,
                               fg_color=t("SURFACE2"),
                               border_color=t("BORDER"),
                               text_color=t("TEXT"),
                               font=ctk.CTkFont(FONT, 13))
            ent.insert(0, self._draft.get(key, ""))
            ent.pack(side="left", padx=8)
            self._entries[key] = ent
            self._entries[f"__sw_{key}"] = swatch

            def _on_key(event, k=key, s=swatch, e=ent):
                val = e.get().strip()
                if len(val) == 7 and val.startswith("#"):
                    try:
                        int(val[1:], 16)
                        s.configure(fg_color=val)
                        self._draft[k] = val
                    except ValueError:
                        pass
            ent.bind("<KeyRelease>", _on_key)

        apply_btn = ctk.CTkButton(
            self, text="Apply & Restart",
            height=46, corner_radius=12,
            fg_color=t("ACCENT"), hover_color=t("ACCENT_HOV"),
            text_color="#000000",
            font=ctk.CTkFont(FONT, 14, "bold"),
            command=self._apply)
        apply_btn.pack(fill="x")

    def _load_preset(self, palette: dict):
        self._draft = dict(palette)
        for key, widget in self._entries.items():
            if key.startswith("__sw_"):
                widget.configure(fg_color=palette.get(key[5:], "#888"))
            elif key in palette:
                widget.delete(0, "end")
                widget.insert(0, palette[key])

    def _save_preset(self):
        self._collect_draft()
        name = self._preset_name.get().strip()
        if not name:
            return
        PALETTES[name] = dict(self._draft)
        import json, os
        pf = PRESETS_FILE
        existing = {}
        if os.path.exists(pf):
            with open(pf, encoding="utf-8") as f:
                existing = json.load(f)
        existing[name] = dict(self._draft)
        with open(pf, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)
        self._preset_name.delete(0, "end")
        self._preset_name.configure(border_color=t("ACCENT"))
        self.after(800, lambda: self._preset_name.configure(
            border_color=t("BORDER")))

    def _collect_draft(self):
        for key, widget in self._entries.items():
            if not key.startswith("__sw_"):
                val = widget.get().strip()
                if val:
                    self._draft[key] = val

    def _apply(self):
        self._collect_draft()
        apply_theme(self._draft, self._app)
        from main import launch
        launch()


# ── Account panel ──────────────────────────────────────────────────────────
class AccountPanel(ctk.CTkFrame):
    def __init__(self, master, username: str, db: dict,
                 master_pw: str, on_logout=None, on_db_update=None,
                 on_master_pw_change=None, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self._user        = username
        self._db          = db
        self._master_pw   = master_pw
        self._on_logout   = on_logout
        self._on_db_update= on_db_update
        self._on_master_pw_change = on_master_pw_change
        self._build()

    def _build(self):
        ctk.CTkLabel(self, text="👤  Account",
                     font=ctk.CTkFont(FONT, 22, "bold"),
                     text_color=t("ACCENT"), anchor="w").pack(
            fill="x", padx=4, pady=(4, 20))

        # ── Profile card ───────────────────────────────────────────────────
        profile_card = ctk.CTkFrame(self, fg_color=t("SURFACE2"),
                                    corner_radius=16)
        profile_card.pack(fill="x", pady=(0, 16))

        ctk.CTkLabel(profile_card, text="🏛",
                     font=ctk.CTkFont(size=48)).pack(pady=(24, 4))
        ctk.CTkLabel(profile_card, text=self._user,
                     font=ctk.CTkFont(FONT, 20, "bold"),
                     text_color=t("TEXT")).pack()
        ctk.CTkLabel(profile_card, text="Local vault account",
                     font=ctk.CTkFont(FONT, 12),
                     text_color=t("SUBTEXT")).pack(pady=(4, 20))

        # ── Change password card ───────────────────────────────────────────
        pw_card = ctk.CTkFrame(self, fg_color=t("SURFACE2"), corner_radius=16)
        pw_card.pack(fill="x", pady=(0, 16))

        ctk.CTkLabel(pw_card, text="Change master password",
                     font=ctk.CTkFont(FONT, 14, "bold"),
                     text_color=t("TEXT"), anchor="w").pack(
            fill="x", padx=20, pady=(20, 12))

        # Current password
        cur_row = ctk.CTkFrame(pw_card, fg_color="transparent")
        cur_row.pack(fill="x", padx=20, pady=(0, 8))
        ctk.CTkLabel(cur_row, text="Current", width=100, anchor="w",
                     font=ctk.CTkFont(FONT, 13),
                     text_color=t("SUBTEXT")).pack(side="left")
        self._cur_pw = ctk.CTkEntry(
            cur_row, show="•", height=40, corner_radius=10,
            fg_color=t("SURFACE"), border_color=t("BORDER"),
            text_color=t("TEXT"), font=ctk.CTkFont(FONT, 13))
        self._cur_pw.pack(side="left", expand=True, fill="x")

        # New password
        new_row = ctk.CTkFrame(pw_card, fg_color="transparent")
        new_row.pack(fill="x", padx=20, pady=(0, 8))
        ctk.CTkLabel(new_row, text="New", width=100, anchor="w",
                     font=ctk.CTkFont(FONT, 13),
                     text_color=t("SUBTEXT")).pack(side="left")
        self._new_pw = ctk.CTkEntry(
            new_row, show="•", height=40, corner_radius=10,
            fg_color=t("SURFACE"), border_color=t("BORDER"),
            text_color=t("TEXT"), font=ctk.CTkFont(FONT, 13))
        self._new_pw.pack(side="left", expand=True, fill="x")

        # Confirm password
        conf_row = ctk.CTkFrame(pw_card, fg_color="transparent")
        conf_row.pack(fill="x", padx=20, pady=(0, 16))
        ctk.CTkLabel(conf_row, text="Confirm", width=100, anchor="w",
                     font=ctk.CTkFont(FONT, 13),
                     text_color=t("SUBTEXT")).pack(side="left")
        self._conf_pw = ctk.CTkEntry(
            conf_row, show="•", height=40, corner_radius=10,
            fg_color=t("SURFACE"), border_color=t("BORDER"),
            text_color=t("TEXT"), font=ctk.CTkFont(FONT, 13))
        self._conf_pw.pack(side="left", expand=True, fill="x")

        # Feedback label
        self._pw_status = ctk.CTkLabel(
            pw_card, text="", font=ctk.CTkFont(FONT, 12),
            text_color=t("SUBTEXT"))
        self._pw_status.pack(pady=(0, 8))

        change_btn = ctk.CTkButton(
            pw_card, text="Update password",
            height=42, corner_radius=10,
            fg_color=t("ACCENT"), hover_color=t("ACCENT_HOV"),
            text_color="#000000",
            font=ctk.CTkFont(FONT, 13, "bold"),
            command=self._change_password)
        change_btn.pack(padx=20, pady=(0, 20), fill="x")

        _tab_chain([self._cur_pw, self._new_pw, self._conf_pw, change_btn])

        # ── Danger zone ────────────────────────────────────────────────────
        danger_card = ctk.CTkFrame(self, fg_color=t("SURFACE2"),
                                   corner_radius=16)
        danger_card.pack(fill="x")

        ctk.CTkLabel(danger_card, text="Session",
                     font=ctk.CTkFont(FONT, 12),
                     text_color=t("SUBTEXT"), anchor="w").pack(
            fill="x", padx=20, pady=(16, 8))

        ctk.CTkButton(danger_card, text="🔓  Log out",
                      height=42, corner_radius=10,
                      fg_color="transparent",
                      hover_color=t("SURFACE"),
                      border_color=t("DANGER"), border_width=1,
                      text_color=t("DANGER"),
                      font=ctk.CTkFont(FONT, 13, "bold"),
                      command=self._on_logout).pack(
            fill="x", padx=20, pady=(0, 20))

    def _change_password(self):
        cur  = self._cur_pw.get()
        new  = self._new_pw.get()
        conf = self._conf_pw.get()

        # Validate current password
        if not verify_master(self._db, self._user, cur):
            self._flash_status("✕  Wrong current password", error=True)
            self._cur_pw.configure(border_color=t("DANGER"))
            self.after(800, lambda: self._cur_pw.configure(
                border_color=t("BORDER")))
            return

        if len(new) < 12:
            self._flash_status("✕  New password too short (min 12 chars)",
                               error=True)
            return

        if new != conf:
            self._flash_status("✕  Passwords don't match", error=True)
            self._conf_pw.configure(border_color=t("DANGER"))
            self.after(800, lambda: self._conf_pw.configure(
                border_color=t("BORDER")))
            return

        # Check new password against HIBP before saving
        self._flash_status("Checking against HaveIBeenPwned…", error=False)

        def _do_change():
            if get_settings(self._db, self._user).get("hibp_enabled", True):
                pwned, count, error = check_password(new)
            else:
                pwned, count, error = False, 0, None
            if pwned:
                msg = (f"⚠  This password appeared in {count:,} breach(es).\n"
                       f"Choose a stronger password.")
                self.after(0, lambda: self._flash_status(msg, error=True))
                self.after(0, lambda: self._new_pw.configure(
                    border_color=t("DANGER")))
                self.after(800, lambda: self._new_pw.configure(
                    border_color=t("BORDER")))
                return
            # Save
            # Re-encrypt only this account's independently stored vault.
            candidate = copy.deepcopy(self._db)
            set_master_password(candidate, self._user, new)
            # Save atomically with the new master password.
            try:
                save_account_db(candidate, self._user, new)
            except Exception as exc:
                self.after(0, lambda e=exc: messagebox.showerror(
                    "Password change failed",
                    f"The current vault remains unchanged.\n{e}", parent=self))
                return
            self._db = candidate
            if self._on_db_update:
                self.after(0, lambda db=candidate: self._on_db_update(db))
            def update_session_password():
                self._master_pw = new
                if self._on_master_pw_change:
                    self._on_master_pw_change(new)
            self.after(0, update_session_password)
            self.after(0, lambda: [e.delete(0, "end")
                                    for e in (self._cur_pw,
                                              self._new_pw,
                                              self._conf_pw)])
            self.after(0, lambda: self._flash_status(
                "✓  Password updated & DB re-encrypted", error=False))

        threading.Thread(target=_do_change, daemon=True).start()

    def _flash_status(self, msg: str, error: bool):
        color = t("DANGER") if error else t("ACCENT")
        self._pw_status.configure(text=msg, text_color=color)
        self.after(3000, lambda: self._pw_status.configure(text=""))


# ── Security panel ─────────────────────────────────────────────────────────
class SecurityPanel(ctk.CTkFrame):
    """Per-user security profile editor."""

    def __init__(self, master, username: str, db: dict,
                 master_pw: str, on_db_update=None, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self._user        = username
        self._db          = db
        self._master_pw   = master_pw
        self._on_db_update= on_db_update
        self._settings    = get_settings(db, username)
        self._vars: dict  = {}
        self._build()

    # ── helpers ────────────────────────────────────────────────────────────
    def _switch_row(self, parent, label: str, key: str,
                    tooltip: str = "") -> ctk.BooleanVar:
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=5)
        var = ctk.BooleanVar(value=bool(self._settings.get(key, False)))
        ctk.CTkSwitch(
            row, text=label, variable=var,
            font=ctk.CTkFont(FONT, 13), text_color=t("TEXT"),
            progress_color=t("ACCENT"), button_color=t("ACCENT_HOV"),
            command=lambda k=key, v=var: self._on_toggle(k, v)
        ).pack(side="left")
        if tooltip:
            ctk.CTkLabel(row, text=tooltip,
                         font=ctk.CTkFont(FONT, 10),
                         text_color=t("SUBTEXT")).pack(side="right")
        self._vars[key] = var
        return var

    def _int_row(self, parent, label: str, key: str,
                 from_: int, to: int) -> ctk.CTkSlider:
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(row, text=label, width=200, anchor="w",
                     font=ctk.CTkFont(FONT, 13),
                     text_color=t("TEXT")).pack(side="left")
        val_lbl = ctk.CTkLabel(row, text=str(self._settings.get(key, from_)),
                               width=40, font=ctk.CTkFont(FONT, 13, "bold"),
                               text_color=t("ACCENT"))
        val_lbl.pack(side="right")
        slider = ctk.CTkSlider(
            row, from_=from_, to=to,
            button_color=t("ACCENT"), button_hover_color=t("ACCENT_HOV"),
            progress_color=t("ACCENT"), width=160,
            command=lambda v, k=key, lbl=val_lbl: self._on_slide(k, v, lbl))
        slider.set(self._settings.get(key, from_))
        slider.pack(side="right", padx=(0, 8))
        return slider

    def _section(self, parent, title: str) -> ctk.CTkFrame:
        ctk.CTkLabel(parent, text=title,
                     font=ctk.CTkFont(FONT, 12),
                     text_color=t("SUBTEXT"), anchor="w").pack(
            fill="x", padx=20, pady=(16, 4))
        card = ctk.CTkFrame(parent, fg_color=t("SURFACE2"), corner_radius=14)
        card.pack(fill="x", pady=(0, 8))
        return card

    # ── build ──────────────────────────────────────────────────────────────
    def _build(self):
        ctk.CTkLabel(self, text="🛡  Security Profile",
                     font=ctk.CTkFont(FONT, 22, "bold"),
                     text_color=t("ACCENT"), anchor="w").pack(
            fill="x", padx=4, pady=(4, 8))

        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent",
                                         corner_radius=0)
        scroll.pack(fill="both", expand=True)

        # ── Clipboard ──────────────────────────────────────────────────────
        c = self._section(scroll, "Clipboard")
        ctk.CTkLabel(c,
            text="Passwords use the system clipboard and are cleared after the selected delay.",
            font=ctk.CTkFont(FONT, 11), text_color=t("SUBTEXT"),
            wraplength=500, justify="left").pack(anchor="w", padx=20, pady=(8, 4))
        self._int_row(c, "Auto-clear after (seconds)",
                      "clipboard_autoclear_seconds", 5, 120)

        c = self._section(scroll, "Session")
        self._int_row(c, "Lock after inactivity (minutes)",
                      "auto_lock_minutes", 1, 60)

        # ── Self-destruct ──────────────────────────────────────────────────
        c = self._section(scroll, "Self-Destruct")
        ctk.CTkLabel(c,
                     text="Entering this passphrase deletes the active encrypted vault file. Saved backups remain recoverable.",
                     font=ctk.CTkFont(FONT, 11),
                     text_color=t("SUBTEXT")).pack(
            anchor="w", padx=20, pady=(12, 4))
        destruct_row = ctk.CTkFrame(c, fg_color="transparent")
        destruct_row.pack(fill="x", padx=20, pady=(0, 14))
        self._destruct_entry = ctk.CTkEntry(
            destruct_row, placeholder_text="Panic passphrase (leave empty to disable)",
            show="•", height=38, corner_radius=10,
            fg_color=t("SURFACE"), border_color=t("BORDER"),
            text_color=t("TEXT"), font=ctk.CTkFont(FONT, 13))
        self._destruct_entry.pack(side="left", expand=True,
                                   fill="x", padx=(0, 8))
        ctk.CTkButton(
            destruct_row, text="Set", width=64, height=38,
            corner_radius=10,
            fg_color=t("DANGER"), hover_color=t("DANGER_HOV"),
            text_color=t("TEXT"), font=ctk.CTkFont(FONT, 12, "bold"),
            command=self._set_destruct
        ).pack(side="left")

        # ── Anti-debug / VM ────────────────────────────────────────────────
        c = self._section(scroll, "Environment Checks")
        self._switch_row(c, "Detect debugger",    "anti_debug")
        self._switch_row(c, "Detect virtual machine", "anti_vm")

        # ── Fail2ban ───────────────────────────────────────────────────────
        c = self._section(scroll, "Fail2Ban")
        self._switch_row(c, "Enable fail2ban",         "fail2ban_enabled")
        self._switch_row(c, "Lock screen on failures", "fail2ban_lock_screen")
        self._int_row(c, "Lock screen after N attempts",
                      "fail2ban_lockscreen_attempts", 1, 10)
        self._int_row(c, "Ban after N attempts",
                      "fail2ban_ban_attempts", 2, 20)
        self._int_row(c, "Ban duration (minutes)",
                      "fail2ban_timeout_minutes", 1, 60)

        # ── HIBP ───────────────────────────────────────────────────────────
        c = self._section(scroll, "Breach Check (HIBP)")
        self._switch_row(c, "Check passwords against HIBP",
                         "hibp_enabled", "Sends 5-char hash prefix and IP, not the password")

        # Save button
        ctk.CTkButton(
            self, text="💾  Save profile",
            height=46, corner_radius=12,
            fg_color=t("ACCENT"), hover_color=t("ACCENT_HOV"),
            text_color="#000000",
            font=ctk.CTkFont(FONT, 14, "bold"),
            command=self._save
        ).pack(fill="x", pady=(12, 0))

    # ── callbacks ──────────────────────────────────────────────────────────
    def _on_toggle(self, key: str, var: ctk.BooleanVar):
        self._settings[key] = var.get()

    def _on_slide(self, key: str, val: float, lbl: ctk.CTkLabel):
        iv = int(val)
        self._settings[key] = iv
        lbl.configure(text=str(iv))

    def _set_destruct(self):
        pw = self._destruct_entry.get()
        self._settings["self_destruct_password"] = (
            hash_destruct(pw) if pw else ""
        )
        self._destruct_entry.delete(0, "end")
        self._destruct_entry.configure(
            border_color=t("ACCENT"),
            placeholder_text="Panic passphrase set ✓")
        self.after(1500, lambda: self._destruct_entry.configure(
            border_color=t("BORDER"),
            placeholder_text="Panic passphrase (leave empty to disable)"))

    def _save(self):
        candidate = copy.deepcopy(self._db)
        save_settings(candidate, self._user, self._settings)
        try:
            save_account_db(candidate, self._user, self._master_pw)
        except Exception as exc:
            messagebox.showerror("Save failed", f"Settings were not saved.\n{exc}",
                                 parent=self)
            return
        self._db = candidate
        if self._on_db_update:
            self._on_db_update(candidate)
        # Visual feedback on save button
        for w in self.winfo_children():
            if isinstance(w, ctk.CTkButton) and "Save" in str(w.cget("text")):
                w.configure(text="✓  Saved!", fg_color=t("ACCENT"),
                            text_color="#000000")
                self.after(2000, lambda btn=w: btn.configure(
                    text="💾  Save profile",
                    fg_color=t("ACCENT")))
                break


# ══════════════════════════════════════════════════════════════════════════
#  Main vault window with sidebar
# ══════════════════════════════════════════════════════════════════════════

class VaultMainWindow(ctk.CTkToplevel):
    """Post-login main window: sidebar + content area."""

    SIDEBAR_W = 220

    def __init__(self, master, username: str, db: dict, master_pw: str,
                 on_logout=None, migrated: bool = False):
        super().__init__(master)
        self.overrideredirect(True)
        # We hide the default titlebar via Windows DWM after build.
        self.geometry("1000x640")
        self.minsize(800, 520)
        self.configure(fg_color=t("BG"))
        self._user        = username
        self._db          = db
        self._master_pw   = master_pw
        self._on_logout   = on_logout
        self._migrated    = migrated
        self._clipboard_generation = 0
        self._clipboard_value = None
        self._panels: dict[str, ctk.CTkFrame] = {}
        self._nav_btns: dict[str, ctk.CTkButton] = {}
        self._active      = None
        self._drag_x = self._drag_y = 0
        self._maximized   = False

        # Center on screen
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f"1000x640+{(sw-1000)//2}+{(sh-640)//2}")

        self._set_rounded_corners()
        self._build()
        self._switch("vault")
        self.bind_all("<Any-KeyPress>", self._on_activity, add="+")
        self.bind_all("<ButtonPress>", self._on_activity, add="+")
        self._reset_lock_timer()
        self.lift()
        self.attributes("-topmost", True)
        self.after(200, lambda: self.attributes("-topmost", False))
        if self._migrated:
            self.after(600, self._show_migration_notice)

    # ── build ──────────────────────────────────────────────────────────────
    def _build(self):
        # ── Title bar ──────────────────────────────────────────────────────
        bar = ctk.CTkFrame(self, fg_color=t("SURFACE"),
                           corner_radius=0, height=48)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        
        title_lbl = ctk.CTkLabel(bar, text=" 🔒 Aegis",
                     font=ctk.CTkFont(FONT, 15, "bold"),
                     text_color=t("SUBTEXT"))
        title_lbl.pack(side="left", padx=12)
        for widget in (bar, title_lbl):
            widget.bind("<ButtonPress-1>", self._start_drag)
            widget.bind("<B1-Motion>",     self._do_drag)

        for sym, cmd, fg, hov in [
            ("✕", self._close,    t("DANGER"),   t("DANGER_HOV")),
            ("⬜", self._maximize, t("SURFACE2"), t("BORDER")),
            ("—", self.iconify,   t("SURFACE2"), t("BORDER")),
        ]:
            ctk.CTkButton(bar, text=sym, width=36, height=36,
                          corner_radius=8, fg_color=fg, hover_color=hov,
                          font=ctk.CTkFont(FONT, 13, "bold"),
                          text_color=t("TEXT"),
                          command=cmd).pack(side="right",
                                            padx=(0, 4), pady=6)

        ctk.CTkFrame(self, fg_color=t("BORDER"),
                     height=1, corner_radius=0).pack(fill="x")

        # ── Body (sidebar + content) ───────────────────────────────────────
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)

        # Sidebar
        sidebar = ctk.CTkFrame(body, fg_color=t("SURFACE"),
                               corner_radius=0, width=self.SIDEBAR_W)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Nav buttons (top)
        nav_top = ctk.CTkFrame(sidebar, fg_color="transparent")
        nav_top.pack(fill="x", pady=(16, 0))

        NAV_ITEMS = [
            ("vault",     "🔐  Vault"),
            ("generator", "🎲  Generator"),
            ("security",  "🛡  Security"),
            ("settings",  "⚙   Settings"),
        ]
        for key, label in NAV_ITEMS:
            btn = ctk.CTkButton(
                nav_top, text=label,
                height=48, corner_radius=12,
                anchor="w",
                fg_color="transparent",
                hover_color=t("SURFACE2"),
                text_color=t("SUBTEXT"),
                font=ctk.CTkFont(FONT, 14),
                command=lambda k=key: self._switch(k))
            btn.pack(fill="x", padx=12, pady=4)
            self._nav_btns[key] = btn

        # Account button (bottom)
        nav_bot = ctk.CTkFrame(sidebar, fg_color="transparent")
        nav_bot.pack(side="bottom", fill="x", pady=16)

        acc_btn = ctk.CTkButton(
            nav_bot, text=f"👤  {self._user}",
            height=48, corner_radius=12,
            anchor="w",
            fg_color="transparent",
            hover_color=t("SURFACE2"),
            text_color=t("SUBTEXT"),
            font=ctk.CTkFont(FONT, 14),
            command=lambda: self._switch("account"))
        acc_btn.pack(fill="x", padx=12)
        self._nav_btns["account"] = acc_btn

        # Thin separator between sidebar and content
        ctk.CTkFrame(body, fg_color=t("BORDER"),
                     width=1, corner_radius=0).pack(side="left", fill="y")

        # Content area
        self._content = ctk.CTkFrame(body, fg_color=t("BG"),
                                     corner_radius=0)
        self._content.pack(side="left", fill="both", expand=True)

        # Pre-create all panels
        self._panels["vault"]     = VaultPanel(
            self._content, self._user, self._db, self._master_pw,
            on_db_update=self._on_db_update)
        self._panels["generator"] = GeneratorPanel(self._content)
        self._panels["settings"]  = SettingsPanel(
            self._content, self.master)
        self._panels["security"]  = SecurityPanel(
            self._content, self._user, self._db, self._master_pw,
            on_db_update=self._on_db_update)
        self._panels["account"]   = AccountPanel(
            self._content, self._user, self._db, self._master_pw,
            on_logout=self._logout, on_db_update=self._on_db_update,
            on_master_pw_change=self._set_master_password)

    # ── db sync ────────────────────────────────────────────────────────────
    def _on_db_update(self, db: dict):
        """Called by child panels when they modify the DB."""
        self._db = db
        # Propagate to all panels that hold a db reference
        for panel in self._panels.values():
            if hasattr(panel, "_db"):
                panel._db = db

    def _set_master_password(self, password: str):
        self._master_pw = password
        for panel in self._panels.values():
            if hasattr(panel, "_master_pw"):
                panel._master_pw = password

    def _show_migration_notice(self):
        messagebox.showwarning(
            "Account vault migrated",
            "This account now has its own encrypted vault. The old shared Aegis.db was preserved so other legacy accounts can still be migrated. After every account is migrated and backed up, move or delete Aegis.db yourself; until then it still contains the old shared vault.",
            parent=self)

    def _on_activity(self, event):
        widget = event.widget
        while widget is not None:
            if widget is self:
                self._reset_lock_timer()
                return
            widget = getattr(widget, "master", None)

    def _clear_clipboard_if_matches(self, expected: str, generation: int):
        if generation != self._clipboard_generation:
            return
        try:
            if self.clipboard_get() == expected:
                self.clipboard_clear()
        except Exception:
            pass
        self._clipboard_value = None

    def _clear_session_clipboard(self):
        if self._clipboard_value is not None:
            self._clear_clipboard_if_matches(
                self._clipboard_value, self._clipboard_generation)

    def _reset_lock_timer(self):
        if hasattr(self, "_lock_timer"):
            self.after_cancel(self._lock_timer)
        minutes = get_settings(self._db, self._user).get("auto_lock_minutes", 5)
        self._lock_timer = self.after(max(1, int(minutes)) * 60_000,
                                      self._auto_lock)

    def _auto_lock(self):
        messagebox.showinfo("Vault locked", "Aegis locked after inactivity. Sign in again.",
                            parent=self)
        self._logout()

    # ── navigation ─────────────────────────────────────────────────────────────
    def _switch(self, key: str):
        if self._active == key:
            return

        # Deactivate old
        if self._active:
            self._panels[self._active].pack_forget()
            self._nav_btns[self._active].configure(
                fg_color="transparent",
                text_color=t("SUBTEXT"))

        # Activate new
        self._active = key
        self._panels[key].pack(fill="both", expand=True, padx=24, pady=20)
        self._nav_btns[key].configure(
            fg_color=t("SURFACE2"),
            text_color=t("ACCENT"))

    # ── drag ───────────────────────────────────────────────────────────────
    def _start_drag(self, e):
        self._drag_x = e.x_root - self.winfo_x()
        self._drag_y = e.y_root - self.winfo_y()

    def _do_drag(self, e):
        if not self._maximized:
            self.geometry(
                f"+{e.x_root - self._drag_x}+{e.y_root - self._drag_y}")

    # ── window controls ────────────────────────────────────────────────────
    def _close(self):
        self._clear_session_clipboard()
        for sequence in ("<Any-KeyPress>", "<ButtonPress>"):
            self.unbind_all(sequence)
        self.destroy()
        self.master.destroy()   # also close login window

    def _maximize(self):
        if self._maximized:
            self._maximized = False
            sw = self.winfo_screenwidth()
            sh = self.winfo_screenheight()
            self.geometry(f"1000x640+{(sw-1000)//2}+{(sh-640)//2}")
        else:
            self._maximized = True
            sw = self.winfo_screenwidth()
            sh = self.winfo_screenheight()
            self.geometry(f"{sw}x{sh}+0+0")

    def _logout(self):
        self._clear_session_clipboard()
        for sequence in ("<Any-KeyPress>", "<ButtonPress>"):
            self.unbind_all(sequence)
        if hasattr(self, "_lock_timer"):
            self.after_cancel(self._lock_timer)
        self.destroy()
        if self._on_logout:
            self._on_logout()

    def _set_rounded_corners(self):
        try:
            import ctypes
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            # Rounded corners
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 33,
                ctypes.byref(ctypes.c_int(2)),
                ctypes.sizeof(ctypes.c_int))
            # Hide default title bar while keeping taskbar presence:
            # Set DWMWA_CAPTION_COLOR to hide caption area (Win11)
            # Extend frame into client to zero height
            class MARGINS(ctypes.Structure):
                _fields_ = [("cxLeftWidth", ctypes.c_int),
                             ("cxRightWidth", ctypes.c_int),
                             ("cyTopHeight", ctypes.c_int),
                             ("cyBottomHeight", ctypes.c_int)]
            m = MARGINS(0, 0, 1, 0)   # 1px top keeps DWM happy
            ctypes.windll.dwmapi.DwmExtendFrameIntoClientArea(hwnd, ctypes.byref(m))
        except Exception:
            pass
