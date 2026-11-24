import threading
import customtkinter as ctk
from crypto import (
    LEGACY_DB_FILE, load_db, load_account_db, save_account_db,
    vault_path_for, db_exists,
    hash_pw, verify_master, create_user,
    get_settings, is_self_destruct, DEFAULT_SETTINGS
)
from styles import theme, apply_theme, PALETTES, FONT, PRESETS_FILE
from instance_lock import AlreadyRunningError, SingleInstanceLock
from security import startup_checks, record_failed_attempt, record_success, get_ban_status
from vault_window import VaultMainWindow
import ctypes

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


def t(key: str) -> str:
    return theme[key]


###### tab helper ######

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

###### tab helper ######


##### toast #####

class Toast(ctk.CTkToplevel):
    def __init__(self, master, message: str, kind: str = "error",
                 duration_ms: int = 3500):
        super().__init__(master)
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.configure(fg_color=t("SURFACE"))
        color = t("DANGER") if kind == "error" else t("ACCENT")
        icon  = "⚠" if kind == "error" else "ℹ"
        ctk.CTkFrame(self, fg_color=color, width=4,
                     corner_radius=0).pack(side="left", fill="y")
        body = ctk.CTkFrame(self, fg_color=t("SURFACE"), corner_radius=0)
        body.pack(side="left", fill="both", expand=True, padx=12, pady=10)
        ctk.CTkLabel(body, text=f"{icon}  {message}",
                     font=ctk.CTkFont(FONT, 13),
                     text_color=t("TEXT"),
                     wraplength=260, justify="left").pack(anchor="w")
        self.update_idletasks()
        w = 300
        h = self.winfo_reqheight() + 10
        mx = master.winfo_x()
        my = master.winfo_y()
        mw = master.winfo_width()
        mh = master.winfo_height()
        self.geometry(f"{w}x{h}+{mx + mw - w - 8}+{my + mh - h - 8}")
        self.after(duration_ms, self.destroy)

##### toast #####     


###### ban screen ######
        
class BanScreen(ctk.CTkToplevel):
    import time as _time

    def __init__(self, master, seconds: int):
        super().__init__(master)
        self.title("Aegis — Locked")
        self.resizable(False, False)
        self.configure(fg_color=t("BG"))
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", lambda: None)
        import time
        self._end = time.time() + seconds
        self._build()
        self._tick()

    def _build(self):
        ctk.CTkLabel(self, text="🔒",
                     font=ctk.CTkFont(size=52)).pack(pady=(40, 0))
        ctk.CTkLabel(self, text="Too many failed attempts",
                     font=ctk.CTkFont(FONT, 18, "bold"),
                     text_color=t("DANGER")).pack(pady=(8, 4))
        ctk.CTkLabel(self, text="Aegis is temporarily locked.",
                     font=ctk.CTkFont(FONT, 13),
                     text_color=t("SUBTEXT")).pack()
        self._timer_lbl = ctk.CTkLabel(
            self, text="",
            font=ctk.CTkFont(FONT, 32, "bold"),
            text_color=t("TEXT"))
        self._timer_lbl.pack(pady=24)
        self.update_idletasks()
        self.geometry("340x280")
        self.after(50, self._center)

    def _center(self):
        self.update_idletasks()
        w, h = 340, 280
        x = self.master.winfo_x() + (self.master.winfo_width()  - w) // 2
        y = self.master.winfo_y() + (self.master.winfo_height() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _tick(self):
        import time
        remaining = max(0, int(self._end - time.time()))
        h, rem = divmod(remaining, 3600)
        m, s   = divmod(rem, 60)
        self._timer_lbl.configure(text=f"{h:02d}:{m:02d}:{s:02d}")
        if remaining > 0:
            self.after(1000, self._tick)
        else:
            self.grab_release()
            self.destroy()
            
###### ban screen ######

###### security warning ######

class SecurityWarningDialog(ctk.CTkToplevel):
    def __init__(self, master, scan: dict):
        super().__init__(master)
        self.title("Aegis — Security Warning")
        self.resizable(False, False)
        self.configure(fg_color=t("BG"))
        self.grab_set()
        self._result = False
        ctk.CTkLabel(self, text="⚠  Security Alert",
                     font=ctk.CTkFont(FONT, 18, "bold"),
                     text_color=t("DANGER")).pack(pady=(28, 8))
        findings = []
        if scan.get("debugger"):        findings.append("• Debugger attached")
        if scan.get("remote_debugger"): findings.append("• Remote debugger")
        if scan.get("vm_registry"):     findings.append("• VM (registry)")
        if scan.get("vm_process"):      findings.append("• VM (guest process)")
        body = ctk.CTkFrame(self, fg_color=t("SURFACE"), corner_radius=12)
        body.pack(padx=24, pady=8, fill="x")
        ctk.CTkLabel(body,
                     text="Suspicious environment:\n\n"
                          + "\n".join(findings),
                     font=ctk.CTkFont(FONT, 13),
                     text_color=t("TEXT"), justify="left").pack(padx=16, pady=16)
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(padx=24, pady=(8, 24), fill="x")
        ctk.CTkButton(row, text="Continue anyway", height=42, corner_radius=10,
                      fg_color=t("SURFACE2"), hover_color=t("BORDER"),
                      text_color=t("SUBTEXT"),
                      command=self._continue).pack(side="left", expand=True,
                                                    fill="x", padx=(0, 8))
        ctk.CTkButton(row, text="Exit", height=42, corner_radius=10,
                      fg_color=t("DANGER"), hover_color=t("DANGER_HOV"),
                      text_color=t("TEXT"),
                      command=self._exit).pack(side="left", expand=True, fill="x")
        self.update_idletasks()
        self.geometry("400x300")

    def _continue(self):
        self._result = True
        self.grab_release()
        self.destroy()

    def _exit(self):
        self.grab_release()
        self.destroy()
        self.master.destroy()

###### security warning ######


###### loading overlay ######
class LoadingOverlay(ctk.CTkToplevel):
    """Shown while Argon2id key derivation is running."""
    def __init__(self, master, message="Deriving key…"):
        super().__init__(master)
        self.overrideredirect(True)
        self.configure(fg_color=t("SURFACE"))
        self.attributes("-topmost", True)
        ctk.CTkLabel(self, text="⏳  " + message,
                     font=ctk.CTkFont(FONT, 14),
                     text_color=t("TEXT")).pack(padx=24, pady=20)
        self.update_idletasks()
        w, h = self.winfo_reqwidth() + 20, self.winfo_reqheight()
        x = master.winfo_x() + (master.winfo_width()  - w) // 2
        y = master.winfo_y() + (master.winfo_height() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

###### loading overlay ######
        
###### main window ######

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.resizable(False, False)
        self.overrideredirect(True)
        self.configure(fg_color=t("BG"))
        self._drag_x = self._drag_y = 0
        self._build()
        self.update_idletasks()
        w, h = 420, 640
        x = (self.winfo_screenwidth()  - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.lift()
        self.attributes("-topmost", True)
        self.after(200, lambda: self.attributes("-topmost", False))
        self._set_rounded_corners()
        self.after(100, self._startup_security)

    def destroy(self):
        lock = getattr(self, "_instance_lock", None)
        if lock is not None:
            lock.release()
            self._instance_lock = None
        super().destroy()
        
###### main window ######

        
##### startup #####
        
    def _startup_security(self):
        status = startup_checks()
        if not status["integrity_ok"]:
            Toast(self, "File integrity check failed.\nSee Aegis.log.",
                  kind="error", duration_ms=6000)
        if status["scan"]["any_threat"]:
            dlg = SecurityWarningDialog(self, status["scan"])
            self.wait_window(dlg)
            if not dlg._result:
                return
        if status["banned"]:
            BanScreen(self, status["ban_remaining"])
            
##### startup #####

    
##### drag func #####
    
    def _start_drag(self, e):
        self._drag_x = e.x_root - self.winfo_x()
        self._drag_y = e.y_root - self.winfo_y()

    def _do_drag(self, e):
        self.geometry(f"+{e.x_root - self._drag_x}+{e.y_root - self._drag_y}")

##### drag func #####
        

##### user interface #####
        
    def _build(self):
        bar = ctk.CTkFrame(self, fg_color=t("SURFACE"),
                           corner_radius=0, height=48)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        bar.bind("<ButtonPress-1>", self._start_drag)
        bar.bind("<B1-Motion>",     self._do_drag)

        title_lbl = ctk.CTkLabel(bar, text=" 🔒 Aegis",
                                 font=ctk.CTkFont(FONT, 15, "bold"),
                                 text_color=t("SUBTEXT"))
        title_lbl.pack(side="left", padx=12)
        title_lbl.bind("<ButtonPress-1>", self._start_drag)
        title_lbl.bind("<B1-Motion>",     self._do_drag)

        for sym, cmd, fg, hov, bold in [
            ("✕", self.destroy,                  t("DANGER"),   t("DANGER_HOV"), True),
            ("—", self.iconify,                  t("SURFACE2"), t("BORDER"),     True),
            ("⚙", lambda: _SettingsWin(self),   t("SURFACE2"), t("BORDER"),     False),
        ]:
            ctk.CTkButton(bar, text=sym, width=36, height=36,
                          corner_radius=8, fg_color=fg, hover_color=hov,
                          font=ctk.CTkFont(FONT, 14, "bold" if bold else "normal"),
                          text_color=t("TEXT"),
                          command=cmd).pack(side="right", padx=(0, 4), pady=6)

        ctk.CTkFrame(self, fg_color=t("BORDER"),
                     height=1, corner_radius=0).pack(fill="x")

        logo_card = ctk.CTkFrame(self, fg_color=t("SURFACE"),
                                 corner_radius=24, width=320, height=110)
        logo_card.pack(pady=(36, 0))
        logo_card.pack_propagate(False)
        ctk.CTkLabel(logo_card, text="🔒",
                     font=ctk.CTkFont(size=36)).pack(pady=(16, 0))
        ctk.CTkLabel(logo_card, text="Aegis",
                     font=ctk.CTkFont(FONT, 22, "bold"),
                     text_color=t("ACCENT")).pack()

        card = ctk.CTkFrame(self, fg_color=t("SURFACE"),
                            corner_radius=28, width=320, height=370)
        card.pack(pady=12)
        card.pack_propagate(False)

        # Username
        self._user_entry = ctk.CTkEntry(
            card, placeholder_text="Enter username…",
            width=264, height=46, corner_radius=14,
            fg_color=t("SURFACE2"), border_color=t("BORDER"),
            border_width=2, font=ctk.CTkFont(FONT, 14),
            
            text_color=t("TEXT"))
        self._user_entry.pack(pady=(24, 0))

        ctk.CTkLabel(card, text="Username",
                     font=ctk.CTkFont(FONT, 12),
                     text_color=t("SUBTEXT")).pack(pady=(0, 4))


        # password
        self._pw_entry = ctk.CTkEntry(
            card, placeholder_text="Enter password…",
            width=264, height=46, corner_radius=14,
            show="•", fg_color=t("SURFACE2"),
            border_color=t("ACCENT"), border_width=2,
            font=ctk.CTkFont(FONT, 14), text_color=t("TEXT"))       
        self._pw_entry.pack(pady=(8, 0))

        ctk.CTkLabel(card, text="Master password",
            font=ctk.CTkFont(FONT, 12),
            text_color=t("SUBTEXT")).pack(pady=(0, 4))

        self._pw_entry.bind("<Return>", lambda _: self._login())


        btn_cfg = dict(width=264, height=48, corner_radius=14,
                       font=ctk.CTkFont(FONT, 14, "bold"))

        login_btn = ctk.CTkButton(card, text="Login",
                                  fg_color=t("ACCENT"),
                                  hover_color=t("ACCENT_HOV"),
                                  text_color="#000000",
                                  command=self._login, **btn_cfg)
        login_btn.pack(pady=(0, 8))

        reg_btn = ctk.CTkButton(card, text="Register",
                                fg_color=t("SURFACE2"),
                                hover_color=t("BORDER"),
                                border_color=t("ACCENT"), border_width=2,
                                text_color=t("ACCENT"),
                                command=self._do_register, **btn_cfg)
        reg_btn.pack(pady=(0, 8))

        exit_btn = ctk.CTkButton(card, text="Exit",
                                 fg_color="transparent",
                                 hover_color=t("SURFACE2"),
                                 border_color=t("BORDER"), border_width=1,
                                 text_color=t("SUBTEXT"),
                                 command=self.destroy, **btn_cfg)
        exit_btn.pack()

        ctk.CTkLabel(self, text="v3.0  ·  AES-256-GCM + Argon2id",
                     font=ctk.CTkFont(FONT, 10),
                     text_color=t("SUBTEXT")).pack(pady=(0, 12))

        _tab_chain([self._user_entry, self._pw_entry,
                    login_btn, reg_btn, exit_btn])

##### user interface #####


##### binds #####
        
    def _login(self):
        banned, remaining = get_ban_status()
        if banned:
            BanScreen(self, remaining)
            return

        username = self._user_entry.get().strip()
        pw       = self._pw_entry.get()
        if not username or not pw:
            self._flash_error(self._pw_entry if pw else self._user_entry)
            return

        # Show loading overlay — Argon2id takes ~1-2 sec
        overlay = LoadingOverlay(self, "Verifying password…")
        self.update()

        def _worker():
            try:
                db, migrated = load_account_db(username, pw)
            except Exception as exc:
                self.after(0, lambda: overlay.destroy())
                self.after(0, lambda e=exc: Toast(
                    self, f"Could not open vault: {e}", duration_ms=5000))
                return
            self.after(0, lambda: overlay.destroy())

            if db is None:
                # Wrong password → can't decrypt
                self.after(0, lambda: self._handle_fail(username, pw, None))
                return

            user_data = db.get("users", {}).get(username)
            if user_data is None:
                self.after(0, lambda: self._handle_fail(username, pw, db))
                return

            # Check self-destruct BEFORE normal verify
            if is_self_destruct(db, username, pw):
                self.after(0, lambda: self._self_destruct(db, pw, username))
                return

            if not verify_master(db, username, pw):
                self.after(0, lambda: self._handle_fail(username, pw, db))
                return

            settings = db.get("users", {}).get(username, {}).get(
                "settings", DEFAULT_SETTINGS)

            # Check anti_debug / anti_vm per user profile
            if settings.get("anti_debug") or settings.get("anti_vm"):
                from security import security_scan
                scan = security_scan()
                if scan["any_threat"]:
                    self.after(0, lambda s=scan: self._warn_env(
                        s, db, username, pw, migrated))
                    return

            self.after(0, lambda: self._open_vault(db, username, pw, migrated))

        threading.Thread(target=_worker, daemon=True).start()

    def _handle_fail(self, username: str, pw: str, db):
        settings = dict(DEFAULT_SETTINGS)
        if db and username in db.get("users", {}):
            settings = get_settings(db, username)

        if not settings.get("fail2ban_enabled", True):
            self._flash_error(self._pw_entry)
            Toast(self, "Wrong username or password.", duration_ms=3000)
            return

        action = record_failed_attempt(settings)
        self._flash_error(self._pw_entry)
        n = action["attempts"]

        if action["banned"]:
            mins = action["ban_seconds"] // 60
            label = f"{mins}m" if mins < 60 else (
                f"{mins//60}h" if mins < 1440 else "24h")
            Toast(self,
                  f"Wrong credentials ({n} attempts).\n"
                  f"App locked for {label}.",
                  duration_ms=5000)
            BanScreen(self, action["ban_seconds"])
        elif action["lock_screen"] and settings.get("fail2ban_lock_screen", True):
            Toast(self,
                  f"Wrong credentials ({n} attempts).\n"
                  "Screen locked.",
                  duration_ms=4000)
        else:
            lock_at = int(settings.get("fail2ban_lockscreen_attempts", 2))
            ban_at = int(settings.get("fail2ban_ban_attempts", 5))
            hint = (f"{max(0, lock_at-n)} attempt(s) until screen lock."
                    if settings.get("fail2ban_lock_screen", True) and n < lock_at
                    else f"{max(0, ban_at-n)} attempt(s) until app lock.")
            Toast(self, f"Wrong credentials. {hint}", duration_ms=3500)

    def _warn_env(self, scan: dict, db, username: str, pw: str,
                  migrated: bool = False):
        dlg = SecurityWarningDialog(self, scan)
        self.wait_window(dlg)
        if dlg._result:
            self._open_vault(db, username, pw, migrated)

    def _open_vault(self, db: dict, username: str, master_pw: str,
                    migrated: bool = False):
        record_success()
        self.withdraw()
        VaultMainWindow(self, username, db, master_pw,
                        on_logout=self._on_logout, migrated=migrated)

    def _on_logout(self):
        self.deiconify()
        self._pw_entry.delete(0, "end")
        self._user_entry.delete(0, "end")

    def _self_destruct(self, db: dict, pw: str, username: str):
        """Delete the active encrypted vault file and exit."""
        from security import _log
        _log("critical",
             f"SELF-DESTRUCT triggered for user '{username}'. Active vault file deleted.")
        db_path = vault_path_for(username)
        if db_path.exists():
            # File overwrites cannot guarantee secure erasure on SSDs or synced drives.
            db_path.unlink()
        self.destroy()

    def _flash_error(self, widget):
        widget.configure(border_color=t("DANGER"))
        self.after(600, lambda: widget.configure(
            border_color=t("ACCENT")))

    def _do_register(self):
        username = self._user_entry.get().strip()
        pw       = self._pw_entry.get()
        if not username:
            self._flash_error(self._user_entry)
            return
        if len(pw) < 12:
            self._flash_error(self._pw_entry)
            Toast(self, "Use a master password of at least 12 characters.",
                  duration_ms=3500)
            return

        overlay = LoadingOverlay(self, "Creating account…")
        self.update()

        def _worker():
            account_path = vault_path_for(username)
            if db_exists(account_path):
                self.after(0, overlay.destroy)
                self.after(0, lambda: Toast(
                    self, "Username already exists.", duration_ms=3000))
                return

            if db_exists(LEGACY_DB_FILE):
                legacy = load_db(pw, LEGACY_DB_FILE)
                if legacy is None:
                    self.after(0, overlay.destroy)
                    self.after(0, lambda: Toast(
                        self, "Migrate legacy accounts first. Aegis.db exists but this password cannot verify its account list.",
                        duration_ms=5500))
                    return
                if username in legacy.get("users", {}):
                    self.after(0, overlay.destroy)
                    self.after(0, lambda: Toast(
                        self, "This is a legacy account. Sign in to migrate it.",
                        duration_ms=4000))
                    return
            db = {"users": {}}

            db = create_user(db, username, pw)
            save_account_db(db, username, pw)
            self.after(0, overlay.destroy)
            self.after(0, lambda: Toast(
                self, f"Account '{username}' created!", kind="info",
                duration_ms=3000))

        threading.Thread(target=_worker, daemon=True).start()

    def _set_rounded_corners(self):
        try:
            import ctypes
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 33,
                ctypes.byref(ctypes.c_int(2)),
                ctypes.sizeof(ctypes.c_int))
        except Exception:
            pass

##### binds #####


##### theme picker #####
        
class _SettingsWin(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Theme")
        self.geometry("400x160")
        self.resizable(False, False)
        self.configure(fg_color=t("BG"))
        self.grab_set()
        ctk.CTkLabel(self, text="Presets",
                     font=ctk.CTkFont(FONT, 13),
                     text_color=t("SUBTEXT")).pack(pady=(20, 8))
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack()
        for name, palette in PALETTES.items():
            if not palette:
                continue
            ctk.CTkButton(
                row, text=name, height=32, corner_radius=8,
                fg_color=palette["SURFACE"],
                hover_color=palette["SURFACE2"],
                border_color=palette["ACCENT"], border_width=2,
                text_color=palette["ACCENT"],
                font=ctk.CTkFont(FONT, 11, "bold"),
                command=lambda p=palette: (apply_theme(p, master), launch())
            ).pack(side="left", padx=4)

##### theme picker #####


##### entry point #####
            
def launch():
    import json
    lock = SingleInstanceLock()
    try:
        lock.acquire()
    except AlreadyRunningError:
        ctypes.windll.user32.MessageBoxW(
            None, "Aegis is already running.", "Aegis", 0x40)
        return
    except OSError as exc:
        ctypes.windll.user32.MessageBoxW(
            None, f"Aegis needs a writable data folder.\n{exc}", "Aegis", 0x10)
        return
    try:
        if PRESETS_FILE.exists():
            with open(PRESETS_FILE, encoding="utf-8") as f:
                for name, palette in json.load(f).items():
                    PALETTES[name] = palette
        app = App()
        app._instance_lock = lock
        app.mainloop()
    finally:
        lock.release()

##### entry point #####

    
if __name__ == "__main__":
    launch()
