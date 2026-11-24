"""
styles.py — centralized theme / palette for Aegis.

Usage:
    from styles import theme, save_theme, FONT

All UI code reads colours from `theme` dict at widget-creation time.
To apply a new palette at runtime, call apply_theme(new_palette_dict, root_window).
"""

import json, os
import customtkinter as ctk
from paths import BASE_DIR

THEME_FILE = BASE_DIR / "Aegis_theme.json"
PRESETS_FILE = BASE_DIR / "Aegis_presets.json"
FONT       = "Consolas"

# ── Built-in palettes ──────────────────────────────────────────────────────
PALETTES: dict[str, dict] = {
    "Dark Premium": {
        "BG":         "#09090E",
        "SURFACE":    "#0F1021",
        "SURFACE2":   "#171830",
        "ACCENT":     "#C9A84C",
        "ACCENT_HOV": "#E2C46A",
        "DANGER":     "#C0392B",
        "DANGER_HOV": "#E74C3C",
        "TEXT":       "#F0EAD6",
        "SUBTEXT":    "#7A7060",
        "BORDER":     "#2A2740",
    },
    "Violet": {
        "BG":         "#0A0010",
        "SURFACE":    "#110022",
        "SURFACE2":   "#1A0035",
        "ACCENT":     "#A855F7",
        "ACCENT_HOV": "#C084FC",
        "DANGER":     "#EF4444",
        "DANGER_HOV": "#F87171",
        "TEXT":       "#EDE9FE",
        "SUBTEXT":    "#7C3AED",
        "BORDER":     "#2D1B4E",
    },
    "Green": {
        "BG":         "#070F0E",
        "SURFACE":    "#0D1F1C",
        "SURFACE2":   "#132E29",
        "ACCENT":     "#2DD4BF",
        "ACCENT_HOV": "#5EEAD4",
        "DANGER":     "#F43F5E",
        "DANGER_HOV": "#FB7185",
        "TEXT":       "#CCFBF1",
        "SUBTEXT":    "#5EEAD4",
        "BORDER":     "#1F4038",
    },
    "Rose": {
        "BG":         "#0E0A0D",
        "SURFACE":    "#1A1118",
        "SURFACE2":   "#251822",
        "ACCENT":     "#F472B6",
        "ACCENT_HOV": "#F9A8D4",
        "DANGER":     "#DC2626",
        "DANGER_HOV": "#EF4444",
        "TEXT":       "#FDF2F8",
        "SUBTEXT":    "#9D174D",
        "BORDER":     "#3B1F31",
    },
    "Custom": {},   # filled from file if saved
}

# ── Load / save user theme ─────────────────────────────────────────────────
def _load_theme() -> dict:
    if os.path.exists(THEME_FILE):
        try:
            with open(THEME_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return dict(PALETTES["Dark Premium"])

def save_theme(palette: dict) -> None:
    with open(THEME_FILE, "w", encoding="utf-8") as f:
        json.dump(palette, f, indent=2)

# ── Live theme dict (mutable, shared by reference) ────────────────────────
theme: dict = _load_theme()

def apply_theme(new: dict, root: ctk.CTk) -> None:
    """Overwrite theme in-place and restart the window."""
    theme.update(new)
    save_theme(new)
    root.destroy()          # caller re-launches App()
