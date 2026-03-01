import tkinter as tk
from tkinter import filedialog
from key_derivation import derive_key
from file_crypto import encrypt_file, decrypt_file
import os

# ── Palette ────────────────────────────────────────────────────────────────────
BG          = "#0f1117"
SURFACE     = "#161b27"
SURFACE2    = "#1e2535"
BORDER      = "#2a3348"
BORDER_LT   = "#3d4f6e"

# Accent — electric blue
BLUE        = "#3b82f6"
BLUE_HOVER  = "#2563eb"
BLUE_LIGHT  = "#93c5fd"
BLUE_BG     = "#1e3a5f"

# Accent2 — violet
VIOLET      = "#8b5cf6"
VIOLET_HOVER= "#7c3aed"
VIOLET_LIGHT= "#c4b5fd"
VIOLET_BG   = "#2e1b5e"

# Status
SUCCESS     = "#10b981"
SUCCESS_BG  = "#064e3b"
ERROR_CLR   = "#f87171"
ERROR_BG    = "#450a0a"
WARNING     = "#f59e0b"

# Text hierarchy
TEXT_H1     = "#f1f5f9"
TEXT_H2     = "#cbd5e1"
TEXT_BODY   = "#94a3b8"
TEXT_DIM    = "#475569"

# Fonts
F_TITLE  = ("Segoe UI", 18, "bold")
F_LABEL  = ("Segoe UI", 9, "bold")
F_BODY   = ("Segoe UI", 10)
F_MONO   = ("Consolas", 9)
F_SMALL  = ("Segoe UI", 8)
F_BTN    = ("Segoe UI", 10, "bold")
F_RUN    = ("Segoe UI", 11, "bold")


class RC6App:
    def __init__(self, root):
        self.root = root
        self.root.title("RC6 Secure Encryptor")
        self.root.geometry("500x640")
        self.root.configure(bg=BG)
        self.root.resizable(False, False)

        self.selected_file = None
        self.show_password = False

        self._build_ui()

    def _build_ui(self):
        # ── Header ──
        hdr = tk.Frame(self.root, bg=SURFACE)
        hdr.pack(fill="x")

        hdr_inner = tk.Frame(hdr, bg=SURFACE)
        hdr_inner.pack(fill="x", padx=24, pady=16)

        tk.Label(hdr_inner, text="RC6", font=("Segoe UI", 20, "bold"),
                 fg=BLUE, bg=SURFACE).pack(side="left")
        tk.Label(hdr_inner, text=" Secure Encryptor", font=("Segoe UI", 14),
                 fg=TEXT_H1, bg=SURFACE).pack(side="left", pady=3)
        tk.Label(hdr_inner, text="v2.0", font=F_SMALL,
                 fg=TEXT_DIM, bg=SURFACE).pack(side="right", pady=3)

        tk.Frame(self.root, bg=BLUE, height=2).pack(fill="x")

        content = tk.Frame(self.root, bg=BG)
        content.pack(fill="both", expand=True, padx=20, pady=18)

        # ── MODE ──
        self._label(content, "Mode")
        mode_row = tk.Frame(content, bg=BG)
        mode_row.pack(fill="x", pady=(6, 16))

        self.mode_var = tk.StringVar(value="encrypt")
        self._mode_btn(mode_row, "🔒  Encrypt", "encrypt", BLUE,    BLUE_BG,   BLUE_LIGHT)
        self._mode_btn(mode_row, "🔓  Decrypt", "decrypt", VIOLET,  VIOLET_BG, VIOLET_LIGHT)

        # ── KEY SIZE ──
        self._label(content, "Key Size")
        ks_row = tk.Frame(content, bg=BG)
        ks_row.pack(fill="x", pady=(6, 16))

        self.key_size_var = tk.StringVar(value="16")
        for ks, desc in (("16", "128-bit"), ("24", "192-bit"), ("32", "256-bit")):
            self._key_btn(ks_row, ks, desc)

        # ── PASSWORD ──
        self._label(content, "Password")
        pw_outer = tk.Frame(content, bg=SURFACE2,
                            highlightthickness=1, highlightbackground=BORDER)
        pw_outer.pack(fill="x", pady=(6, 16))

        self.password_entry = tk.Entry(
            pw_outer, show="●", font=F_BODY,
            fg=TEXT_H1, bg=SURFACE2,
            insertbackground=BLUE,
            relief="flat", bd=10, highlightthickness=0
        )
        self.password_entry.pack(side="left", fill="x", expand=True)
        self.password_entry.bind("<FocusIn>",
            lambda e: pw_outer.config(highlightbackground=BLUE))
        self.password_entry.bind("<FocusOut>",
            lambda e: pw_outer.config(highlightbackground=BORDER))

        self.eye_btn = tk.Button(
            pw_outer, text="○", font=("Segoe UI", 13),
            bg=SURFACE2, fg=TEXT_DIM,
            activebackground=SURFACE2, activeforeground=BLUE,
            relief="flat", bd=0, padx=10,
            cursor="hand2", command=self.toggle_password
        )
        self.eye_btn.pack(side="right")

        # ── FILE ──
        self._label(content, "File")
        file_card = tk.Frame(content, bg=SURFACE2,
                             highlightthickness=1, highlightbackground=BORDER)
        file_card.pack(fill="x", pady=(6, 16))

        file_inner = tk.Frame(file_card, bg=SURFACE2)
        file_inner.pack(fill="x", padx=12, pady=10)

        self.file_icon = tk.Label(file_inner, text="📄", font=("Segoe UI", 16),
                                  bg=SURFACE2, fg=TEXT_DIM)
        self.file_icon.pack(side="left", padx=(0, 10))

        file_text_col = tk.Frame(file_inner, bg=SURFACE2)
        file_text_col.pack(side="left", fill="x", expand=True)

        self.file_name_lbl = tk.Label(file_text_col, text="No file selected",
                                      font=F_BODY, fg=TEXT_DIM, bg=SURFACE2, anchor="w")
        self.file_name_lbl.pack(fill="x")

        self.file_path_lbl = tk.Label(file_text_col, text="Click 'Browse' to choose a file",
                                      font=F_SMALL, fg=TEXT_DIM, bg=SURFACE2, anchor="w")
        self.file_path_lbl.pack(fill="x")

        browse_btn = tk.Button(
            file_inner, text="Browse",
            font=F_BTN, fg=TEXT_H1, bg=SURFACE,
            activeforeground=TEXT_H1, activebackground=BORDER_LT,
            relief="flat", bd=0, padx=16, pady=6,
            cursor="hand2",
            highlightthickness=1, highlightbackground=BORDER_LT,
            command=self.choose_file
        )
        browse_btn.pack(side="right")
        self._hover(browse_btn, BORDER_LT, SURFACE)

        # ── PROGRESS ──
        prog_header = tk.Frame(content, bg=BG)
        prog_header.pack(fill="x", pady=(0, 6))

        tk.Label(prog_header, text="PROGRESS", font=F_LABEL,
                 fg=TEXT_BODY, bg=BG).pack(side="left")
        self._pct_label = tk.Label(prog_header, text="—", font=F_MONO,
                                   fg=TEXT_DIM, bg=BG)
        self._pct_label.pack(side="right")

        prog_track = tk.Frame(content, bg=SURFACE2, height=8,
                              highlightthickness=1, highlightbackground=BORDER)
        prog_track.pack(fill="x")
        prog_track.pack_propagate(False)

        self._prog_fill = tk.Frame(prog_track, bg=BLUE, height=8)
        self._prog_fill.place(relwidth=0, relheight=1)

        # ── RUN ──
        self.run_btn = tk.Button(
            content, text="Run",
            font=F_RUN, fg=TEXT_H1, bg=BLUE,
            activeforeground=TEXT_H1, activebackground=BLUE_HOVER,
            relief="flat", bd=0, pady=12,
            cursor="hand2", command=self.run_crypto
        )
        self.run_btn.pack(fill="x", pady=(16, 10))
        self._hover(self.run_btn, BLUE_HOVER, BLUE)

        # ── STATUS ──
        self.status_frame = tk.Frame(content, bg=BG)
        self.status_frame.pack(fill="x")

        self.status_icon = tk.Label(self.status_frame, text="",
                                    font=("Segoe UI", 12), bg=BG, fg=TEXT_DIM)
        self.status_icon.pack(side="left", padx=(0, 8))

        self.status_label = tk.Label(self.status_frame, text="",
                                     font=F_BODY, fg=TEXT_DIM, bg=BG,
                                     anchor="w", justify="left", wraplength=400)
        self.status_label.pack(side="left", fill="x", expand=True)

        # ── Footer ──
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x")
        tk.Label(self.root,
                 text="RC6-CBC  ·  SHA-256 key derivation  ·  PKCS#7 padding",
                 font=F_SMALL, fg=TEXT_DIM, bg=SURFACE
                 ).pack(fill="x", pady=8, padx=20, anchor="w")

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _label(self, parent, text):
        tk.Label(parent, text=text.upper(), font=F_LABEL,
                 fg=TEXT_BODY, bg=BG, anchor="w").pack(fill="x")

    def _mode_btn(self, parent, label, value, accent, accent_bg, accent_lt):
        btn = tk.Button(
            parent, text=label, font=F_BTN,
            relief="flat", bd=0, padx=0, pady=10,
            cursor="hand2",
            command=lambda v=value: self._select_mode(v)
        )
        side_pad = (0, 6) if value == "encrypt" else (0, 0)
        btn.pack(side="left", fill="x", expand=True, padx=side_pad)
        setattr(self, f"_mbtn_{value}", btn)
        setattr(self, f"_maccent_{value}",    accent)
        setattr(self, f"_maccent_bg_{value}", accent_bg)
        setattr(self, f"_maccent_lt_{value}", accent_lt)
        self._refresh_mode_btns()

    def _select_mode(self, value):
        self.mode_var.set(value)
        self._refresh_mode_btns()

    def _refresh_mode_btns(self):
        for val in ("encrypt", "decrypt"):
            btn = getattr(self, f"_mbtn_{val}", None)
            if not btn:
                continue
            accent    = getattr(self, f"_maccent_{val}")
            accent_bg = getattr(self, f"_maccent_bg_{val}")
            accent_lt = getattr(self, f"_maccent_lt_{val}")
            selected  = self.mode_var.get() == val

            if selected:
                btn.config(bg=accent_bg, fg=accent_lt,
                           highlightthickness=2, highlightbackground=accent,
                           activebackground=accent_bg, activeforeground=accent_lt)
            else:
                btn.config(bg=SURFACE2, fg=TEXT_BODY,
                           highlightthickness=1, highlightbackground=BORDER,
                           activebackground=SURFACE2, activeforeground=TEXT_H2)

    def _key_btn(self, parent, ks, desc):
        btn = tk.Button(
            parent, text=f"{ks} B\n{desc}", font=F_SMALL,
            relief="flat", bd=0, padx=0, pady=8,
            cursor="hand2", justify="center",
            command=lambda k=ks: self._select_key(k)
        )
        btn.pack(side="left", fill="x", expand=True, padx=(0, 6))
        setattr(self, f"_kbtn_{ks}", btn)
        self._refresh_key_btns()

    def _select_key(self, ks):
        self.key_size_var.set(ks)
        self._refresh_key_btns()

    def _refresh_key_btns(self):
        for ks in ("16", "24", "32"):
            btn = getattr(self, f"_kbtn_{ks}", None)
            if not btn:
                continue
            selected = self.key_size_var.get() == ks
            if selected:
                btn.config(bg=BLUE_BG, fg=BLUE_LIGHT,
                           highlightthickness=2, highlightbackground=BLUE,
                           activebackground=BLUE_BG, activeforeground=BLUE_LIGHT)
            else:
                btn.config(bg=SURFACE2, fg=TEXT_BODY,
                           highlightthickness=1, highlightbackground=BORDER,
                           activebackground=SURFACE2, activeforeground=TEXT_H2)

    def _hover(self, widget, bg_on, bg_off, fg_on=None, fg_off=None):
        def on(e):
            widget.config(bg=bg_on)
            if fg_on:
                widget.config(fg=fg_on)
        def off(e):
            widget.config(bg=bg_off)
            if fg_off:
                widget.config(fg=fg_off)
        widget.bind("<Enter>", on)
        widget.bind("<Leave>", off)

    # ── Logic ──────────────────────────────────────────────────────────────────

    def toggle_password(self):
        self.show_password = not self.show_password
        self.password_entry.config(show="" if self.show_password else "●")
        self.eye_btn.config(text="●" if self.show_password else "○",
                            fg=BLUE if self.show_password else TEXT_DIM)

    def choose_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.selected_file = path
            name = os.path.basename(path)
            size_kb = os.path.getsize(path) / 1024
            size_str = (f"{size_kb:.1f} KB" if size_kb < 1024
                        else f"{size_kb/1024:.2f} MB")

            self.file_icon.config(fg=BLUE)
            self.file_name_lbl.config(text=name, fg=TEXT_H1)
            self.file_path_lbl.config(
                text=f"{path}  ·  {size_str}", fg=TEXT_BODY)
            self._set_status("", "", "")

    def update_progress(self, value):
        self._prog_fill.place(relwidth=value / 100, relheight=1)
        self._pct_label.config(text=f"{int(value)}%", fg=TEXT_H2)
        self.root.update_idletasks()

    def _set_status(self, text, color, icon=""):
        self.status_icon.config(text=icon, fg=color)
        self.status_label.config(text=text, fg=color)

    def run_crypto(self):
        if not self.selected_file:
            self._set_status("Please select a file first.", ERROR_CLR, "✖")
            return
        password = self.password_entry.get()
        if not password:
            self._set_status("Password cannot be empty.", ERROR_CLR, "✖")
            return

        key = derive_key(password, int(self.key_size_var.get()))
        self.update_progress(0)
        self._set_status("Processing, please wait…", WARNING, "⏳")
        self.run_btn.config(state="disabled", bg=BORDER, fg=TEXT_DIM)
        self.root.update_idletasks()

        try:
            mode = self.mode_var.get()
            if mode == "encrypt":
                output = self.selected_file + ".rc6"
                elapsed, size = encrypt_file(
                    self.selected_file, output, key, self.update_progress)
                action = "File encrypted"
            else:
                base = self.selected_file.removesuffix(".rc6")
                name, ext = os.path.splitext(base)
                output = name + "_decrypted" + ext
                elapsed, size = decrypt_file(
                    self.selected_file, output, key, self.update_progress)
                action = "File decrypted"

            speed = (size / (1024 * 1024)) / elapsed if elapsed > 0 else 0
            out_name = os.path.basename(output)

            self._prog_fill.config(bg=SUCCESS)
            self._set_status(
                f"{action} in {elapsed:.3f}s  ·  {speed:.2f} MB/s\n→ {out_name}",
                SUCCESS, "✔"
            )
            self.root.after(2200, lambda: self._prog_fill.config(bg=BLUE))

            # Clear password field
            self.password_entry.delete(0, "end")
            if self.show_password:
                self.show_password = False
                self.password_entry.config(show="●")
                self.eye_btn.config(text="○", fg=TEXT_DIM)

            # Clear file selection
            self.selected_file = None
            self.file_icon.config(fg=TEXT_DIM)
            self.file_name_lbl.config(text="No file selected", fg=TEXT_DIM)
            self.file_path_lbl.config(text="Click 'Browse' to choose a file", fg=TEXT_DIM)

        except Exception as e:
            self._set_status(f"Error: {e}", ERROR_CLR, "✖")
            self._prog_fill.place(relwidth=0)
            self._pct_label.config(text="—", fg=TEXT_DIM)

        finally:
            self.run_btn.config(state="normal", bg=BLUE, fg=TEXT_H1)