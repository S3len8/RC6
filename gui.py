import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageTk
from key_derivation import derive_key
from file_crypto import encrypt_file, decrypt_file, encrypt_text, decrypt_text
import os
import sys

# ── Palette ────────────────────────────────────────────────────────────────────
BG          = "#0f1117"
SURFACE     = "#161b27"
SURFACE2    = "#1e2535"
BORDER      = "#2a3348"
BORDER_LT   = "#3d4f6e"

BLUE        = "#3b82f6"
BLUE_HOVER  = "#2563eb"
BLUE_LIGHT  = "#93c5fd"
BLUE_BG     = "#1e3a5f"

VIOLET      = "#8b5cf6"
VIOLET_HOVER= "#7c3aed"
VIOLET_LIGHT= "#c4b5fd"
VIOLET_BG   = "#2e1b5e"

TEAL        = "#14b8a6"
TEAL_LIGHT  = "#5eead4"
TEAL_BG     = "#0f3d38"

SUCCESS     = "#10b981"
ERROR_CLR   = "#f87171"
WARNING     = "#f59e0b"

TEXT_H1     = "#f1f5f9"
TEXT_H2     = "#cbd5e1"
TEXT_BODY   = "#94a3b8"
TEXT_DIM    = "#475569"

F_LABEL  = ("Segoe UI", 9, "bold")
F_BODY   = ("Segoe UI", 10)
F_MONO   = ("Consolas", 9)
F_SMALL  = ("Segoe UI", 8)
F_BTN    = ("Segoe UI", 10, "bold")
F_RUN    = ("Segoe UI", 11, "bold")
F_TEXT   = ("Consolas", 10)

WIN_W = 520


class RC6App:
    def __init__(self, root):
        self.root = root
        self.root.title("RC6 Secure Encryptor")
        self.root.geometry(f"{WIN_W}x700")
        self.root.configure(bg=BG)
        self.root.resizable(False, True)   # можна розтягувати по вертикалі

        self.selected_file = None
        self.show_password = False
        self.input_mode    = tk.StringVar(value="file")
        self.mode_var      = tk.StringVar(value="encrypt")
        self.key_size_var  = tk.StringVar(value="16")
        self._is_placeholder = True
        self._text_placeholder = "Type or paste text here…"

        _here = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        try:
            self.root.iconbitmap(os.path.join(_here, "icon.ico"))
        except Exception:
            pass
        try:
            _img = Image.open(os.path.join(_here, "logo.png")).resize((38, 38), Image.LANCZOS)
            self._logo_photo = ImageTk.PhotoImage(_img)
        except Exception:
            self._logo_photo = None

        self._build_ui()

    # ──────────────────────────────────────────────────────────────────────────
    def _build_ui(self):

        # ── Fixed header ──
        hdr = tk.Frame(self.root, bg=SURFACE)
        hdr.pack(fill="x", side="top")
        hi = tk.Frame(hdr, bg=SURFACE)
        hi.pack(fill="x", padx=24, pady=14)
        tk.Label(hi, text="RC6", font=("Segoe UI", 20, "bold"),
                 fg=BLUE, bg=SURFACE).pack(side="left")
        if self._logo_photo:
            tk.Label(hi, image=self._logo_photo, bg=SURFACE).pack(side="left", padx=(8, 4))
        tk.Label(hi, text="Secure Encryptor", font=("Segoe UI", 14),
                 fg=TEXT_H1, bg=SURFACE).pack(side="left", pady=3)
        tk.Label(hi, text="v2.1", font=F_SMALL, fg=TEXT_DIM, bg=SURFACE).pack(side="right")
        tk.Frame(self.root, bg=BLUE, height=2).pack(fill="x", side="top")

        # ── Fixed footer ──
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", side="bottom")
        tk.Label(self.root,
                 text="RC6-CBC  ·  SHA-256 key derivation  ·  PKCS#7 padding",
                 font=F_SMALL, fg=TEXT_DIM, bg=SURFACE
                 ).pack(fill="x", side="bottom", pady=7, padx=20, anchor="w")

        # ── Scrollable canvas ──
        self._canvas = tk.Canvas(self.root, bg=BG, highlightthickness=0,
                                 bd=0, yscrollincrement=1)
        self._scrollbar = tk.Scrollbar(self.root, orient="vertical",
                                       command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=self._scrollbar.set)

        self._scrollbar.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)

        # inner frame inside canvas
        self._inner = tk.Frame(self._canvas, bg=BG)
        self._inner_id = self._canvas.create_window((0, 0), window=self._inner,
                                                     anchor="nw",
                                                     width=WIN_W - 16)

        self._inner.bind("<Configure>", self._on_inner_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)

        # mousewheel scroll — тільки якщо фокус не на текстовом поле
        def _on_mousewheel(event):
            focused = self.root.focus_get()
            if focused is self.text_input or focused is self.text_output:
                return   # віддаємо скрол самому застосунку
            self._canvas.yview_scroll(-1 * (event.delta // 120), "units")
        self.root.bind_all("<MouseWheel>", _on_mousewheel)

        # Build content inside _inner
        self._build_content(self._inner)

    def _on_inner_configure(self, _event=None):
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self._canvas.itemconfig(self._inner_id, width=event.width)

    # ──────────────────────────────────────────────────────────────────────────
    def _build_content(self, c):
        pad = {"padx": 20}

        # ── MODE ──
        self._label(c, "Mode", **pad)
        mr = tk.Frame(c, bg=BG)
        mr.pack(fill="x", padx=20, pady=(6, 14))
        self._mode_btn(mr, "🔒  Encrypt", "encrypt", BLUE,   BLUE_BG,   BLUE_LIGHT)
        self._mode_btn(mr, "🔓  Decrypt", "decrypt", VIOLET, VIOLET_BG, VIOLET_LIGHT)

        # ── INPUT ──
        self._label(c, "Input", **pad)
        ir = tk.Frame(c, bg=BG)
        ir.pack(fill="x", padx=20, pady=(6, 14))
        self._input_btn(ir, "📄  File", "file")
        self._input_btn(ir, "✏️  Text", "text")

        # ── KEY SIZE ──
        self._label(c, "Key Size", **pad)
        kr = tk.Frame(c, bg=BG)
        kr.pack(fill="x", padx=20, pady=(6, 14))
        for ks, desc in (("16", "128-bit"), ("24", "192-bit"), ("32", "256-bit")):
            self._key_btn(kr, ks, desc)

        # ── PASSWORD ──
        self._label(c, "Password", **pad)
        pw_outer = tk.Frame(c, bg=SURFACE2,
                            highlightthickness=1, highlightbackground=BORDER)
        pw_outer.pack(fill="x", padx=20, pady=(6, 14))
        self.password_entry = tk.Entry(
            pw_outer, show="●", font=F_BODY, fg=TEXT_H1, bg=SURFACE2,
            insertbackground=BLUE, relief="flat", bd=10, highlightthickness=0)
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
            cursor="hand2", command=self.toggle_password)
        self.eye_btn.pack(side="right")

        # ── FILE panel (placeholder frame, always in DOM) ──
        self.file_panel = tk.Frame(c, bg=BG)
        self.file_panel.pack(fill="x", padx=20)

        self._label(self.file_panel, "File")
        file_card = tk.Frame(self.file_panel, bg=SURFACE2,
                             highlightthickness=1, highlightbackground=BORDER)
        file_card.pack(fill="x", pady=(6, 14))
        fi = tk.Frame(file_card, bg=SURFACE2)
        fi.pack(fill="x", padx=12, pady=10)
        self.file_icon = tk.Label(fi, text="📄", font=("Segoe UI", 16),
                                  bg=SURFACE2, fg=TEXT_DIM)
        self.file_icon.pack(side="left", padx=(0, 10))
        ftc = tk.Frame(fi, bg=SURFACE2)
        ftc.pack(side="left", fill="x", expand=True)
        self.file_name_lbl = tk.Label(ftc, text="No file selected",
                                      font=F_BODY, fg=TEXT_DIM, bg=SURFACE2, anchor="w")
        self.file_name_lbl.pack(fill="x")
        self.file_path_lbl = tk.Label(ftc, text="Click 'Browse' to choose a file",
                                      font=F_SMALL, fg=TEXT_DIM, bg=SURFACE2, anchor="w")
        self.file_path_lbl.pack(fill="x")
        browse_btn = tk.Button(
            fi, text="Browse", font=F_BTN, fg=TEXT_H1, bg=SURFACE,
            activeforeground=TEXT_H1, activebackground=BORDER_LT,
            relief="flat", bd=0, padx=16, pady=6, cursor="hand2",
            highlightthickness=1, highlightbackground=BORDER_LT,
            command=self.choose_file)
        browse_btn.pack(side="right")
        self._hover(browse_btn, BORDER_LT, SURFACE)

        # ── TEXT panel ──
        self.text_panel = tk.Frame(c, bg=BG)
        # hidden initially

        self._label(self.text_panel, "Text")
        text_outer = tk.Frame(self.text_panel, bg=SURFACE2,
                              highlightthickness=1, highlightbackground=BORDER)
        text_outer.pack(fill="x", pady=(6, 4))
        self.text_input = tk.Text(
            text_outer, font=F_TEXT, fg=TEXT_DIM, bg=SURFACE2,
            insertbackground=BLUE, relief="flat", bd=10,
            highlightthickness=0, height=5, wrap="word", undo=True)
        self.text_input.pack(fill="x")
        self.text_input.insert("1.0", self._text_placeholder)
        self._text_outer = text_outer   # зберігаєм для використання обробника
        self.text_input.bind("<FocusIn>",  self._on_text_focus_in)
        self.text_input.bind("<FocusOut>", self._on_text_focus_out)

        clr_row = tk.Frame(self.text_panel, bg=BG)
        clr_row.pack(fill="x", pady=(0, 8))
        tk.Button(clr_row, text="Clear", font=F_SMALL,
                  fg=TEXT_BODY, bg=SURFACE2,
                  activeforeground=TEXT_H1, activebackground=BORDER_LT,
                  relief="flat", bd=0, padx=10, pady=4, cursor="hand2",
                  highlightthickness=1, highlightbackground=BORDER,
                  command=self._clear_text).pack(side="right")

        # ── RESULT panel ──
        self.out_panel = tk.Frame(c, bg=BG)
        # hidden initially

        out_hdr = tk.Frame(self.out_panel, bg=BG)
        out_hdr.pack(fill="x")
        self._label(out_hdr, "Result")

        btn_row = tk.Frame(self.out_panel, bg=BG)
        btn_row.pack(fill="x", pady=(4, 4))

        self.copy_btn = tk.Button(
            btn_row, text="📋  Copy", font=F_SMALL,
            fg=TEXT_H1, bg=BLUE_BG,
            activeforeground=TEXT_H1, activebackground=BLUE_HOVER,
            relief="flat", bd=0, padx=12, pady=5, cursor="hand2",
            highlightthickness=1, highlightbackground=BLUE,
            command=self._copy_result)
        self.copy_btn.pack(side="left", padx=(0, 6))

        self.save_btn = tk.Button(
            btn_row, text="💾  Save to file", font=F_SMALL,
            fg=TEXT_H1, bg=SURFACE2,
            activeforeground=TEXT_H1, activebackground=BORDER_LT,
            relief="flat", bd=0, padx=12, pady=5, cursor="hand2",
            highlightthickness=1, highlightbackground=BORDER_LT,
            command=self._save_result)
        self.save_btn.pack(side="left")

        out_outer = tk.Frame(self.out_panel, bg=SURFACE2,
                             highlightthickness=1, highlightbackground=BORDER)
        out_outer.pack(fill="x", pady=(4, 14))
        self.text_output = tk.Text(
            out_outer, font=F_TEXT, fg=TEAL_LIGHT, bg=SURFACE2,
            relief="flat", bd=10, highlightthickness=0,
            height=5, wrap="word", state="disabled")
        self.text_output.pack(fill="x")

        # ── PROGRESS ──
        ph = tk.Frame(c, bg=BG)
        ph.pack(fill="x", padx=20, pady=(4, 6))
        tk.Label(ph, text="PROGRESS", font=F_LABEL, fg=TEXT_BODY, bg=BG).pack(side="left")
        self._pct_label = tk.Label(ph, text="—", font=F_MONO, fg=TEXT_DIM, bg=BG)
        self._pct_label.pack(side="right")

        prog_track = tk.Frame(c, bg=SURFACE2, height=8,
                              highlightthickness=1, highlightbackground=BORDER)
        prog_track.pack(fill="x", padx=20)
        prog_track.pack_propagate(False)
        self._prog_fill = tk.Frame(prog_track, bg=BLUE, height=8)
        self._prog_fill.place(relwidth=0, relheight=1)

        # ── RUN ──
        self.run_btn = tk.Button(
            c, text="Run", font=F_RUN, fg=TEXT_H1, bg=BLUE,
            activeforeground=TEXT_H1, activebackground=BLUE_HOVER,
            relief="flat", bd=0, pady=12, cursor="hand2",
            command=self.run_crypto)
        self.run_btn.pack(fill="x", padx=20, pady=(14, 8))
        self._hover(self.run_btn, BLUE_HOVER, BLUE)

        # ── STATUS ──
        sf = tk.Frame(c, bg=BG)
        sf.pack(fill="x", padx=20, pady=(0, 14))
        self.status_icon = tk.Label(sf, text="", font=("Segoe UI", 12),
                                    bg=BG, fg=TEXT_DIM)
        self.status_icon.pack(side="left", padx=(0, 6))
        self.status_label = tk.Label(sf, text="", font=F_BODY, fg=TEXT_DIM,
                                     bg=BG, anchor="w", justify="left", wraplength=440)
        self.status_label.pack(side="left", fill="x", expand=True)

        # initial panel state
        self._refresh_input_panels()

    # ── Widget helpers ─────────────────────────────────────────────────────────

    def _label(self, parent, text, **pack_kw):
        tk.Label(parent, text=text.upper(), font=F_LABEL,
                 fg=TEXT_BODY, bg=BG, anchor="w").pack(fill="x", **pack_kw)

    def _mode_btn(self, parent, label, value, accent, accent_bg, accent_lt):
        btn = tk.Button(parent, text=label, font=F_BTN,
                        relief="flat", bd=0, padx=0, pady=10, cursor="hand2",
                        command=lambda v=value: self._select_mode(v))
        btn.pack(side="left", fill="x", expand=True,
                 padx=(0, 6) if value == "encrypt" else (0, 0))
        setattr(self, f"_mbtn_{value}",    btn)
        setattr(self, f"_maccent_{value}", accent)
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
            sel = self.mode_var.get() == val
            btn.config(
                bg=accent_bg if sel else SURFACE2,
                fg=accent_lt if sel else TEXT_BODY,
                highlightthickness=2 if sel else 1,
                highlightbackground=accent if sel else BORDER,
                activebackground=accent_bg if sel else SURFACE2,
                activeforeground=accent_lt if sel else TEXT_H2)

    def _input_btn(self, parent, label, value):
        btn = tk.Button(parent, text=label, font=F_BTN,
                        relief="flat", bd=0, padx=0, pady=10, cursor="hand2",
                        command=lambda v=value: self._select_input(v))
        btn.pack(side="left", fill="x", expand=True,
                 padx=(0, 6) if value == "file" else (0, 0))
        setattr(self, f"_ibtn_{value}", btn)
        self._refresh_input_btns()

    def _select_input(self, value):
        self.input_mode.set(value)
        self._refresh_input_btns()
        self._refresh_input_panels()

    def _refresh_input_btns(self):
        for val in ("file", "text"):
            btn = getattr(self, f"_ibtn_{val}", None)
            if not btn:
                continue
            sel = self.input_mode.get() == val
            btn.config(
                bg=TEAL_BG if sel else SURFACE2,
                fg=TEAL_LIGHT if sel else TEXT_BODY,
                highlightthickness=2 if sel else 1,
                highlightbackground=TEAL if sel else BORDER,
                activebackground=TEAL_BG if sel else SURFACE2,
                activeforeground=TEAL_LIGHT if sel else TEXT_H2)

    def _refresh_input_panels(self):
        if self.input_mode.get() == "file":
            self.text_panel.pack_forget()
            self.out_panel.pack_forget()
            self.file_panel.pack(fill="x", padx=20,
                                 before=self._get_widget("_prog_ref"))
        else:
            self.file_panel.pack_forget()
            self.text_panel.pack(fill="x", padx=20,
                                 before=self._get_widget("_prog_ref"))

    def _get_widget(self, name):
        """Helper — returns progress label frame as anchor for before=."""
        return self.run_btn

    def _key_btn(self, parent, ks, desc):
        btn = tk.Button(parent, text=f"{ks} B\n{desc}", font=F_SMALL,
                        relief="flat", bd=0, padx=0, pady=8,
                        cursor="hand2", justify="center",
                        command=lambda k=ks: self._select_key(k))
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
            sel = self.key_size_var.get() == ks
            btn.config(
                bg=BLUE_BG if sel else SURFACE2,
                fg=BLUE_LIGHT if sel else TEXT_BODY,
                highlightthickness=2 if sel else 1,
                highlightbackground=BLUE if sel else BORDER,
                activebackground=BLUE_BG if sel else SURFACE2,
                activeforeground=BLUE_LIGHT if sel else TEXT_H2)

    def _hover(self, widget, bg_on, bg_off, fg_on=None, fg_off=None):
        widget.bind("<Enter>", lambda e: widget.config(bg=bg_on,
                    **({'fg': fg_on} if fg_on else {})))
        widget.bind("<Leave>", lambda e: widget.config(bg=bg_off,
                    **({'fg': fg_off} if fg_off else {})))

    # ── Placeholder ────────────────────────────────────────────────────────────

    def _on_text_focus_in(self, _e):
        self._text_outer.config(highlightbackground=BLUE)
        if self._is_placeholder:
            self.text_input.delete("1.0", "end")
            self.text_input.config(fg=TEXT_H1)
            self._is_placeholder = False

    def _on_text_focus_out(self, _e):
        self._text_outer.config(highlightbackground=BORDER)
        if not self.text_input.get("1.0", "end").strip():
            self.text_input.config(fg=TEXT_DIM)
            self.text_input.delete("1.0", "end")
            self.text_input.insert("1.0", self._text_placeholder)
            self._is_placeholder = True

    def _clear_text(self):
        self.text_input.config(fg=TEXT_DIM)
        self.text_input.delete("1.0", "end")
        self.text_input.insert("1.0", self._text_placeholder)
        self._is_placeholder = True
        self._hide_result()
        self._set_status("", "", "")

    # ── Result panel ───────────────────────────────────────────────────────────

    def _show_result(self, text):
        """Write text to output widget and show the result panel."""
        self.text_output.config(state="normal")
        self.text_output.delete("1.0", "end")
        self.text_output.insert("1.0", text)
        self.text_output.config(state="disabled")
        # Show out_panel right after text_panel
        self.out_panel.pack(fill="x", padx=20, after=self.text_panel)
        # Scroll to bottom so result is visible
        self.root.update_idletasks()
        self._canvas.yview_moveto(1.0)

    def _hide_result(self):
        self.text_output.config(state="normal")
        self.text_output.delete("1.0", "end")
        self.text_output.config(state="disabled")
        self.out_panel.pack_forget()

    def _copy_result(self):
        result = self.text_output.get("1.0", "end").strip()
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            self._set_status("Copied to clipboard.", SUCCESS, "✔")

    def _save_result(self):
        result = self.text_output.get("1.0", "end").strip()
        if not result:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            title="Save result")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(result)
            self._set_status(f"Saved → {os.path.basename(path)}", SUCCESS, "✔")

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
                        else f"{size_kb / 1024:.2f} MB")
            self.file_icon.config(fg=BLUE)
            self.file_name_lbl.config(text=name, fg=TEXT_H1)
            self.file_path_lbl.config(text=f"{path}  ·  {size_str}", fg=TEXT_BODY)
            self._set_status("", "", "")

    def update_progress(self, value):
        self._prog_fill.place(relwidth=value / 100, relheight=1)
        self._pct_label.config(text=f"{int(value)}%", fg=TEXT_H2)
        self.root.update_idletasks()

    def _set_status(self, text, color, icon=""):
        self.status_icon.config(text=icon, fg=color or TEXT_DIM)
        self.status_label.config(text=text, fg=color or TEXT_DIM)

    def _reset_after_success(self):
        """Зброс пароля та файла після успішної операції."""
        self.password_entry.delete(0, "end")
        if self.show_password:
            self.show_password = False
            self.password_entry.config(show="●")
            self.eye_btn.config(text="○", fg=TEXT_DIM)
        if self.input_mode.get() == "file":
            self.selected_file = None
            self.file_icon.config(fg=TEXT_DIM)
            self.file_name_lbl.config(text="No file selected", fg=TEXT_DIM)
            self.file_path_lbl.config(text="Click 'Browse' to choose a file", fg=TEXT_DIM)

    def run_crypto(self):
        password = self.password_entry.get()
        if not password:
            self._set_status("Password cannot be empty.", ERROR_CLR, "✖")
            return

        mode  = self.mode_var.get()
        imode = self.input_mode.get()

        # ── Validate before locking UI ──
        if imode == "text":
            raw_text = ("" if self._is_placeholder
                        else self.text_input.get("1.0", "end").strip())
            if not raw_text:
                self._set_status("Please enter text first.", ERROR_CLR, "✖")
                return
        else:
            if not self.selected_file:
                self._set_status("Please select a file first.", ERROR_CLR, "✖")
                return

        key = derive_key(password, int(self.key_size_var.get()))
        self.update_progress(0)
        self._set_status("Processing, please wait…", WARNING, "⏳")
        self.run_btn.config(state="disabled", bg=BORDER, fg=TEXT_DIM)
        self.root.update_idletasks()

        try:
            if imode == "text":
                if mode == "encrypt":
                    result, elapsed, size = encrypt_text(raw_text, key, self.update_progress)
                    action = "Text encrypted"
                else:
                    result, elapsed, size = decrypt_text(raw_text, key, self.update_progress)
                    action = "Text decrypted"

                speed = (size / (1024 * 1024)) / elapsed if elapsed > 0 else 0
                self._prog_fill.config(bg=SUCCESS)
                self._set_status(
                    f"{action} in {elapsed:.3f}s  ·  {speed:.2f} MB/s", SUCCESS, "✔")
                self.root.after(2200, lambda: self._prog_fill.config(bg=BLUE))
                self._show_result(result)

            else:
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
                self._prog_fill.config(bg=SUCCESS)
                self._set_status(
                    f"{action} in {elapsed:.3f}s  ·  {speed:.2f} MB/s\n"
                    f"→ {os.path.basename(output)}", SUCCESS, "✔")
                self.root.after(2200, lambda: self._prog_fill.config(bg=BLUE))

            self._reset_after_success()

        except Exception as e:
            self._set_status(str(e), ERROR_CLR, "✖")
            self._prog_fill.place(relwidth=0)
            self._pct_label.config(text="—", fg=TEXT_DIM)

        finally:
            self.run_btn.config(state="normal", bg=BLUE, fg=TEXT_H1)