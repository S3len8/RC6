import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from key_derivation import derive_key
from file_crypto import encrypt_file, decrypt_file
import os


# ─── Palette ───────────────────────────────────────────────────────────────────
BG        = "#0d0f14"
PANEL     = "#13161d"
CARD      = "#1a1e28"
BORDER    = "#252a38"
ACCENT    = "#00e5ff"
ACCENT2   = "#7c3aed"
SUCCESS   = "#22c55e"
ERROR_CLR = "#ef4444"
TEXT      = "#e2e8f0"
MUTED     = "#64748b"
WHITE     = "#ffffff"

FONT_TITLE  = ("Courier New", 22, "bold")
FONT_LABEL  = ("Courier New", 9, "bold")
FONT_BODY   = ("Courier New", 10)
FONT_MONO   = ("Courier New", 9)
FONT_SMALL  = ("Courier New", 8)


class RC6App:
    def __init__(self, root):
        self.root = root
        self.root.title("RC6 · Secure Encryptor")
        self.root.geometry("520x620")
        self.root.configure(bg=BG)
        self.root.resizable(False, False)

        self.selected_file = None
        self.show_password = False

        self._build_ui()
        self._animate_title()

    # ── Animation helpers ──────────────────────────────────────────────────────

    def _animate_title(self):
        """Blinking cursor effect on title label."""
        current = self._cursor_visible
        self._cursor_visible = not current
        ch = "█" if self._cursor_visible else " "
        self.title_label.config(text=f"  RC6 ENCRYPTOR {ch}")
        self.root.after(600, self._animate_title)

    # ── UI builder ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        self._cursor_visible = True

        # ── outer canvas with grid lines ──
        self.canvas = tk.Canvas(self.root, bg=BG, highlightthickness=0)
        self.canvas.place(relwidth=1, relheight=1)
        self._draw_grid()

        # ── header ──
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=24, pady=(22, 0))

        self.title_label = tk.Label(
            header,
            text="  RC6 ENCRYPTOR █",
            font=FONT_TITLE,
            fg=ACCENT, bg=BG,
            anchor="w"
        )
        self.title_label.pack(side="left")

        ver_lbl = tk.Label(header, text="v2.0", font=FONT_SMALL, fg=MUTED, bg=BG)
        ver_lbl.pack(side="right", pady=8)

        # separator
        self._sep(self.root, ACCENT, pady=(8, 0))

        # ── main card ──
        card = tk.Frame(self.root, bg=CARD, bd=0, relief="flat",
                        highlightthickness=1, highlightbackground=BORDER)
        card.pack(fill="both", padx=20, pady=14, expand=True)

        inner = tk.Frame(card, bg=CARD)
        inner.pack(fill="both", expand=True, padx=18, pady=16)

        # MODE
        self._section_label(inner, "// MODE")
        mode_row = tk.Frame(inner, bg=CARD)
        mode_row.pack(fill="x", pady=(4, 12))

        self.mode_var = tk.StringVar(value="encrypt")
        self._radio(mode_row, "ENCRYPT", "encrypt")
        self._radio(mode_row, "DECRYPT", "decrypt")

        # KEY SIZE
        self._section_label(inner, "// KEY SIZE")
        ks_row = tk.Frame(inner, bg=CARD)
        ks_row.pack(fill="x", pady=(4, 12))

        self.key_size_var = tk.StringVar(value="16")
        for ks in ("16", "24", "32"):
            self._key_btn(ks_row, ks)

        # PASSWORD
        self._section_label(inner, "// PASSWORD")
        pw_row = tk.Frame(inner, bg=CARD)
        pw_row.pack(fill="x", pady=(4, 12))

        pw_frame = tk.Frame(pw_row, bg=BORDER, highlightthickness=1,
                            highlightbackground=BORDER)
        pw_frame.pack(fill="x")

        self.password_entry = tk.Entry(
            pw_frame, show="●", font=FONT_BODY,
            bg=PANEL, fg=TEXT, insertbackground=ACCENT,
            relief="flat", bd=8,
            highlightthickness=0
        )
        self.password_entry.pack(side="left", fill="x", expand=True)

        eye_btn = tk.Button(
            pw_frame, text="◉", font=("Courier New", 12),
            bg=PANEL, fg=MUTED, relief="flat", bd=0,
            activebackground=PANEL, activeforeground=ACCENT,
            cursor="hand2", command=self.toggle_password
        )
        eye_btn.pack(side="right", padx=6)

        # FILE
        self._section_label(inner, "// FILE")
        file_row = tk.Frame(inner, bg=CARD)
        file_row.pack(fill="x", pady=(4, 12))

        choose_btn = tk.Button(
            file_row, text="[ SELECT FILE ]",
            font=FONT_LABEL, fg=ACCENT, bg=PANEL,
            activeforeground=WHITE, activebackground=ACCENT2,
            relief="flat", bd=0, padx=14, pady=8,
            cursor="hand2",
            highlightthickness=1, highlightbackground=ACCENT,
            command=self.choose_file
        )
        choose_btn.pack(side="left")
        self._hover(choose_btn, ACCENT2, PANEL)

        self.file_label = tk.Label(
            file_row, text="  no file selected",
            font=FONT_MONO, fg=MUTED, bg=CARD,
            anchor="w"
        )
        self.file_label.pack(side="left", fill="x", expand=True, padx=10)

        # PROGRESS
        self._sep(inner, BORDER, pady=(4, 10))

        prog_bg = tk.Frame(inner, bg=BORDER, height=6)
        prog_bg.pack(fill="x", pady=(0, 4))
        prog_bg.pack_propagate(False)

        self._prog_track = tk.Frame(prog_bg, bg=BORDER)
        self._prog_track.place(relwidth=1, relheight=1)

        self._prog_fill = tk.Frame(prog_bg, bg=ACCENT)
        self._prog_fill.place(relwidth=0, relheight=1)

        self._pct_label = tk.Label(inner, text="0%", font=FONT_SMALL,
                                   fg=MUTED, bg=CARD)
        self._pct_label.pack(anchor="e")

        # RUN BUTTON
        run_btn = tk.Button(
            inner, text="▶  RUN",
            font=("Courier New", 13, "bold"),
            fg=BG, bg=ACCENT,
            activeforeground=BG, activebackground=ACCENT2,
            relief="flat", bd=0,
            padx=0, pady=10,
            cursor="hand2",
            command=self.run_crypto
        )
        run_btn.pack(fill="x", pady=(10, 6))
        self._hover(run_btn, ACCENT2, ACCENT, fg_on=WHITE, fg_off=BG)

        # STATUS
        self.status_label = tk.Label(
            inner, text="",
            font=FONT_MONO, fg=MUTED, bg=CARD,
            wraplength=440, justify="left"
        )
        self.status_label.pack(fill="x", pady=(4, 0))

        # footer
        self._sep(self.root, BORDER)
        footer = tk.Label(
            self.root,
            text="RC6-CBC  ·  SHA-256 key derivation  ·  PKCS#7 padding",
            font=FONT_SMALL, fg=MUTED, bg=BG
        )
        footer.pack(pady=(4, 10))

    # ── widget helpers ─────────────────────────────────────────────────────────

    def _sep(self, parent, color, pady=(0, 0)):
        f = tk.Frame(parent, bg=color, height=1)
        f.pack(fill="x", padx=20, pady=pady)

    def _section_label(self, parent, text):
        tk.Label(parent, text=text, font=FONT_LABEL,
                 fg=ACCENT2, bg=CARD, anchor="w").pack(fill="x", pady=(0, 2))

    def _radio(self, parent, label, value):
        btn = tk.Radiobutton(
            parent, text=label, variable=self.mode_var, value=value,
            font=FONT_LABEL, fg=TEXT, bg=CARD,
            selectcolor=CARD,
            activebackground=CARD, activeforeground=ACCENT,
            indicatoron=False,
            relief="flat", bd=0,
            padx=18, pady=7,
            cursor="hand2",
            highlightthickness=1, highlightbackground=BORDER,
            command=lambda: self._update_mode_btns()
        )
        btn.pack(side="left", padx=(0, 8))
        setattr(self, f"_radio_{value}", btn)
        self._update_mode_btns()

    def _update_mode_btns(self):
        for val, color in (("encrypt", ACCENT), ("decrypt", ACCENT2)):
            btn = getattr(self, f"_radio_{val}", None)
            if btn:
                selected = self.mode_var.get() == val
                btn.config(
                    fg=BG if selected else MUTED,
                    bg=color if selected else PANEL,
                    highlightbackground=color if selected else BORDER
                )

    def _key_btn(self, parent, ks):
        btn = tk.Radiobutton(
            parent, text=f"{ks}B", variable=self.key_size_var, value=ks,
            font=FONT_LABEL, fg=MUTED, bg=PANEL,
            selectcolor=PANEL,
            activebackground=PANEL, activeforeground=ACCENT,
            indicatoron=False,
            relief="flat", bd=0,
            padx=14, pady=6,
            cursor="hand2",
            highlightthickness=1, highlightbackground=BORDER
        )
        btn.pack(side="left", padx=(0, 6))
        # Bind to update colors
        btn.config(command=lambda b=btn: self._style_key_btns())
        setattr(self, f"_kbtn_{ks}", btn)
        self._style_key_btns()

    def _style_key_btns(self):
        for ks in ("16", "24", "32"):
            btn = getattr(self, f"_kbtn_{ks}", None)
            if btn:
                sel = self.key_size_var.get() == ks
                btn.config(
                    fg=BG if sel else MUTED,
                    bg=ACCENT if sel else PANEL,
                    highlightbackground=ACCENT if sel else BORDER
                )

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

    def _draw_grid(self):
        """Draw subtle dot-grid background."""
        w, h = 520, 620
        step = 28
        for x in range(0, w, step):
            for y in range(0, h, step):
                self.canvas.create_oval(x, y, x+1, y+1, fill="#1c2030", outline="")

    # ── logic ──────────────────────────────────────────────────────────────────

    def toggle_password(self):
        self.show_password = not self.show_password
        self.password_entry.config(show="" if self.show_password else "●")

    def choose_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.selected_file = path
            name = os.path.basename(path)
            self.file_label.config(
                text=f"  {name}",
                fg=TEXT
            )

    def update_progress(self, value):
        pct = value / 100
        self._prog_fill.place(relwidth=pct, relheight=1)
        self._pct_label.config(text=f"{int(value)}%")
        self.root.update_idletasks()

    def _set_status(self, text, color=MUTED):
        self.status_label.config(text=text, fg=color)

    def run_crypto(self):
        if not self.selected_file:
            self._set_status("✖  No file selected.", ERROR_CLR)
            return

        password = self.password_entry.get()
        if not password:
            self._set_status("✖  Password cannot be empty.", ERROR_CLR)
            return

        key = derive_key(password, int(self.key_size_var.get()))
        self.update_progress(0)
        self._set_status("⏳  Processing...", ACCENT)

        try:
            mode = self.mode_var.get()
            if mode == "encrypt":
                output = self.selected_file + ".rc6"
                elapsed, size = encrypt_file(
                    self.selected_file, output, key, self.update_progress
                )
                action = "Encrypted"
            else:
                # Remove .rc6, then insert _decrypted before the original extension
                base = self.selected_file.removesuffix(".rc6")
                name, ext = os.path.splitext(base)
                output = name + "_decrypted" + ext
                elapsed, size = decrypt_file(
                    self.selected_file, output, key, self.update_progress
                )
                action = "Decrypted"

            speed = (size / (1024 * 1024)) / elapsed if elapsed > 0 else 0
            out_name = os.path.basename(output)

            self._set_status(
                f"✔  {action} successfully  ·  {elapsed:.3f}s  ·  {speed:.2f} MB/s\n"
                f"   → {out_name}",
                SUCCESS
            )

            # Flash progress bar green
            self._prog_fill.config(bg=SUCCESS)
            self.root.after(1800, lambda: self._prog_fill.config(bg=ACCENT))

        except Exception as e:
            self._set_status(f"✖  Error: {e}", ERROR_CLR)
            self._prog_fill.place(relwidth=0)
            self._pct_label.config(text="0%")