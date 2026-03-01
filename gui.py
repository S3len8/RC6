import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from key_derivation import derive_key
from file_crypto import encrypt_file, decrypt_file
import os


class RC6App:
    def __init__(self, root):
        self.root = root
        self.root.title("RC6 Secure Encryptor")
        self.root.geometry("540x500")
        self.root.configure(bg="#1e1e2e")
        self.root.resizable(False, False)

        self.selected_file = None
        self.setup_style()
        self.create_widgets()

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TFrame", background="#1e1e2e")
        style.configure("TLabel", background="#1e1e2e", foreground="white", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10), padding=6)
        style.configure("TEntry", padding=6)
        style.configure("TCombobox", padding=6)

    def create_widgets(self):
        frame = ttk.Frame(self.root, padding=25)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="RC6 File Encryption",
                  font=("Segoe UI", 18, "bold")).pack(pady=10)

        # Mode
        self.mode_var = tk.StringVar(value="encrypt")
        mode_frame = ttk.Frame(frame)
        mode_frame.pack(pady=10)

        ttk.Radiobutton(mode_frame, text="Encrypt",
                        variable=self.mode_var, value="encrypt").pack(side="left", padx=15)

        ttk.Radiobutton(mode_frame, text="Decrypt",
                        variable=self.mode_var, value="decrypt").pack(side="left", padx=15)

        # Key size
        ttk.Label(frame, text="Key Size (bytes):").pack(pady=(15, 5))
        self.key_size = ttk.Combobox(frame,
                                     values=["16", "24", "32"],
                                     state="readonly")
        self.key_size.set("16")
        self.key_size.pack(fill="x")

        # Password
        ttk.Label(frame, text="Password:").pack(pady=(15, 5))

        password_frame = ttk.Frame(frame)
        password_frame.pack(fill="x")

        self.password_entry = ttk.Entry(password_frame, show="*")
        self.password_entry.pack(side="left", fill="x", expand=True)

        self.show_password = False
        ttk.Button(password_frame, text="👁",
                   width=3,
                   command=self.toggle_password).pack(side="left", padx=5)

        # File
        ttk.Button(frame, text="Choose File",
                   command=self.choose_file).pack(pady=15)

        self.file_label = ttk.Label(frame, text="No file selected")
        self.file_label.pack()

        # Progress bar
        self.progress = ttk.Progressbar(frame, length=400, mode="determinate")
        self.progress.pack(pady=15)

        # Run
        ttk.Button(frame, text="Run",
                   command=self.run_crypto).pack(pady=10)

        # Status
        self.status_label = ttk.Label(frame, text="")
        self.status_label.pack(pady=10)

    def toggle_password(self):
        self.show_password = not self.show_password
        self.password_entry.config(show="" if self.show_password else "*")

    def choose_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file = file_path
            self.file_label.config(text=os.path.basename(file_path))

    def update_progress(self, value):
        self.progress["value"] = value
        self.root.update_idletasks()

    def run_crypto(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Select a file first.")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Enter password.")
            return

        key = derive_key(password, int(self.key_size.get()))
        self.progress["value"] = 0

        try:
            if self.mode_var.get() == "encrypt":
                output = self.selected_file + ".rc6"
                elapsed, size = encrypt_file(
                    self.selected_file,
                    output,
                    key,
                    self.update_progress
                )
            else:
                output = self.selected_file.replace(".rc6", "_decrypted")
                elapsed, size = decrypt_file(
                    self.selected_file,
                    output,
                    key,
                    self.update_progress
                )

            speed = (size / (1024 * 1024)) / elapsed if elapsed > 0 else 0

            self.status_label.config(
                text=f"Done in {elapsed:.3f} sec | Speed: {speed:.2f} MB/s"
            )

        except Exception as e:
            messagebox.showerror("Error", str(e))