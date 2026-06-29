# ui.py
# ─────────────────────────────────────────────────────────────────────────────
# CipherVault — Main UI
# Built with CustomTkinter for a modern, professional dark desktop interface.
# ─────────────────────────────────────────────────────────────────────────────

import os
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk
from PIL import Image

# ── Import our encryption algorithms ────────────────────────────────────────
from algorithms import aes_cipher, des_cipher, rsa_cipher
from utils import file_handler

# ── App-wide theme settings ──────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Color palette ────────────────────────────────────────────────────────────
# Keeping all colors in one place makes future re-theming easy.
COLOR_BG_DARK   = "#0d1b2a"   # Main background — deep navy
COLOR_BG_MID    = "#1a2744"   # Sidebar background
COLOR_BG_CARD   = "#1e2d45"   # Card / panel background
COLOR_ACCENT     = "#00d4ff"   # Cyan accent — algorithm buttons, borders
COLOR_ACCENT2    = "#0099cc"   # Slightly darker cyan for hover states
COLOR_TEXT_MAIN  = "#e8f4f8"   # Primary text
COLOR_TEXT_DIM   = "#7a9bb5"   # Dimmed / label text
COLOR_SUCCESS    = "#00c896"   # Green for success messages
COLOR_WARNING    = "#ffb347"   # Orange for warnings
COLOR_ERROR      = "#ff5c5c"   # Red for errors
COLOR_BTN_ENC    = "#00c896"   # Encrypt button — green
COLOR_BTN_DEC    = "#7b5ea7"   # Decrypt button — purple


class CipherVaultApp(ctk.CTk):
    """
    Main application window for CipherVault.

    Inherits from ctk.CTk, which is CustomTkinter's replacement for tk.Tk.
    All UI widgets are created inside __init__ and helper methods.
    """

    def __init__(self):
        super().__init__()

        # ── Window setup ────────────────────────────────────────────────────
        self.title("CipherVault — Multi-Algorithm Encryption Tool")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.configure(fg_color=COLOR_BG_DARK)

        # Set window icon if available
        icon_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
        if os.path.exists(icon_path):
            try:
                icon_img = tk.PhotoImage(file=icon_path)
                self.iconphoto(True, icon_img)
            except Exception:
                pass  # Icon loading is optional

        # ── State variables ──────────────────────────────────────────────────
        # Which algorithm the user has selected
        self.current_algorithm = tk.StringVar(value="AES")

        # RSA key storage (kept in memory during the session)
        self.rsa_private_key = ""
        self.rsa_public_key  = ""

        # ── Build the UI ────────────────────────────────────────────────────
        self._build_layout()

    # ─────────────────────────────────────────────────────────────────────────
    # Layout construction
    # ─────────────────────────────────────────────────────────────────────────

    def _build_layout(self):
        """Create the main two-column layout: sidebar on the left, main panel on the right."""

        # Configure grid: column 0 = sidebar (fixed), column 1 = main (stretchy)
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)  # Status bar row

        self._build_sidebar()
        self._build_main_panel()
        self._build_status_bar()

    def _build_sidebar(self):
        """Build the left sidebar: logo, app name, algorithm selector."""

        sidebar = ctk.CTkFrame(
            self,
            width=210,
            fg_color=COLOR_BG_MID,
            corner_radius=0
        )
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)  # Keep fixed width
        sidebar.grid_rowconfigure(10, weight=1)  # Push content to top
        def _build_sidebar(self):
            sidebar = ctk.CTkFrame(
            self,
            width=210,
            fg_color=COLOR_BG_MID,
            corner_radius=0
        )
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_rowconfigure(10, weight=1)

        # Logo
        logo_path = os.path.join(
            os.path.dirname(__file__),
            "assets",
            "logo.png"
        )

        try:
            logo_pil = Image.open(logo_path)

            self.logo = ctk.CTkImage(
                light_image=logo_pil,
                dark_image=logo_pil,
                size=(80, 80)
            )

            logo_label = ctk.CTkLabel(
                sidebar,
                image=self.logo,
                text=""
            )

            logo_label.grid(
                row=0,
                column=0,
                pady=(20, 10)
            )

        except Exception as e:
            print("Logo Error:", e)

        # App Name
        name_label = ctk.CTkLabel(
            sidebar,
            text="CipherVault",
            font=ctk.CTkFont(family="Arial", size=22, weight="bold"),
            text_color=COLOR_ACCENT
        )

        

        # ── App name ─────────────────────────────────────────────────────────
        name_label = ctk.CTkLabel(
            sidebar,
            text="CipherVault",
            font=ctk.CTkFont(family="Arial", size=22, weight="bold"),
            text_color=COLOR_ACCENT
        )
        name_label.grid(row=1, column=0, pady=(0, 2))

        tagline = ctk.CTkLabel(
            sidebar,
            text="Multi-Algorithm Encryption",
            font=ctk.CTkFont(size=11),
            text_color=COLOR_TEXT_DIM
        )
        tagline.grid(row=2, column=0, pady=(0, 24))

        # ── Divider ──────────────────────────────────────────────────────────
        ctk.CTkLabel(sidebar, text="── SELECT ALGORITHM ──",
                     font=ctk.CTkFont(size=10),
                     text_color=COLOR_TEXT_DIM).grid(row=3, column=0, padx=16, pady=(0, 10))

        # ── Algorithm buttons ────────────────────────────────────────────────
        algorithms = [
            ("🔐  AES-256",  "AES", "AES-256 CBC — Recommended"),
            ("🔑  DES",      "DES", "DES CBC — Learning Only ⚠️"),
            ("🗝️  RSA",      "RSA", "RSA-2048 — Asymmetric"),
        ]
        for row_idx, (label, algo, tooltip) in enumerate(algorithms, start=4):
            btn = ctk.CTkButton(
                sidebar,
                text=label,
                width=174,
                height=44,
                corner_radius=10,
                fg_color=COLOR_ACCENT if self.current_algorithm.get() == algo else COLOR_BG_CARD,
                hover_color=COLOR_ACCENT2,
                text_color=COLOR_BG_DARK if self.current_algorithm.get() == algo else COLOR_TEXT_MAIN,
                font=ctk.CTkFont(size=13, weight="bold"),
                command=lambda a=algo: self._switch_algorithm(a)
            )
            btn.grid(row=row_idx, column=0, padx=18, pady=5)
            # Store button reference so we can re-style it on switch
            setattr(self, f"btn_{algo.lower()}", btn)

        # ── RSA Key Management (shown only when RSA is active) ───────────────
        self.rsa_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        self.rsa_frame.grid(row=7, column=0, padx=12, pady=(10, 0), sticky="ew")
        self.rsa_frame.grid_remove()  # Hidden by default

        ctk.CTkLabel(self.rsa_frame, text="RSA KEY MANAGEMENT",
                     font=ctk.CTkFont(size=10), text_color=COLOR_TEXT_DIM
                     ).pack(pady=(0, 6))

        ctk.CTkButton(self.rsa_frame, text="⚙️  Generate Keys",
                      width=174, height=34, corner_radius=8,
                      fg_color="#2a4a6a", hover_color="#3a5a7a",
                      command=self._generate_rsa_keys
                      ).pack(pady=3)

        ctk.CTkButton(self.rsa_frame, text="💾  Save Keys",
                      width=174, height=34, corner_radius=8,
                      fg_color="#2a4a6a", hover_color="#3a5a7a",
                      command=self._save_rsa_keys
                      ).pack(pady=3)

        ctk.CTkButton(self.rsa_frame, text="📂  Load Keys",
                      width=174, height=34, corner_radius=8,
                      fg_color="#2a4a6a", hover_color="#3a5a7a",
                      command=self._load_rsa_keys
                      ).pack(pady=3)

        # RSA key status indicator
        self.rsa_key_status = ctk.CTkLabel(
            self.rsa_frame, text="No keys loaded",
            font=ctk.CTkFont(size=10), text_color=COLOR_TEXT_DIM, wraplength=170
        )
        self.rsa_key_status.pack(pady=(4, 0))

    def _build_main_panel(self):
        """Build the right main panel: input, password, buttons, output."""

        main = ctk.CTkFrame(self, fg_color=COLOR_BG_DARK)
        main.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(3, weight=1)  # Output box stretches

        # ── Section: Input ────────────────────────────────────────────────────
        input_card = ctk.CTkFrame(main, fg_color=COLOR_BG_CARD, corner_radius=12)
        input_card.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        input_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(input_card, text="PLAIN TEXT INPUT",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=COLOR_TEXT_DIM).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 4))

        self.input_text = ctk.CTkTextbox(
            input_card,
            height=120,
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color="#0f2035",
            text_color=COLOR_TEXT_MAIN,
            border_color=COLOR_ACCENT,
            border_width=1,
            corner_radius=8
        )
        self.input_text.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))

        # ── Section: Password ─────────────────────────────────────────────────
        pass_card = ctk.CTkFrame(main, fg_color=COLOR_BG_CARD, corner_radius=12)
        pass_card.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        pass_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(pass_card, text="🔒  Password / Key:",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=COLOR_TEXT_MAIN).grid(row=0, column=0, padx=(16, 8), pady=12)

        self.password_entry = ctk.CTkEntry(
            pass_card,
            show="●",
            placeholder_text="Enter password for AES / DES  |  Not used for RSA",
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color="#0f2035",
            text_color=COLOR_TEXT_MAIN,
            border_color=COLOR_ACCENT,
            border_width=1,
            corner_radius=8,
            height=38
        )
        self.password_entry.grid(row=0, column=1, sticky="ew", padx=(0, 16), pady=12)

        # Show/hide password toggle
        self._pass_visible = False
        ctk.CTkButton(
            pass_card, text="👁", width=36, height=36,
            fg_color="transparent", hover_color=COLOR_BG_MID,
            command=self._toggle_password_visibility
        ).grid(row=0, column=2, padx=(0, 16))

        # ── Section: Action buttons ───────────────────────────────────────────
        btn_card = ctk.CTkFrame(main, fg_color="transparent")
        btn_card.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        for i in range(4):
            btn_card.grid_columnconfigure(i, weight=1)

        btn_cfg = dict(height=44, corner_radius=10, font=ctk.CTkFont(size=13, weight="bold"))

        ctk.CTkButton(btn_card, text="🔐  ENCRYPT", fg_color=COLOR_BTN_ENC,
                      hover_color="#009f78", text_color="#001a10",
                      command=self._encrypt, **btn_cfg
                      ).grid(row=0, column=0, padx=5, sticky="ew")

        ctk.CTkButton(btn_card, text="🔓  DECRYPT", fg_color=COLOR_BTN_DEC,
                      hover_color="#5a3e87", text_color=COLOR_TEXT_MAIN,
                      command=self._decrypt, **btn_cfg
                      ).grid(row=0, column=1, padx=5, sticky="ew")

        ctk.CTkButton(btn_card, text="📂  Open File",
                      fg_color="#2a4a6a", hover_color="#3a5a7a",
                      command=self._open_file, **btn_cfg
                      ).grid(row=0, column=2, padx=5, sticky="ew")

        ctk.CTkButton(btn_card, text="🗑  Clear All",
                      fg_color="#4a2a2a", hover_color="#6a3a3a",
                      command=self._clear_all, **btn_cfg
                      ).grid(row=0, column=3, padx=5, sticky="ew")

        # ── Section: Output ───────────────────────────────────────────────────
        output_card = ctk.CTkFrame(main, fg_color=COLOR_BG_CARD, corner_radius=12)
        output_card.grid(row=3, column=0, sticky="nsew")
        output_card.grid_columnconfigure(0, weight=1)
        output_card.grid_rowconfigure(1, weight=1)

        # Output header with action buttons
        out_header = ctk.CTkFrame(output_card, fg_color="transparent")
        out_header.grid(row=0, column=0, sticky="ew", padx=16, pady=(10, 4))
        out_header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(out_header, text="OUTPUT",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=COLOR_TEXT_DIM).grid(row=0, column=0, sticky="w")

        small_btn = dict(height=28, corner_radius=6,
                         font=ctk.CTkFont(size=11),
                         fg_color="#2a4a6a", hover_color="#3a5a7a")

        ctk.CTkButton(out_header, text="📋 Copy", width=70,
                      command=self._copy_output, **small_btn
                      ).grid(row=0, column=1, padx=4)

        ctk.CTkButton(out_header, text="💾 Save", width=70,
                      command=self._save_output, **small_btn
                      ).grid(row=0, column=2, padx=4)

        self.output_text = ctk.CTkTextbox(
            output_card,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#0a1828",
            text_color="#a8d8ea",
            border_color="#1a3a5c",
            border_width=1,
            corner_radius=8,
            state="disabled"
        )
        self.output_text.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 12))

    def _build_status_bar(self):
        """Build the bottom status bar."""
        status_bar = ctk.CTkFrame(self, fg_color="#0a1525", height=30, corner_radius=0)
        status_bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        status_bar.grid_propagate(False)
        status_bar.grid_columnconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(
            status_bar,
            text="✅  Ready — Select an algorithm and enter text to begin.",
            font=ctk.CTkFont(size=11),
            text_color=COLOR_TEXT_DIM
        )
        self.status_label.grid(row=0, column=0, sticky="w", padx=16)

        # Right side: algorithm indicator
        self.algo_indicator = ctk.CTkLabel(
            status_bar,
            text="Algorithm: AES-256",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=COLOR_ACCENT
        )
        self.algo_indicator.grid(row=0, column=1, sticky="e", padx=16)

    # ─────────────────────────────────────────────────────────────────────────
    # Algorithm switching
    # ─────────────────────────────────────────────────────────────────────────

    def _switch_algorithm(self, algo: str):
        """
        Switch the active algorithm and update button styles.

        Parameters:
            algo : "AES", "DES", or "RSA"
        """
        self.current_algorithm.set(algo)

        # Re-style all three algo buttons
        for name in ["AES", "DES", "RSA"]:
            btn = getattr(self, f"btn_{name.lower()}")
            if name == algo:
                btn.configure(fg_color=COLOR_ACCENT, text_color=COLOR_BG_DARK)
            else:
                btn.configure(fg_color=COLOR_BG_CARD, text_color=COLOR_TEXT_MAIN)

        # Show/hide RSA key management panel
        if algo == "RSA":
            self.rsa_frame.grid()
        else:
            self.rsa_frame.grid_remove()

        # Update status bar
        algo_names = {"AES": "AES-256", "DES": "DES (Learning)", "RSA": "RSA-2048"}
        self.algo_indicator.configure(text=f"Algorithm: {algo_names[algo]}")
        self._set_status(f"Switched to {algo_names[algo]}.", "info")

        # Warn about DES
        if algo == "DES":
            self._set_status(
                "⚠️  DES is included for learning only — it is not secure for real use.", "warning"
            )

    # ─────────────────────────────────────────────────────────────────────────
    # Core encrypt / decrypt actions
    # ─────────────────────────────────────────────────────────────────────────

    def _encrypt(self):
        """Read input + password, run the selected algorithm's encrypt(), show output."""
        plain_text = self.input_text.get("1.0", "end").strip()
        password   = self.password_entry.get().strip()
        algo       = self.current_algorithm.get()

        try:
            if algo == "AES":
                result = aes_cipher.encrypt(plain_text, password)
            elif algo == "DES":
                result = des_cipher.encrypt(plain_text, password)
            elif algo == "RSA":
                if not self.rsa_public_key:
                    raise ValueError(
                        "No RSA public key loaded.\n"
                        "Click 'Generate Keys' or 'Load Keys' in the sidebar."
                    )
                result = rsa_cipher.encrypt(plain_text, self.rsa_public_key)

            self._set_output(result)
            self._set_status(f"✅  {algo} encryption successful.", "success")

        except ValueError as e:
            self._set_status(f"❌  {e}", "error")
            messagebox.showerror("Encryption Error", str(e))
        except Exception as e:
            self._set_status(f"❌  Unexpected error: {e}", "error")
            messagebox.showerror("Error", f"Unexpected error:\n{e}")

    def _decrypt(self):
        """Read output box (ciphertext) + password, run decrypt(), show plain text."""
        # The user pastes ciphertext into the output box and clicks Decrypt,
        # OR we read from the input box if output is empty.
        encrypted_text = self._get_output_text().strip()
        if not encrypted_text:
            # Fallback: try reading from the input text box
            encrypted_text = self.input_text.get("1.0", "end").strip()

        password = self.password_entry.get().strip()
        algo     = self.current_algorithm.get()

        try:
            if algo == "AES":
                result = aes_cipher.decrypt(encrypted_text, password)
            elif algo == "DES":
                result = des_cipher.decrypt(encrypted_text, password)
            elif algo == "RSA":
                if not self.rsa_private_key:
                    raise ValueError(
                        "No RSA private key loaded.\n"
                        "Click 'Generate Keys' or 'Load Keys' in the sidebar."
                    )
                result = rsa_cipher.decrypt(encrypted_text, self.rsa_private_key)

            self._set_output(result)
            self._set_status(f"✅  {algo} decryption successful.", "success")

        except ValueError as e:
            self._set_status(f"❌  {e}", "error")
            messagebox.showerror("Decryption Error", str(e))
        except Exception as e:
            self._set_status(f"❌  Unexpected error: {e}", "error")
            messagebox.showerror("Error", f"Unexpected error:\n{e}")

    # ─────────────────────────────────────────────────────────────────────────
    # RSA key management
    # ─────────────────────────────────────────────────────────────────────────

    def _generate_rsa_keys(self):
        """Generate a fresh RSA-2048 key pair and store it in memory."""
        self._set_status("⏳  Generating RSA-2048 key pair — this takes a moment…", "info")
        self.update()  # Force UI to refresh before the slow operation

        try:
            self.rsa_private_key, self.rsa_public_key = rsa_cipher.generate_key_pair()
            self.rsa_key_status.configure(
                text="✅ Keys generated (in memory)", text_color=COLOR_SUCCESS
            )
            self._set_status("✅  RSA-2048 key pair generated successfully.", "success")
        except Exception as e:
            self._set_status(f"❌  Key generation failed: {e}", "error")
            messagebox.showerror("RSA Error", f"Key generation failed:\n{e}")

    def _save_rsa_keys(self):
        """Prompt the user for file locations and save both RSA keys."""
        if not self.rsa_private_key or not self.rsa_public_key:
            messagebox.showwarning("No Keys", "No RSA keys in memory.\nGenerate or load keys first.")
            return

        # Ask where to save the private key
        private_path = filedialog.asksaveasfilename(
            title="Save Private Key",
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            initialfile="rsa_private.pem"
        )
        if not private_path:
            return  # User cancelled

        # Ask where to save the public key
        public_path = filedialog.asksaveasfilename(
            title="Save Public Key",
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            initialfile="rsa_public.pem"
        )
        if not public_path:
            return  # User cancelled

        try:
            rsa_cipher.save_keys(
                self.rsa_private_key, self.rsa_public_key,
                private_path, public_path
            )
            self._set_status("✅  RSA keys saved successfully.", "success")
            messagebox.showinfo("Keys Saved",
                                f"Private key → {private_path}\nPublic key  → {public_path}")
        except (PermissionError, OSError) as e:
            self._set_status(f"❌  {e}", "error")
            messagebox.showerror("Save Error", str(e))

    def _load_rsa_keys(self):
        """Prompt the user to select RSA key files and load them into memory."""
        private_path = filedialog.askopenfilename(
            title="Select Private Key (.pem)",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if not private_path:
            return

        public_path = filedialog.askopenfilename(
            title="Select Public Key (.pem)",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if not public_path:
            return

        try:
            self.rsa_private_key, self.rsa_public_key = rsa_cipher.load_keys(
                private_path, public_path
            )
            self.rsa_key_status.configure(
                text="✅ Keys loaded", text_color=COLOR_SUCCESS
            )
            self._set_status("✅  RSA keys loaded successfully.", "success")
        except (FileNotFoundError, PermissionError, ValueError) as e:
            self._set_status(f"❌  {e}", "error")
            messagebox.showerror("Load Error", str(e))

    # ─────────────────────────────────────────────────────────────────────────
    # File operations
    # ─────────────────────────────────────────────────────────────────────────

    def _open_file(self):
        """Open a .txt or .enc file and load its contents into the input box."""
        file_path = filedialog.askopenfilename(
            title="Open File",
            filetypes=[
                ("Text & Encrypted files", "*.txt *.enc"),
                ("Text files", "*.txt"),
                ("Encrypted files", "*.enc"),
                ("All files", "*.*")
            ]
        )
        if not file_path:
            return

        try:
            content = file_handler.read_text_from_file(file_path)
            # Clear input and insert file contents
            self.input_text.delete("1.0", "end")
            self.input_text.insert("1.0", content)
            self._set_status(f"✅  Opened: {os.path.basename(file_path)}", "success")
        except (FileNotFoundError, PermissionError, OSError) as e:
            self._set_status(f"❌  {e}", "error")
            messagebox.showerror("Open Error", str(e))

    def _save_output(self):
        """Save the contents of the output box to a file."""
        content = self._get_output_text().strip()
        if not content:
            messagebox.showwarning("Nothing to Save", "The output box is empty.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Save Output",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("Encrypted files", "*.enc"),
                ("All files", "*.*")
            ]
        )
        if not file_path:
            return

        try:
            file_handler.save_text_to_file(content, file_path)
            self._set_status(f"✅  Saved to: {os.path.basename(file_path)}", "success")
        except (PermissionError, OSError, ValueError) as e:
            self._set_status(f"❌  {e}", "error")
            messagebox.showerror("Save Error", str(e))

    # ─────────────────────────────────────────────────────────────────────────
    # UI helper methods
    # ─────────────────────────────────────────────────────────────────────────

    def _copy_output(self):
        """Copy the output textbox contents to the system clipboard."""
        content = self._get_output_text().strip()
        if not content:
            messagebox.showwarning("Nothing to Copy", "The output box is empty.")
            return
        try:
            import pyperclip
            pyperclip.copy(content)
            self._set_status("📋  Copied to clipboard.", "success")
        except ImportError:
            # Fallback: use tkinter clipboard
            self.clipboard_clear()
            self.clipboard_append(content)
            self._set_status("📋  Copied to clipboard (tkinter fallback).", "success")
        except Exception as e:
            self._set_status(f"❌  Copy failed: {e}", "error")

    def _clear_all(self):
        """Clear both input and output text boxes."""
        self.input_text.delete("1.0", "end")
        self.password_entry.delete(0, "end")
        self._set_output("")
        self._set_status("🗑  All fields cleared.", "info")

    def _toggle_password_visibility(self):
        """Toggle showing/hiding the password characters."""
        self._pass_visible = not self._pass_visible
        self.password_entry.configure(show="" if self._pass_visible else "●")

    def _set_output(self, text: str):
        """Write text to the output textbox (which is normally read-only)."""
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        if text:
            self.output_text.insert("1.0", text)
        self.output_text.configure(state="disabled")

    def _get_output_text(self) -> str:
        """Read and return the current contents of the output textbox."""
        self.output_text.configure(state="normal")
        content = self.output_text.get("1.0", "end").strip()
        self.output_text.configure(state="disabled")
        return content

    def _set_status(self, message: str, level: str = "info"):
        """
        Update the status bar message with a color coded by severity.

        Parameters:
            message : The text to display.
            level   : "info", "success", "warning", or "error"
        """
        color_map = {
            "info":    COLOR_TEXT_DIM,
            "success": COLOR_SUCCESS,
            "warning": COLOR_WARNING,
            "error":   COLOR_ERROR,
        }
        color = color_map.get(level, COLOR_TEXT_DIM)
        self.status_label.configure(text=message, text_color=color)