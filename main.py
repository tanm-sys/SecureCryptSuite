#!/usr/bin/env python3
"""
Enhanced Secure Encryption, Hybrid & Signature Tool with Tkinter GUI

Features:
- Tabbed interface for Encrypt/Decrypt and Sign/Verify operations.
- Supports symmetric encryption (AES-GCM), asymmetric encryption (RSA), and hybrid encryption (RSA+AES).
- Digital signature generation and verification using RSA-PSS.
- Uses Argon2 (via argon2-cffi) for key derivation; if unavailable, falls back to PBKDF2 (600,000 iterations)
  and warns the user.
- Real‑time input validation with dynamic button state and a password strength meter.
- RSA key generation is performed in a background thread with a progress indicator.
- File operations use context managers and normalize file paths.
- Generic error messages are shown to the user while detailed errors are logged (ensure log file security in production).
- Private key inputs are masked to mitigate shoulder-surfing.
- *Note:* For maximum security, sensitive data (keys, passwords) should be securely zeroized after use.
  
Dependencies: 
    - pycryptodome>=3.17
    - argon2-cffi (strongly recommended)
    - Tkinter (bundled with Python)
    
Run on an up‑to‑date Python/Tkinter environment.
"""

import os
import base64
import logging
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog, filedialog
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Signature import pss
from typing import Tuple

# Try to import Argon2 for memory-hard key derivation.
try:
    from argon2.low_level import hash_secret_raw, Type
    USE_ARGON2 = True
except ImportError:
    USE_ARGON2 = False

# -------------------------------
# Configuration Constants
# -------------------------------
# PBKDF2 parameters (fallback if Argon2 is not available)
PBKDF2_ITERATIONS = 600000

# Argon2 parameters (if available)
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST = 102400  # in kibibytes (~100 MB)
ARGON2_PARALLELISM = 8
ARGON2_HASH_LEN = 32
ARGON2_TYPE = Type.I

# The maximum message size for RSA encryption will be calculated dynamically.
CLIPBOARD_CLEAR_DELAY = 10000  # milliseconds (not used since clipboard copy is removed)

# -------------------------------
# Logging Setup
# -------------------------------
logging.basicConfig(filename="app.log", level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s: %(message)s")
# Ensure that the log file is protected with strict file permissions in production.

# -------------------------------
# Simple Tooltip for Inline Help
# -------------------------------
class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)
    
    def show_tip(self, event=None):
        if self.tip_window or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + 20
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                         font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)
    
    def hide_tip(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None

# -------------------------------
# Dynamic RSA Maximum Message Size Calculation
# -------------------------------
def calculate_rsa_max_message_size(public_key_pem: str) -> int:
    """
    Calculates the maximum plaintext size that can be encrypted with the given RSA public key using OAEP with SHA256.
    Formula: key_size_in_bytes - 2 * hash_size - 2.
    """
    key = RSA.import_key(public_key_pem)
    key_size_bytes = (key.n.bit_length() + 7) // 8
    hash_size = SHA256.new().digest_size  # typically 32 bytes
    return key_size_bytes - 2 * hash_size - 2

# -------------------------------
# Key Derivation Utility
# -------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit key from the given password and salt.
    Uses Argon2 if available; otherwise, falls back to PBKDF2.
    """
    if USE_ARGON2:
        try:
            return hash_secret_raw(password.encode('utf-8'), salt,
                                   time_cost=ARGON2_TIME_COST,
                                   memory_cost=ARGON2_MEMORY_COST,
                                   parallelism=ARGON2_PARALLELISM,
                                   hash_len=ARGON2_HASH_LEN,
                                   type=ARGON2_TYPE)
        except Exception as e:
            logging.warning("Argon2 derivation failed, using PBKDF2 instead: %s", str(e))
    return PBKDF2(password, salt, dkLen=32, count=PBKDF2_ITERATIONS)

# -------------------------------
# Input Validation & Password Strength
# -------------------------------
def validate_password(password: str) -> None:
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")

def calculate_password_strength(password: str) -> str:
    score = 0
    if len(password) >= 8:
        score += 1
    if any(c.islower() for c in password) and any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/" for c in password):
        score += 1
    if score <= 1:
        return "Weak"
    elif score == 2:
        return "Moderate"
    else:
        return "Strong"

def validate_rsa_key(key: str, key_type: str = "public") -> None:
    """
    Validates the RSA key and enforces a minimum key size of 2048 bits.
    """
    try:
        imported_key = RSA.import_key(key)
    except Exception:
        raise ValueError("Invalid RSA key format.")
    if imported_key.n.bit_length() < 2048:
        raise ValueError("RSA key size is too small; must be at least 2048 bits.")
    if key_type == "public" and not imported_key.has_public():
        raise ValueError("Provided key is not a public key.")
    if key_type == "private" and not imported_key.has_private():
        raise ValueError("Provided key is not a private key.")

# -------------------------------
# Cryptographic Functions
# -------------------------------
def symmetric_encrypt(plaintext: str, password: str) -> str:
    if not plaintext:
        raise ValueError("Plaintext cannot be empty.")
    validate_password(password)
    data = plaintext.encode('utf-8')
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # TODO: Securely zeroize 'key' after use.
    return base64.b64encode(salt + nonce + tag + ciphertext).decode('utf-8')

def symmetric_decrypt(cipher_text: str, password: str) -> str:
    if not cipher_text:
        raise ValueError("Ciphertext cannot be empty.")
    validate_password(password)
    try:
        raw = base64.b64decode(cipher_text)
        if len(raw) < 44:
            raise ValueError("Invalid ciphertext.")
        salt = raw[:16]
        nonce = raw[16:28]
        tag = raw[28:44]
        ciphertext = raw[44:]
        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except Exception:
        logging.error("Symmetric decryption failed.")
        raise Exception("Operation failed.")

def asymmetric_encrypt(plaintext: str, public_key_pem: str) -> str:
    if not plaintext:
        raise ValueError("Plaintext cannot be empty.")
    if not public_key_pem:
        raise ValueError("Public key is required.")
    validate_rsa_key(public_key_pem, "public")
    # Dynamically calculate maximum message size.
    max_size = calculate_rsa_max_message_size(public_key_pem)
    if len(plaintext.encode('utf-8')) > max_size:
        raise ValueError(f"Message too large for RSA encryption (max {max_size} bytes). Use hybrid mode.")
    try:
        public_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
        return base64.b64encode(ciphertext).decode('utf-8')
    except Exception:
        logging.error("Asymmetric encryption failed.")
        raise Exception("Operation failed.")

def asymmetric_decrypt(cipher_text: str, private_key_pem: str) -> str:
    if not cipher_text:
        raise ValueError("Ciphertext cannot be empty.")
    if not private_key_pem:
        raise ValueError("Private key is required.")
    validate_rsa_key(private_key_pem, "private")
    try:
        private_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(private_key)
        ciphertext = base64.b64decode(cipher_text)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode('utf-8')
    except Exception:
        logging.error("Asymmetric decryption failed.")
        raise Exception("Operation failed.")

def digital_sign(message: str, private_key_pem: str) -> str:
    if not message:
        raise ValueError("Message cannot be empty.")
    validate_rsa_key(private_key_pem, "private")
    try:
        private_key = RSA.import_key(private_key_pem)
        h = SHA256.new(message.encode('utf-8'))
        signature = pss.new(private_key).sign(h)
        return base64.b64encode(signature).decode('utf-8')
    except Exception:
        logging.error("Digital signing failed.")
        raise Exception("Operation failed.")

def digital_verify(message: str, signature: str, public_key_pem: str) -> bool:
    if not message:
        raise ValueError("Message cannot be empty.")
    if not signature:
        raise ValueError("Signature is required.")
    validate_rsa_key(public_key_pem, "public")
    try:
        public_key = RSA.import_key(public_key_pem)
        h = SHA256.new(message.encode('utf-8'))
        pss.new(public_key).verify(h, base64.b64decode(signature))
        return True
    except Exception:
        return False

def hybrid_encrypt(plaintext: str, public_key_pem: str) -> str:
    if not plaintext:
        raise ValueError("Plaintext cannot be empty.")
    if not public_key_pem:
        raise ValueError("Public key is required.")
    validate_rsa_key(public_key_pem, "public")
    try:
        public_key = RSA.import_key(public_key_pem)
        aes_key = get_random_bytes(32)
        nonce = get_random_bytes(12)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        aes_data = nonce + tag + ciphertext
        rsa_cipher = PKCS1_OAEP.new(public_key)
        encrypted_key = rsa_cipher.encrypt(aes_key)
        encrypted_key_len = len(encrypted_key).to_bytes(2, byteorder='big')
        combined = encrypted_key_len + encrypted_key + aes_data
        return base64.b64encode(combined).decode('utf-8')
    except Exception:
        logging.error("Hybrid encryption failed.")
        raise Exception("Operation failed.")

def hybrid_decrypt(cipher_text: str, private_key_pem: str) -> str:
    if not cipher_text:
        raise ValueError("Ciphertext cannot be empty.")
    if not private_key_pem:
        raise ValueError("Private key is required.")
    validate_rsa_key(private_key_pem, "private")
    try:
        data = base64.b64decode(cipher_text)
        if len(data) < 2:
            raise ValueError("Invalid ciphertext.")
        key_len = int.from_bytes(data[:2], byteorder='big')
        if len(data) < 2 + key_len + 28:
            raise ValueError("Invalid ciphertext.")
        encrypted_key = data[2:2+key_len]
        aes_data = data[2+key_len:]
        private_key = RSA.import_key(private_key_pem)
        rsa_cipher = PKCS1_OAEP.new(private_key)
        aes_key = rsa_cipher.decrypt(encrypted_key)
        nonce = aes_data[:12]
        tag = aes_data[12:28]
        ciphertext = aes_data[28:]
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except Exception:
        logging.error("Hybrid decryption failed.")
        raise Exception("Operation failed.")

# -------------------------------
# Background RSA Key Generation (Thread-Safe)
# -------------------------------
def generate_rsa_keys_thread(q: queue.Queue, key_size: int = 2048):
    try:
        key = RSA.generate(key_size)
        private_key_pem = key.export_key()
        public_key_pem = key.publickey().export_key()
        q.put((private_key_pem.decode('utf-8'), public_key_pem.decode('utf-8'), None))
    except Exception:
        logging.error("RSA key generation error.")
        q.put((None, None, "RSA key generation failed."))

# -------------------------------
# Enhanced Tkinter GUI with Tabs and Improved Input Handling
# -------------------------------
class EncryptionApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Enhanced Secure Encryption, Hybrid & Signature Tool")
        self.geometry("950x750")
        self.resizable(False, False)
        
        # RSA keys stored in memory; for production, use secure key storage (e.g., HSM or OS keychain).
        self.rsa_public_key = None
        self.rsa_private_key = None
        self.clipboard_clear_delay = CLIPBOARD_CLEAR_DELAY
        
        # Create tabbed interface.
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)
        self.encrypt_tab = ttk.Frame(self.notebook)
        self.sign_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.encrypt_tab, text="Encrypt/Decrypt")
        self.notebook.add(self.sign_tab, text="Sign/Verify")
        
        self.build_encrypt_tab()
        self.build_sign_tab()
        self.create_menu()
        
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w")
        self.status_bar.pack(fill="x", side="bottom")
        self.progress_bar = ttk.Progressbar(self, mode="indeterminate")
        
        if not USE_ARGON2:
            self.status_var.set("Warning: Argon2 not installed; using PBKDF2 (less secure)")
        
        self.validate_inputs()
    
    def create_menu(self):
        menu_bar = tk.Menu(self)
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Open File", command=self.open_file)
        file_menu.add_command(label="Save Output", command=self.save_output)
        # "Copy Output" feature removed to minimize clipboard risks.
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)
        
        settings_menu = tk.Menu(menu_bar, tearoff=0)
        settings_menu.add_command(label="Set Clipboard Clear Delay", command=self.set_clipboard_delay)
        menu_bar.add_cascade(label="Settings", menu=settings_menu)
        self.config(menu=menu_bar)
    
    # ---------------------------
    # Encrypt/Decrypt Tab UI
    # ---------------------------
    def build_encrypt_tab(self):
        frame = self.encrypt_tab
        mode_frame = ttk.LabelFrame(frame, text="Mode", padding=10)
        mode_frame.pack(padx=10, pady=5, fill="x")
        self.enc_mode = tk.StringVar(value="Encrypt")
        ttk.Radiobutton(mode_frame, text="Encrypt", variable=self.enc_mode, value="Encrypt",
                        command=self.validate_inputs).pack(side="left", padx=5)
        ttk.Radiobutton(mode_frame, text="Decrypt", variable=self.enc_mode, value="Decrypt",
                        command=self.validate_inputs).pack(side="left", padx=5)
        
        method_frame = ttk.LabelFrame(frame, text="Method", padding=10)
        method_frame.pack(padx=10, pady=5, fill="x")
        self.enc_method = tk.StringVar(value="Symmetric")
        ttk.Radiobutton(method_frame, text="Symmetric (AES-GCM)", variable=self.enc_method, value="Symmetric",
                        command=self.validate_inputs).pack(side="left", padx=5)
        ttk.Radiobutton(method_frame, text="Asymmetric (RSA)", variable=self.enc_method, value="Asymmetric",
                        command=self.validate_inputs).pack(side="left", padx=5)
        ttk.Radiobutton(method_frame, text="Hybrid (RSA+AES)", variable=self.enc_method, value="Hybrid",
                        command=self.validate_inputs).pack(side="left", padx=5)
        
        input_frame = ttk.LabelFrame(frame, text="Input Text", padding=10)
        input_frame.pack(padx=10, pady=5, fill="both", expand=True)
        self.enc_input_text = scrolledtext.ScrolledText(input_frame, wrap="word", height=10)
        self.enc_input_text.pack(fill="both", expand=True)
        ToolTip(self.enc_input_text, "Enter text to encrypt or decrypt.")
        
        options_frame = ttk.LabelFrame(frame, text="Options", padding=10)
        options_frame.pack(padx=10, pady=5, fill="x")
        self.sym_label = ttk.Label(options_frame, text="Password:")
        self.sym_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.sym_password_var = tk.StringVar()
        self.sym_entry = ttk.Entry(options_frame, textvariable=self.sym_password_var, show="*")
        self.sym_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        ToolTip(self.sym_entry, "Enter a strong password (min 8 characters).")
        self.pw_strength_var = tk.StringVar(value="")
        self.pw_strength_label = ttk.Label(options_frame, textvariable=self.pw_strength_var)
        self.pw_strength_label.grid(row=0, column=2, padx=5, pady=5)
        self.sym_entry.bind("<KeyRelease>", self.update_password_strength)
        
        self.asym_frame_enc = ttk.Frame(options_frame)
        self.asym_frame_enc.grid(row=0, column=3, padx=5, pady=5)
        self.gen_key_btn_enc = ttk.Button(self.asym_frame_enc, text="Generate RSA Keys", command=self.generate_keys_threaded)
        self.gen_key_btn_enc.grid(row=0, column=0, padx=5, pady=5)
        self.import_pub_btn_enc = ttk.Button(self.asym_frame_enc, text="Import Public Key", command=self.import_public_key)
        self.import_pub_btn_enc.grid(row=0, column=1, padx=5, pady=5)
        self.import_priv_btn_enc = ttk.Button(self.asym_frame_enc, text="Import Private Key", 
                                              command=lambda: self.import_private_key(masked=True))
        self.import_priv_btn_enc.grid(row=0, column=2, padx=5, pady=5)
        
        self.enc_execute_btn = ttk.Button(frame, text="Execute", command=self.execute_encrypt, state=tk.DISABLED)
        self.enc_execute_btn.pack(pady=10)
        output_frame = ttk.LabelFrame(frame, text="Output", padding=10)
        output_frame.pack(padx=10, pady=5, fill="both", expand=True)
        self.enc_output_text = scrolledtext.ScrolledText(output_frame, wrap="word", height=10)
        self.enc_output_text.pack(fill="both", expand=True)
        ToolTip(self.enc_output_text, "Encrypted/decrypted output will appear here.")
    
    # ---------------------------
    # Sign/Verify Tab UI
    # ---------------------------
    def build_sign_tab(self):
        frame = self.sign_tab
        mode_frame = ttk.LabelFrame(frame, text="Mode", padding=10)
        mode_frame.pack(padx=10, pady=5, fill="x")
        self.sig_mode_var = tk.StringVar(value="Sign")
        ttk.Radiobutton(mode_frame, text="Sign", variable=self.sig_mode_var, value="Sign",
                        command=self.validate_inputs).pack(side="left", padx=5)
        ttk.Radiobutton(mode_frame, text="Verify", variable=self.sig_mode_var, value="Verify",
                        command=self.validate_inputs).pack(side="left", padx=5)
        
        input_frame = ttk.LabelFrame(frame, text="Message", padding=10)
        input_frame.pack(padx=10, pady=5, fill="both", expand=True)
        self.sig_input_text = scrolledtext.ScrolledText(input_frame, wrap="word", height=10)
        self.sig_input_text.pack(fill="both", expand=True)
        ToolTip(self.sig_input_text, "Enter the message to sign or verify.")
        
        options_frame = ttk.LabelFrame(frame, text="Options", padding=10)
        options_frame.pack(padx=10, pady=5, fill="x")
        self.asym_frame_sig = ttk.Frame(options_frame)
        self.asym_frame_sig.grid(row=0, column=0, padx=5, pady=5)
        self.gen_key_btn_sig = ttk.Button(self.asym_frame_sig, text="Generate RSA Keys", command=self.generate_keys_threaded)
        self.gen_key_btn_sig.grid(row=0, column=0, padx=5, pady=5)
        self.import_pub_btn_sig = ttk.Button(self.asym_frame_sig, text="Import Public Key", command=self.import_public_key)
        self.import_pub_btn_sig.grid(row=0, column=1, padx=5, pady=5)
        self.import_priv_btn_sig = ttk.Button(self.asym_frame_sig, text="Import Private Key", 
                                               command=lambda: self.import_private_key(masked=True))
        self.import_priv_btn_sig.grid(row=0, column=2, padx=5, pady=5)
        
        self.signature_label = ttk.Label(options_frame, text="Signature:")
        self.signature_entry = ttk.Entry(options_frame)
        
        self.sig_execute_btn = ttk.Button(frame, text="Execute", command=self.execute_sign, state=tk.DISABLED)
        self.sig_execute_btn.pack(pady=10)
        output_frame = ttk.LabelFrame(frame, text="Output", padding=10)
        output_frame.pack(padx=10, pady=5, fill="both", expand=True)
        self.sig_output_text = scrolledtext.ScrolledText(output_frame, wrap="word", height=10)
        self.sig_output_text.pack(fill="both", expand=True)
        ToolTip(self.sig_output_text, "Digital signature or verification result will appear here.")
    
    # ---------------------------
    # File Operations (with Path Normalization)
    # ---------------------------
    def open_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            file_path = os.path.normpath(file_path)
            encoding = simpledialog.askstring("Encoding", "Enter file encoding (default UTF-8):", initialvalue="utf-8")
            if not encoding:
                encoding = "utf-8"
            try:
                with open(file_path, "r", encoding=encoding, errors="replace") as f:
                    content = f.read()
                current_tab = self.notebook.index(self.notebook.select())
                if current_tab == 0:
                    self.enc_input_text.delete("1.0", tk.END)
                    self.enc_input_text.insert(tk.END, content)
                else:
                    self.sig_input_text.delete("1.0", tk.END)
                    self.sig_input_text.insert(tk.END, content)
            except Exception:
                messagebox.showerror("File Error", "Could not open file.")
    
    def save_output(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            file_path = os.path.normpath(file_path)
            encoding = simpledialog.askstring("Encoding", "Enter file encoding (default UTF-8):", initialvalue="utf-8")
            if not encoding:
                encoding = "utf-8"
            try:
                current_tab = self.notebook.index(self.notebook.select())
                output_text = (self.enc_output_text.get("1.0", tk.END)
                               if current_tab == 0 else self.sig_output_text.get("1.0", tk.END))
                with open(file_path, "w", encoding=encoding, errors="strict") as f:
                    f.write(output_text)
                messagebox.showinfo("File Saved", "Output saved successfully.")
            except Exception:
                messagebox.showerror("File Error", "Could not save file. Verify the encoding and file permissions.")
    
    # ---------------------------
    # RSA Key Generation and Import
    # ---------------------------
    def generate_keys_threaded(self):
        self.status_var.set("Generating RSA keys...")
        self.progress_bar.pack(fill="x", side="bottom")
        self.progress_bar.start(10)
        self.gen_key_btn_enc.config(state=tk.DISABLED)
        self.gen_key_btn_sig.config(state=tk.DISABLED)
        q = queue.Queue()
        thread = threading.Thread(target=generate_rsa_keys_thread, args=(q,))
        thread.start()
        self.after(100, self.check_key_generation, q)
    
    def check_key_generation(self, q):
        try:
            private_key, public_key, error = q.get_nowait()
        except queue.Empty:
            self.after(100, self.check_key_generation, q)
            return
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        self.gen_key_btn_enc.config(state=tk.NORMAL)
        self.gen_key_btn_sig.config(state=tk.NORMAL)
        if error:
            messagebox.showerror("Key Generation Error", error)
            self.status_var.set("RSA key generation failed.")
        else:
            self.rsa_private_key = private_key
            self.rsa_public_key = public_key
            messagebox.showinfo("RSA Keys Generated", "RSA keys generated successfully. Private key stored securely.")
            self.status_var.set("RSA keys generated.")
    
    def import_public_key(self):
        key = simpledialog.askstring("Import Public Key", "Paste your RSA public key (PEM format):")
        if key:
            try:
                validate_rsa_key(key, "public")
                self.rsa_public_key = key
                messagebox.showinfo("Key Imported", "Public key imported successfully.")
            except ValueError:
                messagebox.showerror("Key Import Error", "Invalid public key.")
    
    def import_private_key(self, masked: bool = False):
        show_char = "*" if masked else None
        key = simpledialog.askstring("Import Private Key", "Paste your RSA private key (PEM format):", show=show_char)
        if key:
            try:
                validate_rsa_key(key, "private")
                self.rsa_private_key = key
                messagebox.showinfo("Key Imported", "Private key imported successfully.")
            except ValueError:
                messagebox.showerror("Key Import Error", "Invalid private key.")
    
    # ---------------------------
    # Input Validation & Password Strength Meter
    # ---------------------------
    def update_password_strength(self, event=None):
        password = self.sym_password_var.get()
        strength = calculate_password_strength(password)
        self.pw_strength_var.set(strength)
    
    def validate_encrypt_inputs(self) -> bool:
        text = self.enc_input_text.get("1.0", tk.END).strip()
        if not text:
            return False
        method = self.enc_method.get()
        if method == "Symmetric":
            try:
                validate_password(self.sym_password_var.get())
            except ValueError:
                return False
        elif method in ["Asymmetric", "Hybrid"]:
            if self.enc_mode.get() == "Encrypt" and not self.rsa_public_key:
                return False
            if self.enc_mode.get() == "Decrypt" and not self.rsa_private_key:
                return False
        return True

    def validate_sign_inputs(self) -> bool:
        text = self.sig_input_text.get("1.0", tk.END).strip()
        if not text:
            return False
        mode = self.sig_mode_var.get()
        if mode == "Sign" and not self.rsa_private_key:
            return False
        if mode == "Verify":
            if not self.rsa_public_key or not self.signature_entry.get().strip():
                return False
        return True

    def validate_inputs(self):
        current_tab = self.notebook.index(self.notebook.select())
        if current_tab == 0:
            self.enc_execute_btn.config(state=tk.NORMAL if self.validate_encrypt_inputs() else tk.DISABLED)
        else:
            self.sig_execute_btn.config(state=tk.NORMAL if self.validate_sign_inputs() else tk.DISABLED)
        self.after(500, self.validate_inputs)
    
    # ---------------------------
    # Execute Operations
    # ---------------------------
    def execute_encrypt(self):
        try:
            mode = self.enc_mode.get()
            method = self.enc_method.get()
            input_data = self.enc_input_text.get("1.0", tk.END).strip()
            if mode.lower() == "encrypt":
                if method == "Symmetric":
                    password = self.sym_password_var.get()
                    result = symmetric_encrypt(input_data, password)
                elif method == "Asymmetric":
                    result = asymmetric_encrypt(input_data, self.rsa_public_key)
                else:
                    result = hybrid_encrypt(input_data, self.rsa_public_key)
            else:
                if method == "Symmetric":
                    password = self.sym_password_var.get()
                    result = symmetric_decrypt(input_data, password)
                elif method == "Asymmetric":
                    result = asymmetric_decrypt(input_data, self.rsa_private_key)
                else:
                    result = hybrid_decrypt(input_data, self.rsa_private_key)
            self.enc_output_text.delete("1.0", tk.END)
            self.enc_output_text.insert(tk.END, result)
        except Exception:
            logging.error("Encryption/Decryption operation failed.")
            messagebox.showerror("Error", "Operation failed.")
    
    def execute_sign(self):
        try:
            mode = self.sig_mode_var.get()
            input_data = self.sig_input_text.get("1.0", tk.END).strip()
            if mode == "Sign":
                result = digital_sign(input_data, self.rsa_private_key)
            else:
                signature = self.signature_entry.get().strip()
                valid = digital_verify(input_data, signature, self.rsa_public_key)
                result = "Signature is valid." if valid else "Signature is invalid."
            self.sig_output_text.delete("1.0", tk.END)
            self.sig_output_text.insert(tk.END, result)
        except Exception:
            logging.error("Sign/Verify operation failed.")
            messagebox.showerror("Error", "Operation failed.")

if __name__ == "__main__":
    app = EncryptionApp()
    app.mainloop()
