# certiwipe_app.py

import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, scrolledtext, filedialog
import platform
import subprocess
import time
import os
import json
import requests

# Import functions from our other modules
import key_manager
import certificate_utils

class CertiWipeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CertiWipe Pro - Erasure & Verification Tool")
        self.root.geometry("800x650")

        style = ttk.Style(self.root)
        style.theme_use("clam")
        
        main_paned_window = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        notebook = ttk.Notebook(main_paned_window)
        main_paned_window.add(notebook)

        self.wipe_tab = ttk.Frame(notebook, padding=10)
        self.verify_tab = ttk.Frame(notebook, padding=10)
        notebook.add(self.wipe_tab, text=' Wipe Drive ')
        notebook.add(self.verify_tab, text=' Verify Certificate ')
        
        log_frame = ttk.LabelFrame(main_paned_window, text="Process Log", padding=10)
        main_paned_window.add(log_frame, weight=1)
        
        self.status_log = scrolledtext.ScrolledText(log_frame, height=10, state='disabled', font=("Courier", 10), bg="#2c3e50", fg="white", wrap=tk.WORD)
        self.status_log.pack(fill=tk.BOTH, expand=True)

        self._create_wipe_tab_widgets()
        self._create_verify_tab_widgets()
        
        self.log("Welcome to CertiWipe Pro.")
        if key_manager.ensure_keys():
            self.log("New cryptographic keys created and saved.", "WARN")
        else:
            self.log("Existing cryptographic keys found.")
        self.detect_drives()

    def _create_wipe_tab_widgets(self):
        drive_frame = ttk.LabelFrame(self.wipe_tab, text="1. Select Target Drive to Erase", padding=10)
        drive_frame.pack(fill=tk.X, expand=True)
        self.drive_listbox = tk.Listbox(drive_frame, height=5, font=("Courier", 11), selectbackground="#3498db")
        self.drive_listbox.pack(pady=5, fill=tk.X, expand=True)
        
        wipe_frame = ttk.LabelFrame(self.wipe_tab, text="2. Initiate Wipe", padding=10)
        wipe_frame.pack(fill=tk.X, expand=True, pady=10)
        self.wipe_button = ttk.Button(wipe_frame, text="PERMANENTLY ERASE SELECTED DRIVE", command=self.confirm_wipe, style='Danger.TButton')
        self.wipe_button.pack(pady=10)
        style = ttk.Style()
        style.configure('Danger.TButton', foreground='white', background='#c0392b', font=('Helvetica', 12, 'bold'), padding=(10, 5))
        style.map('Danger.TButton', background=[('active', '#e74c3c')])

    def _create_verify_tab_widgets(self):
        verify_frame = ttk.LabelFrame(self.verify_tab, text="Verify a Certificate File", padding=10)
        verify_frame.pack(fill=tk.BOTH, expand=True)
        self.selected_file_var = tk.StringVar(value="No file selected.")
        select_button = ttk.Button(verify_frame, text="Select Certificate (.json)...", command=self._select_verification_file)
        select_button.grid(row=0, column=0, padx=5, pady=10)
        file_label = ttk.Label(verify_frame, textvariable=self.selected_file_var, font=("Helvetica", 10, "italic"), wraplength=500)
        file_label.grid(row=0, column=1, padx=5, pady=10, sticky='w')
        verify_button = ttk.Button(verify_frame, text="VERIFY SIGNATURE", command=self._verify_certificate_file)
        verify_button.grid(row=1, column=0, columnspan=2, pady=10)

    def log(self, message, level="INFO"):
        self.status_log.config(state='normal')
        self.status_log.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] [{level}] {message}\n")
        self.status_log.config(state='disabled')
        self.status_log.see(tk.END)
        self.root.update_idletasks()

    def detect_drives(self):
        self.log("Detecting storage devices...")
        if platform.system() == "Linux":
            try:
                cmd = "lsblk -d -o NAME,SIZE,MODEL --bytes"
                result = subprocess.check_output(cmd.split()).decode("utf-8").strip()
                lines = result.split('\n')[1:]
                for line in lines: self.drive_listbox.insert(tk.END, " ".join(line.split()))
                self.log(f"Success: Found {len(lines)} drives.")
            except Exception as e:
                self.log(f"Could not detect drives: {e}. Using mock data.", "ERROR")
                self._use_mock_data()
        else:
            self.log("Not on Linux. Using mock data for demonstration.")
            self._use_mock_data()

    def _use_mock_data(self):
        for drive in ["sda 512110190592 Samsung SSD 970 EVO", "sdb 1000204886016 Seagate Barracuda"]:
            self.drive_listbox.insert(tk.END, drive)

    def confirm_wipe(self):
        try:
            selected_drive = self.drive_listbox.get(self.drive_listbox.curselection())
        except tk.TclError:
            messagebox.showerror("Error", "Please select a drive from the list.")
            return

        if not messagebox.askokcancel("Are you sure?", f"You are about to erase:\n\n{selected_drive}\n\nThis action is IRREVERSIBLE."):
            self.log("Wipe cancelled.", "WARN")
            return

        if simpledialog.askstring("Final Confirmation", 'To proceed, type "ERASE" below:') == "ERASE":
            self._perform_wipe(selected_drive)
        else:
            self.log("Wipe cancelled. Final confirmation failed.", "WARN")
            messagebox.showerror("Cancelled", "The confirmation text did not match.")

    def _perform_wipe(self, drive_info):
        self.log(f"Starting wipe on /dev/{drive_info.split(' ')[0]}...")
        self.wipe_button.config(state='disabled')
        for i in range(5): # Shorter simulation
            self.log(f"Sanitizing block {i+1} of 5...")
            time.sleep(0.2)
        self.log("Sanitization complete.")
        
        device_data = {"deviceString": drive_info, "wipeMethod": "NIST 800-88 Purge/Clear (Simulated)"}
        
        try:
            self.log("Loading private key for signing...")
            private_key = key_manager.load_private_key()
            self.log("Generating and signing certificate...")
            cert_data, json_file, pdf_file = certificate_utils.generate_certificate(device_data, private_key)
            self.log(f"SUCCESS! Certificate saved as {pdf_file}", "SUCCESS")
            
            # --- NEW: Register certificate with the server ---
            self._register_certificate_with_server(cert_data)
            
            messagebox.showinfo("Wipe Complete", f"Certificate saved as:\n{pdf_file}")
        except Exception as e:
            self.log(f"Certificate generation failed: {e}", "ERROR")
            messagebox.showerror("Certificate Error", f"Error: {e}")
        finally:
            self.wipe_button.config(state='normal')

    def _register_certificate_with_server(self, cert_data):
        """Sends the generated certificate data to the verification server."""
        self.log("Registering certificate with public verification server...")
        server_url = "http://127.0.0.1:5000/api/register_wipe"
        try:
            response = requests.post(server_url, json=cert_data, timeout=5)
            if response.status_code == 201:
                verification_url = f"http://127.0.0.1:5000/verify/{cert_data['certificateId']}"
                self.log(f"Certificate registered successfully. View at: {verification_url}", "SUCCESS")
            else:
                self.log(f"Server error: {response.status_code} - {response.text}", "ERROR")
        except requests.exceptions.RequestException as e:
            self.log(f"Could not connect to verification server: {e}", "ERROR")

    def _select_verification_file(self):
        filepath = filedialog.askopenfilename(title="Select Certificate File", filetypes=(("JSON files", "*.json"),))
        if filepath:
            self.selected_file_var.set(filepath)
            self.log(f"Selected for verification: {os.path.basename(filepath)}")

    def _verify_certificate_file(self):
        json_path = self.selected_file_var.get()
        if not os.path.exists(json_path):
            messagebox.showerror("Error", "Please select a valid certificate file first.")
            return

        self.log(f"--- Verifying {os.path.basename(json_path)} ---")
        try:
            public_key = key_manager.load_public_key()
            is_valid, message = certificate_utils.verify_certificate(json_path, public_key)
            
            if is_valid:
                self.log(message, "SUCCESS")
                messagebox.showinfo("Result: VALID", message)
            else:
                self.log(message, "ERROR")
                messagebox.showerror("Result: INVALID", message)
        except Exception as e:
            self.log(f"Verification failed with an unexpected error: {e}", "ERROR")
            messagebox.showerror("Verification Error", f"An error occurred: {e}")
        self.log("--- Verification complete ---")


if __name__ == "__main__":
    root = tk.Tk()
    app = CertiWipeApp(root)
    root.mainloop()
