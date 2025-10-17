# certiwipe_app.py

import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, scrolledtext, filedialog
import platform
import subprocess
import time
import os
import json
import requests
import re
import sys
import ctypes

# Import functions from our other modules
import key_manager
import certificate_utils

def ensure_admin_privileges():
    """
    Checks for admin privileges and re-launches the script as admin if necessary.
    """
    system = platform.system()
    try:
        if system == "Windows":
            if not ctypes.windll.shell32.IsUserAnAdmin():
                # Re-run the script with the 'runas' verb to trigger the UAC prompt
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                sys.exit(0) # Exit the non-elevated instance
        elif system in ["Linux", "Darwin"]:
            if os.geteuid() != 0:
                # Re-run the script with sudo
                args = ['sudo', sys.executable] + sys.argv
                os.execvp('sudo', args)
                sys.exit(0) # Exit the non-elevated instance
    except Exception as e:
        # If elevation fails, show an error in a simple message box
        root = tk.Tk()
        root.withdraw() # Hide the main window
        messagebox.showerror("Privilege Error", f"Failed to get administrator privileges: {e}\nPlease run as administrator or with sudo manually.")
        sys.exit(1)

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
        self.log("Running with administrator privileges.", "SUCCESS")
        if key_manager.ensure_keys():
            self.log("New cryptographic keys created and saved.", "WARN")
        else:
            self.log("Existing cryptographic keys found.")
        self.detect_drives()

    def _create_wipe_tab_widgets(self):
        drive_frame = ttk.LabelFrame(self.wipe_tab, text="1. Select Target Drive to Erase", padding=10)
        drive_frame.pack(fill=tk.X, expand=True)

        list_frame = ttk.Frame(drive_frame)
        list_frame.pack(fill=tk.X, expand=True, pady=5)
        
        self.drive_listbox = tk.Listbox(list_frame, height=5, font=("Courier", 11), selectbackground="#3498db")
        self.drive_listbox.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        refresh_button = ttk.Button(list_frame, text="Refresh", command=self.detect_drives)
        refresh_button.pack(side=tk.RIGHT, padx=5, anchor='n')
        
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
    
    def _get_system_drive_identifier(self):
        """Identifies the physical drive hosting the OS."""
        system = platform.system()
        try:
            if system == "Windows":
                system_drive = os.environ.get("SystemDrive", "C:")
                query = f"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{system_drive}'}} WHERE AssocClass = Win32_LogicalDiskToPartition"
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                result = subprocess.check_output(["wmic", "path", "Win32_DiskDrive", "get", "DeviceID", "/format:list"], startupinfo=startupinfo).decode()
                for line in result.strip().split('\n\n'):
                    if not line: continue
                    device_id = line.split('=')[1].strip()
                    # Check if this physical drive hosts the system partition
                    partition_query = f"wmic path Win32_DiskPartition where (DeviceID like '%{device_id.replace(os.sep, os.sep*2)}%') get Name /format:list"
                    partition_result = subprocess.check_output(partition_query, startupinfo=startupinfo).decode()
                    if system_drive in partition_result:
                         return device_id
            elif system == "Linux":
                source = subprocess.check_output(['findmnt', '-n', '-o', 'SOURCE', '/']).decode().strip()
                return subprocess.check_output(['lsblk', '-no', 'pkname', source]).decode().strip()
            elif system == "Darwin":
                source = subprocess.check_output(['df', '/']).decode().strip().split('\n')[-1].split()[0]
                output = subprocess.check_output(['diskutil', 'info', source]).decode()
                match = re.search(r'Part of Whole:\s+(\S+)', output)
                if match:
                    return match.group(1)
        except Exception as e:
            self.log(f"Could not determine system drive: {e}", "WARN")
        return None

    def detect_drives(self):
        self.log("Detecting storage devices...")
        self.drive_listbox.delete(0, tk.END)
        system_drive_id = self._get_system_drive_identifier()
        if system_drive_id:
            self.log(f"System drive identified: {system_drive_id}. It will be protected.", "INFO")
        else:
            self.log("Could not reliably identify system drive. Proceed with extra caution.", "WARN")

        system = platform.system()
        found_drives = []

        if system == "Linux":
            try:
                cmd = "lsblk -d -o NAME,SIZE,MODEL --bytes"
                result = subprocess.check_output(cmd.split()).decode("utf-8").strip()
                lines = result.split('\n')[1:]
                for line in lines:
                    if line.strip():
                        name = line.split()[0]
                        drive_string = " ".join(line.split())
                        if name == system_drive_id:
                            self.drive_listbox.insert(tk.END, f"[SYSTEM DRIVE] {drive_string}")
                        else:
                            self.drive_listbox.insert(tk.END, drive_string)
                        found_drives.append(drive_string)
            except Exception as e:
                self.log(f"Could not detect drives: {e}", "ERROR")

        elif system == "Windows":
            try:
                cmd = "wmic diskdrive get Model,Name,Size,Index /FORMAT:CSV"
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                result = subprocess.check_output(cmd.split(), startupinfo=startupinfo).decode("utf-8").strip()
                lines = result.split('\n')[1:]
                for line in lines:
                    line = line.strip()
                    if not line: continue
                    parts = line.split(',')
                    if len(parts) >= 5:
                        index, model, name, size = parts[1].strip(), parts[2].strip(), parts[3].strip(), parts[4].strip()
                        drive_string = f"{name} (Index:{index}) {size} {model}"
                        if name == system_drive_id:
                            self.drive_listbox.insert(tk.END, f"[SYSTEM DRIVE] {drive_string}")
                        else:
                            self.drive_listbox.insert(tk.END, drive_string)
                        found_drives.append(drive_string)
            except Exception as e:
                self.log(f"Could not detect drives: {e}", "ERROR")

        elif system == "Darwin":
            try:
                cmd_list = "diskutil list physical"
                result_list = subprocess.check_output(cmd_list.split()).decode("utf-8")
                drive_identifiers = [line.split(' ')[0] for line in result_list.split('\n') if line.startswith('/dev/disk')]
                for identifier in drive_identifiers:
                    cmd_info = f"diskutil info {identifier}"
                    result_info = subprocess.check_output(cmd_info.split()).decode("utf-8")
                    model, size = "Unknown Model", "0"
                    for info_line in result_info.split('\n'):
                        info_line = info_line.strip()
                        if "Device / Media Name:" in info_line: model = info_line.split(":")[-1].strip()
                        if "Total Size:" in info_line: size = info_line.split('(')[-1].split(' ')[0]
                    drive_string = f"{identifier} {size} {model}"
                    if identifier.endswith(system_drive_id):
                        self.drive_listbox.insert(tk.END, f"[SYSTEM DRIVE] {drive_string}")
                    else:
                        self.drive_listbox.insert(tk.END, drive_string)
                    found_drives.append(drive_string)
            except Exception as e:
                self.log(f"Could not detect drives: {e}", "ERROR")
        
        if not found_drives:
            self.log("No drives detected. Using mock data for demonstration.", "WARN")
            self._use_mock_data()

    def _use_mock_data(self):
        self.drive_listbox.insert(tk.END, "[SYSTEM DRIVE] sda 512110190592 Samsung SSD 970 EVO")
        self.drive_listbox.insert(tk.END, "sdb 1000204886016 Seagate Barracuda")

    def confirm_wipe(self):
        try:
            selected_drive = self.drive_listbox.get(self.drive_listbox.curselection())
        except tk.TclError:
            messagebox.showerror("Error", "Please select a drive from the list.")
            return

        if selected_drive.startswith("[SYSTEM DRIVE]"):
            messagebox.showerror("Action Prohibited", "You cannot wipe the system drive. This action is blocked to prevent data loss.")
            self.log("Wipe cancelled: User selected the protected system drive.", "WARN")
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
        self.log(f"Starting wipe for {drive_info}...", "WARN")
        self.wipe_button.config(state='disabled')
        system = platform.system()
        
        try:
            command = None
            if system == "Linux":
                drive_identifier = drive_info.split(' ')[0]
                command = f"dd if=/dev/zero of={drive_identifier} bs=4M status=progress".split()
            elif system == "Darwin":
                drive_identifier = drive_info.split(' ')[0]
                raw_disk = drive_identifier.replace('/dev/disk', '/dev/rdisk')
                command = f"dd if=/dev/zero of={raw_disk} bs=4M".split()
            elif system == "Windows":
                match = re.search(r'\(Index:(\d+)\)', drive_info)
                if not match: raise ValueError("Could not find disk index in drive string.")
                disk_index = match.group(1)
                
                script_path = os.path.join(os.getcwd(), 'wipe_script.txt')
                with open(script_path, 'w') as f:
                    f.write(f"select disk {disk_index}\n")
                    f.write("clean\n")
                
                command = ["diskpart", "/s", script_path]
            
            if not command: raise OSError("Unsupported OS for real wipe.")

            self.log(f"Executing command: {' '.join(command)}", "WARN")
            self.log("Wipe in progress...", "INFO")
            
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            
            if system == "Windows" and os.path.exists('wipe_script.txt'): os.remove('wipe_script.txt')

            if process.returncode != 0: raise subprocess.CalledProcessError(process.returncode, command, stderr)

            self.log("Sanitization complete.", "SUCCESS")
        
        except Exception as e:
            error_details = str(e)
            if isinstance(e, subprocess.CalledProcessError): error_details = e.stderr
            self.log(f"Wipe command failed: {error_details}", "ERROR")
            messagebox.showerror("Wipe Failed", f"The wipe command failed.\n\nDetails:\n{error_details}")
            self.wipe_button.config(state='normal')
            return

        messagebox.showinfo("Select Save Location", "Wipe complete. Please select where the certificate should be saved.")
        save_path = filedialog.askdirectory(title="Select Save Location for Certificate")

        if not save_path:
            self.log("Certificate generation cancelled by user.", "WARN")
            self.wipe_button.config(state='normal')
            return
            
        wipe_method = "NIST 800-88 Purge (dd, zeros)" if system != "Windows" else "NIST 800-88 Clear (diskpart clean)"
        device_data = {"deviceString": drive_info.replace("[SYSTEM DRIVE] ", ""), "wipeMethod": wipe_method}
        
        try:
            private_key = key_manager.load_private_key()
            cert_data, _, pdf_path = certificate_utils.generate_certificate(device_data, private_key, save_path)
            self.log(f"SUCCESS! Certificate saved as {os.path.basename(pdf_path)}", "SUCCESS")
            self._register_certificate_with_server(cert_data)
            messagebox.showinfo("Wipe Complete", f"Certificate saved in:\n{save_path}")
        except Exception as e:
            self.log(f"Certificate generation failed: {e}", "ERROR")
            messagebox.showerror("Certificate Error", f"Error: {e}")
        finally:
            self.wipe_button.config(state='normal')

    def _register_certificate_with_server(self, cert_data):
        self.log("Registering certificate with public verification server...")
        server_url = "http://127.0.0.1:5000/api/register_wipe"
        try:
            response = requests.post(server_url, json=cert_data, timeout=5)
            if response.status_code == 201:
                verification_url = f"http://127.0.0.1:5000/verify/{cert_data['certificateId']}"
                self.log(f"Certificate registered successfully. View at: {verification_url}", "SUCCESS")
            else:
                error_msg = response.json().get('message', response.text)
                self.log(f"Server error: {response.status_code} - {error_msg}", "ERROR")
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
    # This function must be called BEFORE any GUI elements are created.
    ensure_admin_privileges()

    root = tk.Tk()
    app = CertiWipeApp(root)
    root.mainloop()