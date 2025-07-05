import os
import sys
import time
import shutil
import hashlib
import binascii
import platform
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pystray
from PIL import Image, ImageTk
import threading
import json
import subprocess
from cryptography.fernet import Fernet
import base64

# ==============================================
# MODERN UI CONFIGURATION
# ==============================================
DARK_BG = "#1e1e1e"
DARK_FG = "#ffffff"
ACCENT_COLOR = "#4fc3f7"
DARKER_BG = "#121212"
LIGHT_ACCENT = "#bbdefb"
ERROR_COLOR = "#f44336"
SUCCESS_COLOR = "#4caf50"
FONT_FAMILY = "Segoe UI"
FONT_SIZE = 10
HEADER_SIZE = 14

# ==============================================
# APPLICATION CONFIGURATION
# ==============================================
CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".secure_sentinel_config")
DEFAULT_SAFE_PATH = os.path.join(os.path.expanduser("~"), ".secure_backups")

# ==============================================
# SECURITY UTILITIES
# ==============================================
class SecurityManager:
    @staticmethod
    def generate_key(password: str) -> bytes:
        """Generate encryption key from password"""
        password_bytes = password.encode()
        salt = b'salt_'  # Change this in production!
        kdf = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000)
        return base64.urlsafe_b64encode(kdf)

    @staticmethod
    def encrypt_file(key: bytes, input_path: str, output_path: str):
        """Encrypt a file using Fernet encryption"""
        fernet = Fernet(key)
        with open(input_path, 'rb') as f:
            data = f.read()
        encrypted = fernet.encrypt(data)
        with open(output_path, 'wb') as f:
            f.write(encrypted)

    @staticmethod
    def decrypt_file(key: bytes, input_path: str, output_path: str):
        """Decrypt a file using Fernet encryption"""
        fernet = Fernet(key)
        with open(input_path, 'rb') as f:
            encrypted = f.read()
        decrypted = fernet.decrypt(encrypted)
        with open(output_path, 'wb') as f:
            f.write(decrypted)

    @staticmethod
    def hash_password(password, salt=None):
        """Secure password hashing with PBKDF2-HMAC-SHA512"""
        if not salt:
            salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
        else:
            salt = salt.encode('ascii')
        
        pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                    password.encode('utf-8'), 
                                    salt, 
                                    100000)
        return (salt.decode('ascii'), binascii.hexlify(pwdhash).decode('ascii'))

    @staticmethod
    def verify_password(stored_salt, stored_hash, provided_password):
        """Verify a password against stored hash"""
        try:
            pwdhash = hashlib.pbkdf2_hmac('sha512',
                                         provided_password.encode('utf-8'),
                                         stored_salt.encode('ascii'),
                                         100000)
            return binascii.hexlify(pwdhash).decode('ascii') == stored_hash
        except:
            return False

    @staticmethod
    def hide_path(path):
        """Hide folder/file using platform-specific methods"""
        if not os.path.exists(path):
            return False

        try:
            if platform.system() == 'Windows':
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(path, 2)
            elif platform.system() == 'Darwin':
                subprocess.run(['chflags', 'hidden', path], check=True)
            else:
                dirname, basename = os.path.split(path)
                hidden_path = os.path.join(dirname, f".{basename}")
                if os.path.exists(path):
                    os.rename(path, hidden_path)
            return True
        except Exception:
            return False

# ==============================================
# MODERN UI COMPONENTS
# ==============================================
class ModernButton(ttk.Button):
    """Custom styled button for modern UI"""
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.style = ttk.Style()
        self.style.configure('Modern.TButton', 
                           foreground=DARK_FG,
                           background=ACCENT_COLOR,
                           font=(FONT_FAMILY, FONT_SIZE),
                           padding=8,
                           borderwidth=0)
        self.style.map('Modern.TButton',
                      background=[('active', LIGHT_ACCENT),
                                 ('disabled', DARKER_BG)])
        self.configure(style='Modern.TButton')

class ModernEntry(ttk.Entry):
    """Custom styled entry widget"""
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.style = ttk.Style()
        self.style.configure('Modern.TEntry',
                           fieldbackground=DARKER_BG,
                           foreground=DARK_FG,
                           insertcolor=DARK_FG,
                           borderwidth=0,
                           relief='flat')
        self.configure(style='Modern.TEntry')

# ==============================================
# FILE MONITORING HANDLER
# ==============================================
class SentinelHandler(FileSystemEventHandler):
    def __init__(self, app):
        self.app = app
        os.makedirs(self.app.safe_path, exist_ok=True)
        SecurityManager.hide_path(self.app.safe_path)

    def log(self, message):
        self.app.log_message(message)

    def backup_and_remove(self, src_path):
        """Encrypt and backup file, then remove original"""
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{os.path.basename(src_path)}"
            dest_path = os.path.join(self.app.safe_path, filename)
            
            if os.path.isdir(src_path):
                shutil.copytree(src_path, dest_path)
            else:
                key = SecurityManager.generate_key(self.app.current_password)
                SecurityManager.encrypt_file(key, src_path, dest_path)
            
            SecurityManager.hide_path(dest_path)
            self.log(f"Backed up (encrypted): {src_path}")
            
            try:
                if os.path.isdir(src_path):
                    shutil.rmtree(src_path)
                else:
                    os.remove(src_path)
                self.log(f"Removed original: {src_path}")
            except Exception as e:
                self.log(f"Failed to remove: {src_path} ({str(e)})")
                
        except Exception as e:
            self.log(f"Error processing {src_path}: {str(e)}")

    def on_modified(self, event):
        if not event.is_directory:
            self.backup_and_remove(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.backup_and_remove(event.src_path)

    def on_moved(self, event):
        self.backup_and_remove(event.src_path)

# ==============================================
# MAIN APPLICATION
# ==============================================
class SecureFileSentinel:
    def __init__(self, root):
        self.root = root
        self.current_password = None
        self.safe_path = DEFAULT_SAFE_PATH  # Set default path automatically
        self.monitored_paths = []  # Initialize empty list
        self.setup_app()
        self.load_config()
        
        if not hasattr(self, 'password_hash') or not self.password_hash:
            self.show_first_run()
        else:
            self.show_login()

    def setup_app(self):
        """Initialize application settings and UI style"""
        self.root.title("Secure Sentinel v2.0")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        self.root.configure(bg=DARK_BG)
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Base styles
        self.style.configure('.', 
                           background=DARK_BG, 
                           foreground=DARK_FG,
                           font=(FONT_FAMILY, FONT_SIZE))
        
        # Frame styles
        self.style.configure('TFrame', background=DARK_BG)
        self.style.configure('Modern.TFrame', background=DARKER_BG)
        
        # Label styles
        self.style.configure('TLabel', 
                           background=DARK_BG, 
                           foreground=DARK_FG)
        self.style.configure('Header.TLabel', 
                           font=(FONT_FAMILY, HEADER_SIZE, 'bold'), 
                           foreground=ACCENT_COLOR)
        self.style.configure('Subheader.TLabel',
                           font=(FONT_FAMILY, FONT_SIZE, 'bold'))
        
        # Entry styles
        self.style.configure('Modern.TEntry',
                           fieldbackground=DARKER_BG,
                           foreground=DARK_FG,
                           insertcolor=DARK_FG,
                           borderwidth=0)
        
        # Button styles
        self.style.configure('Modern.TButton', 
                           foreground=DARK_FG,
                           background=ACCENT_COLOR,
                           font=(FONT_FAMILY, FONT_SIZE),
                           padding=8)
        self.style.map('Modern.TButton',
                      background=[('active', LIGHT_ACCENT),
                                 ('disabled', DARKER_BG)])
        
        # Listbox styles (requires direct tkinter styling)
        self.listbox_bg = DARKER_BG
        self.listbox_fg = DARK_FG
        self.listbox_select = ACCENT_COLOR
        
        # Create main container
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    def create_modern_button(self, parent, text, command):
        """Helper to create styled buttons"""
        return ModernButton(parent, text=text, command=command)

    def create_modern_entry(self, parent, **kwargs):
        """Helper to create styled entry fields"""
        return ModernEntry(parent, **kwargs)

    def create_modern_listbox(self, parent, **kwargs):
        """Helper to create styled listboxes"""
        listbox = tk.Listbox(parent,
                           bg=self.listbox_bg,
                           fg=self.listbox_fg,
                           selectbackground=self.listbox_select,
                           borderwidth=0,
                           highlightthickness=0,
                           **kwargs)
        return listbox

    def log_message(self, message):
        """Log a message to the UI and console"""
        if hasattr(self, 'log_text'):
            self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}\n")
            self.log_text.see(tk.END)
        print(message)

    def clear_frame(self):
        """Clear all widgets from main frame"""
        for widget in self.root.winfo_children():
            widget.destroy()
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.password_salt = config.get('salt')
                    self.password_hash = config.get('hash')
                    self.safe_path = config.get('safe_path', DEFAULT_SAFE_PATH)
                    self.monitored_paths = config.get('monitored_paths', [])
            except Exception as e:
                self.log_message(f"Config load error: {str(e)}")

    def save_config(self):
        """Save configuration to file"""
        config = {
            'salt': self.password_salt,
            'hash': self.password_hash,
            'safe_path': self.safe_path,
            'monitored_paths': self.monitored_paths
        }
        
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f)
            SecurityManager.hide_path(CONFIG_FILE)
        except Exception as e:
            self.log_message(f"Config save error: {str(e)}")

    def create_tray_icon(self):
        """Create system tray icon"""
        image = Image.new('RGB', (64, 64), color=DARK_BG)
        menu = pystray.Menu(
            pystray.MenuItem('Open', self.restore_from_tray),
            pystray.MenuItem('Exit', self.quit_app)
        )
        self.tray_icon = pystray.Icon("secure_sentinel", image, "Secure File Sentinel", menu)

    def minimize_to_tray(self):
        """Minimize application to system tray"""
        self.root.withdraw()
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def restore_from_tray(self):
        """Restore application from system tray with password check"""
        if self.tray_icon:
            self.tray_icon.stop()
        self.prompt_password("Enter password to continue", self.root.deiconify)

    def quit_app(self):
        """Cleanup and quit application"""
        self.stop_monitoring()
        if self.tray_icon:
            self.tray_icon.stop()
        self.root.destroy()
        sys.exit(0)

    def show_first_run(self):
        """Simplified first-run setup screen (password only)"""
        self.clear_frame()
        
        container = ttk.Frame(self.main_frame)
        container.pack(expand=True, pady=50)
        
        ttk.Label(container, 
                 text="🔒 SECURE FILE SENTINEL SETUP", 
                 style='Header.TLabel').pack(pady=20)
        
        form_frame = ttk.Frame(container)
        form_frame.pack(pady=20)
        
        ttk.Label(form_frame, 
                 text="Set Admin Password:", 
                 style='Subheader.TLabel').grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.pass_entry = self.create_modern_entry(form_frame, show="•")
        self.pass_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(form_frame, 
                 text="Confirm Password:", 
                 style='Subheader.TLabel').grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.confirm_entry = self.create_modern_entry(form_frame, show="•")
        self.confirm_entry.grid(row=1, column=1, padx=5, pady=5)
        
        btn_frame = ttk.Frame(container)
        btn_frame.pack(pady=20)
        
        self.create_modern_button(btn_frame, 
                                "Initialize System", 
                                self.initialize_system).pack(side=tk.LEFT, padx=10)
        self.create_modern_button(btn_frame, 
                                "Exit", 
                                self.quit_app).pack(side=tk.LEFT, padx=10)

    def show_login(self):
        """Show login screen"""
        self.clear_frame()
        
        container = ttk.Frame(self.main_frame)
        container.pack(expand=True, pady=50)
        
        ttk.Label(container, 
                 text="🔒 SECURE FILE SENTINEL", 
                 style='Header.TLabel').pack(pady=20)
        
        form_frame = ttk.Frame(container)
        form_frame.pack(pady=20)
        
        ttk.Label(form_frame, 
                 text="Password:", 
                 style='Subheader.TLabel').grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.login_entry = self.create_modern_entry(form_frame, show="•")
        self.login_entry.grid(row=0, column=1, padx=5, pady=5)
        self.login_entry.bind('<Return>', lambda e: self.verify_login())
        
        btn_frame = ttk.Frame(container)
        btn_frame.pack(pady=20)
        
        self.create_modern_button(btn_frame, 
                                "Login", 
                                self.verify_login).pack(side=tk.LEFT, padx=10)
        self.create_modern_button(btn_frame, 
                                "Exit", 
                                self.quit_app).pack(side=tk.LEFT, padx=10)

    def show_main_ui(self):
        """Show main application interface"""
        self.clear_frame()
        self.create_tray_icon()
        
        # Header
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(header_frame, 
                 text="🔒 SECURE FILE SENTINEL", 
                 style='Header.TLabel').pack(side=tk.LEFT)
        
        # Main content area
        content_frame = ttk.Frame(self.main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Configuration
        config_frame = ttk.LabelFrame(content_frame, 
                                    text="Configuration", 
                                    padding=15)
        config_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 15))
        
        # Safe path section
        safe_frame = ttk.Frame(config_frame)
        safe_frame.pack(fill=tk.X, pady=5)
        
        self.create_modern_button(safe_frame, 
                                "Set Safe Path", 
                                self.set_safe_path).pack(side=tk.LEFT)
        
        self.safe_label = ttk.Label(safe_frame, 
                                   text="[Hidden Location]", 
                                   relief=tk.SUNKEN, 
                                   padding=5,
                                   width=30,
                                   background=DARKER_BG)
        self.safe_label.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Monitored folders section
        ttk.Label(config_frame, 
                 text="Monitored Folders:", 
                 style='Subheader.TLabel').pack(anchor=tk.W, pady=(10, 5))
        
        self.monitor_list = self.create_modern_listbox(config_frame, height=8)
        self.monitor_list.pack(fill=tk.BOTH, expand=True)
        
        scroll = ttk.Scrollbar(config_frame, 
                              orient=tk.VERTICAL, 
                              command=self.monitor_list.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.monitor_list.config(yscrollcommand=scroll.set)
        
        btn_frame = ttk.Frame(config_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        self.create_modern_button(btn_frame, 
                                "Add Folder", 
                                self.add_monitored_folder).pack(side=tk.LEFT)
        
        # Right panel - Controls and Logs
        control_frame = ttk.Frame(content_frame)
        control_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Monitoring controls
        monitor_ctrl_frame = ttk.LabelFrame(control_frame, 
                                          text="Monitoring Controls", 
                                          padding=15)
        monitor_ctrl_frame.pack(fill=tk.X, pady=(0, 15))
        
        btn_row1 = ttk.Frame(monitor_ctrl_frame)
        btn_row1.pack(fill=tk.X, pady=5)
        
        self.start_btn = self.create_modern_button(btn_row1, 
                                                 "Start Monitoring", 
                                                 self.start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = self.create_modern_button(btn_row1, 
                                                "Stop Monitoring", 
                                                self.stop_monitoring)
        self.stop_btn.config(state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        btn_row2 = ttk.Frame(monitor_ctrl_frame)
        btn_row2.pack(fill=tk.X, pady=5)
        
        self.create_modern_button(btn_row2, 
                                "Restore Files", 
                                self.show_restore_dialog).pack(side=tk.LEFT, padx=5)
        
        self.create_modern_button(btn_row2, 
                                "Minimize to Tray", 
                                self.minimize_to_tray).pack(side=tk.RIGHT, padx=5)
        
        # Activity log
        log_frame = ttk.LabelFrame(control_frame, 
                                 text="Activity Log", 
                                 padding=15)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = tk.Text(log_frame, 
                               wrap=tk.WORD, 
                               bg=DARKER_BG, 
                               fg=DARK_FG,
                               insertbackground=DARK_FG,
                               borderwidth=0,
                               highlightthickness=0)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        log_scroll = ttk.Scrollbar(log_frame, 
                                  orient=tk.VERTICAL, 
                                  command=self.log_text.yview)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=log_scroll.set)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.main_frame, 
                             textvariable=self.status_var, 
                             relief=tk.SUNKEN,
                             background=DARKER_BG,
                             foreground=DARK_FG,
                             padding=5)
        status_bar.pack(fill=tk.X, pady=(10, 0))
        
        # Update UI with existing data
        if hasattr(self, 'monitored_paths'):
            for path in self.monitored_paths:
                self.monitor_list.insert(tk.END, path)
        
        if hasattr(self, 'safe_path') and self.safe_path:
            self.safe_label.config(text="[Hidden Location]")

    def initialize_system(self):
        """Initialize the system with new password (without folder selection)"""
        password = self.pass_entry.get()
        confirm = self.confirm_entry.get()
        
        if not password or password != confirm:
            messagebox.showerror("Error", "Passwords do not match or are empty")
            return
            
        if len(password) < 4:
            messagebox.showerror("Error", "Password must be at least 4 characters")
            return
            
        # Create default safe path if it doesn't exist
        os.makedirs(self.safe_path, exist_ok=True)
        SecurityManager.hide_path(self.safe_path)
            
        self.password_salt, self.password_hash = SecurityManager.hash_password(password)
        self.current_password = password
        self.save_config()
        self.show_main_ui()
        messagebox.showinfo("Success", "Setup complete! You can now add folders to monitor.")

    def verify_login(self):
        """Verify user login credentials"""
        password = self.login_entry.get()
        if SecurityManager.verify_password(self.password_salt, self.password_hash, password):
            self.current_password = password
            self.show_main_ui()
        else:
            messagebox.showerror("Error", "Incorrect password")
            self.login_entry.delete(0, 'end')

    def set_safe_path(self):
        """Optional: Allow user to change safe path later"""
        path = filedialog.askdirectory(title="Select Safe Backup Location")
        if path:
            self.safe_path = os.path.join(path, ".secure_storage")
            os.makedirs(self.safe_path, exist_ok=True)
            SecurityManager.hide_path(self.safe_path)
            if hasattr(self, 'safe_label'):
                self.safe_label.config(text="[Hidden Location]")
            self.save_config()

    def add_monitored_folder(self):
        """Add a folder to monitor"""
        path = filedialog.askdirectory(title="Select Folder to Monitor")
        if path and path not in self.monitored_paths:
            self.monitored_paths.append(path)
            self.monitor_list.insert(tk.END, path)
            self.save_config()

    def start_monitoring(self):
        """Start monitoring selected folders"""
        if not self.safe_path:
            messagebox.showerror("Error", "Safe path not configured")
            return
            
        if not self.monitored_paths:
            messagebox.showerror("Error", "Please add folders to monitor")
            return
            
        if not self.current_password:
            self.prompt_password("Enter password to start monitoring", self.start_monitoring)
            return
            
        self.observer = Observer()
        handler = SentinelHandler(self)
        
        for path in self.monitored_paths:
            self.observer.schedule(handler, path, recursive=True)
            
        self.observer.start()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set("Monitoring active")
        self.log_message("Monitoring started")

    def stop_monitoring(self):
        """Stop monitoring folders"""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Monitoring stopped")
        self.log_message("Monitoring stopped")

    def show_restore_dialog(self):
        """Show dialog to restore files from backup"""
        if not hasattr(self, 'current_password') or not self.current_password:
            self.prompt_password("Enter password to restore files", self.show_restore_dialog)
            return
            
        restore_window = tk.Toplevel(self.root)
        restore_window.title("Restore Files")
        restore_window.geometry("600x400")
        restore_window.configure(bg=DARK_BG)
        
        # Apply modern styling to child widgets
        restore_window.option_add('*TFrame*background', DARK_BG)
        restore_window.option_add('*TLabel*background', DARK_BG)
        restore_window.option_add('*TLabel*foreground', DARK_FG)
        
        # List backup files
        backups = []
        if os.path.exists(self.safe_path):
            backups = [f for f in os.listdir(self.safe_path) 
                      if not f.startswith('.') and os.path.isfile(os.path.join(self.safe_path, f))]
        
        # Listbox with modern styling
        list_frame = ttk.Frame(restore_window)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        ttk.Label(list_frame, 
                 text="Select files to restore:", 
                 style='Subheader.TLabel').pack(anchor=tk.W)
        
        listbox = self.create_modern_listbox(list_frame, selectmode=tk.MULTIPLE)
        listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        
        scroll = ttk.Scrollbar(list_frame, 
                              orient=tk.VERTICAL, 
                              command=listbox.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        listbox.config(yscrollcommand=scroll.set)
        
        for backup in backups:
            listbox.insert(tk.END, backup)
        
        # Button frame
        btn_frame = ttk.Frame(restore_window)
        btn_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        def restore_selected():
            """Restore selected files"""
            selections = listbox.curselection()
            if not selections:
                messagebox.showwarning("Warning", "No files selected")
                return
                
            dest_dir = filedialog.askdirectory(title="Select restore directory")
            if not dest_dir:
                return
                
            success_count = 0
            for idx in selections:
                backup_file = backups[idx]
                src_path = os.path.join(self.safe_path, backup_file)
                
                # Extract original filename (remove timestamp)
                original_name = '_'.join(backup_file.split('_')[1:])
                dest_path = os.path.join(dest_dir, original_name)
                
                try:
                    key = SecurityManager.generate_key(self.current_password)
                    SecurityManager.decrypt_file(key, src_path, dest_path)
                    success_count += 1
                    self.log_message(f"Restored: {backup_file} to {dest_path}")
                except Exception as e:
                    self.log_message(f"Restore failed for {backup_file}: {str(e)}")
            
            messagebox.showinfo("Restore Complete", 
                              f"Successfully restored {success_count}/{len(selections)} files")
            restore_window.destroy()
        
        def restore_all():
            """Restore all backup files"""
            if not backups:
                messagebox.showwarning("Warning", "No backups available")
                return
                
            dest_dir = filedialog.askdirectory(title="Select restore directory")
            if not dest_dir:
                return
                
            success_count = 0
            for backup_file in backups:
                src_path = os.path.join(self.safe_path, backup_file)
                original_name = '_'.join(backup_file.split('_')[1:])
                dest_path = os.path.join(dest_dir, original_name)
                
                try:
                    key = SecurityManager.generate_key(self.current_password)
                    SecurityManager.decrypt_file(key, src_path, dest_path)
                    success_count += 1
                    self.log_message(f"Restored: {backup_file} to {dest_path}")
                except Exception as e:
                    self.log_message(f"Restore failed for {backup_file}: {str(e)}")
            
            messagebox.showinfo("Restore Complete", 
                              f"Successfully restored {success_count}/{len(backups)} files")
            restore_window.destroy()
        
        self.create_modern_button(btn_frame, 
                                "Restore Selected", 
                                restore_selected).pack(side=tk.LEFT, padx=5)
        
        self.create_modern_button(btn_frame, 
                                "Restore All", 
                                restore_all).pack(side=tk.LEFT, padx=5)
        
        self.create_modern_button(btn_frame, 
                                "Cancel", 
                                restore_window.destroy).pack(side=tk.RIGHT)

    def prompt_password(self, message, callback):
        """Show password prompt dialog"""
        pw_window = tk.Toplevel(self.root)
        pw_window.title("Authentication Required")
        pw_window.configure(bg=DARK_BG)
        
        # Apply modern styling
        pw_window.option_add('*TFrame*background', DARK_BG)
        pw_window.option_add('*TLabel*background', DARK_BG)
        pw_window.option_add('*TLabel*foreground', DARK_FG)
        
        ttk.Label(pw_window, 
                 text=message, 
                 style='Subheader.TLabel').pack(padx=10, pady=5)
        
        pw_entry = self.create_modern_entry(pw_window, show="•")
        pw_entry.pack(padx=10, pady=5)
        
        def verify():
            password = pw_entry.get()
            if SecurityManager.verify_password(self.password_salt, self.password_hash, password):
                self.current_password = password
                pw_window.destroy()
                callback()
            else:
                messagebox.showerror("Error", "Incorrect password")
        
        btn_frame = ttk.Frame(pw_window)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.create_modern_button(btn_frame, 
                                "Submit", 
                                verify).pack(side=tk.LEFT, padx=5)
        
        self.create_modern_button(btn_frame, 
                                "Cancel", 
                                pw_window.destroy).pack(side=tk.RIGHT)
        
        pw_entry.bind('<Return>', lambda e: verify())

if __name__ == "__main__":
    root = tk.Tk()
    
    # Windows taskbar icon
    if platform.system() == 'Windows':
        try:
            from ctypes import windll
            windll.shell32.SetCurrentProcessExplicitAppUserModelID("SecureSentinel.2.0")
        except:
            pass
    
    app = SecureFileSentinel(root)
    root.mainloop()