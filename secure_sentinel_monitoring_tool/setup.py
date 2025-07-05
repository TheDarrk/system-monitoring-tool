import sys
import os
from cx_Freeze import setup, Executable

# --- Build Configuration ---
build_options = {
    "packages": [
        "tkinter", 
        "watchdog", 
        "pystray", 
        "PIL", 
        "cryptography",
        "hashlib",
        "json",
        "shutil",
        "threading",
        "base64",
        "binascii"
    ],
    "include_files": [
        ("icon.ico", "icon.ico")  # Ensure this file exists in your project
    ],
    "excludes": ["tkinter.test"],
    "optimize": 2  # Python bytecode optimization
}

# Platform-specific settings
base = "Win32GUI" if sys.platform == "win32" else None
icon = "icon.ico" if os.path.exists("icon.ico") else None

# --- Executable Target ---
executable = Executable(
    script="secure_sentinel.py",
    base=base,
    icon=icon,
    target_name="SecureSentinel",  # Output filename (no .exe needed)
    copyright="Copyright (C) 2024 Secure Sentinel",
    trademarks="Secure File Monitoring System"
)

# --- Build Setup ---
setup(
    name="SecureFileSentinel",
    version="2.0",
    description="Real-time file monitoring with encryption",
    author="Your Name",
    options={"build_exe": build_options},
    executables=[executable],
    url="https://github.com/your-repo/secure-sentinel"
)

print("\n[SUCCESS] Build completed. Check the 'build' directory.")