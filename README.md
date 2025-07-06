# 🔒 Secure Sentinel - ONE CLICK SYSTEM MONITORING TOOL 
*(Portable executable - No installation needed!)*  

![Secure Sentinel Demo](screenshots/demo.gif) <!-- Replace with actual GIF -->

## 🚀 Instant Protection
- **Zero-config encryption** - Just run and protect
- **AES-256 military-grade** encryption
- **Hidden vault** at `~/.secure_backups`
- **Password-locked** - Your data never leaves your device

## 📥 Get Started in 30 Seconds
1. **Download**:  
   → [🔗 Latest Version Here](https://drive.google.com/drive/folders/1nz2yW5ZtqJlxgTXkmrb8P8FwTVX6y8h0?usp=drive_link)  
   *(Look for `SecureSentinel_v2.0.zip`)*

2. **Extract** and run `SecureSentinel.exe`  
3. **Set password** when prompted

> 💡 Pro Tip: Right-click → "Pin to taskbar" for quick access!

## 🖥️ See It in Action
| Setup Password | Monitor Folders | Restore Files |
|----------------|-----------------|---------------|
| ![Login](screenshots/login.png) | ![Main UI](screenshots/main.png) | ![Restore](screenshots/restore.png) |

## 🔄 How Files Are Protected
```mermaid
sequenceDiagram
    User->>+Secure Sentinel: Adds folder
    Secure Sentinel->>+File System: Monitors changes
    File System->>+Secure Sentinel: Detects modification
    Secure Sentinel->>+Encryption: Locks file (AES-256)
    Encryption->>+Vault: Stores encrypted copy
    Vault->>+File System: Deletes original
