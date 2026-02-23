# PowerTriage (Community Edition)

**PowerTriage** is a lightweight, native PowerShell script designed for **Incident Response (IR)** and **Forensic Triage** on compromised Windows systems (Workstation & Server). 

It collects comprehensive forensic artifacts **without external dependencies** (no compiled binaries) and strictly adheres to the **Live Response** philosophy, minimizing system footprint and preserving evidence integrity.

> **Note:** This tool is part of the **PowerForensics** ecosystem.

## 🚀 Key Features

PowerTriage performs **35+ specific forensic tasks**, optimized for speed and reliability:

### 🛡️ System & Security
*   **System Info:** OS details, Patches, Environment Variables, Timezone.
*   **User Recon:** Active Users, **User SIDs mapping**, Local Groups (Admin enumeration).
*   **Persistence:** Scheduled Tasks, Services, **Autoruns** (Registry-based), Startup Folders.
*   **Process Analysis:** Full process tree with **SHA256 Hashing** and Path verification.

### 🌐 Network & Connections
*   **Active Connections:** TCP/UDP mapping with process correlation.
*   **Network Config:** Interfaces, DNS Cache, Routing Table, ARP Cache.
*   **Firewall:** Rules and Profiles status.
*   **Remote Access:** **RDP Logs** (Event ID 1149), **AnyDesk** & **TeamViewer** artifact extraction.

### 🔍 Forensic Artifacts
*   **File System:**
    *   **MFT & NTFS:** Secure extraction via VSS.
    *   **Recycle Bin:** Optimized parsing ($I/$R files).
    *   **Prefetch:** Execution history.
    *   **Recent Activity:** Recent Files, JumpLists (Automatic & Custom Destinations).
    *   **USB History:** Registry-based USB device enumeration.
*   **Browsers (Auto-Discovery):** 
    *   History, Cookies, Login Data, and Profiles from **Chrome, Edge, Firefox, Opera, CCleaner Browser**.
    *   Smart profile discovery for Firefox (randomized path support).
    *   Inventario de extensiones por navegador/usuario con hash SHA256 del manifest.
*   **Email & Cloud:** 
    *   **Outlook:** PST/OST/Config file collection.
    *   **Cloud Storage:** Artifacts from **OneDrive, Teams, Google Drive, Dropbox**.

### ⚡ Performance & Reliability (New)
*   **Optimized Software Inventory:** Uses Registry keys instead of `Win32_Product` for instant, safe software enumeration (avoids MSI reconfiguration events).
*   **Robust VSS Collection:** 
    *   **Language Agnostic:** Uses CIM/WMI class GUIDs to work on any system language.
    *   **Auto-Cleanup:** `Try/Finally` blocks ensure Shadow Copies and Mount Points are always removed, even if the script is interrupted.
    *   **System Drive Agnostic:** Works correctly on systems where Windows is not on `C:\`.

## 📋 Requirements

*   **OS:** Windows 10, Windows 11, Windows Server 2016/2019/2022.
*   **PowerShell:** Version 5.1 or higher.
*   **Privileges:** **Administrator** rights are strictly required to access protected artifacts (VSS, SAM/SYSTEM Hives, Security Logs).

## 🛠️ Usage

### 1. Interactive Mode
Run the script as Administrator. It will prompt for an Output Directory (default is current path).

```powershell
.\PowerTriage.ps1
```

### 2. Unattended / Automation
Ideal for EDR Live Response, GPO, or remote execution. Use parameters to bypass prompts.

```powershell
.\PowerTriage.ps1 -OutputDirectory "Z:\Evidence\Case_001"
```

### 🚩 Troubleshooting Execution Policy
If script execution is disabled on the target machine, use:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\PowerTriage.ps1
```

## 📂 Output Structure

The script creates a directory named `PowerTriage_HOSTNAME_TIMESTAMP` (zipped at the end) containing:

| Folder/File | Description |
| :--- | :--- |
| `Activities_Cache\` | Windows 10/11 Timeline Activity History (CDP) per user. |
| `Browsers\` | History, Cookies, Logins and Extensions inventory (with SHA256 hashes) for Chrome, Edge, Firefox, Opera, CCleaner Browser. |
| `CloudStorage\` | Metadata/Logs from OneDrive, Teams, Google Drive, Dropbox. |
| `EmailArtifacts\` | Outlook (OST/PST), Thunderbird, Windows Mail data. |
| `EventsLogs\` | **Key EVTX:** Security, System, PowerShell, Sysmon, RDP, etc. |
| `Network\` | Active Connections, DNS Cache, Routes, SMB Shares, Interface Info. |
| `PowerShellConsole_History\` | Console history files (`ConsoleHost_history.txt`) per user. |
| `Prefetch\` | Application execution artifacts (`.pf` files). |
| `ProcessInformation\` | Active Processes list (with hashes) and Process Tree. |
| `Recent_Items\` | Recent files accessed (LNK files) per user. |
| `RecycleBin\` | Deleted files metadata (`$I`) and small data files (`$R`). |
| `RemoteAccess\` | Logs/Config from AnyDesk and TeamViewer. |
| `System\` | Services, Autoruns, USB History, Environment Vars, Local Groups, Scheduled Tasks, Installed Software, Clipboard. |
| `SystemConfig\` | Local Users, System Info, Firewall Rules. |
| `VSS_Artifacts\` | **Locked Files:** SAM, SYSTEM, MFT, UsnJrnl, User Hives (NTUSER.DAT). |
| `Hashes.csv` | **Chain of Custody:** SHA256 hashes of all collected files. |
| `PowerTriage.log` | Detailed execution log with timestamps. |

**Final Delivery:** The entire folder is automatically **zipped** and hashed for transport.

## 👤 Author

**Jesús D. Angosto** (@jdangosto)
*   🐦 Twitter/X: [@jdangosto](https://twitter.com/jdangosto)
*   🐙 GitHub: [jdangosto](https://github.com/jdangosto)
*   🌐 Blog: [DFIR Spain](https://www.dfirspain.es)
*   🛡️ Project: [PowerForensics](https://powerforensics.es)

## ⚠️ Disclaimer

This tool is provided "as is" without warranty of any kind. Use it at your own risk. The author is not responsible for any damage caused by the use or misuse of this tool. **Always test in a controlled environment before using in production.**
