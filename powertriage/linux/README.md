# PowerTriage (Linux Edition)

**PowerTriage Linux** is a pure Bash script designed for **Incident Response (IR)** and **Forensic Triage** on compromised Linux systems. It collects comprehensive artifacts using standard system tools, requiring **no external dependencies** or binary installation, making it ideal for **Live Response** on servers, desktops, and containers.

> **Note:** This tool is part of the **PowerForensics** ecosystem.

## 🚀 Features

PowerTriage Linux is built to be robust, fast, and safe (`set -e` protected), capable of running on minimal environments (like Alpine or minimal Cloud Images) as well as full distributions.

*   **System Info:** OS Kernel, Release, Hostname, Timezone, Uptime, CPU/Mem info.
*   **User Activity:** 
    *   **Current Sessions:** `w`, `who`, `last`, `lastb`.
    *   **History Files:** Automatically extracts `.bash_history`, `.zsh_history`, `.viminfo`, `.mysql_history`, etc., for **all users** on the system.
    *   **Privileges:** `/etc/sudoers` parsing, sudo group members.
    *   **Accounts:** Analysis of `/etc/passwd` and `/etc/shadow` (status only) to identify passwordless or locked accounts.
*   **Network:** 
    *   Active Connections (`ss` or `netstat`) with process mapping.
    *   Open Ports (Listening services).
    *   **DNS & Hosts:** `/etc/resolv.conf`, `/etc/hosts` to detect hijacking.
    *   Interface configuration (`ip addr`, `ifconfig`).
*   **Processes & Persistence:** 
    *   Full process list (`ps auxef`).
    *   **Cron Jobs:** System-wide (`/etc/cron*`) and user-specific crontabs (`/var/spool/cron`).
    *   **Systemd:** List of active services and timers.
    *   **Open Files:** `lsof` dump (if available) for network/file correlation.
*   **Software & Containers:**
    *   **Containers:** Auto-detection of **Docker**, **Podman**, and **Crictl** (K8s). Lists running containers, images, and networks.
    *   **Packages:** Inventory of installed software via `dpkg` (Debian/Ubuntu), `rpm` (RHEL/CentOS), or `apk` (Alpine).
*   **File System:** 
    *   **Timeline:** Generates a bodyfile-like timeline of `/etc`, `/tmp`, `/var/www`, `/home` (optional, time-consuming).
    *   **SSH Keys:** Collects `authorized_keys` and `known_hosts` for lateral movement analysis.

## 📋 Requirements

*   **OS:** Most Linux distributions (Debian, Ubuntu, RHEL, CentOS, Fedora, Alpine, Kali, Arch).
*   **Shell:** Bash 4.0+.
*   **Privileges:** **Root** (sudo) is required to access sensitive artifacts (shadow, other users' history, system logs).

## 🛠️ Usage

Make the script executable and run it as root.

```bash
chmod +x PF_Linux.sh
sudo ./PF_Linux.sh
```

### Interactive Mode
By default, the script asks for confirmation before starting and allows you to choose artifact categories.

### Automated / Fast Mode
Ideal for scripting or when speed is crucial.

*   `--auto`: Skips confirmation prompts (Non-interactive).
*   `--fast`: Skips time-consuming tasks (Timeline, full file listing, large log archiving).
*   `--no-memory`: Skips memory dump (Lime) if integrated.
*   `--no-tar`: Skips final compression (leaves raw directory).

**Example:**
```bash
sudo ./PF_Linux.sh --auto --fast
```

## 📂 Output Structure

The script creates a directory named `powertriage_linux_HOSTNAME_TIMESTAMP` (compressed as `.tar.gz` at the end) containing:

| File/Folder | Description |
| :--- | :--- |
| `user_history_files/` | **User Activity:** History files (`.bash_history`, `.zsh_history`, etc.) per user. |
| `00_avml_download_documentation.txt` | **Audit:** Documentation of AVML download decision (if applicable). |
| `00_metadata_pre_triage.txt` | **Chain of Custody:** Pre-triage timestamps and metadata. |
| `containers.txt` | **Containers:** Docker, Podman, and Crictl (K8s) status/images. |
| `directory_and_files.txt` | **Filesystem:** Full listing of files (excluding proc/sys/dev). |
| `ForensicCatalog.json` | **Integration:** JSON catalog for PowerForensics Analysis Platform. |
| `hashes.txt` | **Chain of Custody:** SHA256 hashes of all collected evidence. |
| `home.tar.gz` | **Archive:** Compressed `/home` directory (Full Scope only). |
| `installed_packages.txt` | **Software:** Inventory from dpkg, rpm, or apk. |
| `logs.tar.gz` | **Archive:** Compressed `/var/log` directory. |
| `memory.mem` | **Memory:** RAM dump via AVML (if enabled). |
| `network_info.txt` | **Network:** Interfaces, Ports, Routes, ARP, DNS (`resolv.conf`, `hosts`). |
| `open_files_lsof.txt` | **Processes:** Open files listing (requires `lsof`). |
| `persistence.txt` | **Persistence:** Cron, Init, Systemd, SSH keys, Kernel modules. |
| `powertriage.log` | **Log:** Detailed execution log. |
| `powertriage_errors.log` | **Log:** Execution errors and warnings. |
| `processes.txt` | **Processes:** Process tree (`pstree`), full list (`ps`), and executable links. |
| `root.tar.gz` | **Archive:** Compressed `/root` directory. |
| `system_info.txt` | **System:** OS details, Uptime, Users, Groups, Crontab. |
| `timeline_file.csv` | **Timeline:** Filesystem timeline (MACB timestamps). |
| `users_local.txt` | **Users:** Shadow status, Sudoers configuration, Wheel group. |

**Final Delivery:** The folder is automatically compressed into a **TAR.GZ** file (unless `--no-tar` is used).

## 👤 Author

**Jesús D. Angosto** (@jdangosto)
*   🐦 Twitter/X: [@jdangosto](https://twitter.com/jdangosto)
*   🐙 GitHub: [jdangosto](https://github.com/jdangosto)
*   🌐 Blog: [DFIR Spain](https://www.dfirspain.es)
*   🛡️ Project Web: [PowerForensics](https://powerforensics.es)

## ⚠️ Disclaimer

This tool is provided "as is" without warranty of any kind. Use it at your own risk. The author is not responsible for any damage caused by the use or misuse of this tool. Always test in a controlled environment before using in production.
