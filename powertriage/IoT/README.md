# PowerTriage (IoT Edition)

PowerTriage IoT is a triage script focused on **offline forensic acquisition and analysis of OpenWrt-based devices**.

It is designed to work over a **mounted root filesystem** (rootfs) of the device, so that you can analyze firmware images or extracted filesystems safely from an analyst workstation.

> Status: **BETA / Docente**. This edition is intended for lab, training, and controlled investigations on OpenWrt-style systems.

## Script

- Main script: `PowerTriage_IOT.sh`
- Language: Bash (POSIX environment, typical Linux workstation)
- Mode: Offline (works against a mounted root directory, not directly on the live device)

## High-Level Capabilities

Given a mounted OpenWrt root filesystem, the script:

- Collects **metadata and firmware identity**:
  - `os-release`, `openwrt_release`, `openwrt_version` when present.
  - Filesystem stats and basic host information.
- Builds a **merged_rootfs** view:
  - Combines `rom/`, `overlay/upper/` and the base root into `merged_rootfs/` for easier diffing.
- Copies and inventories **configuration and UCI data**:
  - Full `/etc` and `/etc/config` tree.
  - Generates a `manifest.csv` with SHA256, mtime, size and notes for copied items.
- Extracts **users and authentication artifacts**:
  - `/etc/passwd`, `/etc/shadow`, `/etc/group`.
  - Dropbear and OpenSSH configs and keys.
  - `authorized_keys` and `known_hosts` across the filesystem.
  - Dropbear host key fingerprint (SHA256) for identification.
- Generates **IOC-oriented views**:
  - IP and domain counts (`iocs/ip_counts.txt`, `iocs/domains_counts.txt`).
  - SSH-related events and bruteforce summaries when available.
- Creates a **summary report and archive**:
  - `summary_report.txt` with key findings and counters.
  - Compressed tarball of the output directory with SHA256 hash.

All collected files are tracked in `manifest.csv` to keep a basic chain-of-custody style inventory.

## Usage

Run the script from a Linux workstation where the device rootfs has been mounted.

```bash
chmod +x PowerTriage_IOT.sh
./PowerTriage_IOT.sh /path/to/mounted_rootfs /path/to/output_dir [baseline_luci_manifest.csv]
```

- `ROOT` (first argument): path to the mounted OpenWrt root filesystem (mandatory).
- `OUT` (second argument): output directory (optional, defaults to `./iot_triage_out_v61`).
- `BASELINE` (third argument): optional baseline `luci_manifest.csv` from a known-good firmware to compare against.

Example:

```bash
sudo mount firmware.img /mnt/openwrt_root   # example only
mkdir -p /cases/iot_case01
./PowerTriage_IOT.sh /mnt/openwrt_root /cases/iot_case01
```

At the end of execution you should see:

- The populated output directory with configuration, keys, IOCs and reports.
- A `summary_report.txt` with a quick overview.
- A compressed archive (`.tar.gz`) plus its `.sha256` hash for transport.

## Notes

- This edition is focused specifically on **OpenWrt-style layouts** (directories like `rom/`, `overlay/upper/`, etc.).
- The script is intentionally defensive:
  - Uses robust error handling (`set -uo pipefail` and local try/ignore patterns).
  - Continues even if some `find`, `grep` or `stat` calls fail, ensuring a report is always generated.
- As with any forensic tool, it is recommended to work on **copies** of the rootfs, not on the original evidence media.

