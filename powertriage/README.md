# PowerTriage

PowerTriage is a cross-platform forensic triage toolkit that focuses on **fast, portable, and dependency-free collection of artifacts** during Incident Response.

It is part of the **PowerForensics** ecosystem.

This repository is the home for the **Community Edition** tooling and scripts that will be published on GitHub, currently focused on:

- **PowerTriage Windows** – Native PowerShell triage for workstations and servers.
- **PowerTriage Linux** – Bash-only triage for Linux servers, desktops, and containers.

## Editions & Platforms

- **Windows**
  - Script: `Windows/PowerTriage.ps1`
- **Linux**
  - Script: `Linux/PF_Linux.sh`

Each platform has its own detailed README:

- Windows: `Windows/README.md`
- Linux: `Linux/README.md`

## High-Level Capabilities

Across platforms, PowerTriage is designed to provide:

- **Live Response friendly collection**
  - No external binaries required in CE.
  - Minimal footprint, focused on preserving evidence integrity.
- **Core forensic coverage**
  - System information and security posture.
  - Users, sessions, and persistence mechanisms.
  - Network connections and configuration.
  - File system artifacts (timeline, recent activity, application traces).
  - Browser artifacts (history, cookies, credentials, extensions inventory with hashes in Windows).
- **Output ready for analysis**
  - Structured folders per host and timestamp.
  - CSV / TXT outputs for quick filtering.
  - Hashes (SHA256) of collected files to maintain chain of custody.

For platform-specific details and task lists, refer to each sub-README.

## Basic Usage

> The exact parameters and options are described in each platform README. This section gives a quick overview.

### Windows (Community Edition)

Run from an elevated PowerShell prompt on the target system:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Windows\PowerTriage.ps1 -OutputDirectory "C:\Evidence"
```

### Linux

Run as root on the target system:

```bash
chmod +x ./Linux/PF_Linux.sh
sudo ./Linux/PF_Linux.sh
```

## Repository Layout

- `Windows/` – PowerTriage for Windows and its documentation.
- `Linux/` – PowerTriage for Linux and its documentation.

## License

The components published here are released under the license specified in this repository (to be aligned with the main PowerForensics ecosystem).
