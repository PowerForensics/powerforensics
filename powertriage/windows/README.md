# PowerTriage Windows (Community Edition)

**PowerTriage Windows CE** is a native PowerShell triage script for Incident Response and forensic triage on compromised Windows systems, including workstations and servers.

It is designed around a practical DFIR goal: collect high-value forensic artifacts quickly, with low deployment friction and without external binary dependencies in the Community Edition.

This tool is part of the **PowerForensics** ecosystem.

## Positioning

The Windows Community Edition is intended to be a strong, openly available live-triage tool for analysts, responders, and defenders.

The Community Edition focuses on:

- Fast live triage on Windows.
- Practical artifact coverage for real investigations.
- Simple execution in restricted environments.
- Structured output suitable for escalation and review.

The Pro workflow extends this model with deeper professional capabilities such as offline mounted-volume collection, advanced packaging, chain of custody artifacts, and executive reporting.

## Installation

### Option 1: PowerShell Gallery

```powershell
Install-Script -Name PowerTriage
PowerTriage.ps1
```

### Option 2: Manual Download

Download `PowerTriage.ps1` from this repository and run it locally.

## Key Capabilities

PowerTriage Windows CE is built to provide broad live-response coverage while remaining portable and easy to deploy.

### System and Security

- System information, environment variables, timezone, and general host context.
- Local users, local groups, and administrator enumeration.
- Persistence coverage through scheduled tasks, services, autoruns, and startup locations.
- Installed software inventory.
- USB history and clipboard collection.

### Process and Execution

- Running process collection.
- Process tree output.
- SHA256 hashing of collected process-related artifacts where applicable.

### Network and Remote Access

- TCP connection inventory with process correlation.
- Optional live packet capture via native `pktmon`, including ETL/TXT/PCAPNG output and capture metadata.
- Firewall configuration and rules.
- DNS cache and network configuration data.
- SMB-related information.
- RDP event collection.
- Remote access artifacts such as AnyDesk and TeamViewer.

### User and Application Artifacts

- PowerShell console history.
- Recent files and Timeline-related activity artifacts.
- Live acquisition of per-user `WebCacheV01.*` (`.dat`, `.jfm`, `.log`, `.chk`) with fallback handling for locked files.
- Hardened live acquisition of `ActivitiesCache.db`, `ActivitiesCache.db-wal`, and `ActivitiesCache.db-shm`.
- Browser artifacts from common Windows browsers.
- Email and cloud-storage-related artifacts where present.

### File System and Evidence-Oriented Collection

- Prefetch collection.
- Recycle Bin parsing and export.
- VSS-based collection for selected locked files.
- SHA256 hashing of collected files.
- Final compressed output for easier handling and transfer.

## Community Edition Scope

The Community Edition is designed to remain genuinely useful for the DFIR community. It is not intended to be a token or artificially crippled release.

In general, CE covers live triage well. The main areas reserved for Pro are workflows that add professional acquisition depth or customer-facing delivery value, especially:

- Offline collection from mounted Windows volumes.
- Offline hives and selected NTFS metadata acquisition.
- Advanced evidence packaging and split archives.
- Chain of custody outputs beyond basic hashing.
- Executive or customer-facing reporting.

## Requirements

- Windows 10, Windows 11, Windows Server 2016/2019/2022.
- PowerShell 5.1 or later.
- Administrator rights are recommended for fuller collection.

PowerTriage can still collect a useful subset of artifacts without elevation, but protected areas and some system-level evidence will be limited.

## Usage

### Default Execution

```powershell
.\PowerTriage.ps1
```

If no execution mode is supplied, CE runs the `Full` workflow by default and writes output to the current directory.

### Unattended Mode

```powershell
.\PowerTriage.ps1 -OutputDirectory "Z:\Evidence\Case_001"
```

### Output Retention

```powershell
.\PowerTriage.ps1 -OutputRetention Both
.\PowerTriage.ps1 -OutputRetention DirectoryOnly
.\PowerTriage.ps1 -OutputRetention ZipOnly
```

`Both` is the default and keeps the directory tree plus the final ZIP package.

This is recommended for remote collection workflows where a large ZIP may be difficult to copy in one pass and it can be more practical to recover only the specific files or folders needed from the uncompressed tree.

### Packet Capture

```powershell
.\PowerTriage.ps1 -PacketCaptureQuick -PacketCaptureProtocol TCP -PacketCapturePort 443 -O "Z:\Evidence\Case_001"
```

```powershell
.\PowerTriage.ps1 -PacketCapture -PacketCaptureDropOnly -PacketCaptureFormat pcapng -PacketCaptureProtocol TCP -O "Z:\Evidence\Case_001"
```

### Minimal Collection

```powershell
.\PowerTriage.ps1 -Minimal
```

### Full Workflow

```powershell
.\PowerTriage.ps1 -Full
```

`-Full` now runs the complete CE workflow, including Chronos timeline export, Nexus Lite graph export, findings generation, and `Executive_Report.html`.

The Chronos timeline export is emitted as a JSON array of events and includes the required `id`, `timestamp`, and `title` fields expected by Chronos.

### Execution Policy Bypass

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\PowerTriage.ps1
```

## Output Structure

The script creates a directory named `PowerTriage_HOSTNAME_TIMESTAMP`.

Output retention is controlled with `-OutputRetention`:

- `Both` (default): keep the directory and create `PowerTriage_HOSTNAME_TIMESTAMP.zip`
- `DirectoryOnly`: keep only the directory tree and skip ZIP generation
- `ZipOnly`: create the ZIP and remove the directory tree after successful compression

Typical contents include:

| Folder/File | Description |
|---|---|
| `Activities_Cache\` | Per-user `ConnectedDevicesPlatform` artifacts plus hardened live copies of `ActivitiesCache.db`, `ActivitiesCache.db-wal`, `ActivitiesCache.db-shm`, and `WebCacheV01.*` (`.dat`, `.jfm`, `.log`, `.chk`). |
| `Browsers\` | Browser history, cookies, profiles, extensions, and related artifacts. |
| `CloudStorage\` | Metadata and local artifacts from cloud-storage applications where present. |
| `EmailArtifacts\` | Outlook, Thunderbird, and Windows Mail related artifacts. |
| `EventsLogs\` | Key EVTX exports and event-derived outputs. |
| `Network\` | Active connections, DNS, SMB, routes, and other network-related outputs. |
| `Network\PacketCapture\` | Optional `pktmon` ETL/TXT/PCAPNG outputs, capture metadata, and packet-capture JSON report. |
| `PowerShellConsole_History\` | Console history per user where available. |
| `Prefetch\` | Windows Prefetch artifacts. |
| `ProcessInformation\` | Process inventory, hashes, and process tree output. |
| `Recent_Items\` | Recent file shortcuts and related user activity artifacts. |
| `RecycleBin\` | Deleted-file metadata and small recovered Recycle Bin artifacts. |
| `RemoteAccess\` | AnyDesk and TeamViewer related artifacts. |
| `System\` | Autoruns, services, USB history, local groups, scheduled tasks, software inventory, and more. |
| `SystemConfig\` | System information, local users, and firewall-related outputs. |
| `VSS_Artifacts\` | Selected locked files collected via Volume Shadow Copy workflows. |
| `Hashes.csv` | SHA256 hashes of collected artifacts. |
| `Findings\` | CE findings in CSV, JSONL, and text-summary form. |
| `Executive_Report.html` | Quick HTML summary of host context, findings, and collection overview. |
| `Timeline\PowerTriage_Timeline_Chronos.json` | Chronos-compatible timeline JSON with required event fields. |
| `Network\Nexus_Graph_Lite.json` | Lightweight Nexus graph JSON for CE workflows. |
| `PowerTriage.log` | Execution log with timestamps. |

When `-OutputRetention Both` or `-OutputRetention ZipOnly` is used, the ZIP file is created alongside the output directory in the selected parent path.

## CE vs PRO for Windows

| Capability | CE | PRO |
|---|---|---|
| Windows live triage | Yes | Yes |
| Modular PowerShell collection | Yes | Yes |
| Browser, user, system, process, network, event artifacts | Yes | Yes |
| Optional live packet capture with `pktmon` | Yes | Yes |
| VSS-oriented live collection | Yes | Yes |
| Basic hashing and packaged output | Yes | Yes |
| Offline mounted-volume collection | No | Yes |
| Offline hives and user artifacts | No | Yes |
| Offline NTFS metadata collection | No | Yes |
| Chain of custody package | No | Yes |
| HTML summary reporting | Yes | Yes |
| Advanced archive handling | No | Yes |

## Operational Notes

- Run from an elevated PowerShell session when possible.
- `pktmon` packet capture requires elevation and is intended for live collection only.
- `Both` is the safest default for remote work because it preserves the full tree even if moving a large ZIP becomes inconvenient.
- `ZipOnly` only removes the directory after successful ZIP creation. If compression fails, PowerTriage keeps the directory tree.
- Locked `WebCache` and `ActivitiesCache` files are retried with live fallbacks and each failure is written explicitly to `PowerTriage.log`.
- Test in a controlled lab before production deployment.
- Review collected artifacts according to your organization’s evidence-handling procedures.

## Author

**Jesus D. Angosto** (`@jdangosto`)

- X/Twitter: [@jdangosto](https://twitter.com/jdangosto)
- GitHub: [jdangosto](https://github.com/jdangosto)
- Project: [PowerForensics](https://powerforensics.es)

## Disclaimer

This tool is provided "as is" without warranty of any kind. Use it at your own risk. Always test in a controlled environment before using it in production or during a live investigation.
