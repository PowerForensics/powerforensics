# PowerTriage Windows (Community Edition)

> **Acquire. Preserve. Analyze later.**

**PowerTriage Windows Community Edition** is a native PowerShell collector designed for Digital Forensics and Incident Response (DFIR) on Windows workstations and servers.

Its purpose is deliberately simple:

**Acquire high-value forensic artifacts quickly, consistently and with minimal operational impact.**

Rather than performing automated detection, incident scoring or evidence interpretation, PowerTriage focuses on collecting structured forensic evidence that can be analyzed using the investigator's preferred workflow, forensic tools or the **PowerForensics** ecosystem.

---

# Why PowerTriage?

PowerTriage was developed from real-world Incident Response experience.

Many investigations require obtaining a reliable snapshot of a compromised system quickly, often under operational constraints where deploying additional software, installing agents or executing complex frameworks is not desirable.

PowerTriage addresses this scenario by providing a lightweight native collector that:

* Executes directly in PowerShell.
* Requires no external binaries in the Community Edition.
* Produces structured outputs suitable for later analysis.
* Maintains a modular architecture for targeted acquisitions.
* Prioritizes artifact acquisition over automated interpretation.

PowerTriage is a **collector**, not an analysis platform.

---

# Design Principles

PowerTriage is built around a small number of core design principles.

* Native PowerShell implementation.
* No external binary dependencies (Community Edition).
* Modular acquisition architecture.
* Low deployment friction.
* Low operational impact.
* Structured evidence collection.
* DFIR-first design.
* Practical over theoretical.

---

# Architecture

```
                Windows System

                      │

                      ▼

               PowerTriage Collector

                      │

      ┌───────────────┼────────────────┐

      ▼               ▼                ▼

  System          Network          Processes

      ▼               ▼                ▼

 Persistence      Event Logs      User Activity

      ▼               ▼                ▼

 Browsers        Cloud Apps        File System

                      │

                      ▼

             Structured Evidence

                      │

                      ▼

              Offline Investigation
```

PowerTriage intentionally separates **collection** from **analysis**.

This approach allows investigators to use the collected evidence with their preferred forensic workflow while preserving flexibility and minimizing collection complexity.

---

# Key Capabilities

## System

* Host information
* Environment variables
* Timezone
* Local users
* Local groups
* Administrator enumeration
* Installed software
* USB history
* Clipboard collection

---

## Network

* TCP connections with process correlation
* UDP endpoints
* DNS cache
* Network configuration
* Routing table
* ARP cache
* SMB information
* Firewall configuration
* Firewall rules
* Optional live packet capture using native **pktmon**

---

## Process Execution

* Running processes
* Process tree
* SHA256 hashing
* Executable path verification
* Digital signature verification (where available)

---

## Persistence

* Scheduled Tasks
* Windows Services
* Autoruns
* Startup folders

---

## Event Collection

Collection of key Windows Event Logs including:

* Security
* System
* Application
* PowerShell
* Sysmon (when available)
* RDP
* WMI
* Additional incident-response relevant logs

---

## User Activity

* PowerShell Console History
* Recent Files
* Windows Timeline artifacts
* Recycle Bin
* Prefetch

---

## Browser Artifacts

Collection from common Windows browsers including:

* Browsing history
* Cookies
* Login databases
* Preferences
* Browser profiles
* Installed extensions
* Extension manifests
* SHA256 hashing of collected extension metadata

---

## Email

Where available:

* Microsoft Outlook
* Thunderbird
* Windows Mail

---

## Cloud Storage

Collection of local artifacts related to:

* Microsoft OneDrive
* Microsoft Teams
* Google Drive
* Dropbox

---

## Remote Access

Collection of artifacts related to:

* AnyDesk
* TeamViewer

---

## Locked Evidence

When supported, PowerTriage performs Volume Shadow Copy based acquisition of selected locked artifacts including:

* Registry hives
* User hives
* Amcache
* SRUM
* Selected forensic artifacts

---

# Modular Architecture

PowerTriage is designed around modular collectors.

Depending on the investigation requirements, individual acquisition modules can be executed independently, allowing investigators to reduce acquisition time and operational impact while focusing on the evidence required for a particular case.

---

# Requirements

* Windows 10
* Windows 11
* Windows Server 2016+
* PowerShell 5.1 or later

Administrator privileges are recommended for complete acquisition.

Without elevation, PowerTriage will continue collecting accessible artifacts while safely skipping protected resources.

---

# Installation

## PowerShell Gallery

```powershell
Install-Script PowerTriage
```

## Manual

Download **PowerTriage.ps1** from this repository and execute locally.

---

# Usage

## Default Execution

```powershell
.\PowerTriage.ps1
```

When no collection mode is specified, PowerTriage now runs the full Community Edition workflow by default and writes the output to the current directory.

Use `-Minimal` only when you want a reduced volatile triage focused on `Network`, `System`, and `Process`.

---

## Output Directory

```powershell
.\PowerTriage.ps1 -OutputDirectory "D:\Cases\Case001"
```

---

## Output Retention

```powershell
.\PowerTriage.ps1 -OutputRetention Both
.\PowerTriage.ps1 -OutputRetention DirectoryOnly
.\PowerTriage.ps1 -OutputRetention ZipOnly
```

`Both` is the default and preserves both the uncompressed evidence directory and the final ZIP package.

This is especially useful for remote collection workflows where a large ZIP may be difficult to transfer in a single pass and the analyst may prefer to retrieve only selected files or directories.

---

## Minimal Collection

```powershell
.\PowerTriage.ps1 -Minimal
```

---

## Full Workflow

```powershell
.\PowerTriage.ps1 -Full
```

`-Full` executes the complete Community Edition workflow, including:

* Full artifact collection
* Chronos timeline export
* Nexus Lite graph export
* Findings generation
* `Executive_Report.html`

The Chronos timeline is exported in a compatible JSON format and includes the required `id`, `timestamp`, and `title` fields expected by Chronos.

---

## Packet Capture

```powershell
.\PowerTriage.ps1 -PacketCaptureQuick
```

or

```powershell
.\PowerTriage.ps1 -PacketCapture
```

---

## Help

```powershell
.\PowerTriage.ps1 -Help
```

---

# Output Structure

PowerTriage generates a structured evidence directory and, depending on `-OutputRetention`, can also generate a ZIP package in parallel or keep only one of the two output forms.

Typical outputs include:

* Activities Cache
* Browser Artifacts
* Cloud Storage
* Email Artifacts
* Event Logs
* Network Information
* Packet Capture
* PowerShell History
* Prefetch
* Process Information
* Recent Items
* Recycle Bin
* Remote Access
* System Information
* System Configuration
* VSS Artifacts
* `Timeline\PowerTriage_Timeline_Chronos.json`
* `Network\Nexus_Graph_Lite.json`
* `Findings\Findings.csv`
* `Findings\Findings.jsonl`
* `Findings\Findings_Summary.txt`
* `Executive_Report.html`
* SHA256 Hashes
* Execution Log

---

# Operational Notes

* Execute from an elevated PowerShell session whenever possible.
* Packet capture requires administrative privileges.
* Test in controlled environments before production deployment.
* Always follow your organization's evidence handling procedures.

---

# Roadmap

Current development focuses on:

* Expanding forensic artifact coverage.
* Improving modular acquisition.
* Enhancing server-oriented collection.
* Continuous stability and performance improvements.

PowerTriage will continue evolving while maintaining its core philosophy of lightweight, structured evidence acquisition.

---

# Contributing

Community feedback, testing and artifact suggestions are always welcome.

Practical DFIR experience is especially valuable for guiding future development.

---

# Author

**Jesús D. Angosto**

DFIR | Incident Response | Digital Forensics

GitHub:
https://github.com/jdangosto

Project:

https://powerforensics.es

---

# Disclaimer

PowerTriage is provided **as is**, without warranty of any kind.

Always validate its behaviour in controlled environments before operational deployment.

The operator remains responsible for ensuring that evidence acquisition complies with applicable legal, regulatory and organizational requirements.
