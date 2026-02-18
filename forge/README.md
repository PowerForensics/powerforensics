# Forge - PowerForensics Evidence Processor

**"Forge converts raw evidence into structured investigations."**

Forge is the normalization and processing pillar of the PowerForensics ecosystem. Its main function is to ingest raw logs from various sources (Cloud, Systems, Network) and transform them into standardized formats consumable by analysis tools: **Chronos** (Timeline) and **Nexus** (Relational Graph).

## 🚀 Key Features

*   **Multi-Source Ingestion**: Capable of processing logs from AWS CloudTrail, Azure Monitor, O365, and GCP.
*   **Automatic Normalization**: Converts disparate events into a unified common JSON schema.
*   **Artifact Generation**:
    *   **Chronos Timeline**: Time-ordered events with severity metadata and MITRE ATT&CK mapping.
    *   **Nexus Graph**: Generation of nodes and edges representing relationships between identities, IP addresses, and affected resources.
    *   **Executive Summary**: Text report with key ingestion statistics (volume, severity, sources).

## 📊 Current Status & Roadmap

| Data Source | Status | Notes |
| :--- | :--- | :--- |
| **AWS CloudTrail** | ✅ Implemented | Full support for management and data events. |
| **Azure Monitor** | 🚧 Planned | In active development. |
| **Office 365 UAL** | 🚧 Planned | Coming soon. |
| **GCP Audit Logs** | 🚧 Planned | Coming soon. |

## 🛠️ Usage Guide

### Evidence Processing (Forge)

Run the main script `Forge.ps1` specifying the input file and log type.

```powershell
.\Forge.ps1 -InputPath ".\logs\cloudtrail_events.json" -LogType "CloudTrail" -OutChronos "timeline.json" -OutNexus "graph.json"
```

**Parameters:**

*   `-InputPath`: Path to the raw logs file (required).
*   `-LogType`: Source type (Default: `CloudTrail`). Currently supported options: `CloudTrail`.
*   `-OutChronos`: Output filename for Timeline (Default: `chronos_from_cloudtrail.json`).
*   `-OutNexus`: Output filename for Graph (Default: `nexus_from_cloudtrail.json`).
*   `-OutSummary`: Output filename for summary (Default: `executive_summary_from_cloudtrail.txt`).
*   `-CaseId`: Case identifier for traceability (optional).

### Test Data Generation (Python)

The directory includes Python scripts to generate synthetic logs and test Forge functionality.

**Requirements:** Python 3.x

1.  **Generate CloudTrail logs:**
    ```bash
    python generate_cloudtrailLog.py
    ```
    *Generates a JSON file with simulated CloudTrail events.*

## 📂 File Inventory

*   `Forge_Community_CloudTrail.ps1`: Specific version optimized for the community (focus on CloudTrail).
*   `generate_cloudtrailLog.py`: Utility script to generate CloudTrail test data.


---
*PowerForensics Ecosystem - Documentation Generated 2026*
