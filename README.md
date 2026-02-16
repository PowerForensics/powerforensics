# PowerForensics Ecosystem

PowerForensics is a DFIR ecosystem built for incident responders to go from **evidence acquisition** to **timeline correlation** and **graph analysis** — with clear, transparent workflows (no black boxes).

This organization hosts the **Community Edition (CE)** tools:

- PowerTriage Windows — Portable forensic triage in PowerShell for Windows.
- PowerTriage Linux — Standalone Bash triage for Linux systems.
- PowerTriage IoT — Triage for IoT/OpenWRT and embedded environments.
- Forge (CE) — Normalization engine that converts raw artifacts into unified events.

> Web applications (Chronos, Nexus, Analysis) are offered as services and are not published as source code here. This organization distributes open tooling (CE) and DFIR utilities related to acquisition and normalization.

---

## Ecosystem Pillars

- **PowerTriage**  
  Portable triage tools for Windows, Linux, and IoT:
  - Extract key artifacts (e.g., Amcache, Prefetch, SRUM, auth logs, sessions, persistence).
  - MITRE ATT&CK summaries when applicable.
  - Structured export (JSON/CSV/HTML) ready for downstream analysis.

- **Forge (Community Edition)**  
  Normalizes heterogeneous inputs to a unified event schema:
  - Fields such as `timestamp`, `asset`, `source`, `type`, `severity`, `message`, `metadata`.
  - Designed to feed timeline (Chronos) and relation graphs (Nexus).

---

## Main Repositories

Repository names may vary; this index shows the intended content:

- `powertriage-windows` — PowerShell-based Windows forensic triage.
- `powertriage-linux` — Bash-based triage for Linux environments.
- `powertriage-iot` — Triage for IoT/OpenWRT and embedded systems.
- `forge-ce` — Community Edition normalization engine for DFIR events.

Future additions (optional):

- Parsers (e.g., `authlog-parser`, `syslog-parser`, `apache-access-parser`).
- Auxiliary utilities to integrate results with timeline and graph analysis.

---

## Web & Documentation

- Website: https://powerforensics.es
- Product access:
  - Chronos: https://chronos.powerforensics.es
  - Nexus: https://nexus.powerforensics.es
- Documentation: see the “Docs” section on the website.

---

## Privacy & Data Egress

PowerForensics prioritizes **local-first** analysis and **zero data egress** by default.  
If you integrate cloud APIs or external endpoints in custom workflows:

- Enforce HTTPS and avoid sending sensitive data outside your environment.
- Provide clear responsibility notices in configurations and documentation.

---

## Licensing

- **Community Edition tools (this organization)**  
  Unless stated otherwise, CE tooling repositories in this organization are licensed under the **Apache License 2.0**.  
  See the `LICENSE` file in each repository for full details.

- **Platform applications (Chronos, Nexus, Analysis)**  
  These are **proprietary products**. Their source code is not distributed in this organization.  
  Repositories that reference them serve as informational placeholders only.

---

## Contact

- General: contacto@powerforensics.es  
- GitHub Organization: https://github.com/PowerForensics
