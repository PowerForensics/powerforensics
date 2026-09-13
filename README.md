# PowerForensics Ecosystem

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/powerforensics_bn.png">
    <source media="(prefers-color-scheme: light)" srcset="assets/powerforensics.png">
    <img alt="PowerForensics - Digital Evidence Ecosystem" src="assets/powerforensics_color.png">
  </picture>
</p>

PowerForensics is a DFIR ecosystem built for incident responders to go from **evidence preparation and acquisition** to **timeline correlation** and **graph analysis** — with clear, transparent workflows and no black boxes.

This organization hosts the **Community Edition (CE)** tools and DFIR utilities:

* **PowerForensics - WriteGuard** — Logical write protection and forensic host preparation for Windows.
* **PowerTriage Windows** — Portable forensic triage in PowerShell for Windows.
* **PowerTriage Linux** — Standalone Bash triage for Linux systems.
* **PowerTriage IoT** — Triage for IoT/OpenWRT and embedded environments.
* **Forge (CE)** — Normalization engine that converts raw artifacts into unified events.

> Web applications such as Chronos, Nexus and Analysis are offered as services and are not published as source code here. This organization distributes open tooling, Community Edition components and DFIR utilities related to evidence preparation, acquisition, triage and normalization.

---

## Ecosystem Pillars

* **PowerForensics - WriteGuard**
  Logical write protection and forensic host preparation for Windows:

  * Enables Windows logical write protection through `StorageDevicePolicies`.

  * Disables and verifies automatic volume mounting.

  * Provides a pre-acquisition host Self-Check.

  * Records disk metadata and can calculate SHA-256 directly against physical devices.

  * Supports controlled `Offline` operations for compatible external disks.

  * Includes bilingual GUI and CLI operation.

  > WriteGuard is a logical protection layer. It does **not** replace a validated forensic hardware write blocker and does not by itself guarantee evidence immutability.

* **PowerTriage**
  Portable triage tools for Windows, Linux and IoT:

  * Extract key artifacts such as Amcache, Prefetch, SRUM, authentication logs, sessions and persistence information.
  * MITRE ATT&CK summaries when applicable.
  * Structured export in JSON, CSV and HTML formats ready for downstream analysis.

* **Forge (Community Edition)**
  Normalizes heterogeneous inputs to a unified event schema:

  * Fields such as `timestamp`, `asset`, `source`, `type`, `severity`, `message` and `metadata`.
  * Designed to feed timeline analysis in Chronos and relationship graphs in Nexus.

---

## Investigation Workflow

PowerForensics components can be combined into a modular DFIR workflow:

```text
Prepare
   │
   └── PowerForensics - WriteGuard
            │
            ▼
Acquire / Collect
   │
   └── PowerTriage
            │
            ▼
Normalize
   │
   └── Forge
            │
            ├── Chronos → Timeline analysis
            │
            └── Nexus   → Relationship analysis
                         │
                         ▼
                    Analysis
```

Each component can also be used independently according to the requirements of the investigation.

---

## Main Repositories

Repository names may vary; this index shows the intended content:

* `writeguard` — Windows logical write protection and forensic host preparation.
* `powertriage-windows` — PowerShell-based Windows forensic triage.
* `powertriage-linux` — Bash-based triage for Linux environments.
* `powertriage-iot` — Triage for IoT/OpenWRT and embedded systems.
* `forge-ce` — Community Edition normalization engine for DFIR events.

Future additions may include:

* Parsers such as `authlog-parser`, `syslog-parser` or `apache-access-parser`.
* Auxiliary utilities to integrate evidence and normalized results with timeline and graph analysis.
* Additional evidence-preparation and acquisition utilities.

---

## PowerForensics - WriteGuard

**PowerForensics - WriteGuard** is a Windows PowerShell utility designed to reduce the risk of accidental modification of digital evidence before acquisition.

Its recommended workflow is:

1. Ensure the evidence device is not connected.
2. Prepare the forensic host using WriteGuard.
3. Verify the host state using the built-in Self-Check.
4. Restart Windows when operational procedures allow it.
5. Run the Self-Check again.
6. Connect the evidence only after the host reports that it is ready.
7. Perform acquisition against the physical device using the selected forensic acquisition tool.
8. Restore the host when the acquisition process is complete.

WriteGuard uses native Windows mechanisms including:

* `StorageDevicePolicies\WriteProtect`
* `automount disable`
* `automount scrub`
* `Get-Disk`
* `diskpart`

It can also:

* Record disk model, serial number and capacity.
* Calculate SHA-256 directly against a physical device.
* Maintain an audit log of relevant operations.
* Request compatible external disks to enter an `Offline` state.
* Operate through a graphical interface or CLI.

> Some Windows storage-policy changes may require a system restart before they are applied or reflected consistently. When possible, restart the forensic host after preparation and run the Self-Check again before connecting evidence.

> WriteGuard provides **logical write protection only**. It must not be considered equivalent to a dedicated or validated forensic hardware write blocker.

---

## Web & Documentation

* Website: https://powerforensics.es
* Product access:

  * Chronos: https://chronos.powerforensics.es
  * Nexus: https://nexus.powerforensics.es
* Documentation: see the **Docs** section on the PowerForensics website.

---

## Privacy & Data Egress

PowerForensics prioritizes **local-first** analysis and **zero data egress** by default.

If cloud APIs, external AI providers or third-party endpoints are integrated into custom workflows:

* Enforce HTTPS.
* Avoid sending sensitive evidence outside the authorized environment.
* Follow applicable legal, contractual and organizational requirements.
* Clearly document any external data-processing path.
* Keep evidentiary facts separate from automated or AI-generated interpretation.

---

## Licensing

* **Community Edition tools and DFIR utilities**

  Unless stated otherwise, CE tooling repositories and open DFIR utilities in this organization are licensed under the **Apache License 2.0**.

  See the `LICENSE` file in each repository for the applicable terms.

* **Platform applications — Chronos, Nexus and Analysis**

  These are **proprietary products**. Their source code is not distributed in this organization.

  Repositories that reference them serve as informational placeholders only.

---

## DFIR Principles

PowerForensics follows a simple evidence-first approach:

* Preserve original evidence whenever possible.
* Minimize unnecessary interaction with evidence sources.
* Keep raw evidence separate from derived data.
* Document acquisition and processing limitations.
* Preserve hashes, timestamps and source relationships.
* Separate observable facts from inference and hypothesis.
* Do not treat automated or AI-generated conclusions as evidence.
* Require analyst review for investigative conclusions.

> **Evidence first. AI assists the analyst; it does not replace the analyst.**

---

## Contact

* General: [contacto@powerforensics.es](mailto:contacto@powerforensics.es)
* Website: https://powerforensics.es
* GitHub Organization: https://github.com/PowerForensics
