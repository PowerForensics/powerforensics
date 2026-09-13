# PowerForensics WriteGuard

> **Logical write protection and forensic host preparation for Windows**

> Documentation reviewed against the script on August 18, 2026.

## Description

**WriteGuard** is an interactive PowerShell utility designed specifically for Digital Forensics and Incident Response (DFIR) environments as part of the **PowerForensics** ecosystem.

Its main purpose is to **reduce the risk of accidental evidence contamination** by applying logical write protection at the operating-system level and disabling automatic volume mounting before compatible external storage devices are connected.

WriteGuard is intended to prepare the forensic host **before** evidence is connected, reducing unnecessary interaction between Windows and the device and minimizing the risk of unintended modifications to filesystem metadata, mount information, or other states associated with volume access.

Some Windows configuration changes may not behave consistently until the system has been restarted. Therefore, whenever the operating procedure allows it, it is recommended to **restart the forensic host after preparation and run the Self-Check again before connecting evidence**.

This protection is not absolute. Volumes should not be mounted or opened in Windows Explorer when maximum preservation is required.

> **⚠️ IMPORTANT FORENSIC WARNING**
>
> WriteGuard provides an additional layer of logical write protection and forensic-host preparation using Windows mechanisms, including `StorageDevicePolicies` and `automount` control.
>
> **It does not replace a validated forensic hardware write blocker and does not by itself guarantee evidence immutability.** Its effectiveness may depend on the device, driver, interface, and bridge being used.
>
> WriteGuard should be used as a complementary control or risk-reduction mechanism when dedicated forensic hardware is unavailable, and always within a previously validated acquisition procedure.

---

## Project Status

WriteGuard is under active development as part of the PowerForensics ecosystem.

The tool implements logical protection mechanisms provided by Windows and is intended to act as an additional safety layer for DFIR operations.

It is not a hardware write blocker and does not imply forensic certification of the write-protection mechanism.

Its behavior should be validated in a controlled environment before operational deployment.

---

## Quick Start

```powershell
.\WriteGuard.ps1 -PrepareForensicHost
.\WriteGuard.ps1 -SelfCheck
```

**Connect evidence only after obtaining `HOST READY`.**

Whenever operational procedures allow it, restart Windows after preparing the host and run:

```powershell
.\WriteGuard.ps1 -SelfCheck
```

again before connecting evidence.

---

## Main Features

* **Logical Write Protection:** Modifies the `WriteProtect` value under `StorageDevicePolicies`, requesting that Windows treat compatible removable storage as read-only. Effectiveness depends on the device, driver, interface, and bridge used.

* **Automount Disable:** Uses `diskpart` to prevent Windows from automatically assigning drive letters or mount points to newly connected partitions and validates the effective host state.

* **Automount Scrub:** During preparation, WriteGuard can execute `automount scrub`, removing historical mount-point assignments for volumes that are not currently present.

* **Host Self-Check:** Verifies before acquisition:

  * administrative elevation;
  * `WriteProtect=1`;
  * `NoAutoMount=1`;
  * absence of compatible candidate disks already connected.

  Candidate detection is limited to USB, SD, MMC, FireWire, and 1394 buses as reported by Windows through `Get-Disk`.

* **Dual Interface:**

  * **GUI:** Bilingual Windows Forms interface in Spanish and English with traffic-light-style visual indicators.
  * **CLI:** Command-line operation for automation or remote execution.

* **Automatic Elevation:** Detects whether Administrator privileges are available and requests elevation through UAC when required.

* **Audit Logging:** Automatically creates `WriteGuard.log`, recording protection changes, automount state, Self-Check results, metadata, hashes, cancellations, and relevant Offline operations, including available user, date, host, and status information.

* **Evidence Management:** Allows basic disk metadata to be recorded:

  * model;
  * serial number;
  * size.

* **Integrity Verification:** Calculates SHA-256 directly against the physical device using block-based reads, including progress reporting and safe handle release on completion or failure.

* **Controlled Offline State:** Allows compatible external disks to be requested into an `Offline` state. This reduces operating-system interaction but does not constitute certified ejection or replace safe-removal procedures.

* **Additional Protection:** Evidence Management excludes disks identified as system or boot devices to reduce the risk of accidental operations against internal storage.

---

## Graphical Interface

Run the script without parameters:

```powershell
.\WriteGuard.ps1
```

Depending on Windows file associations, double-clicking a `.ps1` file may open an editor instead of executing the script. Direct PowerShell execution is therefore recommended.

The initial language is selected using `$PSUICulture`:

* `es-*` cultures → Spanish;
* all others → English.

The language can also be selected manually from the GUI or specified with:

```powershell
-Language es
-Language en
```

The selected language is preserved during UAC elevation.

### GUI Buttons

1. **Enable Logical Protection**
   Sets `WriteProtect=1`.

2. **Disable Logical Protection**
   Restores `WriteProtect=0`.

3. **Prepare Forensic Host (⭐ RECOMMENDED)**
   Enables logical write protection and disables `automount`.

   This should be performed **before evidence is connected**.

4. **Restore Host**
   Reverts WriteGuard changes, restoring write access and automatic mounting.

5. **Host Self-Check**
   Verifies that the system is correctly prepared before evidence connection.

6. **View Detected Disks**
   Displays detected disks, including system, boot, and current-state information.

7. **Evidence Management**
   Opens a dedicated panel allowing the operator to:

   * record metadata;
   * calculate SHA-256;
   * request an `Offline` state.

   For safety, only compatible external-bus candidates are shown, while system and boot disks are excluded.

8. **Exit**
   Closes WriteGuard.

9. **About**
   Displays information about WriteGuard and the PowerForensics ecosystem in the selected language.

---

## Command-Line Usage

```powershell
# Launch the graphical interface
.\WriteGuard.ps1

# Explicitly launch the GUI in Spanish or English
.\WriteGuard.ps1 -GUI -Language es
.\WriteGuard.ps1 -GUI -Language en

# Enable logical write protection
.\WriteGuard.ps1 -Lock

# Disable logical write protection
.\WriteGuard.ps1 -Unlock

# Prepare the host for forensic acquisition
# WriteProtect + Automount Disable
.\WriteGuard.ps1 -PrepareForensicHost

# Run the pre-acquisition host validation
.\WriteGuard.ps1 -SelfCheck

# Restore the host
# WriteProtect + Automount Enable
.\WriteGuard.ps1 -RestoreHost

# Display the current status
.\WriteGuard.ps1 -Status
```

`-Language es|en` can also be combined with CLI operations to select the language used by the Self-Check and any elevation-related dialogs.

---

## Recommended Physical Acquisition Workflow

1. Ensure that the evidence or external storage medium is **NOT connected**.

2. Open WriteGuard and select:

   **Prepare Forensic Host**

   or execute:

   ```powershell
   .\WriteGuard.ps1 -PrepareForensicHost
   ```

3. Run:

   ```powershell
   .\WriteGuard.ps1 -SelfCheck
   ```

   and confirm the final result:

   **HOST READY**

4. Whenever operational procedures allow it, **restart the system**.

   Some Windows configuration changes may require a reboot before they are applied or reflected consistently.

5. After rebooting, run:

   ```powershell
   .\WriteGuard.ps1 -SelfCheck
   ```

   again and confirm:

   **HOST READY**

6. Connect the evidence.

7. Use **View Detected Disks** to identify the device and confirm that it has not been mounted or assigned unexpectedly.

8. **Do not open the volume in Windows Explorer or browse its filesystem** when minimizing metadata or access-state modification is required.

9. Optionally, open **Evidence Management**, select the device, and use:

   * **Record Metadata**
   * **Calculate SHA-256**

   Physical hashing can be particularly useful when the acquisition tool does not provide integrated hashing.

10. Open the selected acquisition tool, for example:

* FTK Imager;
* X-Ways Forensics;
* another validated Windows-compatible acquisition tool.

11. Acquire the **Physical Drive** using the required format, such as:

* E01;
* Raw/DD.

If later recovery through file carving is required, perform it against the acquired physical image rather than the original evidence device.

12. Close the acquisition tool when imaging is complete.

13. From **Evidence Management**, request that the device be placed `Offline` when supported.

14. Confirm that no application is still using the disk and follow the safe-removal procedure supported by the device before disconnecting it.

An `Offline` state does not itself constitute safe or certified ejection.

15. Restore the host using the GUI or:

```powershell
.\WriteGuard.ps1 -RestoreHost
```

16. If Windows does not behave as expected after restoration, particularly regarding automount or storage policies, restart the system.

---

## System Requirements

* **Operating System:** Windows 10, Windows 11, or Windows Server 2012+
* **PowerShell:** 5.1 or later
* **Privileges:** Administrator
* **Third-party modules:** None required

WriteGuard relies only on native Windows mechanisms and utilities, including:

* `Get-Disk`
* `diskpart`
* Windows Registry

---

## Forensic Limitations

* `WriteProtect` and `automount disable` reduce the risk of accidental writes but are not equivalent to a validated forensic hardware write blocker.

* Some Windows configuration changes may require a **system restart** before they are applied or reflected consistently.

* After preparing the host, whenever operating procedures allow it, restarting Windows and running the Self-Check again before connecting evidence is recommended.

* When strict preservation of access-related metadata is required, the volume should not be mounted or browsed. Acquisition should be performed against the physical device.

* Some removable USB devices cannot be placed into an `Offline` state by Windows.

* External-device identification depends on the `BusType` reported by Windows.

  An enclosure or adapter presenting the device as:

  * SATA;
  * SCSI;
  * RAID;
  * NVMe;
  * or another unsupported bus;

  may not appear in Evidence Management and may not cause the Self-Check to invalidate host readiness.

* `automount scrub` removes historical mount-point assignments for absent volumes. This must be considered on hosts relying on persistent drive-letter mappings.

* Placing a disk `Offline` does not guarantee that all applications have released their handles and does not replace:

  * safe removal;
  * a hardware write blocker;
  * or a previously validated forensic procedure.

* WriteGuard depends on operating-system, driver, device, and bridge behavior and should be validated within the environment in which it will be used.

---

## Integration and Author

* **Project:** PowerForensics Ecosystem
* **Component:** WriteGuard
* **Website:** https://powerforensics.es
