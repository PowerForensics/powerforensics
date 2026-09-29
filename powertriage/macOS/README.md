# PowerTriage macOS CE

PowerTriage macOS CE is the native macOS live-response and forensic-triage edition of PowerTriage. It is designed for fast field deployment, low dependency overhead, explicit handling of macOS privacy controls, and structured evidence output.

The current `0.1.x` line is a development preview. Validate it on representative Intel and Apple silicon test systems before using it in production investigations.

## Design principles

- One transportable Bash script.
- Native macOS commands and no downloaded runtime dependencies.
- Bash syntax compatible with the system-provided macOS Bash environment.
- Modular collection with `Minimal`, `Full`, and custom profiles.
- Separate reporting of root privileges and Full Disk Access.
- Bounded collection for large stores.
- No recursive permission changes on acquired evidence.
- No bulk collection of user documents or attachments.
- Sensitive communications and keychain databases require explicit consent.
- Source-to-destination manifest, operation status, SHA-256 inventory, and archive hash.
- Uncompressed evidence is retained by default.
- Diagnostic and crash reports receive bounded Windows-portable destination names while their original paths remain in the manifest.

## Quick start

Make the script executable:

```bash
chmod +x ./PowerTriage_macOS.sh
```

Run a first-pass collection:

```bash
sudo ./PowerTriage_macOS.sh --minimal --output-dir=/Volumes/Evidence
```

Run every CE module with bounded deep stores and a 48-hour Unified Log window:

```bash
sudo ./PowerTriage_macOS.sh --full --deep --since=48h --output-dir=/Volumes/Evidence
```

Run a custom unattended collection:

```bash
sudo ./PowerTriage_macOS.sh \
  --system --live --network --persistence --logs \
  --auto --retention=both --output-dir=/Volumes/Evidence
```

Display built-in help:

```bash
./PowerTriage_macOS.sh --help
```

## macOS permissions

Root and Full Disk Access are separate controls.

Running with `sudo` improves access to protected system paths, but it does not automatically grant Terminal, the remote-management agent, or another parent application access to privacy-protected user data. Before a full collection, grant Full Disk Access to the application from which PowerTriage is launched when organizational policy and legal authority permit it.

PowerTriage probes representative protected paths and records Full Disk Access as:

- `available`: a representative protected artifact exists and is readable.
- `limited`: a representative artifact exists but is not readable.
- `unknown`: no reliable representative path was found.

This is a practical preflight signal, not an Apple authorization API. The manifest and collection status remain the authoritative record of what was acquired or blocked.

Without sufficient access, normal execution continues in degraded mode. `--strict` instead requires both root and detected Full Disk Access.

## Profiles

### Minimal

`--minimal` enables:

- Context
- System
- LiveResponse
- Network
- Persistence
- Logs
- Security

It does not acquire per-user activity databases or browser profiles.

### Full

`--full` adds:

- Users
- Browsers
- FileSystem

`--full` remains bounded. It does not imply `--deep` or `--include-sensitive`.

### Custom

Select one or more modules directly:

```bash
sudo ./PowerTriage_macOS.sh --live --network --persistence --auto
```

## Scope and privacy controls

- `--fast`: default bounded scope. Unified Logs are exported using a targeted predicate, while raw high-volume filesystem stores are not copied.
- `--deep`: additionally creates a bounded `.logarchive` and attempts bounded acquisition of FSEvents, Spotlight, and DocumentRevisions stores.
- `--since=24h`: controls the Unified Log lookback. Accepted suffixes are `m`, `h`, and `d`.
- `--max-copy-mb=1024`: skips any individual source whose measured size exceeds the limit.
- `--include-sensitive`: enables selected Messages, Mail envelope-index, and login-keychain database artifacts. Message bodies, mail stores, documents, and attachments are not bulk-copied.

## Modules

| Module | Purpose |
|---|---|
| Context | Execution metadata, macOS version, kernel, time, SIP, FileVault, mounts, and permission state |
| System | Hardware/software profile, APFS and disk layout, accounts, NVRAM, power and configuration context |
| LiveResponse | Processes, hierarchy, open files, sessions, launchd state, memory and activity snapshots |
| Network | Interfaces, sockets, routes, ARP, DNS, proxy, Wi-Fi metadata and firewall state |
| Persistence | System/user LaunchAgents, LaunchDaemons, background tasks, cron, hooks and extensions |
| Logs | Targeted Unified Logs, optional bounded logarchive, install log and diagnostic reports |
| Users | Shell, SSH, quarantine, KnowledgeC, TCC, recent-item and selected preference artifacts |
| Browsers | Safari, Chrome, Edge, Brave, Chromium and Firefox profile databases |
| FileSystem | APFS snapshot context and optional bounded FSEvents, Spotlight and revision stores |
| Security | Gatekeeper, profiles, packages, software history, firewall and XProtect resources |
| FileTree | Optional metadata-only JSONL tree with depth and entry limits |

The detailed acquisition contract is documented in [ARTIFACT_MATRIX.md](ARTIFACT_MATRIX.md). Real-system compatibility results are tracked in [VALIDATION.md](VALIDATION.md).

## FileTree

The FileTree export is optional and metadata-only:

```bash
sudo ./PowerTriage_macOS.sh --minimal --filetree
```

Custom roots and limits:

```bash
sudo ./PowerTriage_macOS.sh --filesystem --filetree \
  --filetree-root=/Library \
  --filetree-root=/Users \
  --filetree-max-depth=10 \
  --filetree-max-entries=75000
```

Default roots are `/Applications`, `/Library`, and `/Users`. Traversal remains on the source root's device and excludes the active PowerTriage output directory.

## Output

A collection directory is named like:

```text
powertriage_macos_HOST_2026-08-12_14-30-00_UTC/
```

Typical output:

```text
00_Context/
System/
LiveResponse/
Network/
Persistence/
Logs/
Users/
Browsers/
FileSystem/
Security/
Timeline/
artifact_manifest.csv
collection_status.csv
ForensicCatalog.json
hashes.sha256
errors.log
powertriage_macos.log
SUMMARY.md
```

The archive is created beside the directory using macOS `ditto`. Its SHA-256 is stored in a separate `.zip.sha256` file.

### Retention

- `--retention=both`: keep the directory and ZIP. This is the default.
- `--retention=directory-only`: do not create a ZIP.
- `--retention=archive-only`: remove the directory only after ZIP creation, hashing, and strict target validation succeed.
- `--no-archive`: alias for `directory-only`.

## Evidence records

- `artifact_manifest.csv`: module, status, source, destination, size, source modification time, per-file SHA-256, and note.
- `collection_status.csv`: success, partial, skipped, missing, blocked, and failed operations.
- `expected_absent` status entries identify optional paths that are not present without inflating the incomplete-collection count.
- `hashes.sha256`: final SHA-256 inventory generated only after internal reports and logs stop changing.
- `ForensicCatalog.json`: normalized case, target, execution, and output metadata.
- `SUMMARY.md`: human-readable handoff and collection boundaries.
- `Timeline/PowerTriage_Timeline_Chronos.json`: Chronos-compatible artifact timeline based on source modification times.

## Important limitations

- This is live triage, not physical or logical disk imaging.
- Running on a live system can affect volatile state and access times.
- APFS snapshots, FileVault, SIP, privacy controls, and application sandboxing can limit access.
- A source can change while it is being copied. PowerTriage records the acquired result and reports command failures, but it cannot freeze the live filesystem.
- Browser and SQLite databases may be live. Associated WAL and SHM files are collected when present.
- Metadata-preserving copies can be restricted by macOS. When file content remains readable, PowerTriage retries without ACLs, extended attributes, and resource forks and reports the result as `partial`.
- The first release requires functional validation on supported macOS versions before production use.

## CE and future Pro scope

PowerTriage macOS CE is intentionally focused on live response. Future Pro-oriented work can add controlled acquisition from mounted APFS volumes and images, snapshot-aware workflows, chain-of-custody records, advanced reporting, and large-case packaging without weakening the CE collector.
