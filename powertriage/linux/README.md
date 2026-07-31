# PowerTriage Linux

PowerTriage Linux is a Bash-based live response and forensic triage collector for Linux systems.

It is designed for DFIR work on servers, cloud workloads, containers, and production systems where the analyst needs fast evidence collection with a low dependency footprint.

PowerTriage Linux is part of the PowerForensics ecosystem.


It can be used as a standalone collector or as the Linux acquisition component within the broader PowerForensics DFIR workflow.

## What's New

Compared with the previously published Linux collector, the current version adds:

- optional AVML memory acquisition with authorization and download auditing
- local account, shadow status, sudoers, and privileged-group review
- Docker, Podman, and CRI/Kubernetes inventory
- installed package inventory for Debian, RPM-based, and Alpine systems
- DNS, host resolution, routing, neighbor, listener, and firewall collection
- advanced persistence checks for recent systemd units, path units, `ld.so.preload`, package integrity, `memfd`, shell profiles, and recently modified web scripts
- dedicated Apache/httpd acquisition for processes, services, virtual hosts, modules, configurations, logs, and web roots
- dedicated Java and Tomcat acquisition for processes, services, environment files, configurations, logs, and deployed web applications
- optional metadata-only `FileTree` export with configurable roots, depth, and entry limits
- fast, strict, and non-interactive execution modes
- structured artifact inventory, SHA256 hashing, execution logs, and error logs

## Positioning

PowerTriage Linux is not intended to be a full Unix artifact framework or a direct replacement for tools such as UAC. Its goal is different:

- provide practical first-pass Linux triage
- run with standard system tooling where possible
- collect high-value artifacts quickly
- produce outputs that are easy to review, archive, and import into PowerForensics workflows
- keep the collector understandable and portable

Future work will move the collector toward a more modular structure while keeping this practical triage focus.

## Main Capabilities

### System Context

- Hostname, kernel, uptime, users, groups, and basic OS information.
- Local account and privilege review using `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/sudoers`, and sudo/wheel/adm groups.
- Installed package inventory using `dpkg`, `rpm`, or `apk` when available.

### Memory

- Optional RAM acquisition through AVML.
- In interactive mode, the script asks for authorization before downloading AVML.
- In `--auto` mode, AVML download is treated as authorized and recorded in the acquisition log.
- In strict mode, external download behavior is disabled.
- The AVML decision is documented in `00_avml_download_documentation.txt`.

### Processes and Open Files

- Process tree and full process listing.
- Environment-rich process output through `ps`.
- Deleted executable references under `/proc`.
- Open file inventory through `lsof` when available.

### Network

- Interfaces, routes, neighbors, listening sockets, and active network services.
- DNS and host resolution files:
  - `/etc/resolv.conf`
  - `/etc/hosts`
  - `/etc/nsswitch.conf`
- Firewall state from `iptables-save`, `nft`, and `ufw` when present.

### Persistence

- Cron and AT-related artifacts.
- Init scripts and `rc.local`.
- Systemd services and timers.
- Kernel modules.
- SSH server configuration and user `authorized_keys` paths.

### Advanced Persistence and Intrusion Clues

- Recently modified systemd units.
- Systemd path units.
- `/etc/ld.so.preload`.
- Basic package integrity checks for core utilities.
- `memfd` usage for potential fileless execution.
- Shell startup files such as `.bashrc`, `.profile`, and `.zshrc`.
- Quick scan for recently modified web script files in common web roots.

### Containers

- Docker containers, images, and networks.
- Podman containers, images, and networks.
- CRI/Kubernetes visibility through `crictl` when available.

### Web Server Artifacts

PowerTriage Linux includes first-pass collection for common web application incident response scenarios.

Apache collection includes:

- Apache/httpd processes.
- Listeners on ports 80 and 443.
- `apache2` and `httpd` systemd service status.
- Apache version and build information.
- Virtual host listing through `apache2ctl`, `apachectl`, or `httpd`.
- Loaded modules.
- Configuration paths such as:
  - `/etc/apache2`
  - `/etc/httpd`
  - `/usr/local/apache2/conf`
  - `/usr/local/etc/apache24`
- Logs from:
  - `/var/log/apache2`
  - `/var/log/httpd`
  - `/usr/local/apache2/logs`
  - `/usr/local/var/log/apache2`
- Web roots such as `/var/www` and `/srv/www`.

Tomcat and Java collection includes:

- Java presence and `java -version`.
- Java home candidates under `/usr/lib/jvm`, `/opt/java`, `/opt/jdk`, and `/usr/java`.
- Tomcat/Catalina processes.
- Common Tomcat listeners on ports 8080, 8005, 8009, and 8443.
- Tomcat-related systemd services.
- Tomcat environment files under `/etc/default` and `/etc/sysconfig`.
- Configuration and runtime paths such as:
  - `/etc/tomcat*`
  - `/usr/share/tomcat*`
  - `/opt/tomcat`
  - `/opt/apache-tomcat`
  - `/opt/apache-tomcat-*`
- Logs from:
  - `/var/log/tomcat*`
  - `/opt/tomcat/logs`
  - `/opt/apache-tomcat/logs`
  - `/opt/apache-tomcat-*/logs`
- Webapps inventory in fast mode, or webapps copy in full mode.

### Filesystem and Timeline

- Filesystem listing with `find`.
- Optional metadata-only `FileTree` export for filesystem navigation and later processing.
- MAC timestamp timeline exported to `timeline_file.csv`.
- In fast mode, filesystem and timeline scope are reduced to high-value paths.

### Archives and Hashes

- Optional archive of `/home`, `/root`, and `/var/log`.
- Recent systemd journal export when `journalctl` is available.
- SHA256 hashes for collected evidence.
- `ForensicCatalog.json` as a structured inventory of collected evidence.

## Requirements

- Linux host with Bash.
- Root privileges are required by the current collector.
- Standard Unix tools such as `ps`, `find`, `tar`, `sha256sum`, `ss`, and `cp`.
- Optional tools improve coverage:
  - `lsof`
  - `pstree`
  - `journalctl`
  - `iptables-save`
  - `nft`
  - `ufw`
  - `docker`
  - `podman`
  - `crictl`
  - `apache2ctl`, `apachectl`, or `httpd`
  - `java`
  - `systemctl`

## Usage

Make the script executable:

```bash
chmod +x PowerTriage_Linux.sh
```

Run interactively:

```bash
sudo ./PowerTriage_Linux.sh
```

Interactive mode asks where the evidence should be written: external storage, `/dev/shm`, or the current directory. It does not present a module-selection menu; the collection scope is controlled through command-line parameters.

Run in non-interactive fast mode:

```bash
sudo ./PowerTriage_Linux.sh --auto --fast
```

`--auto` runs without prompts and uses the current directory as the output base. Because memory collection is enabled by default, use `--no-memory` when automatic AVML download and execution has not been explicitly authorized.

Run in strict mode:

```bash
sudo ./PowerTriage_Linux.sh --strict --fast
```

Skip specific heavy or optional steps:

```bash
sudo ./PowerTriage_Linux.sh --auto --no-memory --no-timeline --no-lsof
```

Skip directory archives and the journal export stage:

```bash
sudo ./PowerTriage_Linux.sh --auto --no-tar
```

Export a navigable metadata-only filesystem tree:

```bash
sudo ./PowerTriage_Linux.sh --auto --filetree
```

Limit FileTree collection to selected roots:

```bash
sudo ./PowerTriage_Linux.sh --auto --fast --filetree --filetree-root=/etc --filetree-root=/var/log
```

## Parameters

| Parameter | Description |
|---|---|
| `--interactive` | Interactive mode. This is the default. |
| `--auto` | Non-interactive execution. |
| `--strict` | Conservative non-interactive mode. Disables external AVML download behavior. |
| `--fast` | Reduces expensive filesystem, timeline, and archive operations. |
| `--no-memory` | Skips memory acquisition. |
| `--no-timeline` | Skips filesystem timeline generation. |
| `--no-tar` | Skips creation of the `/home`, `/root`, and `/var/log` archives and the journal export stage. |
| `--no-lsof` | Skips open file collection through `lsof`. |
| `--filetree` | Exports a metadata-only filesystem tree index. |
| `--filetree-root=<path>` | Adds a custom FileTree root. Repeatable. |
| `--filetree-max-depth=<n>` | Maximum FileTree traversal depth. |
| `--filetree-max-entries=<n>` | Maximum FileTree entries. |
| `--help`, `-h` | Displays command-line help. |

## Output

The script creates a directory named:

```text
powertriage_linux_<hostname>_<UTC timestamp>
```

Typical output includes:

| Path | Description |
|---|---|
| `00_metadata_pre_triage.txt` | Pre-triage metadata and timestamps. |
| `00_avml_download_documentation.txt` | AVML download and authorization context, when applicable. |
| `powertriage.log` | Execution log. |
| `powertriage_errors.log` | Errors and warnings. |
| `system_info.txt` | Host, OS, users, groups, and general system context. |
| `users_local.txt` | Local user, shadow status, sudoers, and privileged groups. |
| `processes.txt` | Process tree, process list, and deleted executable references. |
| `open_files_lsof.txt` | Open files from `lsof`, when available. |
| `network_info.txt` | Network, DNS, routes, neighbors, listeners, and firewall state. |
| `containers.txt` | Docker, Podman, and CRI/Kubernetes inventory. |
| `installed_packages.txt` | Package inventory. |
| `user_history_files/` | Shell and application history files by user. |
| `persistence.txt` | Cron, init, systemd, SSH, and kernel module persistence artifacts. |
| `advanced_persistence.txt` | Rootkit, fileless, shell profile, and recent web script checks. |
| `apache_artifacts/` | Apache inventory, configs, logs, and web root artifacts. |
| `tomcat_artifacts/` | Java/Tomcat inventory, configs, logs, and webapps artifacts. |
| `directory_and_files.txt` | Filesystem listing. |
| `FileSystem/FileTree.jsonl` | Metadata-only filesystem tree index. |
| `FileSystem/FileTree_Summary.json` | FileTree generation summary. |
| `FileSystem/FileTree_Errors.txt` | FileTree traversal errors and skipped paths. |
| `timeline_file.csv` | Filesystem MAC timestamp timeline. |
| `journal_recent.txt` | Recent systemd journal output. |
| `journal_errors.txt` | High-priority journal errors from current boot. |
| `home.tar.gz` | `/home` archive, except in fast mode or when unavailable. |
| `root.tar.gz` | `/root` archive. |
| `logs.tar.gz` | `/var/log` archive. |
| `memory.mem` | Memory image, when AVML is available and enabled. |
| `hashes.txt` | SHA256 hashes of collected files. |
| `ForensicCatalog.json` | Structured inventory of collected artifacts and hashes. |

The collector keeps the evidence directory available for direct review. It does not currently create a single final archive containing the complete acquisition.

## Fast Mode Behavior

`--fast` is intended for first-pass triage when time, disk space, or operational impact matters.

In fast mode:

- broad filesystem listing is limited to high-value paths
- default FileTree roots are limited to `/etc`, `/var/log`, and `/root`
- timeline generation is limited to high-value paths
- `/home` archive is skipped
- Apache web roots are listed selectively instead of copied wholesale
- Apache logs are limited to recent access/error/log files
- Tomcat webapps are listed selectively instead of copied wholesale
- Tomcat logs are limited to recent log-like files

## Forensic Notes

- Run from trusted media where possible.
- Prefer writing output to external storage or a prepared evidence mount.
- Any live response collection changes system state to some degree.
- Memory acquisition and external binary download require explicit authorization in real cases.
- `ForensicCatalog.json` and `FileTree.jsonl` are complementary:
  - the catalog tracks collected artifacts
  - the FileTree index provides a navigable directory view
- Review `powertriage_errors.log` after execution to understand skipped paths or unavailable tools.

## Roadmap

Planned direction:

- modularize collection areas without losing Bash portability

- introduce clearer module inventory and per-module summaries

- improve web server coverage for Apache, Tomcat, Nginx, and common application stacks

- improve structured output for downstream forensic workflows

- keep PowerTriage focused on practical operational triage rather than becoming a generic Unix artifact framework

Future work will continue expanding artifact coverage, improving modularity, and enhancing structured outputs while maintaining the project's practical DFIR-first philosophy.

## Author

Jesus D. Angosto

- Blog: https://www.dfirspain.es
- PowerForensics: https://powerforensics.es

## Disclaimer

This tool is provided as-is, without warranty of any kind. Use it only on systems where you have authorization. Test in a controlled environment before using it in production or during an incident.
