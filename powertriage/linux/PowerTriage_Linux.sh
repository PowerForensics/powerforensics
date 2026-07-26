#!/bin/bash
#############################################################
#                 PowerTriage Linux  v 2.0.0                #
#        Live Response & Forensic Triage Tool               #
#                                                           #
#  Author: Jesús D. Angosto                                 #
#  PowerForensics: https://powerforensics.es                #
#  Blog: https://www.dfirspain.es                           #
#############################################################

set -euo pipefail
IFS=$'\n\t'
umask 077

########################
# MODES / FLAGS
########################
MODE="interactive"   # interactive | auto | strict
SCOPE="full"         # full | fast

DO_MEMORY="yes"
DO_TIMELINE="yes"
DO_TAR="yes"
DO_LSOF="yes"
DO_FILETREE="no"
FILETREE_MAX_DEPTH=20
FILETREE_MAX_ENTRIES=250000
FILETREE_ROOTS=()

usage() {
cat <<'USAGE'
PowerTriage Linux - Live Response & Forensic Triage

Usage:
  sudo ./PowerTriage_Linux.sh [options]

Execution:
  --interactive              Interactive mode (default)
  --auto                     Non-interactive execution
  --strict                   Conservative non-interactive mode
  --fast                     Reduce expensive collection operations

Collection:
  --no-memory                Skip memory acquisition
  --no-timeline              Skip filesystem timeline generation
  --no-lsof                  Skip open-file collection with lsof
  --filetree                 Export a metadata-only filesystem tree
  --filetree-root=<path>     Add a FileTree root (repeatable)
  --filetree-max-depth=<n>   Maximum FileTree depth (default: 20)
  --filetree-max-entries=<n> Maximum FileTree entries (default: 250000)

Output:
  --no-tar                   Keep the output directory without final packaging
  --help, -h                 Show this help
USAGE
}

for arg in "$@"; do
  case "$arg" in
    --help|-h) usage; exit 0 ;;
    --interactive) MODE="interactive" ;;
    --auto) MODE="auto" ;;
    --strict) MODE="strict" ;;
    --fast) SCOPE="fast" ;;
    --no-memory) DO_MEMORY="no" ;;
    --no-timeline) DO_TIMELINE="no" ;;
    --no-tar) DO_TAR="no" ;;
    --no-lsof) DO_LSOF="no" ;;
    --filetree) DO_FILETREE="yes" ;;
    --filetree-root=*) FILETREE_ROOTS+=("${arg#*=}") ;;
    --filetree-max-depth=*) FILETREE_MAX_DEPTH="${arg#*=}" ;;
    --filetree-max-entries=*) FILETREE_MAX_ENTRIES="${arg#*=}" ;;
    *)
      echo "[ERROR] Unknown argument: $arg"
      usage
      exit 1
      ;;
  esac
done

if ! [[ "$FILETREE_MAX_DEPTH" =~ ^[0-9]+$ ]]; then
  echo "[ERROR] --filetree-max-depth must be a non-negative integer."
  exit 1
fi

if ! [[ "$FILETREE_MAX_ENTRIES" =~ ^[1-9][0-9]*$ ]]; then
  echo "[ERROR] --filetree-max-entries must be a positive integer."
  exit 1
fi

########################
# GLOBAL VARIABLES
########################
HOSTNAME_SHORT=$(hostname -s)
CASE_UTC=$(date -u +"%Y-%m-%d_%H-%M-%S_UTC")
BASEDIR_NAME="powertriage_linux_${HOSTNAME_SHORT}_${CASE_UTC}"

BASEDIR=""
LOG_FILE=""
ERROR_FILE=""

########################
# HELPERS
########################
log() {
  echo -e "$*" | tee -a "$LOG_FILE"
}

json_escape() {
  local s="${1-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

sha1_text() {
  local value="${1-}"
  printf '%s' "${value,,}" | sha1sum | awk '{print $1}'
}

epoch_to_utc() {
  local epoch="${1-}"
  if [[ -z "$epoch" || "$epoch" == "-1" || "$epoch" == "0" ]]; then
    printf ''
    return 0
  fi
  date -u -d "@$epoch" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || printf ''
}

filetree_get_roots() {
  local roots=()
  local root=""
  if [[ ${#FILETREE_ROOTS[@]} -gt 0 ]]; then
    for root in "${FILETREE_ROOTS[@]}"; do
      if [[ -n "$root" ]]; then
        roots+=("${root%/}")
      fi
    done
  elif [[ "$SCOPE" == "fast" ]]; then
    roots=(/etc /var/log /root)
  else
    roots=(/)
  fi
  printf '%s\n' "${roots[@]}" | awk 'NF { if (!seen[$0]++) print }'
}

FILETREE_JSONL_PATH=""
FILETREE_SUMMARY_PATH=""
FILETREE_ERRORS_PATH=""
FILETREE_LAST_NODE_ID=""
FILETREE_ENTRY_COUNT=0
FILETREE_DIR_COUNT=0
FILETREE_FILE_COUNT=0
FILETREE_ERROR_COUNT=0
FILETREE_TRUNCATED="no"

filetree_write_node() {
  local actual="$1"
  local parent_id="$2"
  local root_path="$3"
  local depth="$4"
  local full_path="$actual"
  local name parent_path volume node_type extension size created_epoch modified_epoch accessed_epoch
  local created_utc modified_utc accessed_utc attributes node_id

  name="$(basename "$actual")"
  if [[ "$actual" == "/" ]]; then
    name="/"
  fi
  parent_path="$(dirname "$actual")"
  if [[ "$actual" == "/" ]]; then
    parent_path=""
  fi
  volume="/"

  if [[ -d "$actual" ]]; then
    node_type="directory"
    extension=""
    size=0
    attributes="Directory"
  else
    node_type="file"
    extension=""
    if [[ "$name" == *.* && "$name" != .* ]]; then
      extension=".${name##*.}"
    fi
    size="$(stat -c %s "$actual" 2>/dev/null || echo 0)"
    attributes="Regular"
  fi

  if [[ -L "$actual" ]]; then
    attributes="${attributes},Symlink"
  fi
  if [[ ! -w "$actual" ]]; then
    attributes="${attributes},ReadOnly"
  fi

  created_epoch="$(stat -c %W "$actual" 2>/dev/null || echo -1)"
  modified_epoch="$(stat -c %Y "$actual" 2>/dev/null || echo -1)"
  accessed_epoch="$(stat -c %X "$actual" 2>/dev/null || echo -1)"
  created_utc="$(epoch_to_utc "$created_epoch")"
  modified_utc="$(epoch_to_utc "$modified_epoch")"
  accessed_utc="$(epoch_to_utc "$accessed_epoch")"
  node_id="$(sha1_text "$full_path")"

  printf '{"id":"%s","parent_id":"%s","volume":"%s","root":"%s","parent_path":"%s","name":"%s","full_path":"%s","type":"%s","extension":"%s","size":%s,"created_utc":"%s","modified_utc":"%s","accessed_utc":"%s","attributes":"%s","depth":%s,"source":"PowerTriage.FileTree"}\n' \
    "$(json_escape "$node_id")" \
    "$(json_escape "$parent_id")" \
    "$(json_escape "$volume")" \
    "$(json_escape "$root_path")" \
    "$(json_escape "$parent_path")" \
    "$(json_escape "$name")" \
    "$(json_escape "$full_path")" \
    "$(json_escape "$node_type")" \
    "$(json_escape "$extension")" \
    "$size" \
    "$(json_escape "$created_utc")" \
    "$(json_escape "$modified_utc")" \
    "$(json_escape "$accessed_utc")" \
    "$(json_escape "$attributes")" \
    "$depth" >> "$FILETREE_JSONL_PATH"

  FILETREE_LAST_NODE_ID="$node_id"
  FILETREE_ENTRY_COUNT=$((FILETREE_ENTRY_COUNT + 1))
  if [[ "$node_type" == "directory" ]]; then
    FILETREE_DIR_COUNT=$((FILETREE_DIR_COUNT + 1))
  else
    FILETREE_FILE_COUNT=$((FILETREE_FILE_COUNT + 1))
  fi
}

filetree_walk() {
  local actual="$1"
  local parent_id="$2"
  local root_path="$3"
  local depth="$4"

  if [[ "$FILETREE_ENTRY_COUNT" -ge "$FILETREE_MAX_ENTRIES" ]]; then
    FILETREE_TRUNCATED="yes"
    return 0
  fi

  if [[ ! -e "$actual" ]]; then
    printf 'Root not found or inaccessible: %s\n' "$actual" >> "$FILETREE_ERRORS_PATH"
    FILETREE_ERROR_COUNT=$((FILETREE_ERROR_COUNT + 1))
    return 0
  fi

  filetree_write_node "$actual" "$parent_id" "$root_path" "$depth"
  local node_id="$FILETREE_LAST_NODE_ID"

  if [[ ! -d "$actual" || -L "$actual" || "$depth" -ge "$FILETREE_MAX_DEPTH" ]]; then
    return 0
  fi

  local child=""
  while IFS= read -r -d '' child; do
    if [[ "$child" == "$BASEDIR" || "$child" == "$BASEDIR/"* ]]; then
      continue
    fi
    if [[ "$child" == /proc/* || "$child" == /sys/* || "$child" == /dev/* || "$child" == /run/* ]]; then
      continue
    fi
    filetree_walk "$child" "$node_id" "$root_path" $((depth + 1))
    if [[ "$FILETREE_ENTRY_COUNT" -ge "$FILETREE_MAX_ENTRIES" ]]; then
      FILETREE_TRUNCATED="yes"
      break
    fi
  done < <(find "$actual" -xdev -mindepth 1 -maxdepth 1 -print0 2>>"$FILETREE_ERRORS_PATH" | sort -z)
}

check_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "[ERROR] This script must be executed as root."
    exit 1
  fi
}

banner() {
cat <<EOF
=============================================================
    ____                       ______     _                  _
  / __ \____ _      _____ _  /_  __/____(_)___ _____ ____ _(_)
  / /_/ / __ \ | /| / / _ \ |  / / / ___/ / __ '/ __ '/ _ '/ /
 / ____/ /_/ / |/ |/ /  __/ | / / / /  / / /_/ / /_/ /  __/ /
/_/    \____/|__/|__/\___/|_|/_/ /_/  /_/\__,_/\__, /\___/_/
                                              /____/

 PowerTriage Linux - Live Response & Forensic Triage
 MODE: ${MODE} | Scope: ${SCOPE}
 PowerForensics: https://powerforensics.es
=============================================================
EOF
}

FIN() {
  log ""
  log "============================================================="
  log "[INFO] PowerTriage Linux execution completed"
  log "[INFO] Evidence directory: ${BASEDIR}"
  log "============================================================="
}

########################
# METADATA MITIGATION
########################
capture_metadata() {
  local META_FILE="${BASEDIR}/00_metadata_pre_triage.txt"

  log "[MITIGATION] Capturing pre-triage metadata (timestamps)..."

  {
    echo "Host: ${HOSTNAME_SHORT}"
    echo "Case UTC: ${CASE_UTC}"
    echo "Execution UTC: $(date -u)"
    echo
    echo "File | atime | mtime | ctime | atime_epoch | mtime_epoch | ctime_epoch"
    echo "====================================================================="
    for f in /etc/passwd /etc/shadow /var/log/auth.log /var/log/syslog /root/.bash_history; do
      [[ -f "$f" ]] && stat -c "%n | %x | %y | %z | %X | %Y | %Z" "$f"
    done
  } > "$META_FILE" 2>>"$ERROR_FILE"
}

########################
# ACQUISITION SETUP
########################
setupAcquisition() {

  if [[ "$MODE" != "interactive" ]]; then
    BASEDIR="./${BASEDIR_NAME}"
    mkdir -p "$BASEDIR"

    LOG_FILE="${BASEDIR}/powertriage.log"
    ERROR_FILE="${BASEDIR}/powertriage_errors.log"

    log "[INFO] MODE=${MODE}: non-interactive execution."
    log "[INFO] Evidence destination will not be requested."
    log "[INFO] If no external destination is prepared,"
    log "[INFO] local disk will be used by design."

    capture_metadata
    return
  fi

  echo
  echo "[CONFIGURATION] Select evidence destination:"
  echo "1) External storage (recommended)"
  echo "2) RAM (/dev/shm)"
  echo "3) Local disk"
  read -p "> " CHOICE

  case "${CHOICE:-3}" in
    1)
      read -p "Mount point (e.g. /mnt/forensic): " MNT
      if [[ -d "$MNT" ]] && ! mount | grep -q "$MNT.*(ro"; then
        BASEDIR="$MNT/$BASEDIR_NAME"
      else
        echo "[WARNING] Invalid or read-only mount. Using local disk."
        BASEDIR="./$BASEDIR_NAME"
      fi
      ;;
    2)
      if [[ "$(df -m /dev/shm | awk 'NR==2 {print $4}')" -gt 500 ]]; then
        BASEDIR="/dev/shm/$BASEDIR_NAME"
      else
        echo "[WARNING] Insufficient RAM. Using local disk."
        BASEDIR="./$BASEDIR_NAME"
      fi
      ;;
    *)
      BASEDIR="./$BASEDIR_NAME"
      ;;
  esac

  mkdir -p "$BASEDIR"
  LOG_FILE="${BASEDIR}/powertriage.log"
  ERROR_FILE="${BASEDIR}/powertriage_errors.log"

  log "[INFO] Evidence directory: ${BASEDIR}"
  capture_metadata
}

########################
# AVML MEMORY HANDLING
########################
check_internet() {
  [[ "$MODE" == "strict" ]] && return 1
  ping -c1 1.1.1.1 >/dev/null 2>&1 || curl -Is https://github.com >/dev/null 2>&1
}

document_avml_decision() {
  local DOC="${BASEDIR}/00_avml_download_documentation.txt"

  {
    echo "Host: ${HOSTNAME_SHORT}"
    echo "Case UTC: ${CASE_UTC}"
    echo "TS_UTC: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "MODE: ${MODE}"
    echo
    echo "FORENSIC NOTICE:"
    echo " - Downloading/executing external binaries may alter evidence"
    echo " - Operator or client authorization is required"
    echo " - This file and the main log document the decision"
  } > "$DOC"
}

maybe_download_avml() {
  local AVML_BIN="${BASEDIR}/avml"

  [[ -x "$AVML_BIN" ]] && return 0
  [[ "$MODE" == "strict" ]] && return 1
  check_internet || return 1

  document_avml_decision

  if [[ "$MODE" == "interactive" ]]; then
    echo
    echo "[WARNING] AVML download may alter system evidence."
    echo "Do you have explicit authorization to proceed?"
    echo "1) Yes"
    echo "2) No"
    read -p "> " ANSWER
    [[ "$ANSWER" == "1" ]] || return 1
  else
    log "[INFO] MODE=auto: AVML download authorized and documented."
  fi

  local URL="https://github.com/microsoft/avml/releases/download/v0.14.0/avml"
  log "[MEMORY] Downloading AVML from: $URL"

  curl -L --silent "$URL" -o "$AVML_BIN"
  chmod +x "$AVML_BIN"
  sha256sum "$AVML_BIN" | tee -a "$LOG_FILE"
}

collect_memory() {
  [[ "$DO_MEMORY" != "yes" ]] && return
  log "[MEMORY] Memory acquisition started..."
  maybe_download_avml || { log "[MEMORY] AVML not available. Skipping memory capture."; return; }
  "$BASEDIR/avml" "$BASEDIR/memory.mem" 2>>"$ERROR_FILE"
}

########################
# PROCESS COLLECTION
########################
collect_processes() {
  log "[PROCESS] Collecting process information..."
  {
    pstree -p
    ps auxwwwe
    ls -alR /proc/*/exe 2>/dev/null | grep deleted || true
  } > "$BASEDIR/processes.txt"
}

collect_open_files() {
  [[ "$DO_LSOF" != "yes" ]] && return

  if ! command -v lsof >/dev/null 2>&1; then
    log "[LSOF] lsof not available. Skipping open files collection."
    return
  fi

  log "[LSOF] Collecting open files..."
  {
    lsof -nP
  } > "$BASEDIR/open_files_lsof.txt" 2>>"$ERROR_FILE" || true
}

########################
# SYSTEM / NETWORK / FS
########################
collect_system_info() {
  log "[SYSTEM] Collecting system information..."
  {
    hostnamectl || true
    uname -a || true
    uptime || true
    who || true
    last -x 2>/dev/null || echo "[Error] 'last' command not found or failed"
    cat /etc/passwd 2>/dev/null || true
    cat /etc/group 2>/dev/null || true
    crontab -l 2>/dev/null || true
  } > "$BASEDIR/system_info.txt" 2>>"$ERROR_FILE"
}

collect_network() {
  log "[NETWORK] Collecting network information..."
  {
    ip addr
    ss -tulnp
    ip route
    ip neigh
    echo
    echo "===== DNS / HOSTS ====="
    [[ -f /etc/resolv.conf ]] && { echo "--- /etc/resolv.conf ---"; cat /etc/resolv.conf; echo; }
    [[ -f /etc/hosts ]] && { echo "--- /etc/hosts ---"; cat /etc/hosts; echo; }
    [[ -f /etc/nsswitch.conf ]] && { echo "--- /etc/nsswitch.conf ---"; grep "hosts:" /etc/nsswitch.conf; echo; }
    echo

    echo "===== FIREWALL RULES ====="
    if command -v iptables-save >/dev/null 2>&1; then
      echo "--- iptables-save ---"
      iptables-save 2>/dev/null || echo "Error saving iptables rules or permission denied."
      echo
    fi
    if command -v nft >/dev/null 2>&1; then
      echo "--- nft list ruleset ---"
      nft list ruleset 2>/dev/null || echo "Error listing nftables ruleset or permission denied."
      echo
    fi
    if command -v ufw >/dev/null 2>&1; then
      echo "--- ufw status ---"
      ufw status verbose 2>/dev/null || echo "Error checking ufw status."
      echo
    fi
  } > "$BASEDIR/network_info.txt" 2>>"$ERROR_FILE" || true
}

collect_containers() {
  log "[CONTAINERS] Collecting container information..."
  {
    if command -v docker >/dev/null 2>&1; then
      echo "===== DOCKER ====="
      docker ps -a --no-trunc 2>/dev/null || echo "[Error running docker ps]"
      echo
      docker network ls 2>/dev/null || true
      echo
      docker images 2>/dev/null || true
    fi

    if command -v podman >/dev/null 2>&1; then
      echo
      echo "===== PODMAN ====="
      podman ps -a --no-trunc 2>/dev/null || echo "[Error running podman ps]"
      echo
      podman network ls 2>/dev/null || true
      echo
      podman images 2>/dev/null || true
    fi

    if command -v crictl >/dev/null 2>&1; then
      echo
      echo "===== CRICTL (K8s) ====="
      crictl ps -a 2>/dev/null || true
      crictl pods 2>/dev/null || true
    fi
  } > "$BASEDIR/containers.txt" 2>>"$ERROR_FILE" || true
}

collect_packages() {
  log "[PACKAGES] Collecting installed packages..."
  {
    if command -v dpkg >/dev/null 2>&1; then
      echo "===== DPKG (Debian/Ubuntu) ====="
      dpkg -l 2>/dev/null || true
    fi

    if command -v rpm >/dev/null 2>&1; then
      echo "===== RPM (RHEL/CentOS) ====="
      rpm -qa --last 2>/dev/null || rpm -qa 2>/dev/null || true
    fi
    
    if command -v apk >/dev/null 2>&1; then
      echo "===== APK (Alpine) ====="
      apk info -vv 2>/dev/null || true
    fi
  } > "$BASEDIR/installed_packages.txt" 2>>"$ERROR_FILE" || true
}

collect_user_activity() {
  log "[USER_ACTIVITY] Collecting user history files..."
  local HIST_DIR="${BASEDIR}/user_history_files"
  mkdir -p "$HIST_DIR"

  # Helper to collect history
  collect_hist() {
    local user="$1"
    local home="$2"
    [[ -d "$home" ]] || return 0

    for histfile in .bash_history .zsh_history .sh_history .mysql_history .psql_history .viminfo .lesshst .python_history; do
      if [[ -f "${home}/${histfile}" ]]; then
        # Copy file as username_filename.txt
        cp "${home}/${histfile}" "${HIST_DIR}/${user}_${histfile}.txt" 2>/dev/null || true
      fi
    done
    true
  }

  if command -v getent >/dev/null 2>&1; then
    while IFS=: read -r user _ uid _ _ home _; do
      [[ "$uid" -ge 0 ]] && collect_hist "$user" "$home"
    done < <(getent passwd)
  else
    collect_hist "root" "/root"
    for home in /home/*; do
      collect_hist "$(basename "$home")" "$home"
    done
  fi
  true
}

collect_users_local() {
    log "[USERS] Collecting local user info..."
    {
        echo "===== SHADOW STATUS ====="
        # Extract username and password status (P/L/NP) without hashes
        awk -F: '{print $1, $2}' /etc/shadow 2>/dev/null | grep -v '*' | grep -v '!' || echo "No active password users found or no read permission."
        
        echo
        echo "===== SUDOERS ====="
        if [[ -r /etc/sudoers ]]; then
            grep -vE "^#|^$" /etc/sudoers 2>/dev/null || true
        else
            echo "[WARNING] Cannot read /etc/sudoers"
        fi
        
        echo
        echo "===== SUDO/WHEEL GROUPS ====="
        grep -E "^(sudo|wheel|adm):" /etc/group 2>/dev/null || true

    } > "$BASEDIR/users_local.txt" 2>>"$ERROR_FILE" || true
}


collect_persistence() {
  log "[PERSISTENCE] Collecting persistence artifacts..."

  {
    echo "TS_UTC: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "HOST: ${HOSTNAME_SHORT}"
    echo "MODE: ${MODE}"
    echo "SCOPE: ${SCOPE}"
    echo

    echo "===== CRON / AT ====="
    cat /etc/crontab 2>/dev/null || true
    ls -al /etc/cron* 2>/dev/null || true
    if [[ -d /etc/cron.d ]]; then
      for f in /etc/cron.d/*; do
        [[ -f "$f" ]] || continue
        echo
        echo "--- $f ---"
        cat "$f" 2>/dev/null || true
      done
    fi
    echo

    echo "===== INIT ====="
    ls -al /etc/init.d 2>/dev/null || true
    ls -al /etc/rc*.d 2>/dev/null || true
    [[ -f /etc/rc.local ]] && { echo; echo "--- /etc/rc.local ---"; cat /etc/rc.local 2>/dev/null || true; }
    echo

    echo "===== SYSTEMD ====="
    if command -v systemctl >/dev/null 2>&1; then
      systemctl list-unit-files --type=service --no-pager 2>/dev/null || true
      echo
      systemctl list-timers --all --no-pager 2>/dev/null || true
    else
      echo "systemctl not available."
    fi
    echo

    echo "===== KERNEL MODULES ====="
    lsmod 2>/dev/null || true
    echo

    echo "===== SSH (SYSTEM) ====="
    ls -al /etc/ssh 2>/dev/null || true
    [[ -f /etc/ssh/sshd_config ]] && { echo; echo "--- /etc/ssh/sshd_config ---"; cat /etc/ssh/sshd_config 2>/dev/null || true; }
    echo

    echo "===== USER AUTHORIZED_KEYS (PATHS) ====="
    if command -v getent >/dev/null 2>&1; then
      while IFS=: read -r user _ uid _ _ home _; do
        [[ "$uid" -ge 0 ]] || continue
        [[ -d "$home" ]] || continue
        [[ -f "$home/.ssh/authorized_keys" ]] && echo "${user}: ${home}/.ssh/authorized_keys"
      done < <(getent passwd)
    else
      for home in /home/*; do
        [[ -d "$home" ]] || continue
        [[ -f "$home/.ssh/authorized_keys" ]] && echo "$(basename "$home"): ${home}/.ssh/authorized_keys"
      done
      [[ -f /root/.ssh/authorized_keys ]] && echo "root: /root/.ssh/authorized_keys"
    fi
  } > "$BASEDIR/persistence.txt" 2>>"$ERROR_FILE" || true
}

collect_advanced_persistence() {
  log "[ADVANCED] Collecting advanced persistence artifacts (Miners/Rootkits)..."
  {
    echo "TS_UTC: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "HOST: ${HOSTNAME_SHORT}"
    echo
    
    echo "===== SYSTEMD ADVANCED (Path Units & Recent) ====="
    # Buscar unidades modificadas en los ultimos 7 dias
    echo "--- Systemd Units Modified in last 7 days ---"
    find /etc/systemd/system /lib/systemd/system -mtime -7 -type f -ls 2>/dev/null || echo "No recent modifications found."
    echo
    echo "--- Systemd Path Units ---"
    systemctl list-units --type=path --all --no-pager 2>/dev/null || echo "No path units found."
    echo

    echo "===== ROOTKIT INDICATORS ====="
    echo "--- /etc/ld.so.preload ---"
    if [[ -f /etc/ld.so.preload ]]; then
      echo "[WARNING] Found /etc/ld.so.preload:"
      cat /etc/ld.so.preload
    else
      echo "Not found (Good)."
    fi
    echo
    
    echo "===== BINARY INTEGRITY CHECK (Criticals) ====="
    # Verificacion basica de integridad de paquetes para binarios criticos
    if command -v dpkg >/dev/null 2>&1; then
      echo "--- Debian/Ubuntu dpkg verification ---"
      dpkg -V coreutils procps net-tools iproute2 2>/dev/null | grep -E "5.......|..5....." || echo "No obvious modifications detected in core packages."
    elif command -v rpm >/dev/null 2>&1; then
      echo "--- RHEL/CentOS rpm verification ---"
      rpm -Va coreutils procps net-tools iproute 2>/dev/null | grep -E "^..5" || echo "No obvious modifications detected in core packages."
    else
      echo "Package manager verification not available."
    fi
    echo

    echo "===== FILELESS EXECUTION (Memfd) ====="
    echo "--- Processes using memfd (potential fileless malware) ---"
    # Buscar descriptores de archivo que apunten a memfd
    find /proc/*/fd -ls 2>/dev/null | grep "memfd:" || echo "No memfd usage detected."
    echo

    echo "===== SHELL PROFILES & RC SCRIPTS ====="
    for f in /etc/profile /etc/bash.bashrc /etc/rc.local /root/.bashrc /root/.profile; do
      if [[ -f "$f" ]]; then
        echo "--- $f ---"
        tail -n 20 "$f"
        echo
      fi
    done
    # User profiles
    if command -v getent >/dev/null 2>&1; then
        while IFS=: read -r user _ uid _ _ home _; do
            [[ "$uid" -ge 1000 ]] || [[ "$uid" -eq 0 ]] || continue
            [[ -d "$home" ]] || continue
            for p in ".bashrc" ".profile" ".zshrc"; do
                if [[ -f "$home/$p" ]]; then
                    echo "--- $user: $home/$p (Last 10 lines) ---"
                    tail -n 10 "$home/$p"
                    echo
                fi
            done
        done < <(getent passwd)
    fi
    echo

    echo "===== WEB SHELL SUSPICIOUS FILES (Quick Scan) ====="
    # Buscar archivos php, jsp, py, sh recientes en directorios web comunes
    echo "--- Web files modified in last 7 days (Limit 50) ---"
    find /var/www /usr/share/nginx/html -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.py" -o -name "*.sh" \) -mtime -7 -ls 2>/dev/null | head -n 50 || echo "No recent web scripts found."

  } > "$BASEDIR/advanced_persistence.txt" 2>>"$ERROR_FILE" || true
}

collect_apache_artifacts() {
  log "[APACHE] Collecting Apache artifacts..."
  local APACHE_DIR="${BASEDIR}/apache_artifacts"
  local CONFIG_DIR="${APACHE_DIR}/config"
  local LOG_DIR="${APACHE_DIR}/logs"
  mkdir -p "$CONFIG_DIR" "$LOG_DIR"

  copy_apache_path() {
    local src="$1"
    local dest_root="$2"
    local dest="${dest_root}/${src#/}"
    [[ -e "$src" ]] || return 0
    mkdir -p "$(dirname "$dest")"
    cp -a "$src" "$dest" 2>>"$ERROR_FILE" || true
  }

  {
    echo "TS_UTC: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "HOST: ${HOSTNAME_SHORT}"
    echo "MODE: ${MODE}"
    echo "SCOPE: ${SCOPE}"
    echo

    echo "===== APACHE PROCESSES ====="
    ps auxww 2>/dev/null | grep -E "[a]pache2|[h]ttpd" || echo "No Apache/httpd processes found."
    echo

    echo "===== LISTENING PORTS 80/443 ====="
    ss -tulnp 2>/dev/null | grep -E ":(80|443)[[:space:]]" || echo "No listeners detected on 80/443."
    echo

    echo "===== SYSTEMD SERVICES ====="
    if command -v systemctl >/dev/null 2>&1; then
      systemctl status apache2 --no-pager 2>/dev/null || true
      echo
      systemctl status httpd --no-pager 2>/dev/null || true
    else
      echo "systemctl not available."
    fi
    echo

    echo "===== APACHE VERSION / BUILD ====="
    for cmd in apache2ctl apachectl httpd; do
      if command -v "$cmd" >/dev/null 2>&1; then
        echo "--- $cmd -v ---"
        "$cmd" -v 2>/dev/null || true
        echo
        echo "--- $cmd -V ---"
        "$cmd" -V 2>/dev/null || true
        echo
      fi
    done

    echo "===== VIRTUAL HOSTS ====="
    for cmd in apache2ctl apachectl httpd; do
      if command -v "$cmd" >/dev/null 2>&1; then
        echo "--- $cmd -S ---"
        "$cmd" -S 2>/dev/null || true
        echo
      fi
    done

    echo "===== LOADED MODULES ====="
    for cmd in apache2ctl apachectl httpd; do
      if command -v "$cmd" >/dev/null 2>&1; then
        echo "--- $cmd -M ---"
        "$cmd" -M 2>/dev/null || true
        echo
      fi
    done
  } > "${APACHE_DIR}/apache_inventory.txt" 2>>"$ERROR_FILE" || true

  for path in \
    /etc/apache2 \
    /etc/httpd \
    /usr/local/apache2/conf \
    /usr/local/etc/apache24 \
    /var/www \
    /srv/www; do
    if [[ "$SCOPE" == "fast" && ( "$path" == "/var/www" || "$path" == "/srv/www" ) ]]; then
      find "$path" -xdev -maxdepth 3 -type f \
        \( -name "*.conf" -o -name ".htaccess" -o -name "*.php" -o -name "*.jsp" -o -name "*.py" -o -name "*.sh" \) \
        -ls > "${APACHE_DIR}/$(echo "${path#/}" | tr '/' '_')_fast_listing.txt" 2>>"$ERROR_FILE" || true
      continue
    fi
    copy_apache_path "$path" "$CONFIG_DIR"
  done

  for path in \
    /var/log/apache2 \
    /var/log/httpd \
    /usr/local/apache2/logs \
    /usr/local/var/log/apache2; do
    if [[ "$SCOPE" == "fast" ]]; then
      [[ -d "$path" ]] || continue
      find "$path" -xdev -maxdepth 2 -type f \
        \( -name "*access*" -o -name "*error*" -o -name "*.log" \) \
        -mtime -14 -exec cp -a --parents {} "$LOG_DIR" \; 2>>"$ERROR_FILE" || true
    else
      copy_apache_path "$path" "$LOG_DIR"
    fi
  done

  {
    echo "Apache artifact collection summary"
    echo "ConfigDest=${CONFIG_DIR}"
    echo "LogDest=${LOG_DIR}"
    echo "FastMode=$([[ "$SCOPE" == "fast" ]] && echo yes || echo no)"
  } > "${APACHE_DIR}/apache_summary.txt" 2>>"$ERROR_FILE" || true
}

collect_tomcat_artifacts() {
  log "[TOMCAT] Collecting Tomcat and Java artifacts..."
  local TOMCAT_DIR="${BASEDIR}/tomcat_artifacts"
  local CONFIG_DIR="${TOMCAT_DIR}/config"
  local LOG_DIR="${TOMCAT_DIR}/logs"
  local APP_DIR="${TOMCAT_DIR}/webapps"
  mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$APP_DIR"

  copy_tomcat_path() {
    local src="$1"
    local dest_root="$2"
    local dest="${dest_root}/${src#/}"
    [[ -e "$src" ]] || return 0
    mkdir -p "$(dirname "$dest")"
    cp -a "$src" "$dest" 2>>"$ERROR_FILE" || true
  }

  {
    echo "TS_UTC: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "HOST: ${HOSTNAME_SHORT}"
    echo "MODE: ${MODE}"
    echo "SCOPE: ${SCOPE}"
    echo

    echo "===== JAVA PRESENCE ====="
    if command -v java >/dev/null 2>&1; then
      command -v java
      java -version 2>&1 || true
    else
      echo "java not found in PATH."
    fi
    echo

    echo "===== JAVA HOME CANDIDATES ====="
    for path in /usr/lib/jvm /opt/java /opt/jdk /usr/java; do
      [[ -e "$path" ]] && ls -al "$path" 2>/dev/null || true
    done
    echo

    echo "===== TOMCAT PROCESSES ====="
    ps auxww 2>/dev/null | grep -Ei "[t]omcat|[c]atalina|org\\.apache\\.catalina" || echo "No Tomcat/Catalina processes found."
    echo

    echo "===== LISTENING JAVA/TOMCAT PORTS ====="
    ss -tulnp 2>/dev/null | grep -Ei "java|:(8080|8005|8009|8443)[[:space:]]" || echo "No common Tomcat listeners detected."
    echo

    echo "===== SYSTEMD SERVICES ====="
    if command -v systemctl >/dev/null 2>&1; then
      systemctl list-unit-files --type=service --no-pager 2>/dev/null | grep -Ei "tomcat|catalina|java" || true
      echo
      systemctl status tomcat --no-pager 2>/dev/null || true
      echo
      systemctl status tomcat9 --no-pager 2>/dev/null || true
      echo
      systemctl status tomcat10 --no-pager 2>/dev/null || true
    else
      echo "systemctl not available."
    fi
    echo

    echo "===== TOMCAT ENVIRONMENT FILES ====="
    for file in \
      /etc/default/tomcat \
      /etc/default/tomcat7 \
      /etc/default/tomcat8 \
      /etc/default/tomcat9 \
      /etc/default/tomcat10 \
      /etc/sysconfig/tomcat \
      /etc/sysconfig/tomcat7 \
      /etc/sysconfig/tomcat8 \
      /etc/sysconfig/tomcat9 \
      /etc/sysconfig/tomcat10; do
      [[ -f "$file" ]] || continue
      echo "--- $file ---"
      sed -E 's/(password|passwd|secret|token|key)=.*/\1=REDACTED/I' "$file" 2>/dev/null || true
      echo
    done
  } > "${TOMCAT_DIR}/tomcat_inventory.txt" 2>>"$ERROR_FILE" || true

  for path in \
    /etc/tomcat \
    /etc/tomcat7 \
    /etc/tomcat8 \
    /etc/tomcat9 \
    /etc/tomcat10 \
    /usr/share/tomcat \
    /usr/share/tomcat7 \
    /usr/share/tomcat8 \
    /usr/share/tomcat9 \
    /usr/share/tomcat10 \
    /opt/tomcat \
    /opt/apache-tomcat \
    /opt/apache-tomcat-*; do
    for resolved in $path; do
      [[ -e "$resolved" ]] || continue
      copy_tomcat_path "$resolved/conf" "$CONFIG_DIR"
      copy_tomcat_path "$resolved/bin/setenv.sh" "$CONFIG_DIR"
      copy_tomcat_path "$resolved/bin/catalina.sh" "$CONFIG_DIR"
      if [[ "$SCOPE" == "fast" ]]; then
        [[ -d "$resolved/webapps" ]] && find "$resolved/webapps" -xdev -maxdepth 3 -type f \
          \( -name "*.war" -o -name "*.jsp" -o -name "*.jspx" -o -name "*.class" -o -name "*.jar" \) \
          -ls > "${TOMCAT_DIR}/$(echo "${resolved#/}" | tr '/' '_')_webapps_fast_listing.txt" 2>>"$ERROR_FILE" || true
      else
        copy_tomcat_path "$resolved/webapps" "$APP_DIR"
      fi
      copy_tomcat_path "$resolved/logs" "$LOG_DIR"
    done
  done

  for path in \
    /var/log/tomcat \
    /var/log/tomcat7 \
    /var/log/tomcat8 \
    /var/log/tomcat9 \
    /var/log/tomcat10 \
    /opt/tomcat/logs \
    /opt/apache-tomcat/logs \
    /opt/apache-tomcat-*/logs; do
    for resolved in $path; do
      [[ -d "$resolved" ]] || continue
      if [[ "$SCOPE" == "fast" ]]; then
        find "$resolved" -xdev -maxdepth 2 -type f \
          \( -name "*.log" -o -name "*.txt" -o -name "catalina.out" \) \
          -mtime -14 -exec cp -a --parents {} "$LOG_DIR" \; 2>>"$ERROR_FILE" || true
      else
        copy_tomcat_path "$resolved" "$LOG_DIR"
      fi
    done
  done

  {
    echo "Tomcat artifact collection summary"
    echo "ConfigDest=${CONFIG_DIR}"
    echo "LogDest=${LOG_DIR}"
    echo "WebappsDest=${APP_DIR}"
    echo "FastMode=$([[ "$SCOPE" == "fast" ]] && echo yes || echo no)"
  } > "${TOMCAT_DIR}/tomcat_summary.txt" 2>>"$ERROR_FILE" || true
}

collect_filesystem() {
  log "[FILESYSTEM] Enumerating filesystem..."
  if [[ "$SCOPE" == "fast" ]]; then
    {
      find /etc /var/log /root -xdev \
        -not -path "/proc/*" \
        -not -path "/sys/*" \
        -not -path "/dev/*" \
        -not -path "/run/*" \
        -not -path "${BASEDIR}" \
        -not -path "${BASEDIR}/*" \
        -ls
    } > "$BASEDIR/directory_and_files.txt" 2>>"$ERROR_FILE" || true
    return
  fi

  {
    find / -xdev \
      -not -path "/proc/*" \
      -not -path "/sys/*" \
      -not -path "/dev/*" \
      -not -path "/run/*" \
      -not -path "${BASEDIR}" \
      -not -path "${BASEDIR}/*" \
      -ls
  } > "$BASEDIR/directory_and_files.txt" 2>>"$ERROR_FILE" || true
}

collect_filetree() {
  [[ "$DO_FILETREE" != "yes" ]] && return
  log "[FILETREE] Exporting filesystem tree index (metadata only)..."

  local dest="${BASEDIR}/FileSystem"
  mkdir -p "$dest"
  FILETREE_JSONL_PATH="${dest}/FileTree.jsonl"
  FILETREE_SUMMARY_PATH="${dest}/FileTree_Summary.json"
  FILETREE_ERRORS_PATH="${dest}/FileTree_Errors.txt"
  : > "$FILETREE_JSONL_PATH"
  : > "$FILETREE_ERRORS_PATH"

  FILETREE_ENTRY_COUNT=0
  FILETREE_DIR_COUNT=0
  FILETREE_FILE_COUNT=0
  FILETREE_ERROR_COUNT=0
  FILETREE_TRUNCATED="no"

  local started_epoch now_epoch duration_seconds
  started_epoch="$(date +%s)"
  local roots=()
  local root_actual=""
  mapfile -t roots < <(filetree_get_roots)

  for root_actual in "${roots[@]}"; do
    [[ -n "$root_actual" ]] || continue
    filetree_walk "$root_actual" "" "$root_actual" 0
    if [[ "$FILETREE_ENTRY_COUNT" -ge "$FILETREE_MAX_ENTRIES" ]]; then
      FILETREE_TRUNCATED="yes"
      break
    fi
  done

  now_epoch="$(date +%s)"
  duration_seconds=$((now_epoch - started_epoch))

  local roots_json=""
  local first_root="yes"
  for root_actual in "${roots[@]}"; do
    [[ -n "$root_actual" ]] || continue
    if [[ "$first_root" == "yes" ]]; then
      roots_json="\"$(json_escape "$root_actual")\""
      first_root="no"
    else
      roots_json="${roots_json},\"$(json_escape "$root_actual")\""
    fi
  done

  printf '{\n  "generated_utc": "%s",\n  "mode": "Live",\n  "roots": [%s],\n  "max_depth": %s,\n  "max_entries": %s,\n  "entries": %s,\n  "directories": %s,\n  "files": %s,\n  "errors": %s,\n  "truncated": %s,\n  "duration_seconds": %s,\n  "output": "FileSystem\\\\FileTree.jsonl"\n}\n' \
    "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    "$roots_json" \
    "$FILETREE_MAX_DEPTH" \
    "$FILETREE_MAX_ENTRIES" \
    "$FILETREE_ENTRY_COUNT" \
    "$FILETREE_DIR_COUNT" \
    "$FILETREE_FILE_COUNT" \
    "$FILETREE_ERROR_COUNT" \
    "$( [[ "$FILETREE_TRUNCATED" == "yes" ]] && printf 'true' || printf 'false' )" \
    "$duration_seconds" > "$FILETREE_SUMMARY_PATH"
}

########################
# TIMELINE
########################
collect_timeline() {
  [[ "$DO_TIMELINE" != "yes" ]] && return
  log "[TIMELINE] Building filesystem timeline..."
  if [[ "$SCOPE" == "fast" ]]; then
    {
      find /etc /var/log /root -xdev \
        -not -path "${BASEDIR}" \
        -not -path "${BASEDIR}/*" \
        -printf "%Ax;%AT;%Tx;%TT;%Cx;%CT;%m;%U;%u;%G;%g;%s;%p\n"
    } 2>>"$ERROR_FILE" > "$BASEDIR/timeline_file.csv" || true
    return
  fi

  {
    find / -xdev \
      -not -path "/proc/*" \
      -not -path "/sys/*" \
      -not -path "/dev/*" \
      -not -path "/run/*" \
      -not -path "${BASEDIR}" \
      -not -path "${BASEDIR}/*" \
      -printf "%Ax;%AT;%Tx;%TT;%Cx;%CT;%m;%U;%u;%G;%g;%s;%p\n"
  } 2>>"$ERROR_FILE" > "$BASEDIR/timeline_file.csv" || true
}

########################
# ARCHIVE & HASHES
########################
compress_data() {
  [[ "$DO_TAR" != "yes" ]] && return
  log "[ARCHIVE] Compressing key directories..."

  local TAR_OPTS=(--ignore-failed-read --warning=no-file-changed)

  if [[ "$SCOPE" != "fast" ]] && [[ -d /home ]]; then
    tar "${TAR_OPTS[@]}" -czf "$BASEDIR/home.tar.gz" /home 2>>"$ERROR_FILE" || true
  else
    log "[ARCHIVE] Skipping /home archive (Scope=fast or missing /home)."
  fi

  [[ -d /root ]] && tar "${TAR_OPTS[@]}" -czf "$BASEDIR/root.tar.gz" /root 2>>"$ERROR_FILE" || true
  [[ -d /var/log ]] && tar "${TAR_OPTS[@]}" -czf "$BASEDIR/logs.tar.gz" /var/log 2>>"$ERROR_FILE" || true

  # Systemd Journal (Volatile Logs)
  if command -v journalctl >/dev/null 2>&1; then
    log "[ARCHIVE] Exporting recent systemd journal logs..."
    # Ultimas 5000 lineas
    journalctl -n 5000 --no-pager > "$BASEDIR/journal_recent.txt" 2>>"$ERROR_FILE" || true
    # Errores y alertas desde el ultimo arranque
    journalctl -p 3 -xb --no-pager > "$BASEDIR/journal_errors.txt" 2>>"$ERROR_FILE" || true
  fi
}

compute_hashes() {
  log "[HASH] Computing evidence hashes..."
  local HASH_TMP="${BASEDIR}/hashes.txt.tmp"

  {
    find "$BASEDIR" -type f ! -name "hashes.txt" ! -name "hashes.txt.tmp" -print0 2>>"$ERROR_FILE" \
      | xargs -0 sha256sum
  } > "$HASH_TMP" 2>>"$ERROR_FILE" || true

  mv -f "$HASH_TMP" "$BASEDIR/hashes.txt" 2>>"$ERROR_FILE" || true
}

########################
# FORENSIC CATALOG (JSON)
########################
generate_forensic_catalog() {
  log "[CATALOG] Generating Forensic Catalog (JSON)..."
  local CATALOG_FILE="${BASEDIR}/ForensicCatalog.json"
  local HASH_FILE="${BASEDIR}/hashes.txt"

  # Gather System Info for Asset Auto-Creation
  local os_name=$(uname -s)
  local os_version=$(uname -r)
  local os_arch=$(uname -m)
  
  # Attempt to get distribution info
  if [ -f /etc/os-release ]; then
      # Source safely in a subshell or just grep to avoid polluting env
      local dist_name=$(grep "^NAME=" /etc/os-release | cut -d= -f2 | tr -d '"')
      local dist_ver=$(grep "^VERSION_ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
      [ ! -z "$dist_name" ] && os_name="$dist_name"
      [ ! -z "$dist_ver" ] && os_version="$dist_ver"
  fi

  # IPs (comma separated)
  local ip_addresses=$(ip -4 addr show | grep inet | grep -v 127.0.0.1 | awk '{print $2}' | cut -d/ -f1 | paste -sd "," -)
  
  # Users (local users with UID >= 1000 or root)
  local users=$(awk -F: '($3>=1000 || $3==0){print $1}' /etc/passwd | paste -sd "," -)

  # Helper for JSON array
  json_array() {
      local input="$1"
      if [ -z "$input" ]; then
          echo "[]"
      else
          echo "[ \"${input//,/\",\"}\" ]"
      fi
  }

  # Initialize temp files for lists
  local USER_ARTS="${BASEDIR}/_user_arts.tmp"
  local SYS_ARTS="${BASEDIR}/_sys_arts.tmp"
  local FS_ARTS="${BASEDIR}/_fs_arts.tmp"
  > "$USER_ARTS"
  > "$SYS_ARTS"
  > "$FS_ARTS"

  # Process hashes.txt to build catalog items
  if [[ -f "$HASH_FILE" ]]; then
    while read -r line; do
        # Line format: HASH  FILENAME (2 spaces usually)
        local hash
        hash=$(echo "$line" | awk '{print $1}')
        
        local full_path
        full_path=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^[ \t]*//')
        
        # Calculate relative path (strip BASEDIR)
        # full_path is like ./powertriage_linux_.../file.txt or /path/to/mount/powertriage.../file.txt
        # We want just "file.txt" or "subdir/file.txt" relative to the report folder root.
        
        # Get the relative path by removing the prefix up to the BASEDIR name
        # A safer way: relative to the directory containing the catalog
        local rel_path="${full_path#$BASEDIR/}"
        
        # Get file stats
        local size=0
        local ctime="N/A"
        local mtime="N/A"
        
        if [[ -f "$full_path" ]]; then
            # Attempt to get stats. 
            # Note: BusyBox/GNU stat compatible format
            size=$(stat -c %s "$full_path" 2>/dev/null || echo 0)
            # Cut to remove nanoseconds if present, keep YYYY-MM-DD HH:MM:SS
            ctime=$(stat -c %z "$full_path" 2>/dev/null | cut -d. -f1 || echo "N/A")
            mtime=$(stat -c %y "$full_path" 2>/dev/null | cut -d. -f1 || echo "N/A")
        fi

        # Categorize
        local target_file="$SYS_ARTS"
        
        # Heuristics for Linux artifacts
        if [[ "$rel_path" == *"user_history"* ]] || [[ "$rel_path" == *"home.tar.gz"* ]] || [[ "$rel_path" == *"root.tar.gz"* ]]; then
            target_file="$USER_ARTS"
        elif [[ "$rel_path" == *"directory_and_files"* ]] || [[ "$rel_path" == *"timeline"* ]] || [[ "$rel_path" == FileSystem/* ]] || [[ "$rel_path" == *"FileTree"* ]]; then
            target_file="$FS_ARTS"
        elif [[ "$rel_path" == *"memory.mem"* ]]; then
            target_file="$FS_ARTS"
        fi
        
        # Append JSON object (with trailing comma, to be cleaned later)
        echo "{ \"path\": \"$rel_path\", \"size\": $size, \"created\": \"$ctime\", \"modified\": \"$mtime\", \"hash\": \"$hash\" }," >> "$target_file"

    done < "$HASH_FILE"
  fi

  # Helper to remove last comma
  clean_json_list() {
      local f="$1"
      if [[ -s "$f" ]]; then
          sed '$ s/,$//' "$f"
      fi
  }

  # Construct Final JSON
  {
      echo "{"
      echo "  \"metadata\": {"
      echo "    \"hostname\": \"$HOSTNAME_SHORT\","
      echo "    \"timestamp\": \"$(date -u +"%Y-%m-%d %H:%M:%S")\","
      echo "    \"case_id\": \"PowerTriage_Linux\","
      echo "    \"version\": \"1.0.0\","
      echo "    \"edition\": \"Linux Standard\","
      echo "    \"system_info\": {"
      echo "      \"os_name\": \"$os_name\","
      echo "      \"os_version\": \"$os_version\","
      echo "      \"os_build\": \"$(uname -v | tr -d '"')\","
      echo "      \"os_arch\": \"$os_arch\","
      echo "      \"ip_addresses\": $(json_array "$ip_addresses"),"
      echo "      \"users\": $(json_array "$users")"
      echo "    }"
      echo "  },"
      echo "  \"artifacts\": {"
      echo "    \"user\": ["
      clean_json_list "$USER_ARTS"
      echo "    ],"
      echo "    \"system\": ["
      clean_json_list "$SYS_ARTS"
      echo "    ],"
      echo "    \"filesystem\": ["
      clean_json_list "$FS_ARTS"
      echo "    ]"
      echo "  }"
      echo "}"
  } > "$CATALOG_FILE"

  # Cleanup temps
  rm -f "$USER_ARTS" "$SYS_ARTS" "$FS_ARTS"
}

########################
# MAIN
########################
main() {
  if [[ -t 1 && -n "${TERM:-}" ]]; then
    clear || true
  fi
  check_root
  banner
  setupAcquisition

  log "[START] Host: ${HOSTNAME_SHORT} | Case: ${CASE_UTC}"

  collect_memory
  collect_processes
  collect_open_files
  collect_system_info
  collect_users_local
  collect_containers
  collect_packages
  collect_user_activity
  collect_persistence
  collect_advanced_persistence
  collect_apache_artifacts
  collect_tomcat_artifacts
  collect_network
  collect_filesystem
  collect_filetree
  collect_timeline
  compress_data
  compute_hashes
  generate_forensic_catalog

  FIN
}

main "$@"
