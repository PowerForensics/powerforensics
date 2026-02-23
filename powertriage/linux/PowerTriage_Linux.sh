#!/bin/bash
#############################################################
#                 PowerTriage Linux                         #
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

for arg in "$@"; do
  case "$arg" in
    --interactive) MODE="interactive" ;;
    --auto) MODE="auto" ;;
    --strict) MODE="strict" ;;
    --fast) SCOPE="fast" ;;
    --no-memory) DO_MEMORY="no" ;;
    --no-timeline) DO_TIMELINE="no" ;;
    --no-tar) DO_TAR="no" ;;
    --no-lsof) DO_LSOF="no" ;;
  esac
done

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
     
        
        # Get the relative path by removing the prefix up to the BASEDIR name
      
        local rel_path="${full_path#$BASEDIR/}"
        
        # Get file stats
        local size=0
        local ctime="N/A"
        local mtime="N/A"
        
        if [[ -f "$full_path" ]]; then
            # Attempt to get stats. 
          
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
        elif [[ "$rel_path" == *"directory_and_files"* ]] || [[ "$rel_path" == *"timeline"* ]]; then
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
      echo "    \"edition\": \"Linux Standard\""
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
  clear
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
  collect_network
  collect_filesystem
  collect_timeline
  compress_data
  compute_hashes
  generate_forensic_catalog

  FIN
}

main "$@"
