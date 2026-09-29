#!/bin/bash
###############################################################################
# PowerTriage macOS CE
# Live Response & Forensic Triage Tool
#
# PowerForensics: https://powerforensics.es
# This implementation is written specifically for the PowerTriage project.
###############################################################################

set -u
set -o pipefail
IFS=$'\n\t'
umask 077

TOOL_NAME="PowerTriage macOS CE"
TOOL_VERSION="0.1.1"
SCHEMA_VERSION="1.0"

MODE="interactive"
PROFILE=""
SCOPE="fast"
OUTPUT_BASE="$(pwd -P)"
OUTPUT_RETENTION="both"
SINCE="24h"
CASE_ID=""
MAX_COPY_MB=1024
INCLUDE_SENSITIVE="no"
DO_TIMELINE="yes"
DO_FILETREE="no"
FILETREE_MAX_DEPTH=12
FILETREE_MAX_ENTRIES=100000
FILETREE_ROOTS=()

RUN_SYSTEM="no"
RUN_LIVE="no"
RUN_NETWORK="no"
RUN_PERSISTENCE="no"
RUN_LOGS="no"
RUN_USERS="no"
RUN_BROWSERS="no"
RUN_FILESYSTEM="no"
RUN_SECURITY="no"
MODULE_SELECTION_EXPLICIT="no"
PROFILE_MODE_SELECTED="no"
PROFILE_FLAG_COUNT=0
CUSTOM_MODULE_SELECTED="no"

HOSTNAME_SHORT="unknown"
CASE_UTC=""
CASE_NAME=""
BASE_DIR=""
ARCHIVE_PATH=""
ARCHIVE_HASH_PATH=""
LOG_FILE=""
ERROR_FILE=""
STATUS_FILE=""
MANIFEST_FILE=""
HASH_FILE=""
TIMELINE_TEMP=""
TIMELINE_COUNTER=0
TIMELINE_EVENT_COLLECTION_OPEN="yes"
SUCCESS_COUNT=0
PARTIAL_COUNT=0
SKIPPED_COUNT=0
EXPECTED_ABSENT_COUNT=0
FAILED_COUNT=0
ARTIFACT_COUNT=0
IS_ROOT="no"
FDA_STATUS="unknown"
FINALIZED="no"

usage() {
  cat <<'USAGE'
PowerTriage macOS CE - Live Response & Forensic Triage

Usage:
  sudo ./PowerTriage_macOS.sh [execution mode] [options]

Execution modes:
  --minimal                  Fast first-pass triage
  --full                     Enable every collection module
  --auto                     Non-interactive execution
  --strict                   Require root and detected Full Disk Access

Collection modules:
  --system                   System, hardware, storage and account context
  --live                     Processes, sessions, open files and launchd state
  --network                  Interfaces, sockets, routes, DNS, proxy and firewall
  --persistence              Launch items, background tasks, cron and extensions
  --logs                     Unified Logs and selected diagnostic logs
  --users                    High-value per-user forensic artifacts
  --browsers                 Safari, Chromium-family and Firefox artifacts
  --filesystem              APFS snapshots, FSEvents and Spotlight metadata
  --security                 Gatekeeper, XProtect, profiles and security tooling

Scope and privacy:
  --fast                     Bounded collection (default)
  --deep                     Adds bounded raw log and filesystem stores
  --since=<Nm|Nh|Nd>         Unified Log lookback (default: 24h)
  --max-copy-mb=<n>          Maximum size of one copied source (default: 1024)
  --include-sensitive        Include Mail, Messages and keychain database artifacts

FileTree and timeline:
  --filetree                 Export a metadata-only filesystem tree
  --filetree-root=<path>     Add a FileTree root (repeatable)
  --filetree-max-depth=<n>   Maximum recursion depth (default: 12)
  --filetree-max-entries=<n> Maximum entries (default: 100000)
  --no-timeline              Skip Chronos-compatible timeline generation

Output:
  --output-dir=<path>        Parent directory for the collection
  --case-id=<value>          Optional case identifier recorded in metadata
  --retention=<mode>         both, directory-only, or archive-only (default: both)
  --no-archive               Alias for --retention=directory-only
  --version                  Show version
  --help, -h                 Show this help

Examples:
  sudo ./PowerTriage_macOS.sh --minimal --output-dir=/Volumes/Evidence
  sudo ./PowerTriage_macOS.sh --full --deep --since=48h
  sudo ./PowerTriage_macOS.sh --system --live --network --persistence --auto
  sudo ./PowerTriage_macOS.sh --users --browsers --include-sensitive

Notes:
  - Root and Full Disk Access are separate macOS controls.
  - Without either permission, PowerTriage continues in degraded mode unless
    --strict is selected.
  - User documents and attachments are not bulk-copied by this CE workflow.
USAGE
}

version() {
  printf '%s %s\n' "$TOOL_NAME" "$TOOL_VERSION"
}

sanitize_component() {
  local value="${1-}"
  value=$(printf '%s' "$value" | tr -c 'A-Za-z0-9._-' '_')
  value=$(printf '%s' "$value" | sed 's/^_*//; s/_*$//')
  if [[ -z "$value" ]]; then
    value="unknown"
  fi
  printf '%s' "$value"
}

portable_filename() {
  local source_path="$1"
  local original=""
  local stem=""
  local extension=""
  local safe_stem=""
  local safe_extension=""
  local checksum=""

  original=$(basename "$source_path")
  if [[ "$original" == *.* && "$original" != .* ]]; then
    stem=${original%.*}
    extension=.${original##*.}
  else
    stem=$original
  fi

  safe_stem=$(printf '%s' "$stem" | tr -c 'A-Za-z0-9._-' '_' | cut -c 1-72)
  safe_extension=$(printf '%s' "$extension" | tr -c 'A-Za-z0-9._-' '_' | cut -c 1-16)
  safe_stem=$(printf '%s' "$safe_stem" | sed 's/^[. ]*//; s/[. ]*$//')
  [[ -n "$safe_stem" ]] || safe_stem="artifact"
  checksum=$(printf '%s' "$source_path" | cksum | awk '{print $1}')
  printf '%s_%s%s' "$safe_stem" "$checksum" "$safe_extension"
}

csv_quote() {
  local value="${1-}"
  value=$(printf '%s' "$value" | tr '\r\n' '  ')
  value=${value//\"/\"\"}
  printf '"%s"' "$value"
}

json_escape() {
  local value="${1-}"
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}
  value=${value//$'\r'/\\r}
  value=${value//$'\t'/\\t}
  printf '%s' "$value"
}

utc_now() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

epoch_to_utc() {
  local epoch="${1-}"
  if [[ -z "$epoch" || "$epoch" == "0" || "$epoch" == "-1" ]]; then
    printf ''
    return 0
  fi
  date -u -r "$epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf ''
}

file_size_bytes() {
  local path="$1"
  if [[ -f "$path" ]]; then
    stat -f '%z' "$path" 2>/dev/null || printf '0'
  else
    printf '0'
  fi
}

file_mtime_utc() {
  local path="$1"
  local epoch=""
  epoch=$(stat -f '%m' "$path" 2>/dev/null || printf '')
  epoch_to_utc "$epoch"
}

path_size_kb() {
  local path="$1"
  du -sk "$path" 2>/dev/null | awk 'NR==1 {print $1}'
}

sha256_file() {
  local path="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" 2>/dev/null | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$path" 2>/dev/null | awk '{print $NF}'
  else
    printf ''
  fi
}

relative_destination() {
  local path="$1"
  if [[ "$path" == "$BASE_DIR" ]]; then
    printf '.'
  elif [[ "$path" == "$BASE_DIR/"* ]]; then
    printf '%s' "${path#$BASE_DIR/}"
  else
    printf '%s' "$path"
  fi
}

log_message() {
  local level="$1"
  shift
  local message="$*"
  local line="$(utc_now) [$level] $message"
  printf '%s\n' "$line"
  if [[ -n "$LOG_FILE" ]]; then
    printf '%s\n' "$line" >> "$LOG_FILE"
  fi
}

record_error() {
  local module="$1"
  shift
  local message="$*"
  if [[ -n "$ERROR_FILE" ]]; then
    printf '%s [%s] %s\n' "$(utc_now)" "$module" "$message" >> "$ERROR_FILE"
  fi
}

record_status() {
  local module="$1"
  local item="$2"
  local status="$3"
  local detail="${4-}"

  printf '%s,%s,%s,%s,%s\n' \
    "$(csv_quote "$(utc_now)")" \
    "$(csv_quote "$module")" \
    "$(csv_quote "$item")" \
    "$(csv_quote "$status")" \
    "$(csv_quote "$detail")" >> "$STATUS_FILE"

  case "$status" in
    success) SUCCESS_COUNT=$((SUCCESS_COUNT + 1)) ;;
    partial) PARTIAL_COUNT=$((PARTIAL_COUNT + 1)) ;;
    skipped|missing|blocked) SKIPPED_COUNT=$((SKIPPED_COUNT + 1)) ;;
    expected_absent) EXPECTED_ABSENT_COUNT=$((EXPECTED_ABSENT_COUNT + 1)) ;;
    failed) FAILED_COUNT=$((FAILED_COUNT + 1)) ;;
  esac
}

record_manifest() {
  local module="$1"
  local status="$2"
  local source="$3"
  local destination="$4"
  local size_bytes="${5-0}"
  local modified_utc="${6-}"
  local hash="${7-}"
  local note="${8-}"

  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(csv_quote "$module")" \
    "$(csv_quote "$status")" \
    "$(csv_quote "$source")" \
    "$(csv_quote "$destination")" \
    "$(csv_quote "$size_bytes")" \
    "$(csv_quote "$modified_utc")" \
    "$(csv_quote "$hash")" \
    "$(csv_quote "$note")" >> "$MANIFEST_FILE"

  if [[ "$status" == "acquired" || "$status" == "generated" ]]; then
    ARTIFACT_COUNT=$((ARTIFACT_COUNT + 1))
  fi
}

add_timeline_event() {
  local timestamp="$1"
  local title="$2"
  local description="$3"
  local event_type="$4"
  local priority="$5"
  local source="$6"
  local source_path="${7-}"
  local destination="${8-}"
  local event_id=""

  [[ "$DO_TIMELINE" != "yes" || "$TIMELINE_EVENT_COLLECTION_OPEN" != "yes" || -z "$timestamp" ]] && return 0

  TIMELINE_COUNTER=$((TIMELINE_COUNTER + 1))
  event_id=$(printf 'pt-macos-%06d' "$TIMELINE_COUNTER")
  printf '{"id":"%s","timestamp":"%s","title":"%s","description":"%s","type":"%s","priority":"%s","source":"%s","metadata":{"source_path":"%s","destination":"%s"}}\n' \
    "$(json_escape "$event_id")" \
    "$(json_escape "$timestamp")" \
    "$(json_escape "$title")" \
    "$(json_escape "$description")" \
    "$(json_escape "$event_type")" \
    "$(json_escape "$priority")" \
    "$(json_escape "$source")" \
    "$(json_escape "$source_path")" \
    "$(json_escape "$destination")" >> "$TIMELINE_TEMP"
}

command_display() {
  local part=""
  local output=""
  for part in "$@"; do
    if [[ -n "$output" ]]; then
      output="$output "
    fi
    output="$output$(printf '%q' "$part")"
  done
  printf '%s' "$output"
}

command_available() {
  local command_name="$1"
  if [[ "$command_name" == /* ]]; then
    [[ -x "$command_name" ]]
  else
    command -v "$command_name" >/dev/null 2>&1
  fi
}

run_capture() {
  local module="$1"
  local item="$2"
  local relative_path="$3"
  shift 3
  local output_path="$BASE_DIR/$relative_path"
  local command_name="${1-}"
  local display=""
  local rc=0
  local size=0
  local modified=""
  local hash=""

  mkdir -p "$(dirname "$output_path")"
  if [[ -z "$command_name" ]] || ! command_available "$command_name"; then
    record_status "$module" "$item" "missing" "Command not available: $command_name"
    record_manifest "$module" "missing" "command:$command_name" "$relative_path" 0 "" "" "command unavailable"
    return 0
  fi

  display=$(command_display "$@")
  if "$@" > "$output_path" 2>&1; then
    rc=0
  else
    rc=$?
  fi

  size=$(file_size_bytes "$output_path")
  modified=$(file_mtime_utc "$output_path")
  hash=$(sha256_file "$output_path")

  if [[ "$rc" -eq 0 ]]; then
    record_status "$module" "$item" "success" "$display"
    record_manifest "$module" "generated" "command:$display" "$relative_path" "$size" "$modified" "$hash" "exit_code=0"
  else
    record_status "$module" "$item" "partial" "$display (exit $rc)"
    record_manifest "$module" "partial" "command:$display" "$relative_path" "$size" "$modified" "$hash" "exit_code=$rc"
    record_error "$module" "$item failed with exit code $rc: $display"
  fi
}

run_shell_capture() {
  local module="$1"
  local item="$2"
  local relative_path="$3"
  local shell_code="$4"
  run_capture "$module" "$item" "$relative_path" /bin/sh -c "$shell_code"
}

is_path_within_output() {
  local path="$1"
  [[ -n "$BASE_DIR" && ( "$path" == "$BASE_DIR" || "$path" == "$BASE_DIR/"* ) ]]
}

register_copied_file() {
  local module="$1"
  local source="$2"
  local destination="$3"
  local note="${4-}"
  local size=0
  local modified=""
  local hash=""
  local relative=""

  [[ ! -f "$destination" ]] && return 0
  size=$(file_size_bytes "$destination")
  if [[ "$source" != "$destination" && ( -e "$source" || -L "$source" ) ]]; then
    modified=$(file_mtime_utc "$source")
  else
    modified=$(file_mtime_utc "$destination")
  fi
  hash=$(sha256_file "$destination")
  relative=$(relative_destination "$destination")
  record_manifest "$module" "acquired" "$source" "$relative" "$size" "$modified" "$hash" "$note"
  add_timeline_event "$modified" "Artifact acquired: $(basename "$source")" \
    "Source artifact copied by PowerTriage macOS" "artifact" "low" "$module" "$source" "$relative"
}

register_copied_tree() {
  local module="$1"
  local source_root="$2"
  local destination_root="$3"
  local note="${4-}"
  local destination_file=""
  local relative_child=""
  local source_file=""

  while IFS= read -r -d '' destination_file; do
    relative_child=${destination_file#$destination_root/}
    source_file="$source_root/$relative_child"
    register_copied_file "$module" "$source_file" "$destination_file" "$note"
  done < <(find "$destination_root" -type f -print0 2>>"$ERROR_FILE")
}

reset_partial_destination() {
  local destination="$1"
  case "$destination" in
    "$BASE_DIR"/*) ;;
    *) return 1 ;;
  esac
  [[ "$destination" != "$BASE_DIR" ]] || return 1
  rm -rf -- "$destination" 2>>"$ERROR_FILE" || return 1
  mkdir -p "$(dirname "$destination")" || return 1
}

copy_artifact() {
  local module="$1"
  local source="$2"
  local relative_path="$3"
  local note="${4-}"
  local sensitivity="${5-normal}"
  local presence="${6-required}"
  local destination="$BASE_DIR/$relative_path"
  local size_kb=0
  local max_kb=$((MAX_COPY_MB * 1024))
  local rc=0
  local fallback_rc=0

  if [[ "$sensitivity" == "sensitive" && "$INCLUDE_SENSITIVE" != "yes" ]]; then
    record_status "$module" "$source" "skipped" "Sensitive artifact requires --include-sensitive"
    record_manifest "$module" "skipped" "$source" "$relative_path" 0 "" "" "sensitive artifact not requested"
    return 0
  fi

  if [[ ! -e "$source" && ! -L "$source" ]]; then
    if [[ "$presence" == "optional" ]]; then
      record_status "$module" "$source" "expected_absent" "Optional source path not present"
    else
      record_status "$module" "$source" "missing" "Source path not present"
    fi
    return 0
  fi

  if [[ ! -r "$source" ]]; then
    record_status "$module" "$source" "blocked" "Source is not readable; root or Full Disk Access may be required"
    record_manifest "$module" "blocked" "$source" "$relative_path" 0 "" "" "permission denied"
    return 0
  fi

  size_kb=$(path_size_kb "$source")
  size_kb=${size_kb:-0}
  if [[ "$size_kb" =~ ^[0-9]+$ ]] && [[ "$size_kb" -gt "$max_kb" ]]; then
    record_status "$module" "$source" "skipped" "Source size ${size_kb} KiB exceeds --max-copy-mb=$MAX_COPY_MB"
    record_manifest "$module" "skipped" "$source" "$relative_path" $((size_kb * 1024)) "" "" "size limit"
    return 0
  fi

  mkdir -p "$(dirname "$destination")"
  if [[ -d "$source" && ! -L "$source" ]]; then
    mkdir -p "$destination"
    if [[ -x /usr/bin/ditto ]]; then
      /usr/bin/ditto --rsrc --extattr --acl "$source" "$destination" 2>>"$ERROR_FILE" || rc=$?
    else
      /bin/cp -pR "$source/." "$destination/" 2>>"$ERROR_FILE" || rc=$?
    fi
  else
    if [[ -x /usr/bin/ditto ]]; then
      /usr/bin/ditto --rsrc --extattr --acl "$source" "$destination" 2>>"$ERROR_FILE" || rc=$?
    else
      /bin/cp -pP "$source" "$destination" 2>>"$ERROR_FILE" || rc=$?
    fi
  fi

  if [[ "$rc" -ne 0 ]]; then
    if [[ -x /usr/bin/ditto ]] && reset_partial_destination "$destination"; then
      /usr/bin/ditto --norsrc --noextattr --noacl "$source" "$destination" 2>>"$ERROR_FILE" || fallback_rc=$?
      if [[ "$fallback_rc" -eq 0 ]]; then
        if [[ -d "$destination" && ! -L "$destination" ]]; then
          register_copied_tree "$module" "$source" "$destination" "$note; content fallback without ACL, extended attributes, or resource forks"
        else
          register_copied_file "$module" "$source" "$destination" "$note; content fallback without ACL, extended attributes, or resource forks"
        fi
        record_status "$module" "$source" "partial" "Content acquired; metadata-preserving copy failed with exit code $rc"
        record_manifest "$module" "partial" "$source" "$relative_path" 0 "" "" "content acquired by metadata-stripped fallback"
        record_error "$module" "Metadata-preserving copy failed for $source; content-only fallback succeeded"
        return 0
      fi
    fi

    if [[ -d "$destination" && ! -L "$destination" ]]; then
      register_copied_tree "$module" "$source" "$destination" "partial copy; copy exit_code=$rc"
    elif [[ -f "$destination" ]]; then
      register_copied_file "$module" "$source" "$destination" "partial copy; copy exit_code=$rc"
    fi
    record_status "$module" "$source" "partial" "Copy incomplete; exit code $rc"
    record_manifest "$module" "partial" "$source" "$relative_path" 0 "" "" "copy exit_code=$rc"
    record_error "$module" "Copy incomplete for $source -> $relative_path (primary exit $rc, fallback exit $fallback_rc)"
    return 0
  fi

  if [[ -d "$destination" && ! -L "$destination" ]]; then
    register_copied_tree "$module" "$source" "$destination" "$note"
  else
    register_copied_file "$module" "$source" "$destination" "$note"
  fi
  record_status "$module" "$source" "success" "Copied to $relative_path"
}

copy_if_present() {
  copy_artifact "$@"
}

copy_optional_artifact() {
  local module="$1"
  local source="$2"
  local relative_path="$3"
  local note="${4-}"
  local sensitivity="${5-normal}"
  copy_artifact "$module" "$source" "$relative_path" "$note" "$sensitivity" "optional"
}

since_to_seconds() {
  local value="$1"
  local number=${value%[mhd]}
  local unit=${value#${number}}
  case "$unit" in
    m) printf '%s' $((number * 60)) ;;
    h) printf '%s' $((number * 3600)) ;;
    d) printf '%s' $((number * 86400)) ;;
  esac
}

copy_recent_files_portable() {
  local module="$1"
  local source_root="$2"
  local destination_root="$3"
  local note="$4"
  local max_files="$5"
  local source_file=""
  local modified_epoch=""
  local cutoff_epoch=$(( $(date +%s) - $(since_to_seconds "$SINCE") ))
  local copied=0
  local processed=0
  local artifacts_before=0
  local portable_name=""

  if [[ ! -d "$source_root" ]]; then
    record_status "$module" "$source_root" "expected_absent" "Optional diagnostic source not present"
    return 0
  fi
  if [[ ! -r "$source_root" ]]; then
    record_status "$module" "$source_root" "blocked" "Diagnostic source is not readable"
    record_manifest "$module" "blocked" "$source_root" "$destination_root" 0 "" "" "permission denied"
    return 0
  fi

  while IFS= read -r -d '' source_file; do
    if [[ "$SCOPE" == "fast" && "$source_file" == */CoreCapture/* ]]; then
      continue
    fi
    modified_epoch=$(stat -f '%m' "$source_file" 2>/dev/null || printf '0')
    [[ "$modified_epoch" =~ ^[0-9]+$ ]] || modified_epoch=0
    [[ "$modified_epoch" -ge "$cutoff_epoch" ]] || continue

    portable_name=$(portable_filename "$source_file")
    artifacts_before=$ARTIFACT_COUNT
    copy_artifact "$module" "$source_file" "$destination_root/$portable_name" "$note; portable flattened name" "normal" "optional"
    processed=$((processed + 1))
    [[ "$ARTIFACT_COUNT" -gt "$artifacts_before" ]] && copied=$((copied + 1))
    [[ "$processed" -ge "$max_files" ]] && break
  done < <(find "$source_root" -type f -print0 2>>"$ERROR_FILE")

  record_status "$module" "$source_root" "success" "Acquired $copied of $processed recent candidates (limit $max_files, window $SINCE)"
}

enable_minimal_profile() {
  PROFILE_MODE_SELECTED="yes"
  PROFILE_FLAG_COUNT=$((PROFILE_FLAG_COUNT + 1))
  PROFILE="minimal"
  RUN_SYSTEM="yes"
  RUN_LIVE="yes"
  RUN_NETWORK="yes"
  RUN_PERSISTENCE="yes"
  RUN_LOGS="yes"
  RUN_SECURITY="yes"
  MODULE_SELECTION_EXPLICIT="yes"
}

enable_full_profile() {
  PROFILE_MODE_SELECTED="yes"
  PROFILE_FLAG_COUNT=$((PROFILE_FLAG_COUNT + 1))
  PROFILE="full"
  RUN_SYSTEM="yes"
  RUN_LIVE="yes"
  RUN_NETWORK="yes"
  RUN_PERSISTENCE="yes"
  RUN_LOGS="yes"
  RUN_USERS="yes"
  RUN_BROWSERS="yes"
  RUN_FILESYSTEM="yes"
  RUN_SECURITY="yes"
  MODULE_SELECTION_EXPLICIT="yes"
}

enable_module() {
  local module="$1"
  CUSTOM_MODULE_SELECTED="yes"
  PROFILE="custom"
  MODULE_SELECTION_EXPLICIT="yes"
  case "$module" in
    system) RUN_SYSTEM="yes" ;;
    live) RUN_LIVE="yes" ;;
    network) RUN_NETWORK="yes" ;;
    persistence) RUN_PERSISTENCE="yes" ;;
    logs) RUN_LOGS="yes" ;;
    users) RUN_USERS="yes" ;;
    browsers) RUN_BROWSERS="yes" ;;
    filesystem) RUN_FILESYSTEM="yes" ;;
    security) RUN_SECURITY="yes" ;;
  esac
}

parse_arguments() {
  local arg=""
  for arg in "$@"; do
    case "$arg" in
      --help|-h) usage; exit 0 ;;
      --version) version; exit 0 ;;
      --minimal) enable_minimal_profile ;;
      --full) enable_full_profile ;;
      --auto) MODE="auto" ;;
      --strict) MODE="strict" ;;
      --system) enable_module "system" ;;
      --live) enable_module "live" ;;
      --network) enable_module "network" ;;
      --persistence) enable_module "persistence" ;;
      --logs) enable_module "logs" ;;
      --users) enable_module "users" ;;
      --browsers) enable_module "browsers" ;;
      --filesystem) enable_module "filesystem" ;;
      --security) enable_module "security" ;;
      --fast) SCOPE="fast" ;;
      --deep) SCOPE="deep" ;;
      --since=*) SINCE=${arg#*=} ;;
      --max-copy-mb=*) MAX_COPY_MB=${arg#*=} ;;
      --include-sensitive) INCLUDE_SENSITIVE="yes" ;;
      --filetree) DO_FILETREE="yes" ;;
      --filetree-root=*) FILETREE_ROOTS+=("${arg#*=}") ;;
      --filetree-max-depth=*) FILETREE_MAX_DEPTH=${arg#*=} ;;
      --filetree-max-entries=*) FILETREE_MAX_ENTRIES=${arg#*=} ;;
      --no-timeline) DO_TIMELINE="no" ;;
      --output-dir=*) OUTPUT_BASE=${arg#*=} ;;
      --case-id=*) CASE_ID=${arg#*=} ;;
      --retention=*) OUTPUT_RETENTION=${arg#*=} ;;
      --no-archive) OUTPUT_RETENTION="directory-only" ;;
      *)
        printf '[ERROR] Unknown argument: %s\n\n' "$arg" >&2
        usage >&2
        exit 2
        ;;
    esac
  done
}

select_profile_interactive() {
  local choice=""
  if [[ "$MODULE_SELECTION_EXPLICIT" == "yes" ]]; then
    return 0
  fi

  if [[ "$MODE" != "interactive" || ! -t 0 ]]; then
    printf '[ERROR] Select --minimal, --full, or one or more collection modules.\n' >&2
    exit 2
  fi

  printf '\nPowerTriage macOS CE\n'
  printf '1) Minimal - fast first-pass triage\n'
  printf '2) Full    - all CE collection modules\n'
  printf '3) Help\n'
  printf '> '
  IFS= read -r choice
  case "${choice:-}" in
    1) enable_minimal_profile ;;
    2) enable_full_profile ;;
    3) usage; exit 0 ;;
    *) printf '[ERROR] Invalid selection.\n' >&2; exit 2 ;;
  esac
}

validate_configuration() {
  if [[ "$PROFILE_FLAG_COUNT" -gt 1 ]]; then
    printf '[ERROR] Select only one profile: --minimal or --full.\n' >&2
    exit 2
  fi

  if [[ "$PROFILE_MODE_SELECTED" == "yes" && "$CUSTOM_MODULE_SELECTED" == "yes" ]]; then
    printf '[ERROR] Use a profile or custom module flags, not both in the same run.\n' >&2
    exit 2
  fi

  if [[ ! "$SINCE" =~ ^[1-9][0-9]*[mhd]$ ]]; then
    printf '[ERROR] --since must use a value such as 30m, 24h, or 7d.\n' >&2
    exit 2
  fi

  if [[ ! "$MAX_COPY_MB" =~ ^[1-9][0-9]*$ ]]; then
    printf '[ERROR] --max-copy-mb must be a positive integer.\n' >&2
    exit 2
  fi

  if [[ ! "$FILETREE_MAX_DEPTH" =~ ^[0-9]+$ ]]; then
    printf '[ERROR] --filetree-max-depth must be a non-negative integer.\n' >&2
    exit 2
  fi

  if [[ ! "$FILETREE_MAX_ENTRIES" =~ ^[1-9][0-9]*$ ]]; then
    printf '[ERROR] --filetree-max-entries must be a positive integer.\n' >&2
    exit 2
  fi

  case "$OUTPUT_RETENTION" in
    both|directory-only|archive-only) ;;
    *)
      printf '[ERROR] --retention must be both, directory-only, or archive-only.\n' >&2
      exit 2
      ;;
  esac

  if [[ -z "$OUTPUT_BASE" || "$OUTPUT_BASE" == "/" ]]; then
    printf '[ERROR] Refusing to use an empty path or / as the output directory.\n' >&2
    exit 2
  fi
}

detect_permissions() {
  local probe=""
  local user_home=""

  if [[ "$(id -u)" -eq 0 ]]; then
    IS_ROOT="yes"
  fi

  FDA_STATUS="unknown"
  for user_home in /Users/*; do
    [[ -d "$user_home" ]] || continue
    [[ "$(basename "$user_home")" == "Shared" ]] && continue
    for probe in \
      "$user_home/Library/Safari/History.db" \
      "$user_home/Library/Mail" \
      "$user_home/Library/Messages/chat.db"; do
      if [[ -e "$probe" ]]; then
        if [[ -f "$probe" ]] && /usr/bin/head -c 1 "$probe" >/dev/null 2>&1; then
          FDA_STATUS="available"
        elif [[ -d "$probe" ]] && /bin/ls -A "$probe" >/dev/null 2>&1; then
          FDA_STATUS="available"
        else
          FDA_STATUS="limited"
        fi
        return 0
      fi
    done
  done
}

check_platform() {
  local kernel=""
  kernel=$(uname -s 2>/dev/null || printf 'unknown')
  if [[ "$kernel" != "Darwin" ]]; then
    printf '[ERROR] PowerTriage macOS must run on Darwin/macOS. Detected: %s\n' "$kernel" >&2
    exit 1
  fi
}

resolve_output_base() {
  if [[ ! -d "$OUTPUT_BASE" ]]; then
    mkdir -p "$OUTPUT_BASE" 2>/dev/null || {
      printf '[ERROR] Cannot create output directory: %s\n' "$OUTPUT_BASE" >&2
      exit 1
    }
  fi
  OUTPUT_BASE=$(cd "$OUTPUT_BASE" 2>/dev/null && pwd -P) || {
    printf '[ERROR] Cannot resolve output directory: %s\n' "$OUTPUT_BASE" >&2
    exit 1
  }
}

setup_output() {
  local case_suffix=""

  HOSTNAME_SHORT=$(hostname -s 2>/dev/null || hostname 2>/dev/null || printf 'unknown')
  HOSTNAME_SHORT=$(sanitize_component "$HOSTNAME_SHORT")
  CASE_UTC=$(date -u '+%Y-%m-%d_%H-%M-%S_UTC')
  if [[ -n "$CASE_ID" ]]; then
    case_suffix="_$(sanitize_component "$CASE_ID")"
  fi
  CASE_NAME="powertriage_macos_${HOSTNAME_SHORT}_${CASE_UTC}${case_suffix}"
  BASE_DIR="$OUTPUT_BASE/$CASE_NAME"
  ARCHIVE_PATH="$OUTPUT_BASE/${CASE_NAME}.zip"
  ARCHIVE_HASH_PATH="$ARCHIVE_PATH.sha256"

  if [[ -e "$BASE_DIR" || -e "$ARCHIVE_PATH" ]]; then
    printf '[ERROR] Output already exists for this case timestamp: %s\n' "$CASE_NAME" >&2
    exit 1
  fi

  mkdir -p "$BASE_DIR" || {
    printf '[ERROR] Cannot create evidence directory: %s\n' "$BASE_DIR" >&2
    exit 1
  }
  LOG_FILE="$BASE_DIR/powertriage_macos.log"
  ERROR_FILE="$BASE_DIR/errors.log"
  STATUS_FILE="$BASE_DIR/collection_status.csv"
  MANIFEST_FILE="$BASE_DIR/artifact_manifest.csv"
  HASH_FILE="$BASE_DIR/hashes.sha256"
  TIMELINE_TEMP="$BASE_DIR/.timeline_events.jsonl"

  : > "$LOG_FILE"
  : > "$ERROR_FILE"
  printf 'timestamp_utc,module,item,status,detail\n' > "$STATUS_FILE"
  printf 'module,status,source,destination,size_bytes,source_modified_utc,sha256,note\n' > "$MANIFEST_FILE"
  : > "$TIMELINE_TEMP"
}

banner() {
  cat <<EOF
=============================================================
 PowerTriage macOS CE $TOOL_VERSION
 Live Response & Forensic Triage
 Profile: $PROFILE | Scope: $SCOPE | Mode: $MODE
 PowerForensics: https://powerforensics.es
=============================================================
EOF
}

preflight() {
  local free_kb=""

  detect_permissions
  if [[ "$MODE" == "strict" ]]; then
    if [[ "$IS_ROOT" != "yes" ]]; then
      printf '[ERROR] --strict requires execution as root.\n' >&2
      exit 1
    fi
    if [[ "$FDA_STATUS" != "available" ]]; then
      printf '[ERROR] --strict requires detected Full Disk Access; status is %s.\n' "$FDA_STATUS" >&2
      exit 1
    fi
  fi

  free_kb=$(df -k "$OUTPUT_BASE" 2>/dev/null | awk 'NR==2 {print $4}')
  free_kb=${free_kb:-unknown}
  log_message "INFO" "Host=$HOSTNAME_SHORT CaseUTC=$CASE_UTC Profile=$PROFILE Scope=$SCOPE"
  log_message "INFO" "Output=$BASE_DIR Retention=$OUTPUT_RETENTION FreeKiB=$free_kb"
  log_message "INFO" "Root=$IS_ROOT FullDiskAccess=$FDA_STATUS IncludeSensitive=$INCLUDE_SENSITIVE"

  if [[ "$IS_ROOT" != "yes" ]]; then
    log_message "WARN" "Running without root; protected system artifacts will be skipped."
  fi
  if [[ "$FDA_STATUS" != "available" ]]; then
    log_message "WARN" "Full Disk Access was not detected; protected user artifacts may be unavailable."
  fi
}

handle_interruption() {
  if [[ "$FINALIZED" != "yes" && -n "$STATUS_FILE" && -f "$STATUS_FILE" ]]; then
    record_status "Runtime" "signal" "failed" "Collection interrupted"
    log_message "ERROR" "Collection interrupted by signal. Partial output retained at $BASE_DIR"
  fi
  exit 130
}

list_user_homes() {
  if command -v dscl >/dev/null 2>&1; then
    dscl . -list /Users NFSHomeDirectory 2>/dev/null | awk '
      NF >= 2 {
        user=$1
        $1=""
        sub(/^[[:space:]]+/, "", $0)
        if ($0 ~ /^\/Users\// && user != "Shared") print user "\t" $0
      }'
  else
    local home=""
    for home in /Users/*; do
      [[ -d "$home" ]] || continue
      [[ "$(basename "$home")" == "Shared" ]] && continue
      printf '%s\t%s\n' "$(basename "$home")" "$home"
    done
  fi
}

module_enabled_list() {
  local result="Context"
  [[ "$RUN_SYSTEM" == "yes" ]] && result="$result,System"
  [[ "$RUN_LIVE" == "yes" ]] && result="$result,LiveResponse"
  [[ "$RUN_NETWORK" == "yes" ]] && result="$result,Network"
  [[ "$RUN_PERSISTENCE" == "yes" ]] && result="$result,Persistence"
  [[ "$RUN_LOGS" == "yes" ]] && result="$result,Logs"
  [[ "$RUN_USERS" == "yes" ]] && result="$result,Users"
  [[ "$RUN_BROWSERS" == "yes" ]] && result="$result,Browsers"
  [[ "$RUN_FILESYSTEM" == "yes" ]] && result="$result,FileSystem"
  [[ "$RUN_SECURITY" == "yes" ]] && result="$result,Security"
  [[ "$DO_FILETREE" == "yes" ]] && result="$result,FileTree"
  printf '%s' "$result"
}

collect_context() {
  local module="Context"
  local context_file="$BASE_DIR/00_Context/execution_context.txt"
  mkdir -p "$BASE_DIR/00_Context"
  log_message "INFO" "[$module] Capturing execution context."

  {
    printf 'tool_name=%s\n' "$TOOL_NAME"
    printf 'tool_version=%s\n' "$TOOL_VERSION"
    printf 'schema_version=%s\n' "$SCHEMA_VERSION"
    printf 'case_id=%s\n' "$CASE_ID"
    printf 'case_name=%s\n' "$CASE_NAME"
    printf 'case_utc=%s\n' "$CASE_UTC"
    printf 'execution_utc=%s\n' "$(utc_now)"
    printf 'hostname=%s\n' "$HOSTNAME_SHORT"
    printf 'profile=%s\n' "$PROFILE"
    printf 'scope=%s\n' "$SCOPE"
    printf 'mode=%s\n' "$MODE"
    printf 'root=%s\n' "$IS_ROOT"
    printf 'full_disk_access=%s\n' "$FDA_STATUS"
    printf 'include_sensitive=%s\n' "$INCLUDE_SENSITIVE"
    printf 'since=%s\n' "$SINCE"
    printf 'max_copy_mb=%s\n' "$MAX_COPY_MB"
    printf 'output_retention=%s\n' "$OUTPUT_RETENTION"
    printf 'modules=%s\n' "$(module_enabled_list)"
    printf 'script_path=%s\n' "${BASH_SOURCE[0]}"
    printf 'shell=%s\n' "$BASH_VERSION"
  } > "$context_file"
  record_status "$module" "execution_context" "success" "PowerTriage execution metadata"
  register_copied_file "$module" "$context_file" "$context_file" "generated execution context"
  copy_if_present "$module" "${BASH_SOURCE[0]}" "00_Context/Collector/PowerTriage_macOS.sh" "collector source used for this run"

  run_capture "$module" "macOS version" "00_Context/sw_vers.txt" /usr/bin/sw_vers
  run_capture "$module" "kernel" "00_Context/uname.txt" /usr/bin/uname -a
  run_capture "$module" "current date" "00_Context/date.txt" /bin/date
  run_capture "$module" "uptime" "00_Context/uptime.txt" /usr/bin/uptime
  run_capture "$module" "boot time" "00_Context/kern_boottime.txt" /usr/sbin/sysctl kern.boottime
  run_capture "$module" "SIP status" "00_Context/sip_status.txt" /usr/bin/csrutil status
  run_capture "$module" "authenticated root status" "00_Context/authenticated_root_status.txt" /usr/bin/csrutil authenticated-root status
  run_capture "$module" "FileVault status" "00_Context/filevault_status.txt" /usr/bin/fdesetup status
  run_capture "$module" "mounts" "00_Context/mounts.txt" /sbin/mount
  run_capture "$module" "disk free" "00_Context/df.txt" /bin/df -h
}

collect_system() {
  local module="System"
  log_message "INFO" "[$module] Collecting system, hardware, storage and account context."
  mkdir -p "$BASE_DIR/System"

  run_capture "$module" "hardware and software profile" "System/system_profiler.txt" \
    /usr/sbin/system_profiler SPHardwareDataType SPSoftwareDataType SPStorageDataType
  run_capture "$module" "disk layout" "System/diskutil_list.txt" /usr/sbin/diskutil list
  run_capture "$module" "APFS layout" "System/diskutil_apfs_list.txt" /usr/sbin/diskutil apfs list
  run_capture "$module" "local users" "System/dscl_users.txt" /usr/bin/dscl . -list /Users UniqueID PrimaryGroupID NFSHomeDirectory UserShell
  run_capture "$module" "local groups" "System/dscl_groups.txt" /usr/bin/dscl . -list /Groups PrimaryGroupID
  run_capture "$module" "environment" "System/environment.txt" /usr/bin/env
  run_capture "$module" "NVRAM" "System/nvram.txt" /usr/sbin/nvram -p
  run_capture "$module" "power settings" "System/pmset.txt" /usr/bin/pmset -g custom
  run_capture "$module" "time zone" "System/timezone.txt" /usr/sbin/systemsetup -gettimezone
  run_capture "$module" "installed applications" "System/applications.txt" \
    /usr/sbin/system_profiler SPApplicationsDataType

  copy_if_present "$module" "/System/Library/CoreServices/SystemVersion.plist" \
    "System/SystemVersion.plist" "macOS version property list"
  copy_if_present "$module" "/Library/Preferences/SystemConfiguration/preferences.plist" \
    "System/SystemConfiguration/preferences.plist" "system network preferences"
  copy_if_present "$module" "/Library/Preferences/com.apple.loginwindow.plist" \
    "System/Preferences/com.apple.loginwindow.plist" "login window preferences"
}

collect_live_response() {
  local module="LiveResponse"
  log_message "INFO" "[$module] Collecting volatile process, session and open-file state."
  mkdir -p "$BASE_DIR/LiveResponse"

  run_capture "$module" "process list" "LiveResponse/processes.txt" \
    /bin/ps -axo user,pid,ppid,pgid,%cpu,%mem,lstart,etime,state,command
  run_capture "$module" "process hierarchy" "LiveResponse/process_hierarchy.txt" \
    /bin/ps -axjf
  run_capture "$module" "open files" "LiveResponse/open_files.txt" /usr/sbin/lsof -nP
  run_capture "$module" "logged users" "LiveResponse/who.txt" /usr/bin/who -a
  run_capture "$module" "session activity" "LiveResponse/w.txt" /usr/bin/w
  run_capture "$module" "recent logins" "LiveResponse/last.txt" /usr/bin/last -20
  run_capture "$module" "launchctl list" "LiveResponse/launchctl_list.txt" /bin/launchctl list
  run_capture "$module" "system launchd state" "LiveResponse/launchctl_system.txt" /bin/launchctl print system
  run_capture "$module" "virtual memory" "LiveResponse/vm_stat.txt" /usr/bin/vm_stat
  run_capture "$module" "system activity snapshot" "LiveResponse/top.txt" /usr/bin/top -l 1 -n 0
}

collect_network() {
  local module="Network"
  log_message "INFO" "[$module] Collecting interfaces, sockets, routes, DNS and firewall state."
  mkdir -p "$BASE_DIR/Network"

  run_capture "$module" "interfaces" "Network/ifconfig.txt" /sbin/ifconfig -a
  run_capture "$module" "network sockets" "Network/netstat_anv.txt" /usr/sbin/netstat -anv
  run_capture "$module" "routing table" "Network/netstat_routes.txt" /usr/sbin/netstat -rn
  run_capture "$module" "internet sockets by process" "Network/lsof_network.txt" /usr/sbin/lsof -nP -i
  run_capture "$module" "ARP cache" "Network/arp.txt" /usr/sbin/arp -an
  run_capture "$module" "default route" "Network/default_route.txt" /sbin/route -n get default
  run_capture "$module" "DNS configuration" "Network/scutil_dns.txt" /usr/sbin/scutil --dns
  run_capture "$module" "proxy configuration" "Network/scutil_proxy.txt" /usr/sbin/scutil --proxy
  run_capture "$module" "hardware ports" "Network/hardware_ports.txt" /usr/sbin/networksetup -listallhardwareports
  run_capture "$module" "preferred wireless networks" "Network/wifi_known_networks.txt" \
    /usr/sbin/networksetup -listpreferredwirelessnetworks en0
  run_capture "$module" "packet filter rules" "Network/pf_rules.txt" /sbin/pfctl -sr
  run_capture "$module" "application firewall state" "Network/application_firewall.txt" \
    /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
}

collect_persistence() {
  local module="Persistence"
  local user=""
  local home=""
  local safe_user=""
  log_message "INFO" "[$module] Collecting launch items, background tasks, cron and extensions."
  mkdir -p "$BASE_DIR/Persistence"

  copy_if_present "$module" "/Library/LaunchAgents" "Persistence/System/Library_LaunchAgents" "system-wide launch agents"
  copy_if_present "$module" "/Library/LaunchDaemons" "Persistence/System/Library_LaunchDaemons" "system-wide launch daemons"
  copy_optional_artifact "$module" "/Library/StartupItems" "Persistence/System/Library_StartupItems" "legacy startup items"
  copy_optional_artifact "$module" "/etc/periodic" "Persistence/System/etc_periodic" "periodic jobs"
  copy_optional_artifact "$module" "/etc/crontab" "Persistence/System/etc_crontab" "system crontab"
  copy_optional_artifact "$module" "/var/at/tabs" "Persistence/System/var_at_tabs" "per-user cron tabs"

  while IFS=$'\t' read -r user home; do
    [[ -n "$user" && -n "$home" ]] || continue
    safe_user=$(sanitize_component "$user")
    copy_optional_artifact "$module" "$home/Library/LaunchAgents" \
      "Persistence/Users/$safe_user/LaunchAgents" "per-user launch agents"
  done < <(list_user_homes)

  run_capture "$module" "background task management" "Persistence/sfltool_dumpbtm.txt" /usr/bin/sfltool dumpbtm
  run_capture "$module" "system extensions" "Persistence/systemextensionsctl_list.txt" /usr/bin/systemextensionsctl list
  run_capture "$module" "loaded kernel collections" "Persistence/kmutil_showloaded.txt" /usr/bin/kmutil showloaded
  run_shell_capture "$module" "root crontab" "Persistence/root_crontab.txt" \
    '/usr/bin/crontab -l 2>&1 || printf "No root crontab configured\n"'
  run_shell_capture "$module" "login hooks" "Persistence/login_logout_hooks.txt" \
    '/usr/bin/defaults read /Library/Preferences/com.apple.loginwindow LoginHook 2>&1 || printf "LoginHook not configured\n"; /usr/bin/defaults read /Library/Preferences/com.apple.loginwindow LogoutHook 2>&1 || printf "LogoutHook not configured\n"; exit 0'
}

collect_logs() {
  local module="Logs"
  local predicate='(process == "syspolicyd") OR (process == "XProtect") OR (process == "MRT") OR (subsystem == "com.apple.backgroundtaskmanagement") OR (eventMessage CONTAINS[c] "quarantine")'
  local logarchive="$BASE_DIR/Logs/PowerTriage_${HOSTNAME_SHORT}_${CASE_UTC}.logarchive"
  local rc=0
  local diagnostic_limit=100
  [[ "$SCOPE" == "deep" ]] && diagnostic_limit=300
  log_message "INFO" "[$module] Collecting Unified Logs and selected diagnostic logs for the last $SINCE."
  mkdir -p "$BASE_DIR/Logs"

  run_capture "$module" "targeted Unified Logs" "Logs/unified_targeted.log" \
    /usr/bin/log show --style syslog --info --last "$SINCE" --predicate "$predicate"

  if [[ "$SCOPE" == "deep" ]]; then
    if command_available /usr/bin/log; then
      /usr/bin/log collect --last "$SINCE" --output "$logarchive" > "$BASE_DIR/Logs/log_collect_output.txt" 2>&1 || rc=$?
      if [[ "$rc" -eq 0 && -d "$logarchive" ]]; then
        register_copied_tree "$module" "$logarchive" "$logarchive" "generated Unified Log archive"
        record_status "$module" "Unified Log archive" "success" "Collected last $SINCE"
      else
        record_status "$module" "Unified Log archive" "partial" "log collect exit code $rc"
        record_error "$module" "log collect failed with exit code $rc"
      fi
      register_copied_file "$module" "$BASE_DIR/Logs/log_collect_output.txt" "$BASE_DIR/Logs/log_collect_output.txt" "log collect command output"
    else
      record_status "$module" "Unified Log archive" "missing" "/usr/bin/log is unavailable"
    fi
  else
    record_status "$module" "Unified Log archive" "skipped" "Enable --deep to create a bounded logarchive"
  fi

  copy_if_present "$module" "/var/log/install.log" "Logs/Traditional/install.log" "software installation log"
  copy_optional_artifact "$module" "/var/log/system.log" "Logs/Traditional/system.log" "traditional system log"
  copy_recent_files_portable "$module" "/Library/Logs/DiagnosticReports" \
    "Logs/DiagnosticReports/Recent" "recent system diagnostic report" "$diagnostic_limit"
  copy_recent_files_portable "$module" "/Library/Logs/CrashReporter" \
    "Logs/CrashReporter/Recent" "recent system crash report" "$diagnostic_limit"
  if [[ "$SCOPE" == "fast" && -d "/Library/Logs/CrashReporter/CoreCapture" ]]; then
    record_status "$module" "/Library/Logs/CrashReporter/CoreCapture" "skipped" \
      "CoreCapture trees are excluded in fast scope because their names are not cross-platform portable; use --deep for bounded flattened collection"
  fi
}

collect_user_artifacts() {
  local module="Users"
  local user=""
  local home=""
  local safe_user=""
  local mail_index=""
  local mail_version=""
  log_message "INFO" "[$module] Collecting bounded high-value per-user artifacts."

  while IFS=$'\t' read -r user home; do
    [[ -n "$user" && -n "$home" ]] || continue
    safe_user=$(sanitize_component "$user")
    log_message "INFO" "[$module] User=$user Home=$home"

    copy_optional_artifact "$module" "$home/.zsh_history" "Users/$safe_user/Shell/.zsh_history" "zsh history"
    copy_optional_artifact "$module" "$home/.bash_history" "Users/$safe_user/Shell/.bash_history" "bash history"
    copy_optional_artifact "$module" "$home/.sh_history" "Users/$safe_user/Shell/.sh_history" "shell history"
    copy_optional_artifact "$module" "$home/.zsh_sessions" "Users/$safe_user/Shell/.zsh_sessions" "zsh sessions"
    copy_optional_artifact "$module" "$home/.bash_sessions" "Users/$safe_user/Shell/.bash_sessions" "bash sessions"

    copy_optional_artifact "$module" "$home/.ssh/known_hosts" "Users/$safe_user/SSH/known_hosts" "SSH known hosts"
    copy_optional_artifact "$module" "$home/.ssh/authorized_keys" "Users/$safe_user/SSH/authorized_keys" "SSH authorized keys"
    copy_optional_artifact "$module" "$home/.ssh/config" "Users/$safe_user/SSH/config" "SSH client configuration"

    copy_if_present "$module" "$home/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2" \
      "Users/$safe_user/Activity/QuarantineEventsV2" "Launch Services quarantine database"
    copy_if_present "$module" "$home/Library/Application Support/Knowledge/knowledgeC.db" \
      "Users/$safe_user/Activity/Knowledge/knowledgeC.db" "KnowledgeC database"
    copy_optional_artifact "$module" "$home/Library/Application Support/Knowledge/knowledgeC.db-wal" \
      "Users/$safe_user/Activity/Knowledge/knowledgeC.db-wal" "KnowledgeC WAL"
    copy_optional_artifact "$module" "$home/Library/Application Support/Knowledge/knowledgeC.db-shm" \
      "Users/$safe_user/Activity/Knowledge/knowledgeC.db-shm" "KnowledgeC SHM"
    copy_if_present "$module" "$home/Library/Application Support/com.apple.TCC/TCC.db" \
      "Users/$safe_user/Privacy/TCC.db" "per-user TCC database"
    copy_if_present "$module" "$home/Library/Application Support/com.apple.sharedfilelist" \
      "Users/$safe_user/Activity/SharedFileList" "recent items and shared file lists"
    copy_if_present "$module" "$home/Library/Preferences/com.apple.finder.plist" \
      "Users/$safe_user/Preferences/com.apple.finder.plist" "Finder preferences"
    copy_optional_artifact "$module" "$home/Library/Preferences/com.apple.loginitems.plist" \
      "Users/$safe_user/Preferences/com.apple.loginitems.plist" "legacy login items"

    copy_if_present "$module" "$home/Library/Messages/chat.db" \
      "Users/$safe_user/Sensitive/Messages/chat.db" "Messages metadata database" "sensitive"
    copy_if_present "$module" "$home/Library/Messages/chat.db-wal" \
      "Users/$safe_user/Sensitive/Messages/chat.db-wal" "Messages database WAL" "sensitive"
    copy_if_present "$module" "$home/Library/Messages/chat.db-shm" \
      "Users/$safe_user/Sensitive/Messages/chat.db-shm" "Messages database SHM" "sensitive"
    for mail_index in "$home"/Library/Mail/V*/MailData/Envelope\ Index; do
      [[ -f "$mail_index" ]] || continue
      mail_version=$(sanitize_component "$(basename "$(dirname "$(dirname "$mail_index")")")")
      copy_if_present "$module" "$mail_index" \
        "Users/$safe_user/Sensitive/Mail/$mail_version/Envelope_Index" "Mail envelope index" "sensitive"
    done
    copy_if_present "$module" "$home/Library/Keychains/login.keychain-db" \
      "Users/$safe_user/Sensitive/Keychains/login.keychain-db" "login keychain database" "sensitive"
  done < <(list_user_homes)

  copy_if_present "$module" "/Library/Application Support/com.apple.TCC/TCC.db" \
    "Users/System_TCC/TCC.db" "system TCC database"
}

collect_chromium_profile() {
  local module="$1"
  local user_name="$2"
  local browser_name="$3"
  local profile_name="$4"
  local profile_path="$5"
  local destination_root="Browsers/$user_name/$browser_name/$profile_name"
  local artifact=""

  for artifact in \
    "History" "History-wal" "History-shm" \
    "Cookies" "Cookies-wal" "Cookies-shm" \
    "Login Data" "Login Data-wal" "Login Data-shm" \
    "Web Data" "Web Data-wal" "Web Data-shm" \
    "Favicons" "Preferences" "Secure Preferences"; do
    copy_optional_artifact "$module" "$profile_path/$artifact" \
      "$destination_root/$(sanitize_component "$artifact")" "$browser_name $artifact"
  done

  copy_optional_artifact "$module" "$profile_path/Sessions" "$destination_root/Sessions" "$browser_name session state"
  copy_optional_artifact "$module" "$profile_path/Network/Cookies" "$destination_root/Network/Cookies" "$browser_name network cookies"
  copy_optional_artifact "$module" "$profile_path/Network/Cookies-wal" "$destination_root/Network/Cookies-wal" "$browser_name network cookies WAL"
  copy_optional_artifact "$module" "$profile_path/Network/Cookies-shm" "$destination_root/Network/Cookies-shm" "$browser_name network cookies SHM"
}

collect_chromium_browser() {
  local module="$1"
  local user_name="$2"
  local browser_name="$3"
  local browser_root="$4"
  local profile_path=""
  local profile_name=""

  [[ -d "$browser_root" ]] || {
    record_status "$module" "$browser_name for $user_name" "expected_absent" "$browser_root"
    return 0
  }

  copy_optional_artifact "$module" "$browser_root/Local State" \
    "Browsers/$user_name/$browser_name/Local_State" "$browser_name local state"

  for profile_path in "$browser_root/Default" "$browser_root"/Profile\ *; do
    [[ -d "$profile_path" ]] || continue
    profile_name=$(sanitize_component "$(basename "$profile_path")")
    collect_chromium_profile "$module" "$user_name" "$browser_name" "$profile_name" "$profile_path"
  done
}

collect_firefox_profile() {
  local module="$1"
  local user_name="$2"
  local profile_path="$3"
  local profile_name=""
  local artifact=""

  profile_name=$(sanitize_component "$(basename "$profile_path")")
  for artifact in \
    "places.sqlite" "places.sqlite-wal" "places.sqlite-shm" \
    "cookies.sqlite" "cookies.sqlite-wal" "cookies.sqlite-shm" \
    "formhistory.sqlite" "permissions.sqlite" "content-prefs.sqlite" \
    "logins.json" "key4.db" "cert9.db" "prefs.js"; do
    copy_optional_artifact "$module" "$profile_path/$artifact" \
      "Browsers/$user_name/Firefox/$profile_name/$artifact" "Firefox $artifact"
  done
  copy_optional_artifact "$module" "$profile_path/sessionstore-backups" \
    "Browsers/$user_name/Firefox/$profile_name/sessionstore-backups" "Firefox session state"
}

collect_browsers() {
  local module="Browsers"
  local user=""
  local home=""
  local safe_user=""
  local firefox_root=""
  local profile_path=""
  log_message "INFO" "[$module] Collecting browser history, downloads, cookies and session metadata."

  while IFS=$'\t' read -r user home; do
    [[ -n "$user" && -n "$home" ]] || continue
    safe_user=$(sanitize_component "$user")

    copy_optional_artifact "$module" "$home/Library/Safari/History.db" \
      "Browsers/$safe_user/Safari/History.db" "Safari history"
    copy_optional_artifact "$module" "$home/Library/Safari/History.db-wal" \
      "Browsers/$safe_user/Safari/History.db-wal" "Safari history WAL"
    copy_optional_artifact "$module" "$home/Library/Safari/History.db-shm" \
      "Browsers/$safe_user/Safari/History.db-shm" "Safari history SHM"
    copy_optional_artifact "$module" "$home/Library/Safari/Downloads.plist" \
      "Browsers/$safe_user/Safari/Downloads.plist" "Safari downloads"
    copy_optional_artifact "$module" "$home/Library/Safari/BrowserState.db" \
      "Browsers/$safe_user/Safari/BrowserState.db" "Safari browser state"
    copy_optional_artifact "$module" "$home/Library/Safari/LastSession.plist" \
      "Browsers/$safe_user/Safari/LastSession.plist" "Safari last session"
    copy_optional_artifact "$module" "$home/Library/Safari/CloudTabs.db" \
      "Browsers/$safe_user/Safari/CloudTabs.db" "Safari cloud tabs"
    copy_optional_artifact "$module" "$home/Library/Containers/com.apple.Safari/Data/Library/Safari/History.db" \
      "Browsers/$safe_user/Safari_Container/History.db" "sandboxed Safari history"

    collect_chromium_browser "$module" "$safe_user" "Chrome" \
      "$home/Library/Application Support/Google/Chrome"
    collect_chromium_browser "$module" "$safe_user" "Edge" \
      "$home/Library/Application Support/Microsoft Edge"
    collect_chromium_browser "$module" "$safe_user" "Brave" \
      "$home/Library/Application Support/BraveSoftware/Brave-Browser"
    collect_chromium_browser "$module" "$safe_user" "Chromium" \
      "$home/Library/Application Support/Chromium"

    firefox_root="$home/Library/Application Support/Firefox"
    copy_optional_artifact "$module" "$firefox_root/profiles.ini" \
      "Browsers/$safe_user/Firefox/profiles.ini" "Firefox profile configuration"
    copy_optional_artifact "$module" "$firefox_root/installs.ini" \
      "Browsers/$safe_user/Firefox/installs.ini" "Firefox installation mapping"
    for profile_path in "$firefox_root"/Profiles/*; do
      [[ -d "$profile_path" ]] || continue
      collect_firefox_profile "$module" "$safe_user" "$profile_path"
    done
  done < <(list_user_homes)
}

collect_filesystem() {
  local module="FileSystem"
  log_message "INFO" "[$module] Collecting APFS snapshot context and bounded filesystem metadata."
  mkdir -p "$BASE_DIR/FileSystem"

  run_capture "$module" "local APFS snapshots" "FileSystem/tmutil_local_snapshots.txt" \
    /usr/bin/tmutil listlocalsnapshots /
  run_capture "$module" "root volume information" "FileSystem/diskutil_root_info.txt" \
    /usr/sbin/diskutil info /
  run_shell_capture "$module" "root directory metadata" "FileSystem/root_metadata.txt" \
    '/bin/ls -laeO@ /; /bin/ls -laeO@ /System/Volumes/Data 2>&1'

  if [[ "$SCOPE" == "deep" ]]; then
    copy_optional_artifact "$module" "/System/Volumes/Data/.fseventsd" \
      "FileSystem/FSEvents/System_Volumes_Data_fseventsd" "APFS Data volume FSEvents"
    copy_optional_artifact "$module" "/.fseventsd" \
      "FileSystem/FSEvents/root_fseventsd" "legacy root FSEvents"
    copy_optional_artifact "$module" "/System/Volumes/Data/.Spotlight-V100" \
      "FileSystem/Spotlight/System_Volumes_Data_Spotlight-V100" "APFS Data volume Spotlight store"
    copy_optional_artifact "$module" "/.Spotlight-V100" \
      "FileSystem/Spotlight/root_Spotlight-V100" "legacy root Spotlight store"
    copy_optional_artifact "$module" "/System/Volumes/Data/.DocumentRevisions-V100" \
      "FileSystem/DocumentRevisions/DocumentRevisions-V100" "document revision store"
  else
    record_status "$module" "raw FSEvents and Spotlight stores" "skipped" "Enable --deep for bounded raw acquisition"
  fi
}

collect_security() {
  local module="Security"
  log_message "INFO" "[$module] Collecting Gatekeeper, XProtect, profiles and security extension context."
  mkdir -p "$BASE_DIR/Security"

  run_capture "$module" "Gatekeeper status" "Security/gatekeeper_status.txt" /usr/sbin/spctl --status
  run_capture "$module" "system extensions" "Security/system_extensions.txt" /usr/bin/systemextensionsctl list
  run_capture "$module" "configuration profiles" "Security/profiles_show.txt" /usr/bin/profiles show -type configuration
  run_capture "$module" "MDM enrollment" "Security/profiles_enrollment.txt" /usr/bin/profiles status -type enrollment
  run_capture "$module" "installed packages" "Security/pkgutil_packages.txt" /usr/sbin/pkgutil --pkgs
  run_capture "$module" "software update history" "Security/softwareupdate_history.txt" /usr/sbin/softwareupdate --history
  run_capture "$module" "firewall global state" "Security/firewall_global_state.txt" \
    /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
  run_capture "$module" "firewall stealth mode" "Security/firewall_stealth_mode.txt" \
    /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode

  copy_if_present "$module" "/Library/Preferences/com.apple.security.plist" \
    "Security/Preferences/com.apple.security.plist" "system security preferences"
  copy_optional_artifact "$module" "/Library/Preferences/com.apple.alf.plist" \
    "Security/Preferences/com.apple.alf.plist" "application firewall preferences"
  copy_optional_artifact "$module" "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources" \
    "Security/XProtect/Resources" "XProtect definitions"
  copy_optional_artifact "$module" "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Resources" \
    "Security/XProtect/App_Resources" "XProtect application resources"
}

filetree_default_roots() {
  printf '%s\n' "/Applications" "/Library" "/Users"
}

filetree_stat_value() {
  local format="$1"
  local path="$2"
  stat -f "$format" "$path" 2>/dev/null || printf ''
}

filetree_write_node() {
  local path="$1"
  local root="$2"
  local depth="$3"
  local type="file"
  local size="0"
  local mode=""
  local uid=""
  local gid=""
  local modified=""
  local created=""

  if [[ -L "$path" ]]; then
    type="symlink"
  elif [[ -d "$path" ]]; then
    type="directory"
  fi
  if [[ -f "$path" ]]; then
    size=$(file_size_bytes "$path")
  fi
  mode=$(filetree_stat_value '%Sp' "$path")
  uid=$(filetree_stat_value '%u' "$path")
  gid=$(filetree_stat_value '%g' "$path")
  modified=$(epoch_to_utc "$(filetree_stat_value '%m' "$path")")
  created=$(epoch_to_utc "$(filetree_stat_value '%B' "$path")")

  printf '{"root":"%s","path":"%s","name":"%s","type":"%s","size":%s,"mode":"%s","uid":"%s","gid":"%s","created_utc":"%s","modified_utc":"%s","depth":%s,"source":"PowerTriage.FileTree"}\n' \
    "$(json_escape "$root")" \
    "$(json_escape "$path")" \
    "$(json_escape "$(basename "$path")")" \
    "$(json_escape "$type")" \
    "${size:-0}" \
    "$(json_escape "$mode")" \
    "$(json_escape "$uid")" \
    "$(json_escape "$gid")" \
    "$(json_escape "$created")" \
    "$(json_escape "$modified")" \
    "$depth" >> "$BASE_DIR/FileSystem/FileTree.jsonl"
}

FILETREE_ENTRY_COUNT=0
FILETREE_DIR_COUNT=0
FILETREE_FILE_COUNT=0
FILETREE_ERROR_COUNT=0
FILETREE_TRUNCATED="no"

filetree_walk() {
  local path="$1"
  local root="$2"
  local depth="$3"
  local root_device="$4"
  local child=""
  local child_device=""

  if [[ "$FILETREE_ENTRY_COUNT" -ge "$FILETREE_MAX_ENTRIES" ]]; then
    FILETREE_TRUNCATED="yes"
    return 0
  fi
  if is_path_within_output "$path"; then
    return 0
  fi

  filetree_write_node "$path" "$root" "$depth"
  FILETREE_ENTRY_COUNT=$((FILETREE_ENTRY_COUNT + 1))
  if [[ -d "$path" && ! -L "$path" ]]; then
    FILETREE_DIR_COUNT=$((FILETREE_DIR_COUNT + 1))
  else
    FILETREE_FILE_COUNT=$((FILETREE_FILE_COUNT + 1))
  fi

  if [[ ! -d "$path" || -L "$path" || "$depth" -ge "$FILETREE_MAX_DEPTH" ]]; then
    return 0
  fi
  if [[ ! -r "$path" ]]; then
    FILETREE_ERROR_COUNT=$((FILETREE_ERROR_COUNT + 1))
    printf '%s\tpermission_denied\n' "$path" >> "$BASE_DIR/FileSystem/FileTree_Errors.tsv"
    return 0
  fi

  for child in "$path"/* "$path"/.[!.]* "$path"/..?*; do
    [[ -e "$child" || -L "$child" ]] || continue
    child_device=$(filetree_stat_value '%d' "$child")
    if [[ -n "$root_device" && -n "$child_device" && "$child_device" != "$root_device" ]]; then
      continue
    fi
    filetree_walk "$child" "$root" $((depth + 1)) "$root_device"
    if [[ "$FILETREE_ENTRY_COUNT" -ge "$FILETREE_MAX_ENTRIES" ]]; then
      FILETREE_TRUNCATED="yes"
      break
    fi
  done
}

collect_filetree() {
  local module="FileTree"
  local root=""
  local root_device=""
  local roots_file="$BASE_DIR/FileSystem/FileTree_Roots.txt"
  local summary_file="$BASE_DIR/FileSystem/FileTree_Summary.json"
  local roots=()

  [[ "$DO_FILETREE" != "yes" ]] && return 0
  log_message "INFO" "[$module] Exporting metadata-only filesystem tree."
  mkdir -p "$BASE_DIR/FileSystem"
  : > "$BASE_DIR/FileSystem/FileTree.jsonl"
  : > "$BASE_DIR/FileSystem/FileTree_Errors.tsv"
  : > "$roots_file"

  if [[ ${#FILETREE_ROOTS[@]} -gt 0 ]]; then
    roots=("${FILETREE_ROOTS[@]}")
  else
    while IFS= read -r root; do
      roots+=("$root")
    done < <(filetree_default_roots)
  fi

  for root in "${roots[@]}"; do
    if [[ ! -e "$root" ]]; then
      record_status "$module" "$root" "missing" "FileTree root not present"
      continue
    fi
    printf '%s\n' "$root" >> "$roots_file"
    root_device=$(filetree_stat_value '%d' "$root")
    filetree_walk "$root" "$root" 0 "$root_device"
    [[ "$FILETREE_TRUNCATED" == "yes" ]] && break
  done

  cat > "$summary_file" <<EOF
{
  "entries": $FILETREE_ENTRY_COUNT,
  "directories": $FILETREE_DIR_COUNT,
  "files_or_links": $FILETREE_FILE_COUNT,
  "errors": $FILETREE_ERROR_COUNT,
  "max_depth": $FILETREE_MAX_DEPTH,
  "max_entries": $FILETREE_MAX_ENTRIES,
  "truncated": "$FILETREE_TRUNCATED"
}
EOF

  register_copied_file "$module" "$BASE_DIR/FileSystem/FileTree.jsonl" "$BASE_DIR/FileSystem/FileTree.jsonl" "generated FileTree index"
  register_copied_file "$module" "$summary_file" "$summary_file" "generated FileTree summary"
  register_copied_file "$module" "$roots_file" "$roots_file" "FileTree root list"
  register_copied_file "$module" "$BASE_DIR/FileSystem/FileTree_Errors.tsv" "$BASE_DIR/FileSystem/FileTree_Errors.tsv" "FileTree errors"
  if [[ "$FILETREE_TRUNCATED" == "yes" ]]; then
    record_status "$module" "FileTree" "partial" "Entry limit reached at $FILETREE_ENTRY_COUNT"
  else
    record_status "$module" "FileTree" "success" "$FILETREE_ENTRY_COUNT entries"
  fi
}

generate_timeline() {
  local module="Timeline"
  local timeline_dir="$BASE_DIR/Timeline"
  local timeline_file="$timeline_dir/PowerTriage_Timeline_Chronos.json"
  local summary_file="$timeline_dir/Timeline_Summary.txt"
  local first="yes"
  local event=""

  [[ "$DO_TIMELINE" != "yes" ]] && return 0
  TIMELINE_EVENT_COLLECTION_OPEN="no"
  mkdir -p "$timeline_dir"
  printf '[\n' > "$timeline_file"
  while IFS= read -r event; do
    [[ -n "$event" ]] || continue
    if [[ "$first" == "yes" ]]; then
      first="no"
    else
      printf ',\n' >> "$timeline_file"
    fi
    printf '  %s' "$event" >> "$timeline_file"
  done < "$TIMELINE_TEMP"
  printf '\n]\n' >> "$timeline_file"

  {
    printf 'PowerTriage macOS Chronos Timeline\n'
    printf 'Generated UTC: %s\n' "$(utc_now)"
    printf 'Events: %s\n' "$TIMELINE_COUNTER"
    printf 'Source: acquired-artifact source modification times\n'
  } > "$summary_file"

  record_status "$module" "Chronos timeline" "success" "$TIMELINE_COUNTER events"
  register_copied_file "$module" "$timeline_file" "$timeline_file" "Chronos-compatible timeline"
  register_copied_file "$module" "$summary_file" "$summary_file" "timeline summary"
}

generate_forensic_catalog() {
  local module="Catalog"
  local catalog="$BASE_DIR/ForensicCatalog.json"
  local os_version=""
  local os_build=""
  local architecture=""

  os_version=$(/usr/bin/sw_vers -productVersion 2>/dev/null || printf 'unknown')
  os_build=$(/usr/bin/sw_vers -buildVersion 2>/dev/null || printf 'unknown')
  architecture=$(/usr/bin/uname -m 2>/dev/null || printf 'unknown')

  cat > "$catalog" <<EOF
{
  "schema_version": "$(json_escape "$SCHEMA_VERSION")",
  "tool": {
    "name": "$(json_escape "$TOOL_NAME")",
    "version": "$(json_escape "$TOOL_VERSION")",
    "edition": "Community Edition"
  },
  "case": {
    "id": "$(json_escape "$CASE_ID")",
    "name": "$(json_escape "$CASE_NAME")",
    "started_utc": "$(json_escape "$CASE_UTC")",
    "hostname": "$(json_escape "$HOSTNAME_SHORT")"
  },
  "target": {
    "platform": "macOS",
    "version": "$(json_escape "$os_version")",
    "build": "$(json_escape "$os_build")",
    "architecture": "$(json_escape "$architecture")"
  },
  "execution": {
    "profile": "$(json_escape "$PROFILE")",
    "scope": "$(json_escape "$SCOPE")",
    "mode": "$(json_escape "$MODE")",
    "root": "$IS_ROOT",
    "full_disk_access": "$(json_escape "$FDA_STATUS")",
    "include_sensitive": "$INCLUDE_SENSITIVE",
    "since": "$(json_escape "$SINCE")",
    "output_retention": "$(json_escape "$OUTPUT_RETENTION")",
    "modules": "$(json_escape "$(module_enabled_list)")"
  },
  "outputs": {
    "manifest": "artifact_manifest.csv",
    "collection_status": "collection_status.csv",
    "hashes": "hashes.sha256",
    "errors": "errors.log",
    "timeline": "$(if [[ "$DO_TIMELINE" == "yes" ]]; then printf 'Timeline/PowerTriage_Timeline_Chronos.json'; fi)"
  }
}
EOF
  record_status "$module" "ForensicCatalog.json" "success" "Catalog generated"
  register_copied_file "$module" "$catalog" "$catalog" "forensic catalog"
}

generate_summary() {
  local summary="$BASE_DIR/SUMMARY.md"
  cat > "$summary" <<EOF
# PowerTriage macOS CE Collection Summary

- Tool version: $TOOL_VERSION
- Case ID: ${CASE_ID:-Not supplied}
- Case name: $CASE_NAME
- Host: $HOSTNAME_SHORT
- Started UTC: $CASE_UTC
- Finalized UTC: $(utc_now)
- Profile: $PROFILE
- Scope: $SCOPE
- Modules: $(module_enabled_list)
- Root: $IS_ROOT
- Full Disk Access detection: $FDA_STATUS
- Sensitive artifacts requested: $INCLUDE_SENSITIVE
- Output retention: $OUTPUT_RETENTION
- Artifact records: $((ARTIFACT_COUNT + 1))
- Successful operations: $((SUCCESS_COUNT + 1))
- Partial operations: $PARTIAL_COUNT
- Skipped, missing, or blocked operations: $SKIPPED_COUNT
- Expected optional artifacts not present: $EXPECTED_ABSENT_COUNT
- Failed operations: $FAILED_COUNT

## Review order

1. Review \`collection_status.csv\` for incomplete and blocked operations.
2. Review \`artifact_manifest.csv\` for source-to-destination mapping and per-file hashes.
3. Verify the final collection against \`hashes.sha256\`.
4. Review \`errors.log\` before treating a module as complete.
5. When enabled, import \`Timeline/PowerTriage_Timeline_Chronos.json\` into Chronos.

## Collection boundaries

- PowerTriage macOS CE performs live triage; it is not a physical disk acquisition tool.
- Root and Full Disk Access are independent. Missing access is recorded rather than hidden.
- User documents and message or mail attachments are not bulk-copied.
- Raw high-volume stores are bounded by \`--max-copy-mb\` and require \`--deep\` where documented.
EOF
  record_status "Summary" "SUMMARY.md" "success" "Collection summary generated"
  register_copied_file "Summary" "$summary" "$summary" "collection summary"
}

compute_internal_hashes() {
  local file=""
  local relative=""
  local hash=""
  local temp_hash="$BASE_DIR/.hashes.sha256.tmp"

  log_message "INFO" "[Finalize] Computing final SHA-256 inventory."
  : > "$temp_hash"
  while IFS= read -r -d '' file; do
    [[ "$file" == "$HASH_FILE" || "$file" == "$temp_hash" || "$file" == "$TIMELINE_TEMP" ]] && continue
    hash=$(sha256_file "$file")
    relative=$(relative_destination "$file")
    if [[ -n "$hash" ]]; then
      printf '%s  %s\n' "$hash" "$relative" >> "$temp_hash"
    else
      printf '[WARN] Unable to hash: %s\n' "$relative" >&2
    fi
  done < <(find "$BASE_DIR" -type f -print0 2>/dev/null)
  mv -f "$temp_hash" "$HASH_FILE"
}

finalize_internal_output() {
  generate_timeline
  rm -f "$TIMELINE_TEMP"
  generate_forensic_catalog
  generate_summary
  log_message "INFO" "Collection modules complete. Finalizing immutable records."
  log_message "INFO" "Artifacts=$ARTIFACT_COUNT Success=$SUCCESS_COUNT Partial=$PARTIAL_COUNT Skipped=$SKIPPED_COUNT ExpectedAbsent=$EXPECTED_ABSENT_COUNT Failed=$FAILED_COUNT"
  trap - INT TERM
  FINALIZED="yes"
  compute_internal_hashes
}

validate_delete_target() {
  local expected="$OUTPUT_BASE/$CASE_NAME"
  local parent=""
  local name=""
  parent=$(dirname "$BASE_DIR")
  name=$(basename "$BASE_DIR")
  [[ "$BASE_DIR" == "$expected" ]] || return 1
  [[ "$parent" == "$OUTPUT_BASE" ]] || return 1
  [[ "$name" == powertriage_macos_* ]] || return 1
  [[ "$BASE_DIR" != "/" && "$BASE_DIR" != "$OUTPUT_BASE" ]] || return 1
  return 0
}

package_output() {
  local archive_hash=""
  local rc=0

  if [[ "$OUTPUT_RETENTION" == "directory-only" ]]; then
    printf '[INFO] Directory retained: %s\n' "$BASE_DIR"
    printf '[INFO] Archive: not requested\n'
    return 0
  fi

  printf '[INFO] Creating archive: %s\n' "$ARCHIVE_PATH"
  if [[ -x /usr/bin/ditto ]]; then
    /usr/bin/ditto -c -k --sequesterRsrc --keepParent "$BASE_DIR" "$ARCHIVE_PATH" || rc=$?
  else
    printf '[ERROR] /usr/bin/ditto is unavailable; archive was not created.\n' >&2
    return 1
  fi

  if [[ "$rc" -ne 0 || ! -s "$ARCHIVE_PATH" ]]; then
    printf '[ERROR] Archive creation failed with exit code %s. Directory retained.\n' "$rc" >&2
    return 1
  fi

  archive_hash=$(sha256_file "$ARCHIVE_PATH")
  if [[ -z "$archive_hash" ]]; then
    printf '[ERROR] Archive exists but its SHA-256 could not be calculated. Directory retained.\n' >&2
    return 1
  fi
  printf '%s  %s\n' "$archive_hash" "$(basename "$ARCHIVE_PATH")" > "$ARCHIVE_HASH_PATH"
  printf '[INFO] Archive SHA-256: %s\n' "$archive_hash"

  if [[ "$OUTPUT_RETENTION" == "archive-only" ]]; then
    if validate_delete_target; then
      rm -rf "$BASE_DIR"
      printf '[INFO] Uncompressed directory removed because archive-only was explicitly selected.\n'
    else
      printf '[ERROR] Safety validation refused to remove the uncompressed directory.\n' >&2
      return 1
    fi
  else
    printf '[INFO] Directory retained: %s\n' "$BASE_DIR"
  fi
  printf '[INFO] Archive retained: %s\n' "$ARCHIVE_PATH"
}

run_selected_modules() {
  collect_context
  [[ "$RUN_SYSTEM" == "yes" ]] && collect_system
  [[ "$RUN_LIVE" == "yes" ]] && collect_live_response
  [[ "$RUN_NETWORK" == "yes" ]] && collect_network
  [[ "$RUN_PERSISTENCE" == "yes" ]] && collect_persistence
  [[ "$RUN_LOGS" == "yes" ]] && collect_logs
  [[ "$RUN_USERS" == "yes" ]] && collect_user_artifacts
  [[ "$RUN_BROWSERS" == "yes" ]] && collect_browsers
  [[ "$RUN_FILESYSTEM" == "yes" ]] && collect_filesystem
  [[ "$RUN_SECURITY" == "yes" ]] && collect_security
  collect_filetree
}

main() {
  parse_arguments "$@"
  select_profile_interactive
  validate_configuration
  check_platform
  resolve_output_base
  setup_output
  trap handle_interruption INT TERM
  banner
  preflight
  run_selected_modules
  finalize_internal_output
  package_output
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
