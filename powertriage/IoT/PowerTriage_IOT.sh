#!/usr/bin/env bash
# triageX_offline_iot_v6.1.sh
# TRIAGEX IOT - OpenWrt (v6.1 Docente)
# Triage Tool for IoT OpenWrt (bash/python) - BETA
# Author: Jesus D. Angosto (@jdangosto)
# Notas v6.1:
# - Más robusto: no se corta por errores en find/grep
# - Soluciona fingerprint Dropbear (sin "is not a public key file")
# - Siempre genera summary_report.txt (trap EXIT)
# - Mensajes de progreso claros para docencia

# Robustez: no abortar por retornos !=0 en subcomandos
set -uo pipefail
IFS=$'\n\t'

cat <<'BANNER'

################################################################## 
#                      TRIAGEX  IOT - OpenWRT                    #
#                   ---------------------------                  #	
#       		 Triage Tool for IoT OpenWRT (bash/python)       #
#                           BETA Version                         #
#----------------------------------------------------------------#
#                     Author: Jesus D. Angosto                   #
#                            @jdangosto                          #
################################################################## 

BANNER

# -----------------------
# Args & helpers
# -----------------------
ROOT=${1:-}
OUT=${2:-./iot_triage_out_v61}
BASELINE=${3:-}   # opcional: luci_manifest.csv de firmware limpio

NOW(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
hash_file(){ [[ -f "$1" ]] && sha256sum "$1" | awk '{print $1}' || echo ""; }
file_size(){ [[ -f "$1" ]] && stat -c %s "$1" 2>/dev/null || echo ""; }

if [[ -z "$ROOT" || ! -d "$ROOT" ]]; then
  echo "Uso: $0 /ruta/al/root_montado /ruta/de/salida [baseline_luci_manifest.csv]"
  exit 1
fi

mkdir -p "$OUT"
LOG="$OUT/run.log"
exec > >(tee -a "$LOG") 2>&1

# Estado para summary final aunque haya errores intermedios
FOUND_LUCI_CODE="no"; FOUND_LUCI_CGI="no"; FOUND_LUCI_SESS="0"
SUMMARY_WROTE="no"
MANIFEST="$OUT/manifest.csv"
mkdir -p "$OUT"
echo "relative_path,sha256,mtime,size,notes" > "$MANIFEST"

add_manifest(){
  local dst="$1"; local note="${2:-}"
  if [[ -f "$dst" ]]; then
    local sha size mt rel
    sha=$(hash_file "$dst"); size=$(file_size "$dst"); mt=$(stat -c %y "$dst" 2>/dev/null || echo "")
    rel="${dst#$OUT/}"; echo "\"$rel\",\"$sha\",\"$mt\",\"$size\",\"$note\"" >> "$MANIFEST"
  fi
}
safe_cp(){
  local src="$1"; local dst="$2"; local note="${3:-}"
  if [[ -e "$src" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp -a --preserve=mode,ownership,timestamps "$src" "$dst" 2>/dev/null || cp -a "$src" "$dst" 2>/dev/null || true
    add_manifest "$dst" "$note"
  fi
}

# --- función de cierre garantizado ---
finish(){
  [[ "$SUMMARY_WROTE" == "yes" ]] && return 0
  echo "[*] Generando summary_report.txt (auto-final)" | tee -a "$LOG"
  {
    echo "triageX_offline_iot_v6.1 - Summary - $(NOW)"; echo
    echo "LuCI: code=$FOUND_LUCI_CODE cgi=$FOUND_LUCI_CGI sessions=$FOUND_LUCI_SESS"
    [[ -f "$OUT/luci_artifacts/luci_manifest.csv" ]] && echo "  luci_manifest.csv OK"
    [[ -s "$OUT/luci_artifacts/suspicious_lua.txt" ]] && echo "  suspicious_lua.txt OK"
    [[ -f "$OUT/config_diff.txt" ]] && echo "config_diff.txt OK"
    echo
    echo "Top IPs:"; head -n 30 "$OUT/iocs/ip_counts.txt" 2>/dev/null || true; echo
    echo "Top domains:"; head -n 30 "$OUT/iocs/domains_counts.txt" 2>/dev/null || true; echo
    echo "SSH events sample:"; head -n 50 "$OUT/ssh_events.txt" 2>/dev/null || true; echo
    [[ -f "$OUT/iocs/ssh_bruteforce_summary.csv" ]] && { echo "Bruteforce summary (top 20):"; head -n 20 "$OUT/iocs/ssh_bruteforce_summary.csv"; echo; }
  } > "$OUT/summary_report.txt"
  SUMMARY_WROTE="yes"
  # paquete
  ( cd "$OUT/.." && tar -czf "$(basename "$OUT").tar.gz" "$(basename "$OUT")" 2>/dev/null && sha256sum "$(basename "$OUT").tar.gz" > "$(basename "$OUT").tar.gz.sha256" 2>/dev/null ) || true
  echo "[*] Done: $(NOW)"
  echo "[*] Output directory: $OUT"
}
trap finish EXIT

echo "[*] triageX_offline_iot_v6.1 - Inicio: $(NOW)"
echo "[*] Rootfs: $ROOT"
echo "[*] Outdir: $OUT"

# -----------------------
# Metadata & firmware identity
# -----------------------
echo "[1/11] Metadata y firmware info"
stat "$ROOT" > "$OUT/metadata_stat.txt" 2>/dev/null || true
uname -a > "$OUT/host_uname.txt" 2>/dev/null || true
echo "start: $(NOW)" >> "$OUT/metadata_stat.txt"
FIRM="$OUT/firmware_info.txt"
{
  echo "== Firmware identity =="
  for f in "$ROOT/etc/os-release" "$ROOT/etc/openwrt_release" "$ROOT/etc/openwrt_version"; do
    [[ -f "$f" ]] && { echo "--- $f ---"; cat "$f"; echo; }
  done
} > "$FIRM"
add_manifest "$FIRM" "firmware_info"
echo "[+] Metadata OK"

# -----------------------
# MERGE ROOTFS
# -----------------------
echo "[2/11] Construyendo merged_rootfs (rom + overlay + root)"
MERGE="$OUT/merged_rootfs"; mkdir -p "$MERGE"
[[ -d "$ROOT/rom" ]] && rsync -a "$ROOT/rom/" "$MERGE/" 2>/dev/null || true
[[ -d "$ROOT/overlay/upper" ]] && rsync -a "$ROOT/overlay/upper/" "$MERGE/" 2>/dev/null || true
rsync -a --exclude="rom/*" --exclude="overlay/*" "$ROOT/" "$MERGE/" 2>/dev/null || true
echo "[+] merged_rootfs OK"

# -----------------------
# /etc y UCI
# -----------------------
echo "[3/11] Copy /etc y UCI configs"
safe_cp "$ROOT/etc" "$OUT/etc_full" "etc full"
if [[ -d "$ROOT/etc/config" ]]; then
  rsync -a "$ROOT/etc/config" "$OUT/etc_config" 2>/dev/null || true
  for f in "$ROOT/etc/config"/*; do safe_cp "$f" "$OUT/etc_config/$(basename "$f")" "uci config"; done
fi
echo "[+] /etc & UCI OK"

# -----------------------
# Usuarios & SSH / Dropbear fingerprint (robusto)
# -----------------------
echo "[4/11] Users & SSH (Dropbear fingerprint)"
safe_cp "$ROOT/etc/passwd" "$OUT/etc/passwd" "passwd"
safe_cp "$ROOT/etc/shadow" "$OUT/etc/shadow" "shadow"
safe_cp "$ROOT/etc/group" "$OUT/etc/group" "group"
safe_cp "$ROOT/etc/config/dropbear" "$OUT/etc/config/dropbear" "dropbear uci"
safe_cp "$ROOT/etc/dropbear" "$OUT/etc/dropbear" "dropbear dir"
safe_cp "$ROOT/etc/ssh" "$OUT/etc/ssh" "openssh dir"

find "$ROOT" -type f \( -iname "authorized_keys" -o -iname "known_hosts" \) -print0 2>/dev/null | while IFS= read -r -d '' kf; do
  dest="$OUT/ssh_keys${kf#$ROOT}"; mkdir -p "$(dirname "$dest")"; cp -a "$kf" "$dest" 2>/dev/null || true; add_manifest "$dest" "ssh_keys"
done

FP_OUT="$OUT/auth/dropbear_fingerprint.txt"; mkdir -p "$(dirname "$FP_OUT")"
if [[ -f "$ROOT/etc/dropbear/dropbear_rsa_host_key" ]]; then
  cp -a "$ROOT/etc/dropbear/dropbear_rsa_host_key" "$OUT/auth/" 2>/dev/null || true
  add_manifest "$OUT/auth/dropbear_rsa_host_key" "dropbear host key"
  {
    echo "Dropbear host key fingerprint (SHA256):"
    if command -v dropbearkey >/dev/null 2>&1; then
      # Extrae línea en formato openssh "ssh-rsa AAAA..."
      dropbearkey -y -f "$OUT/auth/dropbear_rsa_host_key" 2>/dev/null | awk '/^ssh-rsa/ {print $0}' > "$OUT/auth/db_tmp.pub" 2>/dev/null
      if [[ -s "$OUT/auth/db_tmp.pub" ]] && command -v ssh-keygen >/dev/null 2>&1; then
        ssh-keygen -lf "$OUT/auth/db_tmp.pub" -E sha256 || ssh-keygen -lf "$OUT/auth/db_tmp.pub"
      else
        echo "(fallback) SHA256(file):"; sha256sum "$OUT/auth/dropbear_rsa_host_key"
      fi
      rm -f "$OUT/auth/db_tmp.pub" 2>/dev/null || true
    else
      echo "dropbearkey no disponible; SHA256(file):"; sha256sum "$OUT/auth/dropbear_rsa_host_key"
    fi
  } > "$FP_OUT"
  add_manifest "$FP_OUT" "dropbear fingerprint"
fi
echo "[+] Auth & SSH OK"

# -----------------------
# Persistencia
# -----------------------
echo "[5/11] Persistencia (init, rc, cron, uci-defaults, keep.d, hotplug)"
safe_cp "$ROOT/etc/init.d" "$OUT/persistence/init.d" "init.d"
safe_cp "$ROOT/etc/rc.d" "$OUT/persistence/rc.d" "rc.d"
safe_cp "$ROOT/etc/crontabs" "$OUT/persistence/crontabs" "crontabs"
safe_cp "$ROOT/etc/rc.local" "$OUT/persistence/rc.local" "rc.local"
safe_cp "$ROOT/etc/uci-defaults" "$OUT/persistence/uci-defaults" "uci-defaults"
safe_cp "$ROOT/lib/upgrade/keep.d" "$OUT/persistence/keep.d" "upgrade keep.d"
safe_cp "$ROOT/etc/hotplug.d" "$OUT/persistence/hotplug.d" "hotplug.d"

PERS_SUM="$OUT/persistence/init_persistence.txt"
{
  echo "== Servicios al arranque (rc.d) =="; ls -l "$OUT/persistence/rc.d" 2>/dev/null || true; echo
  echo "== rc.local =="; [[ -f "$OUT/persistence/rc.local" ]] && sed -n '1,200p' "$OUT/persistence/rc.local"; echo
  echo "== uci-defaults =="; ls -l "$OUT/persistence/uci-defaults" 2>/dev/null || true; echo
  echo "== keep.d =="; ls -l "$OUT/persistence/keep.d" 2>/dev/null || true; echo
  echo "== hotplug.d =="; find "$OUT/persistence/hotplug.d" -maxdepth 2 -type f 2>/dev/null || true
} > "$PERS_SUM"
add_manifest "$PERS_SUM" "persistence summary"
echo "[+] Persistencia OK"

# -----------------------
# Red / Servicios
# -----------------------
echo "[6/11] Configuración de red y servicios"
NET_DIR="$OUT/network_configs"; mkdir -p "$NET_DIR"
safe_cp "$ROOT/etc/config/network" "$NET_DIR/network" "uci network"
safe_cp "$ROOT/etc/config/firewall" "$NET_DIR/firewall" "uci firewall"
safe_cp "$ROOT/etc/firewall.user" "$NET_DIR/firewall.user" "firewall user"
safe_cp "$ROOT/etc/config/uhttpd" "$NET_DIR/uhttpd" "uhttpd"
safe_cp "$ROOT/etc/dnsmasq.conf" "$NET_DIR/dnsmasq.conf" "dnsmasq.conf"
safe_cp "$ROOT/etc/config/dhcp" "$NET_DIR/dhcp" "uci dhcp"
safe_cp "$ROOT/etc/config/upnpd" "$NET_DIR/upnpd" "uci upnpd"
safe_cp "$ROOT/usr/sbin/miniupnpd" "$NET_DIR/miniupnpd.bin" "miniupnpd bin"
safe_cp "$ROOT/etc/hosts" "$NET_DIR/hosts" "hosts"
safe_cp "$ROOT/etc/resolv.conf" "$NET_DIR/resolv.conf" "resolv.conf"
echo "[+] Red/Servicios OK"

# -----------------------
# Logs + /tmp /run (robusto)
# -----------------------
echo "[7/11] Logs y artefactos temporales"
LOG_OUT="$OUT/var_log"; mkdir -p "$LOG_OUT"
find "$ROOT/var/log" -maxdepth 5 -type f -size -200M -print0 2>/dev/null | while IFS= read -r -d '' lf; do
  dest="$LOG_OUT${lf#$ROOT}"; mkdir -p "$(dirname "$dest")"; cp -a "$lf" "$dest" 2>/dev/null || true
  add_manifest "$dest" "log"
  if [[ "$dest" =~ \.gz$ ]] && command -v zcat >/dev/null 2>&1; then
    outtxt="${dest%.gz}.decompressed.txt"; zcat "$dest" > "$outtxt" 2>/dev/null || true; add_manifest "$outtxt" "log decompressed"
  fi
done || true

TMP_OUT="$OUT/tmp_run"; mkdir -p "$TMP_OUT"
find "$ROOT/tmp" "$ROOT/run" -maxdepth 3 -type f -size -50M -print0 2>/dev/null | while IFS= read -r -d '' tf; do
  dest="$TMP_OUT${tf#$ROOT}"; mkdir -p "$(dirname "$dest")"; cp -a "$tf" "$dest" 2>/dev/null || true; add_manifest "$dest" "tmp/run"
done || true
echo "[+] Logs/tmp/run OK"

# -----------------------
# LuCI deep scan + IoTGoat
# -----------------------
echo "[8/11] LuCI deep scan (ROOT + merged_rootfs)"
LUCIOUT="$OUT/luci_artifacts"; mkdir -p "$LUCIOUT"
copy_luci_tree(){
  local base="$1"
  local src="$base/usr/lib/lua/luci"
  local cgi="$base/www/cgi-bin/luci"
  if [[ -d "$src" ]]; then
    rsync -a "$src" "$LUCIOUT/usr_lib_lua_luci" 2>/dev/null || true
    FOUND_LUCI_CODE="yes"
  fi
  if [[ -f "$cgi" ]]; then
    cp -a "$cgi" "$LUCIOUT/www_cgi_luci" 2>/dev/null || true
    add_manifest "$LUCIOUT/www_cgi_luci" "luci cgi entry"; FOUND_LUCI_CGI="yes"
  fi
}
copy_luci_tree "$ROOT"
copy_luci_tree "$MERGE"

for d in "$ROOT/var/run" "$ROOT/run" "$ROOT/tmp" "$MERGE/var/run" "$MERGE/run" "$MERGE/tmp"; do
  [[ -d "$d" ]] || continue
  find "$d" -maxdepth 2 -type f -iname "luci-*" -print0 2>/dev/null | while IFS= read -r -d '' sf; do
    dest="$LUCIOUT/sessions${sf#$ROOT}"
    [[ "$sf" == "$MERGE"* ]] && dest="$LUCIOUT/sessions${sf#$MERGE}"
    mkdir -p "$(dirname "$dest")"; cp -a "$sf" "$dest" 2>/dev/null || true
    add_manifest "$dest" "luci session"; ((FOUND_LUCI_SESS++)) || true
  done || true
done

if [[ -d "$LUCIOUT/usr_lib_lua_luci" ]]; then
  LUCIMAN="$LUCIOUT/luci_manifest.csv"; echo "relative_path,sha256,mtime,size" > "$LUCIMAN"
  find "$LUCIOUT/usr_lib_lua_luci" -type f -iname "*.lua" -print0 2>/dev/null | while IFS= read -r -d '' lf; do
    rel="${lf#$OUT/}"; sha=$(hash_file "$lf"); mt=$(stat -c %y "$lf" 2>/dev/null || echo ""); sz=$(file_size "$lf")
    echo "\"$rel\",\"$sha\",\"$mt\",\"$sz\"" >> "$LUCIMAN"
  done || true
  grep -RInE "os\.execute|io\.popen|os\.spawn|popen\(" "$LUCIOUT/usr_lib_lua_luci" 2>/dev/null | head -n 2000 > "$LUCIOUT/suspicious_lua.txt" || true
fi

IOT_SUM="$LUCIOUT/luci_iotgoat_analysis.txt"
{
  echo "== IoTGoat controller & views =="
  find "$LUCIOUT/usr_lib_lua_luci" -path "*/controller/iotgoat*" -type f 2>/dev/null || true
  find "$LUCIOUT/usr_lib_lua_luci" -path "*/view/iotgoat*" -type f 2>/dev/null || true
  echo; echo "== sensordata.db (ROOT/MERGE) =="
  find "$ROOT" -type f -iname "sensordata.db" 2>/dev/null || true
  find "$MERGE" -type f -iname "sensordata.db" 2>/dev/null || true
} > "$IOT_SUM"
add_manifest "$IOT_SUM" "luci_iotgoat_analysis"

echo "==== LuCI SUMMARY ===="
echo "LuCI code: $FOUND_LUCI_CODE"
echo "LuCI CGI : $FOUND_LUCI_CGI"
echo "LuCI sessions count: $FOUND_LUCI_SESS"
[[ -f "$LUCIOUT/luci_manifest.csv" ]] && echo "Manifest: luci_artifacts/luci_manifest.csv"
[[ -s "$LUCIOUT/suspicious_lua.txt" ]] && echo "Suspicious: luci_artifacts/suspicious_lua.txt"
echo "======================"
echo "[+] LuCI OK"

# -----------------------
# Config diff /etc/config vs /rom/etc/config
# -----------------------
echo "[9/11] Config diff /etc/config vs /rom/etc/config"
ROM_CFG_SRC="$ROOT/rom/etc/config"
if [[ -d "$ROM_CFG_SRC" ]]; then
  ROM_CFG_DST="$OUT/rom_etc_config"; rsync -a "$ROM_CFG_SRC" "$ROM_CFG_DST" 2>/dev/null || true
  diff -ruN "$OUT/rom_etc_config" "$OUT/etc_full/config" > "$OUT/config_diff.txt" 2>/dev/null || true
  add_manifest "$OUT/config_diff.txt" "config diff"
  echo "[+] Config diff OK"
else
  echo "[-] No /rom/etc/config; se omite diff."
fi

# -----------------------
# SQLite
# -----------------------
echo "[10/11] SQLite inspect"
SQL_OUT="$OUT/sqlite_inspect"; mkdir -p "$SQL_OUT"
find "$ROOT" "$MERGE" -type f \( -iname "*.db" -o -iname "*.sqlite" \) -print0 2>/dev/null | sort -z -u | while IFS= read -r -d '' db; do
  reln="$(echo "${db#$ROOT/}" | sed 's#/#_#g')"
  [[ "$db" == "$MERGE"* ]] && reln="MERGED_$(echo "${db#$MERGE/}" | sed 's#/#_#g')"
  out="$SQL_OUT/${reln}.txt"
  {
    echo "DB: $db"
    sqlite3 "$db" "SELECT name FROM sqlite_master WHERE type='table';" 2>/dev/null || echo "sqlite read error"
    for t in users auth session logs events sensor; do
      echo "=== SAMPLE ${t} ==="
      sqlite3 "$db" "SELECT * FROM ${t} LIMIT 20;" 2>/dev/null || true
    done
  } > "$out"
  add_manifest "$out" "sqlite_inspect"
done || true
echo "[+] SQLite OK"

# -----------------------
# MQTT / Mosquitto
# -----------------------
echo "[11/11] Mosquitto / MQTT"
safe_cp "$ROOT/etc/mosquitto/mosquitto.conf" "$OUT/mqtt/mosquitto.conf" "mosquitto conf"
find "$ROOT" -type f -iname "*mosquitto*" -print0 2>/dev/null | while IFS= read -r -d '' mf; do
  dest="$OUT/mqtt${mf#$ROOT}"; mkdir -p "$(dirname "$dest")"; cp -a "$mf" "$dest" 2>/dev/null || true; add_manifest "$dest" "mosquitto"
done || true
echo "[+] MQTT OK"

# -----------------------
# Paquetes (opkg) + anomalías
# -----------------------
OPKG="$OUT/opkg_status"; ANOM="$OUT/opkg_anomalies.txt"
if [[ -f "$ROOT/usr/lib/opkg/status" ]]; then cp -a "$ROOT/usr/lib/opkg/status" "$OPKG"; add_manifest "$OPKG" "opkg status"
elif [[ -f "$ROOT/var/lib/opkg/status" ]]; then cp -a "$ROOT/var/lib/opkg/status" "$OPKG"; add_manifest "$OPKG" "opkg status"
fi
if [[ -f "$OPKG" ]]; then
  {
    echo "== Paquetes sospechosos / herramientas potentes ==";
    egrep -i "netcat|nc |curl|wget|socat|tcpdump|nmap|python|perl|lua|shellback|telnetd|dropbear|dropbearkey" "$OPKG" || true
    echo; echo "== Paquetes no estándar (heurística simple) ==";
    awk -v RS="" '/Package: /{print $0"\n"}' "$OPKG" | awk '/^Package:/{print $2}' | sort -u \
      | egrep -v "base-files|busybox|libc|uci|uhttpd|procd|ubox|ubus|netifd|dropbear|dnsmasq|opkg|luci" || true
  } > "$ANOM"
  add_manifest "$ANOM" "opkg anomalies"
fi

# -----------------------
# Ejecutables, certs/keys, greps, IoCs
# -----------------------
BIN_HASH_DIR="$OUT/bin_hashes"; mkdir -p "$BIN_HASH_DIR"
find "$ROOT" -type f -perm /111 -print0 2>/dev/null | while IFS= read -r -d '' f; do
  echo "$f" >> "$OUT/bin_hashes/list_exec.txt"; sha256sum "$f" >> "$OUT/bin_hashes/executables_sha256.txt" 2>/dev/null || true
done || true
find "$ROOT" -type f \( -iname "*.pem" -o -iname "*.key" -o -iname "*.crt" \) -print0 2>/dev/null | while IFS= read -r -d '' cf; do
  dest="$OUT/ssl${cf#$ROOT}"; mkdir -p "$(dirname "$dest")"; cp -a "$cf" "$dest" 2>/dev/null || true; add_manifest "$dest" "cert/key"
done || true

GREP_OUT="$OUT/findings"; mkdir -p "$GREP_OUT"
grep -RInE "password|passwd|pwd|secret|token|api_key|apikey|aws|s3|curl|wget|nc |netcat|telnet|ssh|dropbear|os.execute|io.popen" "$ROOT" 2>/dev/null | head -n 3000 > "$GREP_OUT/possible_credentials_and_cmds.txt" || true
mkdir -p "$OUT/iocs"
grep -Eo "([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,6}" "$ROOT" -R 2>/dev/null | sort | uniq -c | sort -nr > "$OUT/iocs/domains_counts.txt" || true
grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" "$ROOT" -R 2>/dev/null | sort | uniq -c | sort -nr > "$OUT/iocs/ip_counts.txt" || true

# -----------------------
# SSH/auth + bruteforce
# -----------------------
grep -RInE "Failed password|Accepted password|Invalid user|authentication failure|dropbear|sshd|login" "$OUT/var_log" "$OUT/tmp_run" 2>/dev/null > "$OUT/ssh_events.txt" || true
if [[ ! -s "$OUT/ssh_events.txt" ]]; then
  grep -RInE "Failed password|Accepted password|Invalid user|authentication failure|dropbear|sshd|login" "$ROOT" 2>/dev/null > "$OUT/ssh_events.txt" || true
fi
SSH_EVENTS_FILE="$OUT/ssh_events.txt"; BRUTE_SUM="$OUT/iocs/ssh_bruteforce_summary.csv"; mkdir -p "$(dirname "$BRUTE_SUM")"
if [[ -s "$SSH_EVENTS_FILE" ]]; then
python3 - <<'PY' 2>/dev/null > "$BRUTE_SUM"
import re
from datetime import datetime,timedelta
fname = "$SSH_EVENTS_FILE"
ip_re = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
syslog_ts_re = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
iso_ts_re = re.compile(r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})")
def parse_syslog(s):
    from datetime import datetime
    try:
        now=datetime.utcnow(); dt=datetime.strptime(s,"%b %d %H:%M:%S"); return dt.replace(year=now.year)
    except: return None
def parse_iso(s):
    from datetime import datetime
    for fmt in ("%Y-%m-%dT%H:%M:%S","%Y-%m-%d %H:%M:%S"):
        try: return datetime.strptime(s,fmt)
        except: pass
    return None
ip_times={}
with open(fname,"r",errors="ignore") as fh:
    for line in fh:
        ts=None
        m=iso_ts_re.search(line); ts=parse_iso(m.group(1)) if m else None
        if not ts:
            m=syslog_ts_re.match(line); ts=parse_syslog(m.group(1)) if m else None
        for ip in ip_re.findall(line):
            ip_times.setdefault(ip,[]).append(ts)
window=timedelta(minutes=5)
rows=[]
for ip,times in ip_times.items():
    ts=[t for t in times if t]; ts.sort()
    attempts=len(times)
    first=ts[0].isoformat() if ts else ""
    last=ts[-1].isoformat() if ts else ""
    maxw=0; i=0
    for j in range(len(ts)):
        while ts[j]-ts[i]>window: i+=1
        maxw=max(maxw,j-i+1)
    flag="SUSPECT" if attempts>50 or maxw>10 else ""
    rows.append((ip,attempts,first,last,maxw,flag))
rows.sort(key=lambda x:x[1], reverse=True)
print("ip,attempts,first_seen,last_seen,max_5min,flag")
for r in rows: print(",".join([str(x) for x in r]))
PY
fi

# -----------------------
# Informe Markdown ligero (si no existe)
# -----------------------
REPORT="$OUT/forensic_report.md"
if [[ ! -f "$REPORT" ]]; then
  {
    echo "# DFIR IoT – TriageX IoT v6.1 (OpenWrt/IoTGoat)"
    echo "- Fecha: $(NOW)"
    echo "- Rootfs: $ROOT"
    echo
    echo "## Resumen rápido"
    echo "- LuCI: code=$FOUND_LUCI_CODE, cgi=$FOUND_LUCI_CGI, sesiones=$FOUND_LUCI_SESS"
    echo "- Config diff: $( [[ -f "$OUT/config_diff.txt" ]] && echo 'generado' || echo 'no disponible' )"
    echo "- Bruteforce: $( [[ -f "$OUT/iocs/ssh_bruteforce_summary.csv" ]] && echo 'detector ejecutado' || echo 'sin eventos' )"
    echo
    echo "## Archivos clave"
    echo "- summary_report.txt"
    echo "- manifest.csv"
    echo "- luci_artifacts/ (manifest, suspicious_lua.txt, controller/view iotgoat)"
    echo "- persistence/ (rc.d, uci-defaults, keep.d, hotplug)"
    echo "- network_configs/ (uhttpd, firewall, upnpd, dnsmasq)"
    echo "- opkg_status / opkg_anomalies.txt"
  } > "$REPORT"
  add_manifest "$REPORT" "forensic report"
fi

# --- escribir summary explícito antes del EXIT trap ---
finish
