#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# Integración Wazuh -> MISP (reputación de hash del programa PLC)
# - Extiende automation/wazuh-misp.sh (reputación de IP) al nivel de
#   artefacto: cuando dispara la regla de subida HTTP a OpenPLC (600430
#   por defecto, Ejercicio 3.4), el Wazuh Manager no tiene el hash del
#   programa subido (Snort no lo captura), así que este script:
#     1. Se conecta por SSH a plc-server (único salto de red nuevo de
#        esta integración) y calcula el sha256 del programa .st más
#        reciente subido a OpenPLC.
#     2. Consulta ese hash contra los atributos de tipo sha256 en MISP,
#        igual que custom-misp_ip.py hace con IPs.
# - Reutiliza la MISMA clave SSH que ya usa todo el laboratorio
#   (automation/key-generate.sh): se copia una vez a wazuh-manager para
#   que pueda alcanzar plc-server. No se instala ningún agente ni
#   servicio permanente en plc-server (Ejercicio 3.0).
# - Idempotente en la práctica (reaplica configuración sin duplicados).
# =========================================================

SCRIPT_START=$(date +%s)
format_time() { local total="$1"; echo "$((total/60)) minutos y $((total%60)) segundos"; }

# -------------------------
# Flags / modo
# -------------------------
DRY_RUN=0
MAKE_BACKUPS="${MAKE_BACKUPS:-no}"   # no | yes

usage() {
  cat <<'USAGE'
Uso: bash wazuh-misp-hash.sh [opciones]

Opciones:
  --dry-run        Muestra el plan y valida SSH. No modifica nada remoto.
  -h, --help       Muestra esta ayuda.

Variables opcionales (env):
  MAKE_BACKUPS=yes   Crea backup .bak de ficheros antes de reescribirlos.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[-] Opción no reconocida: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

# -------------------------
# Config por defecto
# -------------------------
DEFAULT_KEY_BASENAME="mykey"
DEFAULT_KEY_PATH="$(pwd)/${DEFAULT_KEY_BASENAME}"
DEFAULT_KNOWN_HOSTS_PATH="$(pwd)/known_hosts_${DEFAULT_KEY_BASENAME}"

DEFAULT_SSH_USER="debian"
DEFAULT_SSH_PORT="22"

DEFAULT_WAZUH_MANAGER_HOST=""
DEFAULT_MISP_URL=""
DEFAULT_MISP_RULE_ID="600430"
DEFAULT_MISP_TIMEOUT="10"
DEFAULT_MISP_RETRIES="2"

DEFAULT_PLC_USER="openplc"
DEFAULT_PLC_ST_DIR='~/OpenPLC_v3/webserver/st_files'
DEFAULT_SSH_TIMEOUT="15"

SSH_WAIT_TIMEOUT=300

# -------------------------
# Helpers
# -------------------------
die()  { echo "[-] $*" >&2; exit 1; }
ok()   { echo "[+] $*"; }
inf()  { echo "[*] $*"; }
warn() { echo "[!] $*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Falta el comando '$1'."
}

ssh_supports_accept_new() {
  local ver
  ver="$(ssh -V 2>&1 || true)"
  [[ "$ver" =~ OpenSSH_([0-9]+)\.([0-9]+) ]] || return 1
  local maj="${BASH_REMATCH[1]}"
  local min="${BASH_REMATCH[2]}"
  (( maj > 7 )) && return 0
  (( maj == 7 && min >= 6 )) && return 0
  return 1
}

wait_for_ssh() {
  local host="$1"
  local start now

  inf "Comprobando SSH en ${SSH_USER}@${host}:${SSH_PORT} (timeout ${SSH_WAIT_TIMEOUT}s)..."

  ssh-keygen -f "$KNOWN_HOSTS_PATH" -R "$host" >/dev/null 2>&1 || true
  ssh-keygen -f "$KNOWN_HOSTS_PATH" -R "[$host]:$SSH_PORT" >/dev/null 2>&1 || true

  start=$(date +%s)
  until ssh -i "$SSH_KEY_PATH" -p "$SSH_PORT" "${SSH_OPTS[@]}" -o BatchMode=yes \
      "${SSH_USER}@${host}" "echo ok" >/dev/null 2>&1; do
    sleep 5
    echo -n "."
    now=$(date +%s)
    if (( now - start > SSH_WAIT_TIMEOUT )); then
      echo
      return 1
    fi
  done
  echo
  return 0
}

# Ejecuta script remoto subiéndolo temporalmente y lanzándolo con TTY para sudo interactivo.
run_remote_script_tty() {
  local host="$1"; shift
  local local_script="$1"; shift

  if (( DRY_RUN )); then
    inf "[dry-run] Ejecutaría en ${host}: $(basename "$local_script") $*"
    return 0
  fi

  local remote_tmp="/tmp/remote_job_${RANDOM}_$$.sh"
  local remote_tmp_q
  printf -v remote_tmp_q '%q' "$remote_tmp"

  if ! ssh -i "$SSH_KEY_PATH" -p "$SSH_PORT" "${SSH_OPTS[@]}" \
      "${SSH_USER}@${host}" \
      "umask 077; cat > ${remote_tmp_q} && chmod 700 ${remote_tmp_q}" < "$local_script"; then
    return 1
  fi

  local cmd a aq
  printf -v cmd 'bash %q' "$remote_tmp"
  for a in "$@"; do
    printf -v aq '%q' "$a"
    cmd+=" $aq"
  done
  printf -v aq '%q' "$remote_tmp"
  cmd+="; rc=\$?; rm -f ${aq}; exit \$rc"

  ssh -tt -i "$SSH_KEY_PATH" -p "$SSH_PORT" "${SSH_OPTS[@]}" \
      "${SSH_USER}@${host}" "$cmd"
}

TMP_FILES=()
register_tmp() { TMP_FILES+=("$1"); }
cleanup_tmps() {
  local f
  for f in "${TMP_FILES[@]:-}"; do
    [[ -n "$f" ]] && rm -f "$f" >/dev/null 2>&1 || true
  done
}
trap cleanup_tmps EXIT

# -------------------------
# Dependencias locales
# -------------------------
require_cmd bash
require_cmd ssh
require_cmd ssh-keygen
require_cmd mktemp
require_cmd tee

# -------------------------
# Banner
# -------------------------
echo "===================================================="
echo " Integración Wazuh ➜ MISP (reputación de hash del programa PLC)"
echo "===================================================="

(( DRY_RUN )) && warn "MODO DRY-RUN activo: no se modificará el manager."

# -------------------------
# Inputs SSH (Wazuh Manager)
# -------------------------
echo
echo "=== Configuración SSH (VM de Wazuh Manager) ==="
read -r -p "Usuario SSH remoto [${DEFAULT_SSH_USER}]: " SSH_USER
SSH_USER="${SSH_USER:-$DEFAULT_SSH_USER}"
[[ -n "$SSH_USER" ]] || die "Usuario SSH remoto vacío."

read -r -p "Puerto SSH [${DEFAULT_SSH_PORT}]: " SSH_PORT
SSH_PORT="${SSH_PORT:-$DEFAULT_SSH_PORT}"
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "Puerto inválido: '$SSH_PORT'"

read -r -p "Ruta a la clave privada SSH del laboratorio (la misma de key-generate.sh) [${DEFAULT_KEY_PATH}]: " SSH_KEY_PATH
SSH_KEY_PATH="${SSH_KEY_PATH:-$DEFAULT_KEY_PATH}"
[[ -f "$SSH_KEY_PATH" ]] || die "No se encuentra la clave privada: $SSH_KEY_PATH"

DEFAULT_KH_FROM_KEY="$(pwd)/known_hosts_$(basename "$SSH_KEY_PATH")"
read -r -p "Ruta de known_hosts dedicado [${DEFAULT_KH_FROM_KEY}]: " KNOWN_HOSTS_PATH
KNOWN_HOSTS_PATH="${KNOWN_HOSTS_PATH:-$DEFAULT_KH_FROM_KEY}"

mkdir -p "$(dirname "$KNOWN_HOSTS_PATH")"
touch "$KNOWN_HOSTS_PATH"
chmod 600 "$KNOWN_HOSTS_PATH" || true
chmod 600 "$SSH_KEY_PATH" || true

ok "Clave privada: $SSH_KEY_PATH"
ok "Known hosts:   $KNOWN_HOSTS_PATH"

echo
read -r -p "IP/hostname de la VM Wazuh Manager (SSH): " WAZUH_MANAGER_HOST
WAZUH_MANAGER_HOST="${WAZUH_MANAGER_HOST:-$DEFAULT_WAZUH_MANAGER_HOST}"
[[ -n "$WAZUH_MANAGER_HOST" ]] || die "La IP/hostname del Wazuh Manager no puede estar vacía."

# -------------------------
# Inputs plc-server (segundo salto SSH, desde wazuh-manager)
# -------------------------
echo
echo "=== Configuración de plc-server (destino del segundo salto SSH) ==="
echo "El propio Wazuh Manager necesitará SSH a plc-server para calcular el hash"
echo "del programa subido. Se copiará ahí la MISMA clave privada de arriba"
echo "(la del laboratorio, ya autorizada en plc-server por key-generate.sh):"
echo "no hace falta generar ni instalar ninguna clave nueva en plc-server."
echo
read -r -p "IP/hostname de plc-server (tal como lo ve wazuh-manager): " PLC_HOST
[[ -n "$PLC_HOST" ]] || die "La IP/hostname de plc-server no puede estar vacía."

echo "Ojo: 'openplc'/'openplc' (Ejercicio 3.0) es el login de la interfaz WEB de OpenPLC (HTTP),"
echo "no tiene por qué ser un usuario del sistema operativo con acceso SSH. Indique el usuario"
echo "con el que YA tiene acceso SSH real a esta VM (a menudo el mismo del resto del laboratorio,"
echo "p.ej. root); si no lo tiene, instálelo antes con key-generate.sh -u <usuario> -H ${PLC_HOST} --reuse-key -y"
read -r -p "Usuario SSH en plc-server [${DEFAULT_PLC_USER}]: " PLC_USER
PLC_USER="${PLC_USER:-$DEFAULT_PLC_USER}"

read -r -p "Directorio de programas .st de OpenPLC en plc-server [${DEFAULT_PLC_ST_DIR}]: " PLC_ST_DIR
PLC_ST_DIR="${PLC_ST_DIR:-$DEFAULT_PLC_ST_DIR}"

read -r -p "Timeout SSH hacia plc-server, en segundos [${DEFAULT_SSH_TIMEOUT}]: " PLC_SSH_TIMEOUT
PLC_SSH_TIMEOUT="${PLC_SSH_TIMEOUT:-$DEFAULT_SSH_TIMEOUT}"
[[ "$PLC_SSH_TIMEOUT" =~ ^[0-9]+$ ]] || die "Timeout inválido: '$PLC_SSH_TIMEOUT'"

# -------------------------
# Inputs MISP
# -------------------------
echo
echo "=== Configuración de MISP ==="
read -r -p "URL base de MISP (p.ej. https://10.0.0.50): " MISP_URL
MISP_URL="${MISP_URL:-$DEFAULT_MISP_URL}"
[[ -n "$MISP_URL" ]] || die "La URL de MISP no puede estar vacía."
MISP_URL="${MISP_URL%/}"

echo "La API key es la misma que ya usa automation/wazuh-misp.sh."
read -r -s -p "API key de MISP: " MISP_API_KEY
echo
[[ -n "$MISP_API_KEY" ]] || die "La API key de MISP no puede estar vacía."

read -r -p "ID de regla Wazuh que dispara esta consulta [${DEFAULT_MISP_RULE_ID}]: " MISP_RULE_ID
MISP_RULE_ID="${MISP_RULE_ID:-$DEFAULT_MISP_RULE_ID}"
[[ "$MISP_RULE_ID" =~ ^[0-9]+(,[0-9]+)*$ ]] || die "Lista de rule_id inválida: '$MISP_RULE_ID'"

read -r -p "Timeout en segundos por petición a MISP [${DEFAULT_MISP_TIMEOUT}]: " MISP_TIMEOUT
MISP_TIMEOUT="${MISP_TIMEOUT:-$DEFAULT_MISP_TIMEOUT}"
[[ "$MISP_TIMEOUT" =~ ^[0-9]+$ ]] || die "Timeout inválido: '$MISP_TIMEOUT'"

read -r -p "Reintentos por petición a MISP [${DEFAULT_MISP_RETRIES}]: " MISP_RETRIES
MISP_RETRIES="${MISP_RETRIES:-$DEFAULT_MISP_RETRIES}"
[[ "$MISP_RETRIES" =~ ^[0-9]+$ ]] || die "Reintentos inválidos: '$MISP_RETRIES'"

# -------------------------
# Resumen
# -------------------------
echo
echo "=== Resumen de configuración ==="
(( DRY_RUN )) && echo "Dry-run:                    sí"
echo "Wazuh Manager (SSH):        ${WAZUH_MANAGER_HOST}"
echo "plc-server (2º salto SSH):  ${PLC_USER}@${PLC_HOST}"
echo "Directorio de programas:    ${PLC_ST_DIR}"
echo "URL de MISP:                ${MISP_URL}"
echo "Regla que dispara:          ${MISP_RULE_ID}"
echo "Timeout / reintentos MISP:  ${MISP_TIMEOUT}s / ${MISP_RETRIES}"
echo "Timeout SSH a plc-server:   ${PLC_SSH_TIMEOUT}s"
echo "Backups remotos:            ${MAKE_BACKUPS}"
echo
echo "Nota: el certificado de MISP es autofirmado; la consulta a la API se hace"
echo "      sin verificar el certificado (-k / verify=False), igual que en wazuh-misp.sh."
echo
read -r -p "¿Continuar? (y/N): " CONFIRM
CONFIRM="${CONFIRM:-N}"
[[ "$CONFIRM" =~ ^[Yy]$ ]] || die "Cancelado por el usuario."

# -------------------------
# SSH opts
# -------------------------
STRICT_OPT="accept-new"
if ! ssh_supports_accept_new; then
  inf "Tu OpenSSH no parece soportar accept-new. Usaré StrictHostKeyChecking=no."
  STRICT_OPT="no"
fi
SSH_OPTS=(
  -o "ConnectTimeout=5"
  -o "StrictHostKeyChecking=${STRICT_OPT}"
  -o "UserKnownHostsFile=${KNOWN_HOSTS_PATH}"
)

# -------------------------
# Comprobar SSH al Wazuh Manager
# -------------------------
echo
inf "Comprobando acceso SSH al Wazuh Manager..."
wait_for_ssh "$WAZUH_MANAGER_HOST" || die "No hay SSH en Wazuh Manager: $WAZUH_MANAGER_HOST"
ok "SSH disponible en Wazuh Manager ($WAZUH_MANAGER_HOST)"

if (( DRY_RUN )); then
  echo
  inf "DRY-RUN completado. Se validó conectividad SSH y parámetros."
  echo "Acciones previstas:"
  echo "  - Copiar la clave privada del laboratorio a wazuh-manager (para el salto a plc-server)"
  echo "  - Instalar el script de integración custom-misp_hash.py en /var/ossec/integrations/"
  echo "  - Instalar las reglas locales en /var/ossec/etc/rules/misp_hash_rules.xml (600250-600254)"
  echo "  - Añadir/actualizar el bloque <integration> de custom-misp_hash.py en ossec.conf"
  echo "  - Probar el salto SSH wazuh-manager -> plc-server como usuario 'wazuh'"
  echo "  - Reiniciar wazuh-manager"
  exit 0
fi

# =========================
# 1) Copiar la clave privada del laboratorio a wazuh-manager
# =========================
echo
inf "Copiando la clave privada del laboratorio a wazuh-manager (para el salto a plc-server)..."
REMOTE_KEY_PATH="/var/ossec/integrations/.misp_hash_ssh_key"
REMOTE_KH_PATH="/var/ossec/integrations/.misp_hash_known_hosts"
REMOTE_KEY_TMP="/tmp/misp_hash_labkey_$$"

# Paso A (sin -tt, sin sudo): sube los bytes de la clave privada a un temporal
# en /tmp. No se mezcla con el prompt interactivo de sudo del paso B: hacerlo
# en la misma sesión -tt arriesga corromper la clave o que se mezcle con el
# prompt de contraseña.
if ! ssh -i "$SSH_KEY_PATH" -p "$SSH_PORT" "${SSH_OPTS[@]}" \
    "${SSH_USER}@${WAZUH_MANAGER_HOST}" \
    "umask 077; cat > ${REMOTE_KEY_TMP} && chmod 600 ${REMOTE_KEY_TMP}" < "$SSH_KEY_PATH"; then
  die "No se pudo subir la clave privada del laboratorio a wazuh-manager."
fi

# Paso B (con -tt, permite sudo interactivo si hace falta): mueve el temporal
# a su ubicación final con el propietario correcto (usuario 'wazuh', que es
# quien ejecuta las integraciones), y prepara el known_hosts dedicado.
if ! ssh -tt -i "$SSH_KEY_PATH" -p "$SSH_PORT" "${SSH_OPTS[@]}" \
    "${SSH_USER}@${WAZUH_MANAGER_HOST}" "
      set -e
      SUDO=''
      if [ \"\$(id -u)\" -ne 0 ]; then SUDO='sudo'; fi
      \$SUDO install -d -m 750 -o root -g wazuh /var/ossec/integrations
      \$SUDO install -o wazuh -g wazuh -m 600 ${REMOTE_KEY_TMP} ${REMOTE_KEY_PATH}
      rm -f ${REMOTE_KEY_TMP}
      \$SUDO touch ${REMOTE_KH_PATH}
      \$SUDO chown wazuh:wazuh ${REMOTE_KH_PATH}
      \$SUDO chmod 600 ${REMOTE_KH_PATH}
      echo '[remote-wazuh] Clave privada instalada en ${REMOTE_KEY_PATH} (propietario wazuh:wazuh, modo 600).'
    "; then
  die "No se pudo instalar la clave privada del laboratorio en wazuh-manager (paso con sudo)."
fi
ok "Clave privada disponible en wazuh-manager ($REMOTE_KEY_PATH)."

# =========================
# 2) Desplegar script de integración + reglas + bloque <integration>
# =========================
echo
inf "Desplegando integración de hash en Wazuh Manager..."

MISP_HASH_SETUP_SCRIPT="$(mktemp)"; register_tmp "$MISP_HASH_SETUP_SCRIPT"

cat > "$MISP_HASH_SETUP_SCRIPT" <<'REMOTE_MISP_HASH_SETUP'
#!/usr/bin/env bash
set -euo pipefail
MISP_URL="$1"
MISP_API_KEY="$2"
MISP_RULE_ID="$3"
MISP_TIMEOUT="$4"
MISP_RETRIES="$5"
MAKE_BACKUPS="$6"
PLC_HOST="$7"
PLC_USER="$8"
PLC_ST_DIR="$9"
PLC_SSH_TIMEOUT="${10}"
REMOTE_KEY_PATH="${11}"
REMOTE_KH_PATH="${12}"

log(){ echo "$*"; }
SUDO=""; SUDO_KEEPALIVE_PID=""
if [[ "$(id -u)" -ne 0 ]]; then
  SUDO="sudo"
  if sudo -n true >/dev/null 2>&1; then
    log "[remote-wazuh] sudo sin contraseña disponible"
  else
    log "[remote-wazuh] sudo requiere contraseña. Se pedirá ahora..."
    sudo -v || { log "[remote-wazuh][ERROR] sudo -v falló"; exit 1; }
    (
      while true; do sudo -n true >/dev/null 2>&1 || exit; sleep 60; kill -0 "$$" >/dev/null 2>&1 || exit; done
    ) &
    SUDO_KEEPALIVE_PID="$!"
    trap '[[ -n "${SUDO_KEEPALIVE_PID:-}" ]] && kill "${SUDO_KEEPALIVE_PID}" >/dev/null 2>&1 || true' EXIT
  fi
fi

[[ -x /var/ossec/bin/wazuh-control ]] || { log "[remote-wazuh][ERROR] No se detecta wazuh-manager instalado (/var/ossec/bin/wazuh-control)"; exit 1; }
[[ -f "$REMOTE_KEY_PATH" ]] || { log "[remote-wazuh][ERROR] No se encuentra la clave privada en $REMOTE_KEY_PATH (paso 1 no se completó)"; exit 1; }

# ===============================
# 2.1) Probar el salto SSH wazuh-manager -> plc-server, como usuario 'wazuh'
# ===============================
log "[remote-wazuh] Probando SSH hacia plc-server como usuario 'wazuh'..."
if $SUDO -u wazuh ssh -i "$REMOTE_KEY_PATH" \
    -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -o "UserKnownHostsFile=${REMOTE_KH_PATH}" \
    -o "ConnectTimeout=${PLC_SSH_TIMEOUT}" \
    "${PLC_USER}@${PLC_HOST}" "echo OK-DESDE-WAZUH" 2>/tmp/misp_hash_ssh_test_$$.log \
    | grep -q "OK-DESDE-WAZUH"; then
  log "[remote-wazuh] SSH wazuh-manager -> plc-server OK (usuario wazuh)."
else
  log "[remote-wazuh][WARN] No se pudo confirmar el SSH del usuario 'wazuh' hacia plc-server."
  log "[remote-wazuh][WARN] Detalle:"
  $SUDO cat /tmp/misp_hash_ssh_test_$$.log 2>/dev/null | sed 's/^/[remote-wazuh][WARN]   /' || true
  log "[remote-wazuh][WARN] La integración se instalará igualmente, pero probablemente no funcione hasta resolver esto."
  log "[remote-wazuh][WARN] Pista: confirme que ${PLC_USER}@${PLC_HOST} acepta la clave del laboratorio (key-generate.sh) y que el puerto 22 es accesible desde wazuh-manager."
fi
$SUDO rm -f /tmp/misp_hash_ssh_test_$$.log 2>/dev/null || true

# ===============================
# 2.2) Script de integración Python
# ===============================
log "[remote-wazuh] Instalando script de integración custom-misp_hash.py..."
INTEGRATION_PATH="/var/ossec/integrations/custom-misp_hash.py"
TMP_INTEGRATION="/tmp/custom-misp_hash_$$.py"

cat > "$TMP_INTEGRATION" <<'PYEOF'
#!/var/ossec/framework/python/bin/python3
# Wazuh - MISP program-hash reputation integration (OpenPLC, Ejercicio 3.5)
#
# Extiende el patron de custom-misp_ip.py (mismo directorio, misma familia
# de integraciones) al nivel de artefacto: la alerta que dispara este script
# (por defecto 600430, subida HTTP a OpenPLC) no trae el hash del programa
# subido, Snort no lo captura. Este script primero lo obtiene por SSH desde
# plc-server (unico salto de red nuevo de esta integracion; no se instala
# nada en plc-server, ver Ejercicio 3.5 del laboratorio) y despues
# consulta ese hash contra los atributos de tipo sha256 en MISP, igual que
# custom-misp_ip.py hace con IPs.
#
# ossec.conf:
# <integration>
#   <name>custom-misp_hash.py</name>
#   <hook_url>https://MISP_HOST</hook_url>
#   <api_key>API_KEY</api_key>
#   <rule_id>600430</rule_id>
#   <alert_format>json</alert_format>
#   <options>{"timeout": 10, "retries": 2, "debug": false,
#             "plc_host": "IP_PLC_SERVER", "plc_user": "openplc",
#             "plc_key": "/var/ossec/integrations/.misp_hash_ssh_key",
#             "plc_known_hosts": "/var/ossec/integrations/.misp_hash_known_hosts",
#             "plc_st_dir": "~/OpenPLC_v3/webserver/st_files", "ssh_timeout": 15}
# </integration>

import json
import os
import re
import subprocess
import sys
from socket import AF_UNIX, SOCK_DGRAM, socket

ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_NO_RESPONSE_MISP = 4
ERR_SOCKET_OPERATION = 5
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
    import urllib3
    from requests.exceptions import Timeout
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
# Mismo respaldo que custom-misp_ip.py: el decoder "snort"/"snort2" de Wazuh
# no siempre matchea el full_log de Snort 3 usado en este laboratorio, asi
# que si no hay srcip decodificado se extrae directamente del full_log.
FULL_LOG_IP_RE = re.compile(
    r"\{[A-Za-z0-9_]+\}\s+(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\s*->\s*(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?"
)

debug_enabled = False
timeout = 10
retries = 2
ssh_timeout = 15
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_options = {}

LOG_FILE = f"{pwd}/logs/integrations.log"
SOCKET_ADDR = f"{pwd}/queue/sockets/queue"

ALERT_INDEX = 1
APIKEY_INDEX = 2
MISP_URL_INDEX = 3


def main(args):
    global debug_enabled
    try:
        if len(args) < 4:
            debug("# Error: Exiting, bad arguments. Inputted: %s" % args)
            sys.exit(ERR_BAD_ARGUMENTS)
        debug_enabled = len(args) > 4 and args[4] == "debug"
        process_args(args)
    except Exception as e:
        debug(str(e))
        raise


def process_args(args) -> None:
    global debug_enabled, timeout, retries, ssh_timeout, json_options

    debug("# Running MISP program-hash reputation script")

    alert_file_location: str = args[ALERT_INDEX]
    apikey: str = args[APIKEY_INDEX]
    misp_url: str = args[MISP_URL_INDEX].rstrip("/")
    options_file_location: str = ""

    for idx in range(4, len(args)):
        if args[idx][-7:] == "options":
            options_file_location = args[idx]
            break

    json_options = get_json_options(options_file_location)
    debug(f"# Opening options file at '{options_file_location}' with '{json_options}'")

    if isinstance(json_options.get("timeout"), int) and json_options["timeout"] > 0:
        timeout = json_options["timeout"]
    if isinstance(json_options.get("retries"), int) and json_options["retries"] >= 0:
        retries = json_options["retries"]
    if isinstance(json_options.get("ssh_timeout"), int) and json_options["ssh_timeout"] > 0:
        ssh_timeout = json_options["ssh_timeout"]
    if isinstance(json_options.get("debug"), bool):
        debug_enabled = json_options["debug"]

    for required in ("plc_host", "plc_user", "plc_key", "plc_st_dir"):
        if not json_options.get(required):
            debug(f"# Error: falta '{required}' en <options> del bloque <integration>")
            sys.exit(ERR_BAD_ARGUMENTS)

    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    msg = build_hash_report(json_alert, misp_url, apikey)
    if not msg:
        return

    send_msg(msg, json_alert.get("agent"))


def debug(msg: str) -> None:
    if debug_enabled:
        print(msg)
        try:
            with open(LOG_FILE, "a") as f:
                f.write(msg + "\n")
        except Exception:
            pass


def extract_srcip(alert):
    srcip = alert.get("srcip") or alert.get("data", {}).get("srcip")
    if srcip:
        return srcip
    match = FULL_LOG_IP_RE.search(alert.get("full_log", ""))
    return match.group(1) if match else None


def fetch_remote_hash():
    """SSH a plc-server: localiza el .st mas reciente en plc_st_dir y calcula
    su sha256. Devuelve (hash, ruta_remota) si tiene exito, o (None, motivo)
    si falla en cualquier paso (SSH, find o sha256sum)."""
    host = json_options["plc_host"]
    user = json_options["plc_user"]
    key = json_options["plc_key"]
    st_dir = json_options["plc_st_dir"]
    known_hosts = json_options.get("plc_known_hosts", key + ".known_hosts")

    ssh_base = [
        "ssh", "-i", key,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", f"ConnectTimeout={ssh_timeout}",
        f"{user}@{host}",
    ]

    find_cmd = (
        f"find {st_dir} -iname '*.st' -printf '%T@ %p\\n' 2>/dev/null "
        f"| sort -n | tail -1 | cut -d' ' -f2-"
    )
    try:
        result = subprocess.run(
            ssh_base + [find_cmd], capture_output=True, text=True, timeout=ssh_timeout + 5,
        )
    except subprocess.TimeoutExpired:
        return None, "timeout localizando el fichero .st en plc-server"
    except Exception as e:
        return None, f"error de SSH localizando el fichero .st: {e}"

    remote_path = result.stdout.strip()
    if result.returncode != 0:
        debug(f"# SSH find rc={result.returncode} stderr: {result.stderr}")
        return None, f"SSH fallo (rc={result.returncode}) buscando el .st en plc-server"
    if not remote_path:
        return None, "no se encontro ningun .st en el directorio de programas de plc-server"

    hash_cmd = f"sha256sum {remote_path} 2>/dev/null | cut -d' ' -f1"
    try:
        result = subprocess.run(
            ssh_base + [hash_cmd], capture_output=True, text=True, timeout=ssh_timeout + 5,
        )
    except subprocess.TimeoutExpired:
        return None, "timeout calculando el hash en plc-server"
    except Exception as e:
        return None, f"error de SSH calculando el hash: {e}"

    file_hash = result.stdout.strip().lower()
    if result.returncode != 0 or not SHA256_RE.match(file_hash):
        debug(f"# SSH sha256sum rc={result.returncode} stderr: {result.stderr}")
        return None, "no se pudo calcular el hash del .st en plc-server"

    return file_hash, remote_path


def build_hash_report(alert, misp_url, api_key):
    alert_output = {"misp_hash": {}, "integration": "misp_hash"}

    srcip = extract_srcip(alert)
    alert_output["misp_hash"]["source"] = {
        "alert_id": alert.get("id"),
        "rule_id": alert.get("rule", {}).get("id"),
        "srcip": srcip,
    }

    file_hash, path_or_reason = fetch_remote_hash()
    if not file_hash:
        alert_output["misp_hash"]["found"] = 0
        alert_output["misp_hash"]["ssh_error"] = path_or_reason
        debug(f"# No se pudo obtener el hash remoto: {path_or_reason}")
        return alert_output

    alert_output["misp_hash"]["found"] = 0
    alert_output["misp_hash"]["hash"] = file_hash
    alert_output["misp_hash"]["remote_path"] = path_or_reason

    misp_response_data = request_hash_from_api(file_hash, alert_output, misp_url, api_key)
    if misp_response_data is None:
        return alert_output

    attributes = misp_response_data.get("response", {}).get("Attribute", [])
    if not attributes:
        debug("# El hash calculado no coincide con ningun atributo conocido en MISP")
        return alert_output

    alert_output["misp_hash"]["found"] = 1
    misp_attribute = attributes[0]
    event_uuid = misp_attribute.get("Event", {}).get("uuid")
    attribute_uuid = misp_attribute.get("uuid")

    if srcip:
        alert_output["srcip"] = srcip

    alert_output["misp_hash"].update(
        {
            "type": misp_attribute.get("type"),
            "value": misp_attribute.get("value"),
            "uuid": attribute_uuid,
            "event_uuid": event_uuid,
            "permalink": f"{misp_url}/events/view/{event_uuid}/searchFor:{attribute_uuid}",
        }
    )

    return alert_output


def request_hash_from_api(file_hash, alert_output, misp_url, api_key):
    for attempt in range(retries + 1):
        try:
            return query_api(file_hash, misp_url, api_key)
        except Timeout:
            debug("# Error: Request timed out. Remaining retries: %s" % (retries - attempt))
            continue
        except Exception as e:
            debug(str(e))
            return None

    debug("# Error: Request timed out and maximum number of retries was exceeded")
    alert_output["misp_hash"]["error"] = 408
    alert_output["misp_hash"]["description"] = "Error: API request timed out"
    send_msg(alert_output)
    return None


def query_api(file_hash, misp_url, api_key):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Python-library-client-Wazuh-MISP",
        "Authorization": api_key,
    }

    rest_search_payload = {
        "value": file_hash,
        "type": ["sha256"],
        "to_ids": 1,
        "includeEventTags": 0,
        "includeProposals": 0,
        "includeContext": 0,
        "returnFormat": "json",
        "page": 1,
        "limit": 1,
    }

    debug("# MISP API request payload: %s" % json.dumps(rest_search_payload))

    response = requests.post(
        f"{misp_url}/attributes/restSearch",
        json=rest_search_payload,
        headers=headers,
        timeout=timeout,
        verify=False,
    )

    if response.status_code == 200:
        return response.json()

    alert_output = {"misp_hash": {}, "integration": "misp_hash"}
    alert_output["misp_hash"]["error"] = response.status_code
    if response.status_code == 403:
        alert_output["misp_hash"]["description"] = "Error: Check MISP credentials"
    elif response.status_code == 429:
        alert_output["misp_hash"]["description"] = "Error: MISP API rate limit reached"
    else:
        alert_output["misp_hash"]["description"] = "Error: API request failed"
    send_msg(alert_output)
    raise Exception("# Error: MISP API request failed with status %s" % response.status_code)


def send_msg(msg, agent=None) -> None:
    if not agent or agent.get("id") == "000":
        string = "1:misp_hash:{0}".format(json.dumps(msg))
    else:
        location = "[{0}] ({1}) {2}".format(agent["id"], agent["name"], agent.get("ip", "any"))
        location = location.replace("|", "||").replace(":", "|:")
        string = "1:{0}->misp_hash:{1}".format(location, json.dumps(msg))

    debug("# Request result: %s" % string)
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except FileNotFoundError:
        debug("# Error: Unable to open socket connection at %s" % SOCKET_ADDR)
        sys.exit(ERR_SOCKET_OPERATION)


def get_json_alert(file_location):
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug("Failed getting JSON alert. Error: %s" % e)
        sys.exit(ERR_INVALID_JSON)


def get_json_options(file_location):
    try:
        with open(file_location) as options_file:
            return json.load(options_file)
    except FileNotFoundError:
        debug("# JSON file for options %s doesn't exist" % file_location)
        return {}
    except BaseException as e:
        debug("Failed getting JSON options. Error: %s" % e)
        sys.exit(ERR_INVALID_JSON)


if __name__ == "__main__":
    main(sys.argv)
PYEOF

$SUDO install -m 750 -o root -g wazuh "$TMP_INTEGRATION" "$INTEGRATION_PATH"
rm -f "$TMP_INTEGRATION"
log "[remote-wazuh] custom-misp_hash.py instalado en $INTEGRATION_PATH"

# ===============================
# 2.3) Reglas locales de Wazuh
# ===============================
log "[remote-wazuh] Instalando reglas locales misp_hash_rules.xml..."
RULES_PATH="/var/ossec/etc/rules/misp_hash_rules.xml"
TMP_RULES="/tmp/misp_hash_rules_$$.xml"

cat > "$TMP_RULES" <<'EOF'
<group name="local,misp,threat_intel,">
  <rule id="600250" level="0">
    <decoded_as>json</decoded_as>
    <field name="integration">misp_hash</field>
    <description>MISP: comprobación de hash de programa PLC</description>
    <options>no_full_log</options>
  </rule>

  <rule id="600251" level="0">
    <if_sid>600250</if_sid>
    <field name="misp_hash.found">0</field>
    <description>MISP: hash del programa subido sin coincidencias en threat intel</description>
  </rule>

  <rule id="600252" level="12">
    <if_sid>600250</if_sid>
    <field name="misp_hash.found">1</field>
    <description>MISP: hash de programa PLC coincide con artefacto conocido de threat intel $(misp_hash.event_uuid)</description>
  </rule>

  <rule id="600253" level="10">
    <if_sid>600250</if_sid>
    <field name="misp_hash.error">\.+</field>
    <description>MISP ERROR: $(misp_hash.description)</description>
  </rule>

  <rule id="600254" level="5">
    <if_sid>600250</if_sid>
    <field name="misp_hash.ssh_error">\.+</field>
    <description>MISP: no se pudo obtener el hash remoto de plc-server ($(misp_hash.ssh_error))</description>
  </rule>
</group>
EOF

if ! $SUDO cmp -s "$TMP_RULES" "$RULES_PATH" 2>/dev/null; then
  [[ "$MAKE_BACKUPS" == "yes" && -f "$RULES_PATH" ]] && $SUDO cp -p "$RULES_PATH" "${RULES_PATH}.bak" || true
  $SUDO install -m 640 "$TMP_RULES" "$RULES_PATH"
  $SUDO chown root:wazuh "$RULES_PATH" 2>/dev/null || $SUDO chown root:root "$RULES_PATH"
  log "[remote-wazuh] misp_hash_rules.xml actualizado."
else
  log "[remote-wazuh] misp_hash_rules.xml ya estaba en el estado deseado."
fi
$SUDO rm -f "$TMP_RULES" >/dev/null 2>&1 || true

# ===============================
# 2.4) Bloque <integration> en ossec.conf
# ===============================
log "[remote-wazuh] Configurando bloque <integration> de custom-misp_hash.py en ossec.conf..."
OSSEC_CONF="/var/ossec/etc/ossec.conf"
TMP_OSSEC="/tmp/ossec_conf_misp_hash_$$.xml"
$SUDO cat "$OSSEC_CONF" > "$TMP_OSSEC"

# Elimina un bloque <integration> de custom-misp_hash.py previo, si existe.
$SUDO perl -0777 -i -pe 's#\s*<integration>\s*<name>custom-misp_hash\.py</name>.*?</integration>\s*##sg' "$TMP_OSSEC"

OPTIONS_JSON="{\"timeout\": ${MISP_TIMEOUT}, \"retries\": ${MISP_RETRIES}, \"debug\": false, \"plc_host\": \"${PLC_HOST}\", \"plc_user\": \"${PLC_USER}\", \"plc_key\": \"${REMOTE_KEY_PATH}\", \"plc_known_hosts\": \"${REMOTE_KH_PATH}\", \"plc_st_dir\": \"${PLC_ST_DIR}\", \"ssh_timeout\": ${PLC_SSH_TIMEOUT}}"

INTEGRATION_BLOCK="  <integration>\n    <name>custom-misp_hash.py</name>\n    <hook_url>${MISP_URL}</hook_url>\n    <api_key>${MISP_API_KEY}</api_key>\n    <rule_id>${MISP_RULE_ID}</rule_id>\n    <alert_format>json</alert_format>\n    <options>${OPTIONS_JSON}</options>\n  </integration>\n"

$SUDO perl -0777 -i -pe "s#</ossec_config>#${INTEGRATION_BLOCK}</ossec_config>#s" "$TMP_OSSEC"

if ! $SUDO cmp -s "$TMP_OSSEC" "$OSSEC_CONF"; then
  [[ "$MAKE_BACKUPS" == "yes" ]] && $SUDO cp -p "$OSSEC_CONF" "${OSSEC_CONF}.bak" || true
  $SUDO install -m 640 "$TMP_OSSEC" "$OSSEC_CONF"
  $SUDO chown root:wazuh "$OSSEC_CONF" 2>/dev/null || $SUDO chown root:root "$OSSEC_CONF"
  log "[remote-wazuh] ossec.conf actualizado."
else
  log "[remote-wazuh] ossec.conf ya estaba en el estado deseado."
fi
$SUDO rm -f "$TMP_OSSEC" >/dev/null 2>&1 || true

# ===============================
# 2.5) Reiniciar wazuh-manager
# ===============================
log "[remote-wazuh] Reiniciando wazuh-manager..."
$SUDO systemctl restart wazuh-manager
$SUDO tail -n 40 /var/ossec/logs/ossec.log || true

log "[remote-wazuh] Integración de hash lista."
REMOTE_MISP_HASH_SETUP
chmod 700 "$MISP_HASH_SETUP_SCRIPT"

if ! run_remote_script_tty "$WAZUH_MANAGER_HOST" "$MISP_HASH_SETUP_SCRIPT" \
    "$MISP_URL" "$MISP_API_KEY" "$MISP_RULE_ID" "$MISP_TIMEOUT" "$MISP_RETRIES" "$MAKE_BACKUPS" \
    "$PLC_HOST" "$PLC_USER" "$PLC_ST_DIR" "$PLC_SSH_TIMEOUT" "$REMOTE_KEY_PATH" "$REMOTE_KH_PATH"; then
  die "Falló el despliegue de la integración de hash en el Wazuh Manager."
fi

ok "Integración de hash desplegada en Wazuh Manager."

# -------------------------
# Resumen final
# -------------------------
SCRIPT_END=$(date +%s)

echo
echo "===================================================="
echo " Integración Wazuh -> MISP, hash de programa PLC (resultado)"
echo "===================================================="
echo "Wazuh Manager (SSH):        ${WAZUH_MANAGER_HOST}"
echo "plc-server (2º salto SSH):  ${PLC_USER}@${PLC_HOST}"
echo "URL de MISP:                ${MISP_URL}"
echo "Regla que dispara:          ${MISP_RULE_ID}"
echo "Reglas MISP generadas:      600250-600254 (/var/ossec/etc/rules/misp_hash_rules.xml)"
echo "[⏱] Tiempo TOTAL: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "===================================================="
echo
echo "Cómo probarlo:"
echo "  1. Registre el hash de OpenPLC/tanque_sabotaje.st como atributo sha256"
echo "     en MISP (Ejercicio 3.5), marcado IDS."
echo "  2. Dispare la subida del programa (Ejercicio 3.4, la ability de Impact)."
echo "  3. En Wazuh Manager, compruebe:"
echo "       sudo tail -f /var/ossec/logs/integrations.log"
echo "       sudo grep -A10 '\"integration\":\"misp_hash\"' /var/ossec/logs/alerts/alerts.json"
echo "     Debería aparecer una alerta de nivel 12 (regla 600252) con el hash y"
echo "     el 'permalink' al evento de MISP."
echo
echo "Si falla, depure por capas (de más a menos probable):"
echo "  a) El salto SSH wazuh-manager -> plc-server en sí mismo:"
echo "       sudo -u wazuh ssh -i ${REMOTE_KEY_PATH} -o BatchMode=yes \\"
echo "         -o UserKnownHostsFile=${REMOTE_KH_PATH} ${PLC_USER}@${PLC_HOST} echo OK"
echo "  b) El script a mano, con una alerta 600430 real capturada:"
echo "       sudo grep '\"rule\":{\"id\":\"600430\"' /var/ossec/logs/alerts/alerts.json | tail -1 | sudo tee /tmp/test_alert.json"
echo "       sudo /var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-misp_hash.py \\"
echo "         /tmp/test_alert.json \"<API_KEY>\" \"${MISP_URL}\" /tmp/test_options debug"
echo "     (cree /tmp/test_options con el mismo JSON que ve en <options> de ossec.conf)"
echo "  c) sudo grep -i integrat /var/ossec/logs/ossec.log  — busque 'Exit status was: 1'"
echo
