#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# Integración Wazuh -> MISP (enriquecimiento de IPs de Snort)
# - Solo toca la VM de wazuh-manager (MISP se consulta por su API REST)
# - Idempotente en la práctica (reaplica configuración sin duplicados)
# - Dispara sobre las reglas de Snort ya creadas por wazuh-snort.sh
#   (600001 ICMP / 600010 SYN scan por defecto) y consulta la IP origen
#   contra los atributos de tipo IP en MISP.
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
Uso: bash wazuh-misp.sh [opciones]

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
DEFAULT_MISP_RULE_IDS="600001,600010"
DEFAULT_MISP_TIMEOUT="10"
DEFAULT_MISP_RETRIES="2"

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
echo " Integración Wazuh ➜ MISP (enriquecimiento de IPs de Snort)"
echo "===================================================="

(( DRY_RUN )) && warn "MODO DRY-RUN activo: no se modificará el manager."

# -------------------------
# Inputs SSH
# -------------------------
echo
echo "=== Configuración SSH (VM de Wazuh Manager) ==="
read -r -p "Usuario SSH remoto [${DEFAULT_SSH_USER}]: " SSH_USER
SSH_USER="${SSH_USER:-$DEFAULT_SSH_USER}"
[[ -n "$SSH_USER" ]] || die "Usuario SSH remoto vacío."

read -r -p "Puerto SSH [${DEFAULT_SSH_PORT}]: " SSH_PORT
SSH_PORT="${SSH_PORT:-$DEFAULT_SSH_PORT}"
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "Puerto inválido: '$SSH_PORT'"

read -r -p "Ruta a la clave privada SSH [${DEFAULT_KEY_PATH}]: " SSH_KEY_PATH
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
# Inputs MISP
# -------------------------
echo
echo "=== Configuración de MISP ==="
read -r -p "URL base de MISP (p.ej. https://10.0.0.50): " MISP_URL
MISP_URL="${MISP_URL:-$DEFAULT_MISP_URL}"
[[ -n "$MISP_URL" ]] || die "La URL de MISP no puede estar vacía."
MISP_URL="${MISP_URL%/}"

echo "La API key es la que guardó install-misp.sh en misp-logs/misp-settings.txt"
echo "(campo 'Admin API key'), o la que generes en MISP > Administration > List Auth Keys."
read -r -s -p "API key de MISP: " MISP_API_KEY
echo
[[ -n "$MISP_API_KEY" ]] || die "La API key de MISP no puede estar vacía."

read -r -p "IDs de reglas Wazuh que disparan la consulta [${DEFAULT_MISP_RULE_IDS}]: " MISP_RULE_IDS
MISP_RULE_IDS="${MISP_RULE_IDS:-$DEFAULT_MISP_RULE_IDS}"
[[ "$MISP_RULE_IDS" =~ ^[0-9]+(,[0-9]+)*$ ]] || die "Lista de rule_id inválida: '$MISP_RULE_IDS'"

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
echo "URL de MISP:                ${MISP_URL}"
echo "Reglas que disparan:        ${MISP_RULE_IDS}"
echo "Timeout / reintentos:       ${MISP_TIMEOUT}s / ${MISP_RETRIES}"
echo "Backups remotos:            ${MAKE_BACKUPS}"
echo
echo "Nota: el certificado de MISP es autofirmado (lo genera install-misp.sh)."
echo "      La consulta a la API se hace sin verificar el certificado (-k / verify=False),"
echo "      igual que ya se hace con el dashboard HTTPS de Wazuh en este entorno de laboratorio."
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
# Comprobar SSH
# -------------------------
echo
inf "Comprobando acceso SSH al Wazuh Manager..."
wait_for_ssh "$WAZUH_MANAGER_HOST" || die "No hay SSH en Wazuh Manager: $WAZUH_MANAGER_HOST"
ok "SSH disponible en Wazuh Manager ($WAZUH_MANAGER_HOST)"

if (( DRY_RUN )); then
  echo
  inf "DRY-RUN completado. Se validó conectividad SSH y parámetros."
  echo "Acciones previstas:"
  echo "  - Instalar el script de integración custom-misp_ip.py en /var/ossec/integrations/"
  echo "  - Instalar las reglas locales de MISP en /var/ossec/etc/rules/misp_ip_rules.xml"
  echo "  - Añadir/actualizar el bloque <integration> en ossec.conf"
  echo "  - Comprobar conectividad del manager hacia MISP"
  echo "  - Reiniciar wazuh-manager"
  exit 0
fi

# =========================
# Despliegue en Wazuh Manager
# =========================
echo
inf "Desplegando integración MISP en Wazuh Manager..."

MISP_SETUP_SCRIPT="$(mktemp)"; register_tmp "$MISP_SETUP_SCRIPT"

cat > "$MISP_SETUP_SCRIPT" <<'REMOTE_MISP_SETUP'
#!/usr/bin/env bash
set -euo pipefail
MISP_URL="$1"
MISP_API_KEY="$2"
MISP_RULE_IDS="$3"
MISP_TIMEOUT="$4"
MISP_RETRIES="$5"
MAKE_BACKUPS="$6"

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

# ===============================
# Script de integración Python
# ===============================
log "[remote-wazuh] Instalando script de integración custom-misp_ip.py..."
INTEGRATION_PATH="/var/ossec/integrations/custom-misp_ip.py"
TMP_INTEGRATION="/tmp/custom-misp_ip_$$.py"

cat > "$TMP_INTEGRATION" <<'PYEOF'
#!/var/ossec/framework/python/bin/python3
# Wazuh - MISP IP reputation integration
#
# Adaptado del script oficial custom-misp_file_hashes.py de MISP/wazuh-integration
# (Copyright (C) 2025, CIRCL and Luciano Righetti, licencia AGPL-3.0) para
# consultar direcciones IP en lugar de hashes de fichero. Pensado para
# encadenarse tras la integracion Snort -> Wazuh de wazuh-snort.sh: cuando
# dispara una regla derivada de Snort (por defecto 600001/600010), consulta
# el srcip contra los atributos de tipo IP en MISP y, si no hay coincidencia,
# también el dstip (util para reglas de trafico saliente, p. ej. hacia un C2).
#
# ossec.conf:
# <integration>
#   <name>custom-misp_ip.py</name>
#   <hook_url>https://MISP_HOST</hook_url>
#   <api_key>API_KEY</api_key>
#   <rule_id>600001,600010</rule_id>
#   <alert_format>json</alert_format>
#   <options>{"timeout": 10, "retries": 2, "debug": false, "push_sightings": false}</options>
# </integration>

import json
import os
import re
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

IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
# Respaldo: el decoder "snort"/"snort2" de Wazuh no siempre matchea el
# full_log de alert_fast.txt (algunas versiones de Snort anteponen la marca
# de tiempo a "[**]", lo que rompe su <prematch> y deja "decoder":{} vacío,
# sin "srcip"). Cuando pasa eso, se extrae la IP directamente del full_log:
# "... {ICMP} 192.168.1.10 -> 192.168.1.20" (ICMP, sin puerto) o
# "... {TCP} 192.168.1.10:46548 -> 192.168.1.20:4444" (TCP/UDP, con puerto).
FULL_LOG_IP_RE = re.compile(
    r"\{[A-Za-z0-9_]+\}\s+(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\s*->\s*(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?"
)

debug_enabled = False
timeout = 10
retries = 2
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
    global debug_enabled, timeout, retries, json_options

    debug("# Running MISP IP reputation script")

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

    if "timeout" in json_options:
        if isinstance(json_options["timeout"], int) and json_options["timeout"] > 0:
            timeout = json_options["timeout"]
        else:
            debug("# Warning: Invalid timeout value. Using default")
    if "retries" in json_options:
        if isinstance(json_options["retries"], int) and json_options["retries"] >= 0:
            retries = json_options["retries"]
        else:
            debug("# Warning: Invalid retries value. Using default")
    if "debug" in json_options:
        if isinstance(json_options["debug"], bool):
            debug_enabled = json_options["debug"]
        else:
            debug("# Warning: Invalid debug value. Using default")

    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    msg = request_misp_info(json_alert, misp_url, apikey)
    if not msg:
        debug("# No hay srcip valida en la alerta; no se reporta a MISP")
        return

    send_msg(msg, json_alert.get("agent"))


def debug(msg: str) -> None:
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")


def extract_ips(alert):
    srcip = alert.get("srcip") or alert.get("data", {}).get("srcip")
    dstip = alert.get("dstip") or alert.get("data", {}).get("dstip")
    srcip = srcip if srcip and IP_RE.match(srcip) else None
    dstip = dstip if dstip and IP_RE.match(dstip) else None
    if srcip is None or dstip is None:
        match = FULL_LOG_IP_RE.search(alert.get("full_log", ""))
        if match:
            srcip = srcip or match.group(1)
            dstip = dstip or match.group(2)
    return srcip, dstip


def request_misp_info(alert, misp_url, api_key):
    alert_output = {"misp_ip": {}, "integration": "misp_ip"}

    srcip, dstip = extract_ips(alert)
    if not srcip and not dstip:
        debug("# No valid srcip/dstip field present in the alert (ni decoder ni full_log)")
        return None

    alert_output["misp_ip"]["found"] = 0
    alert_output["misp_ip"]["source"] = {
        "alert_id": alert.get("id"),
        "rule_id": alert.get("rule", {}).get("id"),
        "srcip": srcip,
        "dstip": dstip,
    }

    # Se consulta primero el origen (caso habitual: escaneo/ataque entrante,
    # donde el srcip es el atacante externo) y, si no hay coincidencia ni
    # error, se prueba el destino (trafico saliente hacia un C2 conocido,
    # p. ej. un intento de exfiltracion, donde el srcip es un host interno
    # y el dato relevante para MISP es el dstip).
    for candidate_ip, field in ((srcip, "srcip"), (dstip, "dstip")):
        if not candidate_ip:
            continue

        misp_response_data = request_ip_from_api(candidate_ip, alert_output, misp_url, api_key)
        if misp_response_data is None:
            return alert_output

        attributes = misp_response_data.get("response", {}).get("Attribute", [])
        if not attributes:
            debug("# No information found in MISP for %s (%s)" % (candidate_ip, field))
            continue

        alert_output["misp_ip"]["found"] = 1
        misp_attribute = attributes[0]
        event_uuid = misp_attribute.get("Event", {}).get("uuid")
        attribute_uuid = misp_attribute.get("uuid")

        alert_output["misp_ip"].update(
            {
                "matched_field": field,
                "ip": candidate_ip,
                "type": misp_attribute.get("type"),
                "value": misp_attribute.get("value"),
                "uuid": attribute_uuid,
                "timestamp": misp_attribute.get("timestamp"),
                "event_uuid": event_uuid,
                "permalink": f"{misp_url}/events/view/{event_uuid}/searchFor:{attribute_uuid}",
            }
        )

        if json_options.get("push_sightings"):
            push_misp_sighting(misp_url, api_key, candidate_ip)

        return alert_output

    return alert_output


def request_ip_from_api(ip, alert_output, misp_url, api_key):
    for attempt in range(retries + 1):
        try:
            return query_api(ip, misp_url, api_key)
        except Timeout:
            debug("# Error: Request timed out. Remaining retries: %s" % (retries - attempt))
            continue
        except Exception as e:
            debug(str(e))
            return None

    debug("# Error: Request timed out and maximum number of retries was exceeded")
    alert_output["misp_ip"]["error"] = 408
    alert_output["misp_ip"]["description"] = "Error: API request timed out"
    send_msg(alert_output)
    return None


def query_api(ip, misp_url, api_key):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Python-library-client-Wazuh-MISP",
        "Authorization": api_key,
    }

    # MISP se instala con certificado autofirmado (install-misp.sh): no se
    # verifica el certificado TLS, igual que ya se acepta en el dashboard de Wazuh.
    rest_search_payload = {
        "value": ip,
        "type": ["ip-src", "ip-dst"],
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

    alert_output = {"misp_ip": {}, "integration": "misp_ip"}
    alert_output["misp_ip"]["error"] = response.status_code
    if response.status_code == 403:
        alert_output["misp_ip"]["description"] = "Error: Check MISP credentials"
    elif response.status_code == 429:
        alert_output["misp_ip"]["description"] = "Error: MISP API rate limit reached"
    else:
        alert_output["misp_ip"]["description"] = "Error: API request failed"
    send_msg(alert_output)
    raise Exception("# Error: MISP API request failed with status %s" % response.status_code)


def push_misp_sighting(misp_url, api_key, ip):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Python-library-client-Wazuh-MISP",
        "Authorization": api_key,
    }
    payload = {"values": [ip], "source": json_options.get("sightings_source", "wazuh")}
    debug("# Pushing MISP sighting: %s" % json.dumps(payload))
    try:
        response = requests.post(
            f"{misp_url}/sightings/add", json=payload, headers=headers, timeout=timeout, verify=False
        )
        if response.status_code == 200:
            debug("# MISP Sighting pushed successfully")
        else:
            debug("# An error occurred pushing MISP sighting: %s" % response.text)
    except Exception as e:
        debug("# Error pushing sighting: %s" % str(e))


def send_msg(msg, agent=None) -> None:
    if not agent or agent.get("id") == "000":
        string = "1:misp_ip:{0}".format(json.dumps(msg))
    else:
        location = "[{0}] ({1}) {2}".format(agent["id"], agent["name"], agent.get("ip", "any"))
        location = location.replace("|", "||").replace(":", "|:")
        string = "1:{0}->misp_ip:{1}".format(location, json.dumps(msg))

    debug("# Request result from MISP server: %s" % string)
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
log "[remote-wazuh] custom-misp_ip.py instalado en $INTEGRATION_PATH"

# ===============================
# Reglas locales de Wazuh
# ===============================
log "[remote-wazuh] Instalando reglas locales misp_ip_rules.xml..."
RULES_PATH="/var/ossec/etc/rules/misp_ip_rules.xml"
TMP_RULES="/tmp/misp_ip_rules_$$.xml"

cat > "$TMP_RULES" <<'EOF'
<group name="local,misp,threat_intel,">
  <rule id="600200" level="0">
    <decoded_as>json</decoded_as>
    <field name="integration">misp_ip</field>
    <description>MISP: comprobación de reputación de IP</description>
    <options>no_full_log</options>
  </rule>

  <rule id="600201" level="0">
    <if_sid>600200</if_sid>
    <field name="misp_ip.found">0</field>
    <description>MISP: IP $(misp_ip.source.srcip) / $(misp_ip.source.dstip) sin coincidencias en threat intel</description>
  </rule>

  <rule id="600202" level="12">
    <if_sid>600200</if_sid>
    <field name="misp_ip.found">1</field>
    <description>MISP: IP $(misp_ip.ip) ($(misp_ip.matched_field)) coincide con evento de threat intel $(misp_ip.event_uuid)</description>
  </rule>

  <rule id="600203" level="10">
    <if_sid>600200</if_sid>
    <field name="misp_ip.error">\.+</field>
    <description>MISP ERROR: $(misp_ip.description)</description>
  </rule>
</group>
EOF

if ! $SUDO cmp -s "$TMP_RULES" "$RULES_PATH" 2>/dev/null; then
  [[ "$MAKE_BACKUPS" == "yes" && -f "$RULES_PATH" ]] && $SUDO cp -p "$RULES_PATH" "${RULES_PATH}.bak" || true
  $SUDO install -m 640 "$TMP_RULES" "$RULES_PATH"
  $SUDO chown root:wazuh "$RULES_PATH" 2>/dev/null || $SUDO chown root:root "$RULES_PATH"
  log "[remote-wazuh] misp_ip_rules.xml actualizado."
else
  log "[remote-wazuh] misp_ip_rules.xml ya estaba en el estado deseado."
fi
$SUDO rm -f "$TMP_RULES" >/dev/null 2>&1 || true

# ===============================
# Bloque <integration> en ossec.conf
# ===============================
log "[remote-wazuh] Configurando bloque <integration> en ossec.conf..."
OSSEC_CONF="/var/ossec/etc/ossec.conf"
TMP_OSSEC="/tmp/ossec_conf_misp_$$.xml"
$SUDO cat "$OSSEC_CONF" > "$TMP_OSSEC"

# Elimina un bloque <integration> de custom-misp_ip.py previo, si existe.
$SUDO perl -0777 -i -pe 's#\s*<integration>\s*<name>custom-misp_ip\.py</name>.*?</integration>\s*##sg' "$TMP_OSSEC"

INTEGRATION_BLOCK="  <integration>\n    <name>custom-misp_ip.py</name>\n    <hook_url>${MISP_URL}</hook_url>\n    <api_key>${MISP_API_KEY}</api_key>\n    <rule_id>${MISP_RULE_IDS}</rule_id>\n    <alert_format>json</alert_format>\n    <options>{\"timeout\": ${MISP_TIMEOUT}, \"retries\": ${MISP_RETRIES}, \"debug\": false, \"push_sightings\": false}</options>\n  </integration>\n"

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
# Comprobar conectividad hacia MISP
# ===============================
log "[remote-wazuh] Comprobando conectividad hacia MISP (${MISP_URL})..."
if command -v curl >/dev/null 2>&1; then
  HTTP_CODE="$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 10 \
      -H "Authorization: ${MISP_API_KEY}" -H "Accept: application/json" \
      "${MISP_URL}/servers/getVersion" || true)"
  if [[ "$HTTP_CODE" == "200" ]]; then
    log "[remote-wazuh] MISP responde correctamente (HTTP 200)."
  else
    log "[remote-wazuh][WARN] MISP respondió HTTP ${HTTP_CODE:-sin respuesta}. Revisa URL/API key/red."
  fi
fi

# ===============================
# Reiniciar wazuh-manager
# ===============================
log "[remote-wazuh] Reiniciando wazuh-manager..."
$SUDO systemctl restart wazuh-manager
$SUDO tail -n 40 /var/ossec/logs/ossec.log || true

log "[remote-wazuh] Integración MISP lista."
REMOTE_MISP_SETUP
chmod 700 "$MISP_SETUP_SCRIPT"

if ! run_remote_script_tty "$WAZUH_MANAGER_HOST" "$MISP_SETUP_SCRIPT" \
    "$MISP_URL" "$MISP_API_KEY" "$MISP_RULE_IDS" "$MISP_TIMEOUT" "$MISP_RETRIES" "$MAKE_BACKUPS"; then
  die "Falló el despliegue de la integración MISP en el Wazuh Manager."
fi

ok "Integración MISP desplegada en Wazuh Manager."

# -------------------------
# Resumen final
# -------------------------
SCRIPT_END=$(date +%s)

echo
echo "===================================================="
echo " Integración Wazuh -> MISP (resultado)"
echo "===================================================="
echo "Wazuh Manager (SSH):        ${WAZUH_MANAGER_HOST}"
echo "URL de MISP:                ${MISP_URL}"
echo "Reglas que disparan:        ${MISP_RULE_IDS}"
echo "Reglas MISP generadas:      600200-600203 (/var/ossec/etc/rules/misp_ip_rules.xml)"
echo "[⏱] Tiempo TOTAL: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "===================================================="
echo
echo "Cómo probarlo:"
echo "  1. En MISP, crea un evento con un atributo de tipo 'ip-src' (marcado"
echo "     'IDS' / to_ids=true) con la IP de caldera-server."
echo "  2. Desde caldera-server, genera tráfico que dispare Snort (p.ej. ping"
echo "     o nmap contra snort-server), como en los ejercicios de lab/README.md."
echo "  3. En Wazuh Manager, comprueba:"
echo "       sudo tail -f /var/ossec/logs/integrations.log"
echo "       sudo grep -A5 '\"integration\":\"misp_ip\"' /var/ossec/logs/alerts/alerts.json"
echo "     Debería aparecer una alerta de nivel 12 (regla 600202) con la IP y"
echo "     el enlace ('permalink') al evento de MISP."
echo
