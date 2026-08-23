#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# Preparación de inspectores nativos en Snort (snort-server)
# - Habilita el inspector "modbus" de Snort 3 y lo enlaza al
#   puerto 502/TCP mediante el binder, para que las reglas con
#   la opción "modbus_func" (p. ej. detectar FC6, Write Single
#   Register) funcionen.
# - Habilita también el inspector "http_inspect" y lo enlaza al
#   puerto 8080/TCP (interfaz web de OpenPLC), para que las
#   reglas con "http_uri" (p. ej. detectar una subida de
#   programa no autorizada) funcionen.
# - Es pura fontanería de configuración (sin valor pedagógico
#   en teclearla a mano); las reglas de detección en sí y el
#   resto de la integración (Wazuh, MISP, Caldera) se hacen
#   a mano como parte de los ejercicios.
# - Solo toca snort-server. Idempotente.
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
Uso: bash prep-openplc-snort.sh [opciones]

Opciones:
  --dry-run        Muestra el plan y valida SSH. No modifica nada remoto.
  -h, --help       Muestra esta ayuda.

Variables opcionales (env):
  MAKE_BACKUPS=yes   Crea backup .bak de snort.lua antes de reescribirlo.
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

DEFAULT_SNORT_HOST=""
DEFAULT_SNORT_LUA_PATH="/etc/snort/snort.lua"

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

# -------------------------
# Banner
# -------------------------
echo "===================================================="
echo " Preparación del inspector Modbus en Snort (snort-server)"
echo "===================================================="

(( DRY_RUN )) && warn "MODO DRY-RUN activo: no se modificará el manager."

# -------------------------
# Inputs SSH
# -------------------------
echo
echo "=== Configuración SSH (VM de Snort) ==="
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
read -r -p "IP/hostname de la VM Snort (SSH): " SNORT_HOST
SNORT_HOST="${SNORT_HOST:-$DEFAULT_SNORT_HOST}"
[[ -n "$SNORT_HOST" ]] || die "La IP/hostname de Snort no puede estar vacía."

read -r -p "Ruta de snort.lua en la VM [${DEFAULT_SNORT_LUA_PATH}]: " SNORT_LUA_PATH
SNORT_LUA_PATH="${SNORT_LUA_PATH:-$DEFAULT_SNORT_LUA_PATH}"

# -------------------------
# Resumen
# -------------------------
echo
echo "=== Resumen de configuración ==="
(( DRY_RUN )) && echo "Dry-run:                    sí"
echo "Snort (SSH):                 ${SNORT_HOST}"
echo "Fichero snort.lua:           ${SNORT_LUA_PATH}"
echo "Backups remotos:             ${MAKE_BACKUPS}"
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
inf "Comprobando acceso SSH a la VM de Snort..."
wait_for_ssh "$SNORT_HOST" || die "No hay SSH en la VM de Snort: $SNORT_HOST"
ok "SSH disponible en Snort ($SNORT_HOST)"

if (( DRY_RUN )); then
  echo
  inf "DRY-RUN completado. Se validó conectividad SSH."
  echo "Acciones previstas:"
  echo "  - Habilitar 'stream'/'stream_tcp' (reensamblado TCP, requisito del inspector Modbus)"
  echo "  - Habilitar el inspector 'modbus' en ${SNORT_LUA_PATH} y enlazarlo al puerto 502/TCP"
  echo "  - Habilitar el inspector 'http_inspect' y enlazarlo al puerto 8080/TCP (web OpenPLC)"
  echo "  - Validar la sintaxis con 'snort -T -c ${SNORT_LUA_PATH}'"
  exit 0
fi

# =========================
# Despliegue en Snort
# =========================
echo
inf "Preparando el inspector Modbus en snort-server..."

SETUP_SCRIPT="$(mktemp)"; register_tmp "$SETUP_SCRIPT"

cat > "$SETUP_SCRIPT" <<'REMOTE_SETUP'
#!/usr/bin/env bash
set -euo pipefail
SNORT_LUA_PATH="$1"
MAKE_BACKUPS="$2"

log(){ echo "$*"; }
SUDO=""; SUDO_KEEPALIVE_PID=""
if [[ "$(id -u)" -ne 0 ]]; then
  SUDO="sudo"
  if sudo -n true >/dev/null 2>&1; then
    log "[remote-snort] sudo sin contraseña disponible"
  else
    log "[remote-snort] sudo requiere contraseña. Se pedirá ahora..."
    sudo -v || { log "[remote-snort][ERROR] sudo -v falló"; exit 1; }
    (
      while true; do sudo -n true >/dev/null 2>&1 || exit; sleep 60; kill -0 "$$" >/dev/null 2>&1 || exit; done
    ) &
    SUDO_KEEPALIVE_PID="$!"
    trap '[[ -n "${SUDO_KEEPALIVE_PID:-}" ]] && kill "${SUDO_KEEPALIVE_PID}" >/dev/null 2>&1 || true' EXIT
  fi
fi

[[ -f "$SNORT_LUA_PATH" ]] || { log "[remote-snort][ERROR] No se encuentra $SNORT_LUA_PATH"; exit 1; }
command -v snort >/dev/null 2>&1 || { log "[remote-snort][ERROR] No se detecta el comando 'snort'"; exit 1; }

# Copia de seguridad INTERNA (independiente de MAKE_BACKUPS/.bak, que es para
# el usuario): si tras escribir los bloques la validacion de Snort falla,
# se restaura este contenido en vez de dejar el fichero a medias. Protege
# contra cualquier fallo en la deteccion de idempotencia de mas abajo,
# sea cual sea la causa: peor caso, la ejecucion no cambia nada.
PRE_STATE="$($SUDO cat "$SNORT_LUA_PATH")"
restore_pre_state() {
  log "[remote-snort][ERROR] Restaurando $SNORT_LUA_PATH a su estado anterior a esta ejecucion..."
  printf '%s\n' "$PRE_STATE" | $SUDO tee "$SNORT_LUA_PATH" >/dev/null
}

MARKER="-- [nics-cyberlab] inspector Modbus (OpenPLC)"
HTTP_MARKER="-- [nics-cyberlab] inspector HTTP (OpenPLC web, puerto 8080)"

if $SUDO grep -qF "$MARKER" "$SNORT_LUA_PATH" 2>/dev/null; then
  log "[remote-snort] El inspector Modbus ya estaba habilitado en $SNORT_LUA_PATH."
else
  log "[remote-snort] Añadiendo inspector Modbus + binder (puerto 502/TCP)..."
  [[ "$MAKE_BACKUPS" == "yes" ]] && $SUDO cp -p "$SNORT_LUA_PATH" "${SNORT_LUA_PATH}.bak" || true

  # Este es el primer bloque que toca "binder" en este snort.lua (config
  # minima del laboratorio, sin binder por defecto previo): tiene que
  # CREAR la tabla con "binder = { ... }". Si en tu instalacion snort.lua
  # SI trae un binder previo con bindings por defecto (HTTP, SSL, wizard...),
  # cambia esta linea por table.insert(binder, { ... }) para no perderlos.
  {
    echo ""
    echo "$MARKER"
    echo "stream = { }"
    echo "stream_tcp = { }"
    echo "modbus = { }"
    echo "binder = { { when = { proto = 'tcp', ports = '502' }, use = { type = 'modbus' } } }"
  } | $SUDO tee -a "$SNORT_LUA_PATH" >/dev/null

  log "[remote-snort] snort.lua actualizado (Modbus)."
fi

if $SUDO grep -qF "$HTTP_MARKER" "$SNORT_LUA_PATH" 2>/dev/null; then
  log "[remote-snort] El inspector HTTP ya estaba habilitado en $SNORT_LUA_PATH."
else
  log "[remote-snort] Añadiendo inspector HTTP + binder (puerto 8080/TCP)..."
  [[ "$MAKE_BACKUPS" == "yes" ]] && ! $SUDO grep -qF "$MARKER" "$SNORT_LUA_PATH" 2>/dev/null && $SUDO cp -p "$SNORT_LUA_PATH" "${SNORT_LUA_PATH}.bak" || true

  # OJO: NO se reasigna "binder = { ... }" aquí (sobreescribiría la entrada del
  # puerto 502 añadida por el bloque Modbus, ya que en Lua es una simple
  # reasignación de variable global). Se usa table.insert() para añadir esta
  # entrada a la tabla "binder" ya existente, en vez de reemplazarla.
  {
    echo ""
    echo "$HTTP_MARKER"
    echo "http_inspect = { }"
    echo "table.insert(binder, { when = { proto = 'tcp', ports = '8080' }, use = { type = 'http_inspect' } })"
  } | $SUDO tee -a "$SNORT_LUA_PATH" >/dev/null

  log "[remote-snort] snort.lua actualizado (HTTP)."
fi

log "[remote-snort] Validando sintaxis con 'snort -T -c ${SNORT_LUA_PATH}'..."
if ! $SUDO snort -T -c "$SNORT_LUA_PATH"; then
  log "[remote-snort][ERROR] La validación de snort.lua falló."
  restore_pre_state
  log "[remote-snort][ERROR] Fichero restaurado a como estaba antes de esta ejecución. No se ha dejado nada roto."
  log "[remote-snort][ERROR] Revisa manualmente ${SNORT_LUA_PATH} y vuelve a intentarlo."
  exit 1
fi

log "[remote-snort] Configuración válida."
log "[remote-snort] IMPORTANTE: si Snort ya está en ejecución, este cambio no se aplica en"
log "[remote-snort] caliente. Detén el proceso (Ctrl+C en su terminal) y vuelve a lanzarlo:"
log "[remote-snort]   sudo snort -i ens3 -c ${SNORT_LUA_PATH} -A alert_fast -k none -l /var/log/snort"
REMOTE_SETUP
chmod 700 "$SETUP_SCRIPT"

if ! run_remote_script_tty "$SNORT_HOST" "$SETUP_SCRIPT" "$SNORT_LUA_PATH" "$MAKE_BACKUPS"; then
  die "Falló la preparación del inspector Modbus en snort-server."
fi

ok "Inspector Modbus preparado en snort-server."

# -------------------------
# Resumen final
# -------------------------
SCRIPT_END=$(date +%s)

echo
echo "===================================================="
echo " Preparación Modbus en Snort (resultado)"
echo "===================================================="
echo "Snort (SSH):                 ${SNORT_HOST}"
echo "Fichero modificado:          ${SNORT_LUA_PATH}"
echo "[⏱] Tiempo TOTAL: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "===================================================="
echo
echo "Siguiente paso: escribe a mano la regla de detección en local.rules"
echo "(opción 'modbus_func') y relanza Snort para que recoja ambos cambios."
echo "===================================================="
