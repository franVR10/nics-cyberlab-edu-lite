#!/bin/bash
# =========================================================
#  Instalación completa de OpenPLC Runtime v3
#  Envuelve el instalador oficial de OpenPLC_v3 para Linux/Debian
#  (https://github.com/thiagoralves/OpenPLC_v3)
# =========================================================

# ===== Comprobación de root =====
if [[ $EUID -ne 0 ]]; then
   echo "[✖] Este script debe ejecutarse como root."
   echo "    Usa: sudo bash install-openplc.sh"
   exit 1
fi

# ===== Detectar usuario real =====
if [[ -z "$SUDO_USER" ]]; then
    echo "[✖] Este script debe ejecutarse con sudo, no como root directo."
    echo "    Usa: sudo bash install-openplc.sh"
    exit 1
fi

LOCAL_USER="$SUDO_USER"
LOCAL_USER_HOME=$(eval echo "~$LOCAL_USER")

echo "INICIANDO DESPLIEGUE DE OPENPLC - NICS-CYBERLAB"
echo "----------------------------------------------------"
echo "[i] Usuario real: $LOCAL_USER"
echo "[i] HOME real: $LOCAL_USER_HOME"

# ===== Timer global =====
SCRIPT_START=$(date +%s)
format_time() { local total=$1; echo "$((total/60)) minutos y $((total%60)) segundos"; }

# ===== Carpeta de logs =====
LOG_DIR="$LOCAL_USER_HOME/openplc-logs"
mkdir -p "$LOG_DIR"

LOG_FILE="$LOG_DIR/openplc-install.log"

# Redirigir toda la salida al log + pantalla
exec > >(tee -a "$LOG_FILE") 2>&1

echo "===================================================="
echo " Instalación automática de OpenPLC Runtime v3"
echo " Carpeta de logs: $LOG_DIR"
echo " Log: $LOG_FILE"
echo "===================================================="

set -e

# ===============================
# CONFIGURACIÓN
# ===============================
OPENPLC_REPO="https://github.com/thiagoralves/OpenPLC_v3.git"
OPENPLC_DIR="$LOCAL_USER_HOME/OpenPLC_v3"
OPENPLC_PORT="8080"
OPENPLC_PID_FILE="$LOG_DIR/openplc.pid"
OPENPLC_SERVER_LOG="$LOG_DIR/openplc-server.log"

# IP con la que se accederá a la interfaz web (autodetectada)
OPENPLC_DOMAIN="${OPENPLC_DOMAIN:-$(hostname -I | awk '{print $1}')}"

# ===============================
# IDEMPOTENCIA: ¿ya está instalado?
# ===============================
if [[ -x "$OPENPLC_DIR/start_openplc.sh" ]]; then
    echo "[i] OpenPLC ya está instalado (se encontró $OPENPLC_DIR/start_openplc.sh)."

    if [[ -f "$OPENPLC_PID_FILE" ]] && kill -0 "$(cat "$OPENPLC_PID_FILE")" 2>/dev/null; then
        echo "[✔] El runtime ya está en ejecución (PID $(cat "$OPENPLC_PID_FILE"))."
    else
        echo "[+] El runtime no está en ejecución. Arrancándolo..."
        cd "$OPENPLC_DIR"
        nohup ./start_openplc.sh > "$OPENPLC_SERVER_LOG" 2>&1 &
        echo $! > "$OPENPLC_PID_FILE"
        sleep 3
        echo "[✔] OpenPLC arrancado (PID $(cat "$OPENPLC_PID_FILE"))."
    fi

    echo "-----------------------------------------------"
    echo "[✔] OpenPLC ya estaba desplegado, no se reinstala."
    echo "    Para forzar una reinstalación limpia ejecuta antes:"
    echo "      sudo bash uninstall-openplc.sh"
    echo "-----------------------------------------------"
    echo "Acceso a OpenPLC:"
    echo "  URL      : http://$OPENPLC_DOMAIN:$OPENPLC_PORT"
    echo "  Usuario  : openplc"
    echo "  Password : openplc"
    echo "===================================================="
    exit 0
fi

if [[ -d "$OPENPLC_DIR" ]]; then
    echo "[!] Se detectó una instalación previa incompleta en $OPENPLC_DIR (sin start_openplc.sh)."
    echo "    Se eliminará para reintentar una instalación limpia."
    rm -rf "$OPENPLC_DIR"
fi

# ===============================
# DEPENDENCIAS PREVIAS
# ===============================
echo "[+] Actualizando sistema..."
apt-get update -o Acquire::Retries=3
apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

echo "[+] Instalando dependencias previas (git)..."
apt-get install -y git

# ===============================
# DESCARGA DEL CÓDIGO OFICIAL
# ===============================
echo "[+] Descargando OpenPLC Runtime v3 (rama master)..."
git clone --depth 1 "$OPENPLC_REPO" "$OPENPLC_DIR"

# ===============================
# EJECUTAR INSTALADOR OFICIAL
# ===============================
echo "[+] Ejecutando instalador oficial de OpenPLC (compila MatIEC, libmodbus, etc.; puede tardar 15-30 minutos)..."
cd "$OPENPLC_DIR"
chmod +x install.sh
if ! ./install.sh linux; then
    echo "[✖] La instalación de OpenPLC falló."
    echo "    Revisa $LOG_FILE para más detalle."
    exit 1
fi

echo "[✔] Instalador oficial de OpenPLC finalizado."

if [[ ! -x "$OPENPLC_DIR/start_openplc.sh" ]]; then
    echo "[✖] El instalador terminó pero no se generó start_openplc.sh en $OPENPLC_DIR."
    echo "    Revisa $LOG_FILE para más detalle."
    exit 1
fi

# ===============================
# ARRANCAR OPENPLC EN SEGUNDO PLANO
# ===============================
echo "[+] Arrancando OpenPLC en segundo plano..."
cd "$OPENPLC_DIR"
nohup ./start_openplc.sh > "$OPENPLC_SERVER_LOG" 2>&1 &
echo $! > "$OPENPLC_PID_FILE"

echo "[+] Esperando a que la interfaz web esté disponible..."
READY=0
for _ in $(seq 1 30); do
    if curl -fs --max-time 2 -o /dev/null "http://127.0.0.1:${OPENPLC_PORT}"; then
        READY=1
        break
    fi
    sleep 2
done

if [[ "$READY" -eq 1 ]]; then
    echo "[✔] OpenPLC está listo y accesible (PID $(cat "$OPENPLC_PID_FILE"))."
else
    echo "[!] OpenPLC se lanzó pero no se pudo confirmar que la web responda todavía."
    echo "    Revisa $OPENPLC_SERVER_LOG."
fi

# =========================
# MOSTRAR DATOS DE ACCESO
# =========================
echo "-----------------------------------------------"
echo "Acceso a OpenPLC:"
echo "  URL      : http://$OPENPLC_DOMAIN:$OPENPLC_PORT"
echo "  Usuario  : openplc"
echo "  Password : openplc"
echo "-----------------------------------------------"
echo "[i] Cambia la contraseña por defecto desde Users → openplc en la propia interfaz web."
echo "[i] Log del proceso en segundo plano: $OPENPLC_SERVER_LOG"
echo "[i] Para detener OpenPLC:  kill \$(cat $OPENPLC_PID_FILE)"
echo "[i] Para volver a arrancarlo manualmente:"
echo "      cd $OPENPLC_DIR && ./start_openplc.sh"
echo "[✔] Instalación de OpenPLC completada."

# ===== Ajustar permisos =====
echo "[+] Ajustando permisos para el usuario local..."
chown -R "$LOCAL_USER:$LOCAL_USER" "$OPENPLC_DIR" "$LOG_DIR" 2>/dev/null || true

# ===== Tiempo total =====
SCRIPT_END=$(date +%s)
echo "[⏱] Tiempo TOTAL de instalación: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "===================================================="
echo "Log completo disponible en: $LOG_FILE"
echo "===================================================="
