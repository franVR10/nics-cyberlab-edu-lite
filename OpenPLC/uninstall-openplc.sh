#!/bin/bash
# =========================================================
#  Desinstalación completa de OpenPLC Runtime v3
# =========================================================

# ===== Comprobación de root =====
if [[ $EUID -ne 0 ]]; then
   echo "[✖] Este script debe ejecutarse como root."
   echo "    Usa: sudo bash uninstall-openplc.sh"
   exit 1
fi

# ===== Detectar usuario real =====
if [[ -z "$SUDO_USER" ]]; then
    echo "[✖] Este script debe ejecutarse con sudo, no como root directo."
    echo "    Usa: sudo bash uninstall-openplc.sh"
    exit 1
fi

LOCAL_USER="$SUDO_USER"
LOCAL_USER_HOME=$(eval echo "~$LOCAL_USER")

echo "[i] Usuario real: $LOCAL_USER"
echo "[i] HOME real: $LOCAL_USER_HOME"

# ===== Timer global =====
SCRIPT_START=$(date +%s)
format_time() { local total=$1; echo "$((total/60)) minutos y $((total%60)) segundos"; }

# ===== Carpeta de logs =====
LOG_DIR="$LOCAL_USER_HOME/openplc-logs"
mkdir -p "$LOG_DIR"

LOG_FILE="$LOG_DIR/openplc-uninstall.log"

# Redirigir salida al log + pantalla
exec > >(tee -a "$LOG_FILE") 2>&1

echo "===================================================="
echo " Desinstalación automática de OpenPLC"
echo " Carpeta de logs: $LOG_DIR"
echo " Log: $LOG_FILE"
echo "===================================================="

set -e

OPENPLC_DIR="$LOCAL_USER_HOME/OpenPLC_v3"
OPENPLC_PID_FILE="$LOG_DIR/openplc.pid"

# ===============================
# DETENER EL PROCESO EN EJECUCIÓN
# ===============================
echo "[+] Deteniendo OpenPLC si está en ejecución..."
if [[ -f "$OPENPLC_PID_FILE" ]]; then
    PID="$(cat "$OPENPLC_PID_FILE")"
    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null || true
        sleep 2
        kill -9 "$PID" 2>/dev/null || true
        echo "[✔] Proceso OpenPLC (PID $PID) detenido."
    else
        echo "[i] El PID guardado ($PID) ya no está en ejecución."
    fi
    rm -f "$OPENPLC_PID_FILE"
else
    echo "[i] No se encontró fichero de PID; buscando el proceso por nombre..."
    pkill -f "webserver.py" 2>/dev/null && echo "[✔] Proceso webserver.py detenido." || echo "[i] No había ningún proceso webserver.py en ejecución."
fi

# ===============================
# ELIMINAR DIRECTORIOS Y FICHEROS DE OPENPLC
# ===============================
echo "[+] Eliminando directorio de OpenPLC..."
rm -rf "$OPENPLC_DIR"

# ===============================
# AJUSTAR PERMISOS
# ===============================
echo "[+] Ajustando permisos para el usuario local..."
chown -R "$LOCAL_USER:$LOCAL_USER" "$LOG_DIR" 2>/dev/null || true

echo "-----------------------------------------------"
echo "[✔] OpenPLC ha sido desinstalado."
echo "    Nota: las dependencias de sistema instaladas por el instalador oficial"
echo "    (build-essential, cmake, git, python3, etc.) NO se han eliminado,"
echo "    ya que son herramientas genéricas que pueden usarse para otros fines"
echo "    en esta VM. Si quieres purgarlas también, hazlo manualmente."
echo "-----------------------------------------------"

# ===== Tiempo total =====
SCRIPT_END=$(date +%s)
echo "[⏱] Tiempo TOTAL de desinstalación: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "===================================================="
echo "Log completo disponible en: $LOG_FILE"
echo "===================================================="
