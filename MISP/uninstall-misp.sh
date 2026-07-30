#!/bin/bash
# =========================================================
#  Desinstalación completa de MISP (Threat Intelligence Platform)
# =========================================================

# ===== Comprobación de root =====
if [[ $EUID -ne 0 ]]; then
   echo "[✖] Este script debe ejecutarse como root."
   echo "    Usa: sudo bash uninstall-misp.sh"
   exit 1
fi

# ===== Detectar usuario real =====
if [[ -z "$SUDO_USER" ]]; then
    echo "[✖] Este script debe ejecutarse con sudo, no como root directo."
    echo "    Usa: sudo bash uninstall-misp.sh"
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
LOG_DIR="$LOCAL_USER_HOME/misp-logs"
mkdir -p "$LOG_DIR"

LOG_FILE="$LOG_DIR/misp-uninstall.log"

# Redirigir salida al log + pantalla
exec > >(tee -a "$LOG_FILE") 2>&1

echo "===================================================="
echo " Desinstalación automática de MISP"
echo " Carpeta de logs: $LOG_DIR"
echo " Log: $LOG_FILE"
echo "===================================================="

set -e

MISP_PATH="/var/www/MISP"

# ===============================
# DETENER Y DESHABILITAR SERVICIOS
# ===============================
echo "[+] Deteniendo servicios..."
systemctl stop supervisor 2>/dev/null || true
systemctl stop apache2 2>/dev/null || true
systemctl stop redis-server 2>/dev/null || true
systemctl stop mariadb 2>/dev/null || true

echo "[+] Deshabilitando servicios..."
systemctl disable supervisor 2>/dev/null || true
systemctl disable apache2 2>/dev/null || true
systemctl disable redis-server 2>/dev/null || true
systemctl disable mariadb 2>/dev/null || true

# ===============================
# ELIMINAR BASE DE DATOS DE MISP
# ===============================
echo "[+] Eliminando base de datos y usuario de MISP..."
systemctl start mariadb 2>/dev/null || true
if command -v mysql >/dev/null 2>&1; then
    mysql -e "DROP DATABASE IF EXISTS misp;" 2>/dev/null || true
    mysql -e "DROP USER IF EXISTS 'misp'@'localhost';" 2>/dev/null || true
    mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true
fi
systemctl stop mariadb 2>/dev/null || true

# ===============================
# ELIMINAR PAQUETES
# ===============================
echo "[+] Eliminando paquetes..."
apt-get remove --purge -y \
    apache2 apache2-utils apache2-bin \
    mariadb-server mariadb-client \
    redis-server supervisor \
    'php8.2*' libapache2-mod-php8.2 \
    2>/dev/null || true
apt-get autoremove --purge -y
apt-get autoclean -y

# ===============================
# ELIMINAR DIRECTORIOS Y FICHEROS DE MISP
# ===============================
echo "[+] Eliminando directorios y ficheros residuales de MISP..."
rm -rf "$MISP_PATH"
rm -f /etc/apache2/sites-available/misp-ssl.conf
rm -f /etc/apache2/sites-enabled/misp-ssl.conf
rm -f /etc/ssl/private/misp.local.crt
rm -f /etc/ssl/private/misp.local.key
rm -f /etc/mysql/mariadb.conf.d/z-misp.cnf
rm -f /etc/supervisor/conf.d/misp-workers.conf
rm -f /usr/local/bin/composer
rm -f /var/log/misp_install.log
rm -f /root/misp_settings.txt

# ===============================
# AJUSTAR PERMISOS
# ===============================
echo "[+] Ajustando permisos para el usuario local..."
chown -R "$LOCAL_USER:$LOCAL_USER" "$LOG_DIR" 2>/dev/null || true

echo "-----------------------------------------------"
echo "[✔] MISP ha sido desinstalado COMPLETAMENTE."
echo "-----------------------------------------------"

# ===== Tiempo total =====
SCRIPT_END=$(date +%s)
echo "[⏱] Tiempo TOTAL de desinstalación: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "===================================================="
echo "Log completo disponible en: $LOG_FILE"
echo "===================================================="
