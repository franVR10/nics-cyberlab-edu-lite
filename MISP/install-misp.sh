#!/bin/bash
# =========================================================
#  Instalación completa de MISP (Threat Intelligence Platform)
#  Envuelve el instalador oficial de MISP para Debian 12
#  (https://github.com/MISP/MISP/blob/2.5/INSTALL/INSTALL.debian12.sh)
# =========================================================

# ===== Comprobación de root =====
if [[ $EUID -ne 0 ]]; then
   echo "[✖] Este script debe ejecutarse como root."
   echo "    Usa: sudo bash install-misp.sh"
   exit 1
fi

# ===== Detectar usuario real =====
if [[ -z "$SUDO_USER" ]]; then
    echo "[✖] Este script debe ejecutarse con sudo, no como root directo."
    echo "    Usa: sudo bash install-misp.sh"
    exit 1
fi

LOCAL_USER="$SUDO_USER"
LOCAL_USER_HOME=$(eval echo "~$LOCAL_USER")

echo "INICIANDO DESPLIEGUE DE MISP - NICS-CYBERLAB"
echo "----------------------------------------------------"
echo "[i] Usuario real: $LOCAL_USER"
echo "[i] HOME real: $LOCAL_USER_HOME"

# ===== Timer global =====
SCRIPT_START=$(date +%s)
format_time() { local total=$1; echo "$((total/60)) minutos y $((total%60)) segundos"; }

# ===== Carpeta de logs =====
LOG_DIR="$LOCAL_USER_HOME/misp-logs"
mkdir -p "$LOG_DIR"

LOG_FILE="$LOG_DIR/misp-install.log"

# Redirigir toda la salida al log + pantalla
exec > >(tee -a "$LOG_FILE") 2>&1

echo "===================================================="
echo " Instalación automática de MISP"
echo " Carpeta de logs: $LOG_DIR"
echo " Log: $LOG_FILE"
echo "===================================================="

set -e

# ===============================
# CONFIGURACIÓN
# ===============================
MISP_BRANCH="2.5"
MISP_INSTALLER_URL="https://raw.githubusercontent.com/MISP/MISP/${MISP_BRANCH}/INSTALL/INSTALL.debian${MISP_BRANCH%%.*}.sh"
MISP_PATH="/var/www/MISP"
MISP_SETTINGS_FILE="/root/misp_settings.txt"
MISP_INSTALLER_LOCAL="$LOG_DIR/INSTALL.debian12.sh"
MISP_DOMAIN_FILE="$LOG_DIR/.misp_domain"

# Dominio/IP con el que se accederá a MISP (autodetectado; puede fijarse con MISP_DOMAIN=... sudo -E bash install-misp.sh)
MISP_DOMAIN="${MISP_DOMAIN:-$(hostname -I | awk '{print $1}')}"
MISP_DOMAIN="${MISP_DOMAIN:-misp.local}"

# ===============================
# IDEMPOTENCIA: ¿ya está instalado?
# ===============================
if [[ -f "$MISP_SETTINGS_FILE" && -d "$MISP_PATH" ]]; then
    echo "[i] MISP ya está instalado (se encontró $MISP_SETTINGS_FILE)."
    echo "[+] Comprobando y reactivando servicios..."
    systemctl start mariadb 2>/dev/null || true
    systemctl start redis-server 2>/dev/null || true
    systemctl start apache2 2>/dev/null || true
    systemctl start supervisor 2>/dev/null || true

    [[ -f "$MISP_DOMAIN_FILE" ]] && MISP_DOMAIN="$(cat "$MISP_DOMAIN_FILE")"

    echo "-----------------------------------------------"
    echo "[✔] MISP ya estaba desplegado, no se reinstala."
    echo "    Para forzar una reinstalación limpia ejecuta antes:"
    echo "      sudo bash uninstall-misp.sh"
    echo "-----------------------------------------------"
    echo "Acceso a MISP:"
    echo "  URL      : https://$MISP_DOMAIN"
    echo "Credenciales guardadas en: $MISP_SETTINGS_FILE"
    [[ -f "$LOG_DIR/misp-settings.txt" ]] && echo "Copia legible por tu usuario: $LOG_DIR/misp-settings.txt"
    echo "===================================================="
    exit 0
fi

if [[ -d "$MISP_PATH" ]]; then
    echo "[!] Se detectó una instalación previa incompleta en $MISP_PATH (sin $MISP_SETTINGS_FILE)."
    echo "    Se eliminará para reintentar una instalación limpia."
    systemctl stop apache2 2>/dev/null || true
    rm -rf "$MISP_PATH"
    if command -v mysql >/dev/null 2>&1; then
        mysql -e "DROP DATABASE IF EXISTS misp;" 2>/dev/null || true
        mysql -e "DROP USER IF EXISTS 'misp'@'localhost';" 2>/dev/null || true
    fi
fi

# ===============================
# DEPENDENCIAS PREVIAS
# ===============================
echo "[+] Actualizando sistema..."
apt-get update -o Acquire::Retries=3
apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

echo "[+] Instalando dependencias previas (curl, lsb-release, gnupg, git)..."
apt-get install -y curl ca-certificates gnupg lsb-release apt-transport-https git

# ===============================
# DESCARGA DEL INSTALADOR OFICIAL
# ===============================
# raw.githubusercontent.com puede devolver 404 puntualmente en según qué
# edge de su CDN tras cambios en la rama; si pasa, se recurre a git clone
# sobre github.com como alternativa.
echo "[+] Descargando instalador oficial de MISP (rama ${MISP_BRANCH})..."
if ! curl -fsSL "$MISP_INSTALLER_URL" -o "$MISP_INSTALLER_LOCAL"; then
    echo "[!] Fallo al descargar vía raw.githubusercontent.com, se prueba con git clone..."
    MISP_CLONE_TMP="$(mktemp -d)"
    git clone --depth 1 --branch "$MISP_BRANCH" https://github.com/MISP/MISP.git "$MISP_CLONE_TMP"
    cp "$MISP_CLONE_TMP/INSTALL/INSTALL.debian${MISP_BRANCH%%.*}.sh" "$MISP_INSTALLER_LOCAL"
    rm -rf "$MISP_CLONE_TMP"
fi
chmod +x "$MISP_INSTALLER_LOCAL"

# ===============================
# ADAPTAR DOMINIO AL ENTORNO DEL LABORATORIO
# ===============================
echo "[i] Dominio/IP para MISP: $MISP_DOMAIN"
echo "$MISP_DOMAIN" > "$MISP_DOMAIN_FILE"

sed -i "s|^MISP_DOMAIN='misp.local'|MISP_DOMAIN='${MISP_DOMAIN}'|" "$MISP_INSTALLER_LOCAL"

# ===============================
# EJECUTAR INSTALADOR OFICIAL
# ===============================
echo "[+] Ejecutando instalación oficial de MISP (esto puede tardar 15-30 minutos)..."
if ! bash "$MISP_INSTALLER_LOCAL"; then
    echo "[✖] La instalación de MISP falló."
    echo "    Revisa $LOG_FILE y /var/log/misp_install.log para más detalle."
    exit 1
fi

echo "[✔] Instalador oficial de MISP finalizado."

# ===============================
# GUARDAR CREDENCIALES ACCESIBLES AL USUARIO LOCAL
# ===============================
if [[ -f "$MISP_SETTINGS_FILE" ]]; then
    cp "$MISP_SETTINGS_FILE" "$LOG_DIR/misp-settings.txt"
    chmod 600 "$LOG_DIR/misp-settings.txt"
fi

# =========================
# MOSTRAR DATOS DE ACCESO
# =========================
echo "-----------------------------------------------"
echo "Acceso a MISP:"
echo "  URL      : https://$MISP_DOMAIN"

if [[ -f "$MISP_SETTINGS_FILE" ]]; then
    ADMIN_USER=$(grep -m1 '^- Admin Username:' "$MISP_SETTINGS_FILE" | awk -F': ' '{print $2}')
    ADMIN_PASS=$(grep -m1 '^- Admin Password:' "$MISP_SETTINGS_FILE" | awk -F': ' '{print $2}')
    echo "  Usuario  : ${ADMIN_USER:-admin@admin.test}"
    echo "  Password : ${ADMIN_PASS:-(ver $MISP_SETTINGS_FILE)}"
else
    echo "  Password : (No encontrada automáticamente, revisa $MISP_SETTINGS_FILE)"
fi

echo "-----------------------------------------------"
echo "[i] El certificado SSL es autofirmado: el navegador mostrará un aviso de seguridad, es esperado."
echo "[i] Credenciales completas (DB, GPG, supervisor) en: $MISP_SETTINGS_FILE"
echo "[✔] Instalación de MISP completada."

# ===== Ajustar permisos =====
echo "[+] Ajustando permisos para el usuario local..."
chown -R "$LOCAL_USER:$LOCAL_USER" "$LOG_DIR" 2>/dev/null || true

# ===== Tiempo total =====
SCRIPT_END=$(date +%s)
echo "[⏱] Tiempo TOTAL de instalación: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "===================================================="
echo "Log completo disponible en: $LOG_FILE"
echo "===================================================="
