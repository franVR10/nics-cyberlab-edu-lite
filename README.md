# NICS | CyberLab Lite — Guía de uso (versión low resources)
![Fondos_INCIBE](https://github.com/nicslabdev/nics-cyberlab-edu-lite/raw/main/logo_fondos_incibe.png)
This repository is part of the Programa Global de Innovación en Seguridad for the promotion of Cátedras de Ciberseguridad en España, funded by the European Union NextGeneration-EU Funds, through the Instituto Nacional de Ciberseguridad (INCIBE).

### Mini SOC en local con 3 a 5 VMs (Snort + Wazuh + MITRE Caldera + MISP + OpenPLC)

Este repositorio contiene la versión **Lite / Low Resources** de **NICS | CyberLab**, un entorno de laboratorio **manual y ligero** pensado para usuarios con **recursos limitados** que quieran reproducir en **local** el laboratorio completo: **Level-01 (Mini SOC**, 3 VMs), ampliable con **Level-02 (Cyber Threat Intelligence con MISP**, +1 VM) y **Level-03 (seguridad OT/ICS con OpenPLC**, +1 VM).

El objetivo didáctico se mantiene: entrenar un flujo realista de un SOC:

**detección → investigación → mejora → reporte**

> ⚠️ **Aviso:** todo lo incluido está pensado para un **entorno de laboratorio autorizado y controlado**. No reutilice técnicas o automatizaciones fuera del contexto permitido.

---

## Relación con la versión automatizada

Esta versión **Lite** está diseñada como alternativa para equipos con menos recursos o para quien prefiera entender el laboratorio **pieza a pieza**.

* **Versión automatizada (OpenStack + despliegue integral):** referencia completa del proyecto principal
  → *(repositorio principal con instalación automatizada, niveles y logs integrados)*

* **Versión Lite (este repo):** despliegue **local** en **3 a 5 VMs** según el nivel, con pasos más manuales, pensado para:

  * aprender la arquitectura
  * reducir dependencia de OpenStack
  * ejecutar los ejercicios de Level-01, Level-02 y Level-03 con infraestructura mínima

Los **ejercicios de `lab/README.md`** están disponibles también en esta versión Lite y se pueden ejecutar en local.

> ℹ️ **Estado actual del repo Lite:** incluye scripts por componente (Snort, Wazuh, MITRE Caldera, MISP, OpenPLC), scripts de automatización de integración (`automation/`) y un script de preparación (`prep-lab.sh`) para facilitar la ejecución de los ejercicios.

---

## Índice

* [1. Qué ofrece este repositorio](#1-qué-ofrece-este-repositorio)
* [2. Requisitos mínimos y recomendados](#2-requisitos-mínimos-y-recomendados)
* [3. Arquitectura (3 a 5 VMs, según nivel)](#3-arquitectura-3-a-5-vms-según-nivel)
* [4. Preparación rápida de VMs en VMware (manual, por encima)](#4-preparación-rápida-de-vms-en-vmware-manual-por-encima)
* [5. Flujo recomendado (Quickstart)](#5-flujo-recomendado-quickstart)
* [6. Logs y evidencias](#6-logs-y-evidencias)
* [7. Estructura real del proyecto](#7-estructura-real-del-proyecto)
* [8. Ejercicios y niveles](#8-ejercicios-y-niveles)
* [9. Buenas prácticas](#9-buenas-prácticas)
* [10. Troubleshooting rápido](#10-troubleshooting-rápido)

---

## 1. Qué ofrece este repositorio

Este repositorio le permite:

1. Montar un **Mini SOC** en local con **3 VMs** (Level-01):

   * **Snort** como IDS (detección de tráfico)
   * **Wazuh** como SIEM/XDR (ingesta, correlación e investigación)
   * **MITRE Caldera** como Adversary Emulation (generación de actividad controlada)

2. Ampliarlo con **inteligencia de amenazas** (Level-02, VM adicional `misp-server`):

   * **MISP** como plataforma de Cyber Threat Intelligence (CTI): eventos, IOCs, feeds, y enriquecimiento automático de alertas de Wazuh.

3. Ampliarlo con **seguridad OT/ICS** (Level-03, VM adicional `plc-server`):

   * **OpenPLC** como PLC simulado (Modbus/TCP), con detección de red, correlación IT-OT, respuesta activa y detección de artefactos más allá de la IP.

4. Ejecutar los **ejercicios del laboratorio** (documentados en `lab/README.md`) para entrenar:

   * detecciones (Snort)
   * ingesta/correlación (Wazuh)
   * simulación ofensiva controlada (Caldera)
   * inteligencia de amenazas (MISP)
   * seguridad de sistemas de control industrial (OpenPLC)
   * metodología SOC y evidencias

5. Desplegarlo en equipos de recursos escasos, evitando OpenStack.

> ⚠️ **Importante:** la filosofía de esta versión Lite es que el usuario haga **solo lo mínimo manual**:
>
> * crear las VMs (3 para Level-01; 4 si se añade Level-02; 5 si se añade Level-03)
> * ejecutar los scripts de instalación en cada VM
> * ejecutar la integración en el orden correcto
> * preparar el entorno del lab y lanzar ejercicios

---

## 2. Requisitos mínimos y recomendados

Esta versión está pensada para funcionar en un host modesto. Los requisitos de host de esta sección son **acumulativos**: si solo va a montar Level-01, use la columna "Solo Level-01"; si añade Level-02 y/o Level-03, sume las VMs correspondientes de la tabla siguiente.

### Host (máquina física)

|        Recurso | Solo Level-01 (3 VMs) | + Level-02 (4 VMs) | + Level-03 (5 VMs) |          Recomendado (5 VMs) |
| -------------: | --------------------: | ------------------: | ------------------: | --------------------: |
|            CPU |                4 vCPU |               6 vCPU |               7 vCPU |               12 vCPU |
|            RAM |                 12 GB |                17 GB |                19 GB |                 32 GB |
|          Disco |            120 GB SSD |          160 GB SSD |          180 GB SSD |           300+ GB SSD |
| Virtualización | VT-x/AMD-V habilitada | VT-x/AMD-V habilitada | VT-x/AMD-V habilitada | VT-x/AMD-V habilitada |

### VMs del laboratorio (mismo hardware que el escenario base)

> **Importante:** mantenga la configuración de hardware como la del escenario original. Las specs de cada VM coinciden con las de `lab/README.md` (sección "Visión general de los escenarios").

| VM                 | Rol                          | Nivel     | CPU |     RAM | Disco | S.O |
| ------------------ | ----------------------------- | --------- | --: | ------: | ----: | -----: |
| **snort-server**   | IDS                           | Level-01  |   1 |    2 GB | 20 GB | Debian 12 |
| **wazuh-manager**  | SIEM/XDR                      | Level-01  |   2 |    4 GB | 40 GB | Debian 12 |
| **caldera-server** | Adversary Emulation           | Level-01  |   1 |    2 GB | 20 GB | Debian 12 |
| **misp-server**    | CTI (Threat Intelligence)     | Level-02  |   2 | 4-6 GB | 50 GB | Debian 12 |
| **plc-server**     | PLC simulado (OT/ICS)         | Level-03  |   1 |    2 GB | 20 GB | Debian 12 |

### Red

* Modo **NAT** en VMware (recomendado para simplicidad).
* Las VMs deben tener **comunicación entre ellas** (misma red NAT de VMware).
* Acceso a Internet para instalar paquetes.

---

## 3. Arquitectura (3 a 5 VMs, según nivel)

**Topología básica Level-01 (local):**

* **caldera-server** → genera actividad (nmap/hydra/comandos) contra **snort-server**
* **snort-server** → detecta tráfico (Snort) y genera logs (`alert_fast`)
* **wazuh-manager** → recibe eventos del agente en snort-server y permite investigar en dashboard

**Flujo SOC entrenado (Level-01):**

1. Atacante (Caldera) ejecuta acciones
2. Snort detecta actividad de red
3. Wazuh ingesta y correlaciona
4. Analista investiga, documenta, mejora reglas y reporte

**Ampliación Level-02 (+ `misp-server`):**

* **wazuh-manager** ↔ **misp-server**: enriquecimiento bidireccional. Wazuh consulta a MISP la reputación de IPs de sus alertas (reactivo), y MISP exporta reglas a **snort-server** (proactivo).
* No se instala ningún agente Wazuh en `misp-server`: se consulta por su API REST, igual que un analista real consultaría una plataforma de CTI externa.

**Ampliación Level-03 (+ `plc-server`):**

* **caldera-server** (vía el agente ya desplegado en `snort-server`) → ataca **plc-server** (Modbus/TCP y HTTP), reutilizando el mismo actor con antecedentes de Level-01/Level-02: el laboratorio modela un ataque transversal IT→OT, no un escenario OT aislado.
* **snort-server** detecta tanto el tráfico Modbus como la reprogramación HTTP del PLC (inspectores nativos).
* **wazuh-manager** ↔ **plc-server**: sin agente Wazuh (decisión deliberada, ver `lab/README.md`). El único acceso es un salto SSH puntual para verificación de artefactos (Ejercicio 3.5).
* No se instala ningún agente Wazuh en `plc-server`, igual que en `misp-server`: la monitorización OT es pasiva, por diseño.

---

## 4. Preparación rápida de VMs en VMware (manual, por encima)

> Esta sección es intencionalmente breve: es lo único que el usuario debe hacer “a mano” antes de usar el repo.

### 4.1) Crear las VMs (plantilla rápida)

En VMware (Workstation/Player):

1. **Create a New Virtual Machine**
2. Seleccione ISO (Debian 12)
3. Configure **CPU/RAM/DISCO** según tabla [sección 2](#vms-del-laboratorio-mismo-hardware-que-el-escenario-base)
4. Red: seleccione **NAT**
5. Marque la opción de instalar **SSH** durante la instalación.
6. Finalice instalación del SO
7. Repita para las VMs de los niveles que vaya a montar:

   * `snort-server`, `wazuh-manager`, `caldera-server` (Level-01, siempre)
   * `misp-server` (si añade Level-02)
   * `plc-server` (si añade Level-03)

### 4.2) Ajustes recomendados en cada VM

En cada VM:

* Instale OpenSSH Server:

  ```bash
  sudo apt update && sudo apt install -y openssh-server
  sudo systemctl enable --now ssh
  ```

* Compruebe IP:

  ```bash
  ip a
  ```

* (Opcional) añada entradas en `/etc/hosts` para nombres:

  ```bash
  sudo nano /etc/hosts
  # Ejemplo:
  # 10.0.XXX.XXX snort-server
  # 10.0.XXX.XXX wazuh-manager
  # 10.0.XXX.XXX caldera-server
  ```

### 4.3) Verificar conectividad entre VMs

Desde cada VM (ejemplo desde `caldera-server`):

```bash
ping -c 2 <IP_SNORT>
ping -c 2 <IP_WAZUH>
```

Si hay ping, la comunicación base está lista.

---

## 5. Flujo recomendado (Quickstart)

> [✓] **Orden recomendado:**
>
> **1) Crear VMs → 2) Instalar herramientas → 3) Generar claves → 4) Integrar → 5) Preparar lab → 6) Ejecutar ejercicios**

### 5.1) Clonar el repositorio

Puede clonar el repo en su host (o en una VM de administración) y después copiarlo a cada VM, o clonarlo directamente en cada una.

```bash
git clone https://github.com/franVR10/nics-cyberlab-edu-lite.git
cd nics-cyberlab-edu-lite
```

---

### 5.2) Paso 1 — Crear y preparar las VMs

Antes de ejecutar scripts del repo:

* Cree `snort-server`, `wazuh-manager` y `caldera-server` (siempre)
* Cree además `misp-server` si va a montar Level-02, y/o `plc-server` si va a montar Level-03
* Verifique red NAT y conectividad entre ellas
* Asegure acceso SSH (recomendado)
* Compruebe conectividad a Internet

---

### 5.3) Paso 2 — Instalar cada herramienta **dentro de su VM correspondiente**

La instalación se realiza **por componente**, ejecutando el script de su carpeta en la **VM que le corresponde**.

#### 5.3.1) Wazuh (en `wazuh-manager`) — primero

```bash
chmod +x Wazuh/install-wazuh.sh
sudo bash install-wazuh.sh
```

Verifique:

* servicios levantados
* acceso al dashboard
* credenciales de acceso

#### 5.3.2) Snort (en `snort-server`) — segundo

```bash
chmod +x install-snort.sh
sudo bash install-snort.sh
```

Verifique:

* instalación de Snort 3
* interfaz de red correcta
* generación de logs (ej. `alert_fast`)

#### 5.3.3) MITRE Caldera (en `caldera-server`) — tercero

```bash
chmod +x install-caldera.sh
sudo bash install-caldera.sh
```

Verifique:

* servicio levantado
* acceso web por puerto `8888`
* conectividad desde `snort-server` y desde el host (si aplica)

> ℹ️ **Nota:** Los scripts `uninstall-*.sh` están disponibles en cada carpeta para desinstalación/rollback durante pruebas.

#### 5.3.4) MISP (en `misp-server`) — solo si añade Level-02

```bash
chmod +x MISP/install-misp.sh
sudo bash install-misp.sh
```

Verifique:

* servicio levantado y acceso HTTPS al dashboard (certificado autofirmado, es esperado)
* credenciales de administrador, guardadas por el propio script en `~/misp-logs/misp-settings.txt`

> ℹ️ Level-02 requiere Level-01 ya desplegado e integrado (`wazuh-snort.sh` ejecutado, paso 5.5.1).

#### 5.3.5) OpenPLC (en `plc-server`) — solo si añade Level-03

```bash
chmod +x OpenPLC/install-openplc.sh
sudo bash install-openplc.sh
```

Verifique:

* servicio levantado y acceso web por puerto `8080` (usuario/contraseña por defecto: `openplc`/`openplc`)

> ℹ️ Level-03 requiere Level-01 ya desplegado e integrado, y el inspector Modbus de Snort habilitado (`prep-openplc-snort.sh`, paso 5.5.3). Los Ejercicios 3.0 y 3.1 (visibilidad pasiva y cadena de ataque Modbus) no requieren Level-02, pero a partir del Ejercicio 3.2 (correlación con CTI) sí es necesario tener Level-02 desplegado e integrado (`wazuh-misp.sh` ya ejecutado).

---

### 5.4) Paso 3 — Generación de claves (**obligatorio antes de integrar**)

Antes de ejecutar las integraciones, debe ejecutarse el script de generación de claves en el anfitrion:

```bash
cd nics-cyberlab-edu-lite/automation
sudo chmod +x key-generate.sh
sudo bash key-generate.sh
```

> ⚠️ **Importante:** los scripts de **integración** y de **generación de claves** deben ejecutarse con **`sudo`** desde el anfitrion.

---

### 5.5) Paso 4 — Integración de herramientas (con `sudo`)

Una vez instaladas las 3 herramientas y generadas las claves, ejecute la integración.

#### 5.5.1) Integración Wazuh ↔ Snort

```bash
cd nics-cyberlab-edu-lite/automation
sudo chmod +x wazuh-snort.sh
sudo bash wazuh-snort.sh
```

Objetivo:

* preparar la ingesta/correlación de logs de Snort en Wazuh
* dejar el flujo de eventos operativo para investigación en dashboard

#### 5.5.2) Integración Caldera ↔ Snort

```bash
cd nics-cyberlab-edu-lite/automation
sudo chmod +x caldera-snort.sh
sudo bash caldera-snort.sh
```

Objetivo:

* habilitar la generación de actividad controlada desde Caldera hacia el nodo monitorizado por Snort
* facilitar validaciones y ejercicios del laboratorio

#### 5.5.3) Integración OpenPLC ↔ Snort (solo si añade Level-03)

```bash
cd nics-cyberlab-edu-lite/automation
sudo chmod +x prep-openplc-snort.sh
sudo bash prep-openplc-snort.sh
```

Objetivo:

* habilitar los inspectores nativos de Snort (Modbus y HTTP) necesarios para detectar el tráfico contra `plc-server`

> [✓] **Regla general:**
>
> * **Instaladores por componente** (`MITRE-Caldera/`, `Snort/`, `Wazuh/`, `MISP/`, `OpenPLC/`) → ejecutar en la VM correspondiente
> * **Integración + keys** (`automation/`) → ejecutar con **`sudo`**

---

### 5.6) Paso 5 — Preparar el entorno del laboratorio (`prep-lab.sh`)

Una vez desplegadas e integradas las herramientas, ejecute el script de preparación del lab para dejar el entorno listo para completar los ejercicios de `lab/README.md`.

```bash
cd nics-cyberlab-edu-lite/automation
chmod +x prep-lab.sh
sudo bash prep-lab.sh
```
---

### 5.7) Paso 6 — Ejecutar ejercicios (`lab/README.md`)

Con todo desplegado, integrado y preparado:

1. Abra `lab/README.md`
2. Ejecute los ejercicios propuestos del laboratorio, en orden: Level-01 (Ejercicios 1.1-1.8), Level-02 (2.0-2.7, si desplegó `misp-server`), Level-03 (3.0-3.6, si desplegó `plc-server`)
3. Recoja evidencias de:

   * tráfico/detección (Snort)
   * eventos/correlación (Wazuh)
   * actividad controlada (Caldera)
   * inteligencia de amenazas (MISP, si aplica)
   * proceso industrial simulado (OpenPLC, si aplica)

Ejemplos típicos de validación (según el ejercicio):

* `ping`
* `nmap`
* `hydra`
* habilidades/operaciones de Caldera
* consultas a la API REST de MISP
* lectura/escritura Modbus contra OpenPLC

---

## 6. Logs y evidencias

En versión Lite, **la evidencia se recoge por nodo**, como en un entorno real:

### Snort (`snort-server`)

* Snort en ejecución (ejemplo):

  ```bash
  sudo snort -i ens33 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
  ```

* Alertas:

  ```bash
  sudo tail -f /var/log/snort/alert_fast.txt
  ```

### Wazuh (`wazuh-manager`)

* Eventos e investigación desde Dashboard:

  * Threat Hunting / Events
  * Endpoints Summary

* Logs del manager:

  ```bash
  sudo tail -f /var/ossec/logs/ossec.log
  ```

### Caldera (`caldera-server`)

* Acceso web (por defecto):

  ```text
  http://IP_CALDERA:8888
  ```

* Validar herramientas (si aplican en su versión):

  ```bash
  nmap --version
  hydra -h | head
  ```

### MISP (`misp-server`, Level-02)

* Acceso web (certificado autofirmado, es esperado):

  ```text
  https://IP_MISP
  ```

* Credenciales de administrador y logs de instalación:

  ```bash
  cat ~/misp-logs/misp-settings.txt
  ```

* Log de la integración con Wazuh (una vez desplegada en el Ejercicio 2.4), en `wazuh-manager`:

  ```bash
  sudo tail -f /var/ossec/logs/integrations.log
  ```

### OpenPLC (`plc-server`, Level-03)

* Acceso web (por defecto, usuario/contraseña `openplc`/`openplc`):

  ```text
  http://IP_PLC_SERVER:8080
  ```

* Log del runtime y PID del proceso:

  ```bash
  cat ~/openplc-logs/openplc-server.log
  cat ~/openplc-logs/openplc.pid
  ```

---

## 7. Estructura real del proyecto

La estructura actual del repositorio (por componente + automatización + lab) es:

```text
.
├── MISP/
│   ├── install-misp.sh
│   └── uninstall-misp.sh
├── MITRE-Caldera/
│   ├── install-caldera.sh
│   └── uninstall-caldera.sh
├── OpenPLC/
│   ├── install-openplc.sh
│   ├── uninstall-openplc.sh
│   ├── tanque_control.st
│   └── tanque_sabotaje.st
├── Snort/
│   ├── install-snort.sh
│   └── uninstall-snort.sh
├── Wazuh/
│   ├── install-wazuh.sh
│   └── uninstall-wazuh.sh
├── automation/
│   ├── caldera-snort.sh
│   ├── key-generate.sh
│   ├── prep-lab.sh
│   ├── prep-openplc-snort.sh
│   ├── wazuh-misp.sh
│   ├── wazuh-misp-hash.sh
│   └── wazuh-snort.sh
├── lab/
│   └── README.md
└── README.md
```

> ℹ️ `automation/` también genera, en tiempo de uso, la clave privada/pública del laboratorio (`mykey`, `mykey.pub`) y sus ficheros `known_hosts_*` — son material local/sensible de cada despliegue, no forman parte de la estructura fija del repositorio.

### Descripción de carpetas

* **`MISP/`**

  * Scripts de instalación/desinstalación de MISP (Level-02).

* **`MITRE-Caldera/`**

  * Scripts de instalación/desinstalación de MITRE Caldera.

* **`OpenPLC/`**

  * Scripts de instalación/desinstalación de OpenPLC (Level-03).
  * Programas de ejemplo en IEC 61131-3 usados en los ejercicios: `tanque_control.st` (legítimo) y `tanque_sabotaje.st` (usado por Caldera en el Ejercicio 3.4).

* **`Snort/`**

  * Scripts de instalación/desinstalación de Snort.

* **`Wazuh/`**

  * Scripts de instalación/desinstalación de Wazuh.

* **`automation/`**

  * Scripts de integración entre herramientas: `wazuh-snort.sh`, `caldera-snort.sh` (infraestructura, Level-01), `prep-openplc-snort.sh` (infraestructura, Level-03).
  * `wazuh-misp.sh` y `wazuh-misp-hash.sh`: integraciones con MISP que se despliegan como parte de los Ejercicios 2.4 y 3.5 respectivamente, no como preparación previa (ver sección 5.5).
  * Script de generación de claves (`key-generate.sh`).
  * Script de preparación del entorno del lab (`prep-lab.sh`).

* **`lab/README.md`**

  * Ejercicios y metodología SOC para ejecutar el laboratorio en local.

> ⚠️ **Recuerde:** siempre `key-generate.sh` y los scripts de integración (`wazuh-snort.sh`, `caldera-snort.sh`, `prep-openplc-snort.sh`) deben ejecutarse con **`sudo`**.

---

## 8. Ejercicios y niveles

Los ejercicios están descritos en:

📌 **`lab/README.md`**

Esta versión Lite permite ejecutar en local, con menos recursos, los tres niveles del laboratorio, manteniendo la metodología didáctica:

* **Level-01** (Ejercicios 1.1-1.8): Mini SOC — detección, investigación, mejora, documentación/reporte.
* **Level-02** (Ejercicios 2.0-2.7): Cyber Threat Intelligence con MISP — enriquecimiento de alertas, feeds, correlación IT.
* **Level-03** (Ejercicios 3.0-3.6): seguridad OT/ICS con OpenPLC — correlación IT-OT, respuesta activa, detección de artefactos y TTPs, playbook de respuesta a incidentes.

Level-01 es la base obligatoria del laboratorio: ni Level-02 ni Level-03 son niveles autónomos, ambos se despliegan sobre Level-01 ya integrado (Level-02, en concreto, lo necesita desde el Ejercicio 2.4). Entre sí, Level-02 y Level-03 son independientes solo hasta cierto punto: puede añadir Level-02 sin Level-03, y Level-03 funciona sin Level-02 únicamente para sus dos primeros ejercicios (3.0-3.1); a partir del Ejercicio 3.2, Level-03 pasa a necesitar Level-02 ya desplegado e integrado, así que completar el itinerario de Level-03 exige desplegar también Level-02.

> ℹ️ **Nota:** **Diferencia principal respecto al repo automatizado:** cambia el **método de despliegue** (manual/semi-automatizado), pero **los ejercicios y el enfoque SOC siguen siendo aplicables**.

---

## 9. Buenas prácticas

* Use **snapshots** de VMware antes de cambios grandes.
* Mantenga nombres coherentes:

  * `snort-server`
  * `wazuh-manager`
  * `caldera-server`
  * `misp-server` (Level-02)
  * `plc-server` (Level-03)

* Documente evidencias con:

  * timestamp
  * nodo implicado
  * comando ejecutado
  * log/alerta/evento correlacionado

* Use la misma **NAT network** en todas las VMs desplegadas.

* Revise permisos de ejecución:

  * `chmod +x` en scripts
  * `sudo` en scripts de integración/keys

---

## 10. Troubleshooting rápido

### 10.1 No hay conectividad entre VMs

* Compruebe que están en **NAT** y en la misma red NAT.
* Revise IPs:

  ```bash
  ip a
  ```
* Pruebe ping:

  ```bash
  ping -c 2 <IP_OTRA_VM>
  ```

---

### 10.2 Caldera no abre en 8888

* Compruebe servicio y puerto:

  ```bash
  ss -tulpn | grep 8888
  ```
* Pruebe desde `snort-server`:

  ```bash
  curl -I http://IP_CALDERA:8888
  ```

---

### 10.3 Wazuh no recibe logs de Snort

* Verifique que Snort escribe en:

  ```text
  /var/log/snort/alert_fast.txt
  ```

* Verifique la configuración del agente (`localfile`) en:

  ```text
  /var/ossec/etc/ossec.conf
  ```

* Reinicie el agente:

  ```bash
  sudo systemctl restart wazuh-agent
  ```

---

### 10.4 Errores al ejecutar scripts de `automation/`

Síntomas comunes:

* `Permission denied`
* cambios parciales
* comandos que requieren privilegios

Comprobación rápida:

```bash
cd nics-cyberlab-edu-lite/automation
ls -l
```

---

### 10.5 MISP no responde, o `install-misp.sh` falla (Level-02)

* MISP usa certificado **autofirmado**: un aviso de certificado no confiable en el navegador es esperado, no un error.
* Compruebe el servicio y el log de instalación:

  ```bash
  cat ~/misp-logs/misp-install.log
  ```
* Si la integración con Wazuh (Ejercicio 2.4) no encuentra coincidencias, confirme primero que el evento en MISP está **`Published`** y el atributo marcado **IDS**, antes de sospechar del script.

---

### 10.6 OpenPLC no arranca, o el puerto 8080/502 no responde (Level-03)

* Compruebe el proceso y el log:

  ```bash
  cat ~/openplc-logs/openplc-server.log
  sudo ss -ltnp | grep -E ':(8080|502)'
  ```
* Si el puerto aparece ocupado por un proceso viejo que no responde (`Address already in use` en el log), localice el PID real con `ss` (no confíe solo en el fichero `.pid`, puede estar desactualizado) y mátelo antes de relanzar.
* Sin un programa **compilado y arrancado** (`Start PLC` en la interfaz web), OpenPLC no abre el puerto Modbus (502) aunque la opción esté activada — no es un fallo de red.

---

###### © NICS LAB — NICS | CyberLab Lite

*Proyecto experimental para entornos de laboratorio y formación en ciberseguridad.*

