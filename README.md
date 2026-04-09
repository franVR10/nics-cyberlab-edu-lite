# NICS | CyberLab Lite — Guía de uso (versión low resources)
![Fondos_INCIBE](https://github.com/nicslabdev/nics-cyberlab-edu-lite/raw/main/logo_fondos_incibe.png)
This repository is part of the Programa Global de Innovación en Seguridad for the promotion of Cátedras de Ciberseguridad en España, funded by the European Union NextGeneration-EU Funds, through the Instituto Nacional de Ciberseguridad (INCIBE).

### Mini SOC en local con 3 VMs (Snort + Wazuh + MITRE Caldera)

Este repositorio contiene la versión **Lite / Low Resources** de **NICS | CyberLab**, un entorno de laboratorio **manual y ligero** pensado para usuarios con **recursos limitados** que quieran reproducir el escenario **Level-01 (Mini SOC)** en **local**, utilizando **3 máquinas virtuales**.

El objetivo didáctico se mantiene: entrenar un flujo realista de un SOC:

**detección → investigación → mejora → reporte**

> ⚠️ **Aviso:** todo lo incluido está pensado para un **entorno de laboratorio autorizado y controlado**. No reutilice técnicas o automatizaciones fuera del contexto permitido.

---

## Relación con la versión automatizada

Esta versión **Lite** está diseñada como alternativa para equipos con menos recursos o para quien prefiera entender el laboratorio **pieza a pieza**.

* **Versión automatizada (OpenStack + despliegue integral):** referencia completa del proyecto principal
  → *(repositorio principal con instalación automatizada, niveles y logs integrados)*

* **Versión Lite (este repo):** despliegue **local** en **3 VMs**, con pasos más manuales, pensado para:

  * aprender la arquitectura
  * reducir dependencia de OpenStack
  * ejecutar ejercicios del Level-01 con infraestructura mínima

Los **ejercicios de `lab/README.md`** están disponibles también en esta versión Lite y se pueden ejecutar en local.

> ℹ️ **Estado actual del repo Lite:** incluye scripts por componente (Snort, Wazuh, MITRE Caldera), scripts de automatización de integración (`automation/`) y un script de preparación (`prep-lab.sh`) para facilitar la ejecución de los ejercicios.

---

## Índice

* [1. Qué ofrece este repositorio](#1-qué-ofrece-este-repositorio)
* [2. Requisitos mínimos y recomendados](#2-requisitos-mínimos-y-recomendados)
* [3. Arquitectura (3 VMs)](#3-arquitectura-3-vms)
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

1. Montar un **Mini SOC** en local con **3 VMs**:

   * **Snort** como IDS (detección de tráfico)
   * **Wazuh** como SIEM/XDR (ingesta, correlación e investigación)
   * **MITRE Caldera** como Adversary Emulation (generación de actividad controlada)

2. Ejecutar los **ejercicios del laboratorio** (documentados en `lab/README.md`) para entrenar:

   * detecciones (Snort)
   * ingesta/correlación (Wazuh)
   * simulación ofensiva controlada (Caldera)
   * metodología SOC y evidencias

3. Desplegarlo en equipos de recursos escasos, evitando OpenStack.

> ⚠️ **Importante:** la filosofía de esta versión Lite es que el usuario haga **solo lo mínimo manual**:
>
> * crear las 3 VMs
> * ejecutar los scripts de instalación en cada VM
> * ejecutar la integración en el orden correcto
> * preparar el entorno del lab y lanzar ejercicios

---

## 2. Requisitos mínimos y recomendados

Esta versión está pensada para funcionar en un host modesto, pero con recursos suficientes para 3 VMs simultáneas.

### Host (máquina física)

|        Recurso |      Mínimo funcional |           Recomendado |
| -------------: | --------------------: | --------------------: |
|            CPU |                4 vCPU |                8 vCPU |
|            RAM |                 12 GB |              16–24 GB |
|          Disco |            120 GB SSD |           200+ GB SSD |
| Virtualización | VT-x/AMD-V habilitada | VT-x/AMD-V habilitada |

### VMs del laboratorio (mismo hardware que el escenario base)

> **Importante:** mantenga la configuración de hardware como la del escenario original.

| VM                 | Rol                 | CPU |  RAM | Disco | S.O |
| ------------------ | ------------------- | --: | ---: | ----: | -----: |
| **snort-server**   | IDS                 |   1 | 2 GB | 20 GB | Debian 12 |
| **wazuh-manager**  | SIEM/XDR            |   2 | 4 GB | 40 GB | Debian 12 |
| **caldera-server** | Adversary Emulation |   1 | 2 GB | 20 GB | Debian 12 |

### Red

* Modo **NAT** en VMware (recomendado para simplicidad).
* Las VMs deben tener **comunicación entre ellas** (misma red NAT de VMware).
* Acceso a Internet para instalar paquetes.

---

## 3. Arquitectura (3 VMs)

**Topología básica (local):**

* **caldera-server** → genera actividad (nmap/hydra/comandos) contra **snort-server**
* **snort-server** → detecta tráfico (Snort) y genera logs (`alert_fast`)
* **wazuh-manager** → recibe eventos del agente en snort-server y permite investigar en dashboard

**Flujo SOC entrenado:**

1. Atacante (Caldera) ejecuta acciones
2. Snort detecta actividad de red
3. Wazuh ingesta y correlaciona
4. Analista investiga, documenta, mejora reglas y reporte

---

## 4. Preparación rápida de VMs en VMware (manual, por encima)

> Esta sección es intencionalmente breve: es lo único que el usuario debe hacer “a mano” antes de usar el repo.

### 4.1) Crear 3 VMs (plantilla rápida)

En VMware (Workstation/Player):

1. **Create a New Virtual Machine**
2. Seleccione ISO (Debian 12)
3. Configure **CPU/RAM/DISCO** según tabla [sección 2](#vms-del-laboratorio-mismo-hardware-que-el-escenario-base)
4. Red: seleccione **NAT**
5. Marque la opción de instalar **SSH** durante la instalación.
6. Finalice instalación del SO
7. Repita para las 3 VMs:

   * `snort-server`
   * `wazuh-manager`
   * `caldera-server`

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
git clone https://github.com/crismillan06/nics-cyberlab-lite.git
cd nics-cyberlab-lite
```

---

### 5.2) Paso 1 — Crear y preparar las 3 VMs

Antes de ejecutar scripts del repo:

* Cree `snort-server`, `wazuh-manager` y `caldera-server`
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

---

### 5.4) Paso 3 — Generación de claves (**obligatorio antes de integrar**)

Antes de ejecutar las integraciones, debe ejecutarse el script de generación de claves en el anfitrion:

```bash
cd nics-cyberlab-lite/automation
sudo chmod +x key-generate.sh
sudo bash key-generate.sh
```

> ⚠️ **Importante:** los scripts de **integración** y de **generación de claves** deben ejecutarse con **`sudo`** desde el anfitrion.

---

### 5.5) Paso 4 — Integración de herramientas (con `sudo`)

Una vez instaladas las 3 herramientas y generadas las claves, ejecute la integración.

#### 5.5.1) Integración Wazuh ↔ Snort

```bash
cd nics-cyberlab-lite/automation
sudo chmod +x wazuh-snort.sh
sudo bash wazuh-snort.sh
```

Objetivo:

* preparar la ingesta/correlación de logs de Snort en Wazuh
* dejar el flujo de eventos operativo para investigación en dashboard

#### 5.5.2) Integración Caldera ↔ Snort

```bash
cd nics-cyberlab-lite/automation
sudo chmod +x caldera-snort.sh
sudo bash caldera-snort.sh
```

Objetivo:

* habilitar la generación de actividad controlada desde Caldera hacia el nodo monitorizado por Snort
* facilitar validaciones y ejercicios del laboratorio

> [✓] **Regla general:**
>
> * **Instaladores por componente** (`MITRE-Caldera/`, `Snort/`, `Wazuh/`) → ejecutar en la VM correspondiente
> * **Integración + keys** (`automation/`) → ejecutar con **`sudo`**

---

### 5.6) Paso 5 — Preparar el entorno del laboratorio (`prep-lab.sh`)

Una vez desplegadas e integradas las herramientas, ejecute el script de preparación del lab para dejar el entorno listo para completar los ejercicios de `lab/README.md`.

```bash
cd nics-cyberlab-lite/automation
chmod +x prep-lab.sh
sudo bash prep-lab.sh
```

> ℹ️ **Nota:** si `prep-lab.sh` realiza cambios del sistema (paquetes, permisos, servicios, rutas, etc.), ejecútelo con `sudo`:

---

### 5.7) Paso 6 — Ejecutar ejercicios (`lab/README.md`)

Con todo desplegado, integrado y preparado:

1. Abra `lab/README.md`
2. Ejecute los ejercicios propuestos del laboratorio (Level-01 en local)
3. Recoja evidencias de:

   * tráfico/detección (Snort)
   * eventos/correlación (Wazuh)
   * actividad controlada (Caldera)

Ejemplos típicos de validación (según el ejercicio):

* `ping`
* `nmap`
* `hydra`
* habilidades/operaciones de Caldera

---

## 6. Logs y evidencias

En versión Lite, **la evidencia se recoge por nodo**, como en un entorno real:

### Snort (`snort-server`)

* Snort en ejecución (ejemplo):

  ```bash
  sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
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

---

## 7. Estructura real del proyecto

La estructura actual del repositorio (por componente + automatización + lab) es:

```text
.
├── MITRE-Caldera/
│   ├── install-caldera.sh
│   └── uninstall-caldera.sh
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
│   └── wazuh-snort.sh
├── lab/
│   └── README.md
└── README.md
```

### Descripción de carpetas

* **`MITRE-Caldera/`**

  * Scripts de instalación/desinstalación de MITRE Caldera.

* **`Snort/`**

  * Scripts de instalación/desinstalación de Snort.

* **`Wazuh/`**

  * Scripts de instalación/desinstalación de Wazuh.

* **`automation/`**

  * Scripts de integración entre herramientas.
  * Script de generación de claves.
  * Script de preparación del entorno del lab (`prep-lab.sh`).

* **`lab/README.md`**

  * Ejercicios y metodología SOC para ejecutar el laboratorio en local.

> ⚠️ **Recuerde:** siempre `key-generate.sh` y los scripts de integración (`wazuh-snort.sh`, `caldera-snort.sh`) deben ejecutarse con **`sudo`**.

---

## 8. Ejercicios y niveles

Los ejercicios están descritos en:

📌 **`lab/README.md`**

Esta versión Lite permite ejecutar el flujo del **Level-01** en local con menos recursos, manteniendo la metodología didáctica:

* detección
* investigación
* mejora
* documentación/reporte

> ℹ️ **Nota:** **Diferencia principal respecto al repo automatizado:** cambia el **método de despliegue** (manual/semi-automatizado), pero **los ejercicios y el enfoque SOC siguen siendo aplicables**.

---

## 9. Buenas prácticas

* Use **snapshots** de VMware antes de cambios grandes.
* Mantenga nombres coherentes:

  * `snort-server`
  * `wazuh-manager`
  * `caldera-server`

* Documente evidencias con:

  * timestamp
  * nodo implicado
  * comando ejecutado
  * log/alerta/evento correlacionado

* Use la misma **NAT network** en las 3 VMs.

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
cd nics-cyberlab-lite/automation
ls -l
```


---

###### © NICS LAB — NICS | CyberLab Lite

*Proyecto experimental para entornos de laboratorio y formación en ciberseguridad.*

