# 🧪 Laboratorio Práctico con Diferentes Niveles — NICS | CyberLab

> **Aviso de uso responsable:** todo lo descrito está orientado a un **entorno de laboratorio autorizado y controlado**. No reutilice procedimientos fuera de un contexto permitido.

## Índice
- [Introducción](#introducción)
- [Visión general de los escenarios](#visión-general-de-los-escenarios)
  - [Level-01 – Mini SOC: detección y monitorización](#level-01--mini-soc-detección-y-monitorización)
  - [Level-02 – MISP: Cyber Threat Intelligence](#level-02--misp-cyber-threat-intelligence)
- [Normas generales del laboratorio](#normas-generales-del-laboratorio)
- [Metodología de trabajo y evidencias](#metodología-de-trabajo-y-evidencias)
- [Logs y verificaciones](#logs-y-verificaciones)
---
- [Ejercicio 1.1 — Snort: detección de tráfico ICMP](#ejercicio-11--snort-detección-de-tráfico-icmp)
- [Ejercicio 1.2 — Wazuh: agentes, integración de logs y dashboard](#ejercicio-12--wazuh-agentes-integración-de-logs-y-dashboard)
- [Ejercicio 1.3 — MITRE Caldera: ataque básico y detección en Wazuh](#ejercicio-13--mitre-caldera-ataque-básico-y-detección-en-wazuh)
- [Ejercicio 1.4 — Simulación Mini SOC: escaneo de reconocimiento con Nmap](#ejercicio-14--simulación-mini-soc-escaneo-de-reconocimiento-con-nmap)
- [Ejercicio 1.5 — Reglas personalizadas en Snort y Wazuh](#ejercicio-15--reglas-personalizadas-en-snort-y-wazuh)
- [Ejercicio 1.6 — Ataque de fuerza bruta contra servicio SSH](#ejercicio-16--ataque-de-fuerza-bruta-contra-servicio-ssh)
- [Ejercicio 1.7 — Diseño e implementación de estrategia defensiva ante ataques a SSH](#ejercicio-17--diseño-e-implementación-de-estrategia-defensiva-ante-ataques-a-ssh)
- [Ejercicio 1.8 — Creación de un KPI operativo basado en un ataque real](#ejercicio-18--creación-de-un-kpi-operativo-basado-en-un-ataque-real)
- [Investigación Opcional — MITRE Caldera (profundización teórico-práctica)](#investigación-opcional--mitre-caldera-profundización-teórico-práctica)
- [Ejercicio 2.0 — MISP: creación de un usuario y organización con mínimo privilegio](#ejercicio-20--misp-creación-de-un-usuario-y-organización-con-mínimo-privilegio)
- [Ejercicio 2.1 — MISP: creación manual de un evento e IOCs](#ejercicio-21--misp-creación-manual-de-un-evento-e-iocs)
- [Ejercicio 2.2 — MISP: consumo de un feed público de threat intelligence](#ejercicio-22--misp-consumo-de-un-feed-público-de-threat-intelligence)
- [Ejercicio 2.3 — MISP: consultas a la API REST con curl](#ejercicio-23--misp-consultas-a-la-api-rest-con-curl)
- [Ejercicio 2.4 — MISP: integración automática con Wazuh](#ejercicio-24--misp-integración-automática-con-wazuh)
- [Ejercicio 2.5 — MISP: exportación de reglas Snort (NIDS)](#ejercicio-25--misp-exportación-de-reglas-snort-nids)
- [Investigación Opcional — MISP → Snort: automatización de IoCs e IDPS](#investigación-opcional--misp--snort-automatización-de-iocs-e-idps)

---

## Introducción

Este documento recoge los **escenarios prácticos y ejercicios** asociados a los distintos niveles del laboratorio **NICS | CyberLab**. El objetivo es guiar prácticas **realistas, progresivas y alineadas con el trabajo de un SOC**, combinando simulación ofensiva controlada y capacidades defensivas (detección, correlación y mejora).

Cada nivel parte de un despliegue automatizado y refuerza el ciclo operativo:

**detección → investigación → mejora → reporte**

## Visión general de los escenarios

El laboratorio se estructura en **niveles progresivos**, donde cada nivel amplía o profundiza en los conceptos del anterior.

### Level-01 – Mini SOC: detección y monitorización

Nivel orientado a la **aclimatación y familiarización** con herramientas y tareas básicas de un **SOC**, mediante un entorno **controlado** desplegado en OpenStack. El foco del Level-01 no es “hacer de pentester”, sino **aprender el flujo operacional**: generar actividad → observar telemetría → investigar → documentar.

#### **Nodos principales**

* **Nodo víctima (IDS):** Snort _v.3.10.2.0_
  * S.O: Debian 12
  * Configuración de recursos _(mínimo requerido)_:
    * 1CPU
    * 2GB de RAM
    * 20GB de Disco

* **Nodo monitor (SIEM/XDR):** Wazuh _v.4.9.2_ (Manager + Dashboard)
  * S.O: Debian 12 
  * Configuración de recursos _(mínimo requerido)_:
    * 2CPU
    * 4GB de RAM
    * 40GB de Disco

* **Nodo atacante (Adversary Emulation):** MITRE Caldera _v.5.3.0-52_
  * S.O: Debian 12 
  * Configuración de recursos _(mínimo requerido)_:
    * 1CPU
    * 2GB de RAM
    * 20GB de Disco

**Flujo operativo (qué se entrena)**

1. **Generación de actividad** (tráfico y acciones controladas).
2. **Detección primaria** (alertas IDS / logs).
3. **Ingesta y correlación** en SIEM/XDR (eventos centralizados).
4. **Investigación rápida** (búsqueda, filtros, timeline).
5. **Evidencias + conclusión** (qué pasó, por qué importa, cómo se mejora).

**Qué aprende el alumnado (competencias)**

* Detectar tráfico y actividad sospechosa en un entorno realista.
* Localizar y analizar **logs**, eventos y alertas.
* Correlacionar eventos (relación **origen → acción → evidencia → alerta**).
* Documentar evidencias con criterio (capturas, timestamps, agente, regla, severidad).

#### Expliación del escenario

Este Level-01 se apoya en un “mini SOC” con ruta simple, pero suficiente para entender el ciclo completo.

**Nodos / componentes**

* **Atacante (emulación controlada):** genera acciones representativas (p. ej. comandos remotos, reconocimiento, pruebas de conectividad).
* **Víctima (telemetría + IDS):** inspecciona tráfico y genera alertas (IDS) + eventos de sistema.
* **Monitor (SIEM/XDR):** centraliza, normaliza y permite investigar (dashboards, hunting, eventos).

**Flujo didáctico**

1. **Provoca actividad** desde el nodo atacante (tráfico y/o ejecución controlada).
2. **Comprueba** si Snort genera alertas (visibilidad inmediata en logs).
3. **Integra y valida** que Wazuh recibe esa telemetría (agente activo + eventos).
4. **Investiga** en Wazuh (Threat Hunting / Events) filtrando por agente y rango temporal.
5. **Entrega evidencias** (capturas de alertas/eventos + detalle de regla y severidad) y redacta **conclusión técnica**.

#### Nota importante (alcance y recursos)

El Level-01 está diseñado para ser **simple y consistente**: prioriza que el alumnado domine el flujo end-to-end antes de añadir complejidad. Aun así, el mismo esquema permite crecer en dificultad según recursos disponibles (más fuentes de logs, más reglas, más escenarios, más volumen de eventos), sin cambiar la base del laboratorio.

---

### Level-02 – MISP: Cyber Threat Intelligence

Nivel que **amplía** el Mini SOC del Level-01 añadiendo una plataforma de **Cyber Threat Intelligence (CTI)**: MISP. El foco pasa de "detectar y correlacionar" a **detectar y enriquecer con contexto**: no basta con saber que hubo tráfico sospechoso, sino entender si ese origen está ya fichado como amenaza conocida.

#### Nodo adicional

* **Nodo CTI (Threat Intelligence):** MISP _v2.5_
  * S.O: Debian 12
  * Configuración de recursos _(mínimo requerido)_:
    * 2 CPU
    * 4-6 GB de RAM
    * 50 GB de Disco

> **Requisito:** las 3 VMs del Level-01 (`snort-server`, `wazuh-manager`, `caldera-server`) deben estar desplegadas e integradas (`wazuh-snort.sh` ya ejecutado) antes de empezar este nivel, más esta 4ª VM `misp-server`.

**Flujo operativo (qué se entrena)**

1. **Generación de inteligencia** propia (evento manual) y externa (feed) en MISP.
2. **Consulta programática** de esa inteligencia (API REST autenticada).
3. **Enriquecimiento automático** de alertas de Wazuh con contexto de MISP.
4. **Investigación ampliada**: pasar de "hubo un ataque" a "es una IP con antecedentes conocidos".

**Qué aprende el alumnado (competencias)**

* Aplicar el principio de **mínimo privilegio** (cuentas y roles limitados) en una plataforma de seguridad, en vez de operar siempre como administrador.
* Modelar inteligencia de amenazas (eventos, atributos, flag IDS, TLP/distribución).
* Diferenciar inteligencia propia frente a inteligencia de fuentes externas (feeds).
* Consultar una API REST de seguridad con autenticación por clave.
* Entender cómo un SIEM puede automatizar el enriquecimiento de alertas con CTI, y qué valor aporta eso al triage de un SOC.

#### Nota importante (alcance y recursos)

En el Ejercicio 2.2, el feed de threat intelligence que se active debe ser **pequeño y curado**: la VM `misp-server` está dimensionada para un laboratorio educativo (50 GB de disco), no para ingerir feeds masivos de producción.

---

## Normas generales del laboratorio

Estas normas aplican a **todos los niveles** del laboratorio **NICS | CyberLab** y se han redactado para que tengan sentido directo en los ejercicios (simulación ofensiva controlada + defensa/SOC), alineando prácticas con **ENS (España)**, **NIS2 (UE)** y **RGPD (UE)**.

### 1) Alcance, autorización y uso aceptable (NICS | CyberLab)

* **Uso exclusivamente educativo** y **solo dentro del entorno autorizado** (proyecto OpenStack/laboratorio asignado).
* Queda **prohibido** ejecutar técnicas, herramientas o tráfico ofensivo **fuera del laboratorio** (infraestructura externa, redes corporativas, terceros, etc.).
* La actividad “red” (Caldera/Nmap/Hydra/…) se considera **simulación controlada**: se limita a lo necesario para generar telemetría y evidencias SOC (sin objetivos “de impacto”).
* **Reglas de Engagement (RoE) de laboratorio**:

  * sin DoS/estrés deliberado,
  * sin persistencia innecesaria,
  * sin exfiltración de datos,
  * sin escaneo masivo fuera del rango/objetivo indicado,
  * sin reutilizar credenciales fuera del entorno.

### 2) Principios operativos tipo ENS (seguridad por diseño en el LAB)

En los ejercicios se trabaja bajo un enfoque de **gestión de riesgos** y ciclo **prevención → detección → respuesta → recuperación**, con trazabilidad y control del cambio. ([Boletín Oficial del Estado](https://www.boe.es/buscar/act.php?id=BOE-A-2022-7191))

Aplicación práctica en el LAB:

* **Mínimo privilegio**: usar cuentas/roles justos para cada tarea (y documentar cuándo/por qué se eleva).
* **Trazabilidad**: todo cambio relevante (reglas Snort/Wazuh, parsers, configuración) debe quedar reflejado en evidencias.
* **Reversibilidad**: si se activa una regla o ajuste, se registra el *antes/después* y cómo se revierte.

### 3) Gestión de incidentes y notificación (NIS2)

[NIS2](https://www.nis-2-directive.com/) introduce disciplina de **notificación por fases**. En el laboratorio **no se notifica a autoridades**, pero **se entrena el formato** como entregable:

* **Aviso temprano (early warning)**,
* **Notificación de incidente**,
* **Informe final** (y, si procede, **intermedios/progreso**).

Regla didáctica (para que encaje con los ejercicios):

* Si un ejercicio genera una “ruta coherente” (p. ej. Recon → Acceso → Post-Access), el alumnado redacta:

  1. **Early warning** (qué ha pasado + impacto potencial + si parece malicioso),
  2. **Notificación** (IOCs, severidad, alcance, medidas iniciales),
  3. **Informe final** (timeline, causa probable, contención/mitigación, lecciones aprendidas).

### 4) Protección de datos y tratamiento de evidencias (RGPD)

En el LAB, por defecto:

* **No se usan datos personales reales**. Si por diseño del ejercicio aparece información potencialmente personal (usuarios, IPs asociables, logs con identificadores), se aplica **minimización** en el entregable (capturas, informes).
* Las evidencias se almacenan en ubicación controlada (repositorio/carpeta del curso) y con acceso restringido a quienes “necesitan saber” (principio de **confidencialidad**).

**Brechas de datos (en modo formación):** si un escenario simula exposición/compromiso de datos, el alumnado debe elaborar un **borrador de notificación** (qué datos, alcance, medidas), entrenando la lógica de RGPD (notificación “sin dilación indebida” y, cuando aplique, en el marco temporal establecido).

---

## Metodología de trabajo y evidencias

Para **cada ejercicio**, se entrega obligatoriamente:

### Evidencias técnicas

* **Capturas de terminal** (comandos + salida).
* **Logs relevantes** (Snort, Wazuh, sistema, Caldera tasks/output).
* **Capturas de dashboard** cuando aplique (filtros visibles).

Cada evidencia debe permitir reconstruir:

* **Nodo implicado** (hostname/agent.name).
* **Herramienta/acción** (comando, ability, rule.id).
* **Momento del ejercicio** (timestamp o rango temporal del dashboard).

### Conclusión técnica

Al final de cada ejercicio, incluir:

* **Acción realizada** (qué se ejecutó y dónde).
* **Eventos generados/detectados** (qué reglas saltaron, severidad, correlación).
* **Valor operativo SOC** (triage, hipótesis, respuesta, hardening/mejora propuesta).

---

## Logs y verificaciones

### Consultas recomendadas

Observe siempre los **logs personalizados** generados por los scripts de instalación en cada una de las **VMs**, además de los **logs de ejecución** de cada herramienta.

> ℹ️ **Importante:** los scripts usan `SUDO_USER`, por lo que los logs de instalación se guardan en el **HOME del usuario que lanzó el script con `sudo`** (por ejemplo: `/home/usuario/...`), no en `/root`.


### 1) Wazuh (`wazuh-manager`)

#### Log personalizado de instalación (generado por el script)

```bash
cat ~/wazuh-logs/wazuh-install.log
```

#### Ver log en tiempo real (recomendado durante instalación)

```bash
tail -f ~/wazuh-logs/wazuh-install.log
```

#### Log operativo de Wazuh Manager (servicio)

```bash
sudo tail -f /var/ossec/logs/ossec.log
```

#### Comprobaciones útiles (servicio/puertos)

```bash
sudo systemctl status wazuh-manager --no-pager
sudo ss -tulpn | grep -E '1514|1515|55000|443'
```

### 2) Snort (`snort-server`)

#### Log personalizado de instalación (generado por el script)

```bash
cat ~/snort-logs/snort-install.log
```

#### Ver log en tiempo real (recomendado durante instalación/compilación)

```bash
tail -f ~/snort-logs/snort-install.log
```

#### Log de alertas de Snort (runtime)

```bash
tail -f /var/log/snort/alert_fast.txt
```

#### Consultar alertas ya registradas

```bash
cat /var/log/snort/alert_fast.txt
```

#### Comprobaciones útiles

```bash
snort -V
ip link show
ls -l /var/log/snort/
```

> ℹ️ **Nota:** recuerde que `alert_fast.txt` se rellena cuando Snort está ejecutándose y capturando tráfico con una regla que dispare alertas.

### 3) MITRE Caldera (`caldera-server`)

#### Log personalizado de instalación (generado por el script)

```bash
cat ~/caldera-logs/caldera-install.log
```

#### Ver log en tiempo real (recomendado durante instalación)

```bash
tail -f ~/caldera-logs/caldera-install.log
```

#### Log del servidor Caldera (ejecución en segundo plano)

```bash
tail -f ~/caldera-logs/caldera-server.log
```

#### Consultar PID guardado por el script

```bash
cat ~/caldera-logs/caldera.pid
```

#### Comprobaciones útiles (proceso/puerto)

```bash
ps -ef | grep -i caldera | grep -v grep
ss -tulpn | grep 8888
curl -I http://127.0.0.1:8888
```

### 4) Consulta rápida de errores (todas las VMs)

Para revisar rápidamente errores comunes en los logs de instalación:

```bash
grep -Ei "error|fail|failed|exception|traceback" ~/wazuh-logs/wazuh-install.log
grep -Ei "error|fail|failed|exception|traceback" ~/snort-logs/snort-install.log
grep -Ei "error|fail|failed|exception|traceback" ~/caldera-logs/caldera-install.log
```

> ℹ️ **Nota:** Ejecute solo el comando correspondiente a la VM en la que se encuentre.

### 5) Recomendación de uso durante el despliegue

Mientras ejecuta cada instalador, mantenga otra terminal abierta con:

```bash
tail -f ~/nombre-carpeta-logs/*.log
```

Ejemplos:

```bash
tail -f ~/wazuh-logs/wazuh-install.log
tail -f ~/snort-logs/snort-install.log
tail -f ~/caldera-logs/caldera-install.log
```

---

## Ejercicio 1.1 — Snort: detección de tráfico ICMP 

### Objetivo

Verificar detección de tráfico **ICMP (ping)** y generación de alertas en formato rápido (`alert_fast`) en tiempo real.

### Prerrequisitos

* Acceso SSH al **nodo víctima (Snort)**.
* IP de la interfaz de red del nodo Snort (receptora del ping).
* Host con conectividad para ejecutar el ping (nodo atacante o cliente externo).

### Preparación e identificación (Nodo Snort)

Identificación de interfaz e IP 

En el **nodo Snort**, ejecute:

```bash
ip a
```

* Identifique la interfaz conectada a la red del laboratorio (por ejemplo, `ens3`).
* Anote la IP asignada (por ejemplo, `10.0.0.X`).

> A partir de aquí se asume `ens3`. Sustituya la interfaz si corresponde.

---

### Ejecución

> Este ejercicio se realiza con **tres terminales** (dos en Snort y una en el atacante/cliente).

#### Terminal 1 (Nodo Snort) — Arranque de Snort capturando tráfico

Inicie Snort en modo captura usando:

* interfaz `ens3`
* configuración `/etc/snort/snort.lua`
* salida rápida `alert_fast`
* logs en `/var/log/snort`

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

**Observación esperada**

* Arranque sin errores.
* Proceso en ejecución (no devuelve prompt).

**Si falla**

* Verifique interfaz, permisos y ruta de configuración.

#### Terminal 2 (Nodo Snort) — Monitorización de alertas en tiempo real

En otra sesión SSH al mismo nodo, monitorice:

```bash
sudo tail -f /var/log/snort/alert_fast.txt
```

**Observación esperada**

* Espera de nuevas líneas.
* Aparición de entradas cuando exista coincidencia de reglas.

> Si el fichero no existe, valide el arranque de Snort y la ruta de logs (`-l /var/log/snort`).

#### Terminal 3 (Cliente externo o Nodo atacante) — Generación de ICMP (ping)

Ejecute:

```bash
ping -c 4 <IP_tarjeta_snort>
```

Ejemplo:

```bash
ping -c 4 10.0.0.25
```

**Resultado esperado**

* Aparición de alertas ICMP en `alert_fast.txt`.

**Criterio de éxito**

* Snort capturando en Terminal 1.
* Alertas visibles en Terminal 2 al ejecutar ping en Terminal 3.

---

### Validación / Troubleshooting (si no aparece alerta)

1. Confirmar llegada de ICMP a la interfaz:

```bash
sudo tcpdump -ni ens3 icmp
```

2. Confirmar escritura de logs:

```bash
ls -lah /var/log/snort/
```

3. Confirmar reglas ICMP habilitadas según set de reglas instalado.

### Evidencias a entregar

Capture pantalla o copie salida de:

* Snort en ejecución (Terminal 1)
* alertas en `alert_fast.txt` (Terminal 2)
* salida del ping (Terminal 3)

### Conclusión final

Incluya:

* Acción realizada (ping + captura IDS)
* Evidencia generada (alerta en `alert_fast`)
* Valor SOC (detección inicial + base de integración con SIEM)

---

## Ejercicio 1.2 — Wazuh: agentes, integración de logs y dashboard

### Objetivo

1. Ubicar y utilizar módulos clave del **Dashboard de Wazuh** (agentes, hunting, eventos).
2. Desplegar un **agente** desde la GUI del Manager.
3. Configurar el **Wazuh Agent** (nodo Snort) para ingerir logs de Snort (`alert_fast.txt`).
4. Verificar en el Dashboard la llegada de eventos y documentar evidencias.

### Prerrequisitos

> La IP/URL y credenciales del Dashboard se obtienen del despliegue (por ejemplo, `log/level.log`).

* Acceso al **Dashboard de Wazuh** (nodo monitor).
* Acceso SSH al **nodo Snort**.
* IP/hostname del **Wazuh Manager** alcanzable desde el nodo Snort.
* IP del nodo Snort para generar ICMP en la validación.

---

### 1.2.1. Preparación e identificación (Dashboard)

#### Identificación de Endpoints Summary

1. Acceda al Dashboard e inicie sesión.
2. Navegue a: **☰ → Server management → Endpoints Summary**
3. Observe el listado de agentes.

**Evidencie**

* Capture la vista **Endpoints Summary**.

#### Identificación de Threat Hunting

Ubique: **☰ → Threat Intelligence → Threat Hunting**

No ejecute búsquedas todavía; únicamente localice el módulo.

**Evidencie**

* Capture la pantalla de **Threat Hunting**.

### 1.2.2. Ejecución

#### Inicio del asistente de despliegue (Dashboard / Wazuh Manager)

1. Acceda a **☰ → Server management → Endpoints Summary**
2. Pulse **+ Deploy new agent**

**Evidencie**

* Capture el inicio del **asistente guiado** de despliegue (“Deploy new agent”).

#### Completar el asistente y obtener comandos (Dashboard / especificación)

Complete el asistente. Habitualmente se solicitará:

1. **Sistema operativo del endpoint**

   * Seleccione Linux (si el nodo Snort es Linux).

2. **Dirección del Manager**

   * Indique IP/hostname del Wazuh Manager **alcanzable desde el nodo Snort**.

3. **Nombre del agente**

   * Defina un nombre consistente (por ejemplo, `snort-server`).

4. **Grupo (opcional)**

   * Asigne un grupo (por ejemplo, `soc-lab` o `snort-endpoints`).

5. **Bloque de comandos**

   * Obtenga los comandos generados para:

     * instalar `wazuh-agent` (repositorio + paquete)
     * configurar variables básicas (Manager/Nombre)
     * registrar/enrolar el agente
     * iniciar y habilitar el servicio

> **Nota operativa:** la forma exacta del comando varía por versión (instalación por repositorio, script, o enrolamiento). Ejecute exactamente lo generado por el Dashboard.

**Evidencie**

* Capture la pantalla donde se visualicen los **comandos generados**.

#### Ejecución de comandos del asistente (Nodo Snort)

Conéctese por SSH al **nodo Snort** y ejecute el bloque de comandos generado por el Dashboard.

**Evidencie**

* Capture la salida que muestre instalación/registro sin errores.

#### Verificación del estado del servicio (Nodo Snort)

```bash
sudo systemctl status wazuh-agent
```

Si no está activo:

```bash
sudo systemctl enable --now wazuh-agent
sudo systemctl status wazuh-agent
```

**Evidencie**

* Capture `status` mostrando **active (running)**.

#### Verificación del agente en el Dashboard

Regrese al Dashboard:

* **☰ → Server management → Endpoints Summary**
* Localice el agente por nombre y valide:

  * estado **Active/Connected**
  * “last keep alive” reciente

**Evidencie**

* Capture el agente en estado **Active**.

### 1.2.3. Integración de Snort (Nodo Snort)

#### Configuración de ingesta en el agente: lectura de `alert_fast.txt`

> Este apartado puede estar **ya realizado** en el entorno. Proceda así:
>
> * Si ya existe el bloque `localfile`, **visualice y evidencie** la configuración.
> * Si no existe, **genere uno nuevo** para el agente creado.

Edite la configuración:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Localice la sección:

```xml
<!-- Log analysis -->
```

Añada o verifique:

```xml
<!-- Log analysis -->
  <localfile>
    <log_format>snort-fast</log_format>
    <location>/var/log/snort/alert_fast.txt</location>
  </localfile>
```

**Evidencie**

* Capture el fragmento de `ossec.conf` donde se visualice `<localfile>`.


#### Reinicio del agente (Nodo Snort)

```bash
sudo systemctl restart wazuh-agent && sudo systemctl status wazuh-agent
```

**Evidencie**

* Capture el `status` tras el reinicio (servicio activo).

### 1.2.4. Validación end-to-end (Snort → Wazuh)

#### Generación de eventos en Snort (Nodo Snort)

Arranque Snort:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

#### Visualización de logs de Snort en vivo (Nodo Snort)

En otra terminal:

```bash
sudo tail -f /var/log/snort/alert_fast.txt
```

**Evidencie**

* Capture el `tail -f` mostrando entradas nuevas.

#### Generación de ICMP desde un cliente (externo o nodo atacante)

```bash
ping -c 4 <IP_tarjeta_snort>
```

**Evidencie**

* Capture la salida del `ping`.

### 1.2.5. Visualización en Wazuh (Eventos y Threat Hunting)

#### Acceso a Threat Hunting y selección del agente

En el Dashboard:

1. Acceda a **☰ → Threat Intelligence → Threat Hunting**
2. Seleccione el agente `snort-server` (o el nombre definido)
3. Ajuste el rango temporal a **Last 15 minutes** (amplíe si hubo pausas)

**Evidencie**

* Capture **Threat Hunting** con agente seleccionado y rango temporal visible.

#### Ruta de “Events” y validación alternativa

Según versión, los eventos también se consultan desde:

* **☰ → Threat Intelligence → Threat Hunting → Events**

**Evidencie**

* Capture la vista **Events/Discover** con eventos listados y rango temporal visible.

#### Filtrado de eventos relacionados con Snort

En Threat Hunting o Events/Discover, aplique filtros típicos:

* palabra clave: `snort`
* fragmentos del mensaje del log
* filtro por agente/host (cuando exista selector)

**Evidencie**

* Capture la lista de eventos evidenciando que corresponden a Snort.

#### Revisión del detalle de un evento

Abra un evento y revise:

* timestamp
* agente/host
* mensaje/payload
* campos relevantes (si se muestran)

**Evidencie**

* Capture el detalle del evento.

---

### Limpieza (recomendable)

#### Eliminación del agente

> Realice esta limpieza especialmente si se repetirán despliegues o si se requiere dejar el entorno estable.

En el nodo Wazuh a través del terminal:

```bash
sudo /var/ossec/bin/manage_agents
```

Acciones típicas:

* listar agentes
* seleccionar agente a eliminar
* confirmar eliminación

**Evidencie**

* Capture la pantalla donde se observe la eliminación.

### Conclusión final

Redacte una conclusión técnica:

* Integración realizada (agente registrado y activo).
* Log integrado (`/var/log/snort/alert_fast.txt`) y mecanismo de ingesta (`localfile` con `snort-fast`).
* Validación end-to-end (alerta Snort generada por ping y evento visible en Wazuh).
* Utilidad SOC (detección, trazabilidad, triage y base para casos de uso/reglas).

---

## Ejercicio 1.3 — MITRE Caldera: ataque básico y detección en Wazuh

### Objetivo

Ejecutar una **operación básica de ataque** desde **MITRE Caldera** contra el nodo víctima y verificar si la actividad generada es **detectada y registrada en Wazuh**.

El ejercicio permite comprender el flujo:

> **ataque (Caldera) → ejecución en víctima → telemetría → detección (Wazuh)**

### Prerrequisitos

> Las IPs y credenciales pueden consultarse en: `cat log/level.log`

* Acceso al **Dashboard de MITRE Caldera** (nodo atacante).
* Acceso al **Dashboard de Wazuh** (nodo monitor).
* Agente de Caldera **activo** en el nodo víctima (Snort).
* Agente de Wazuh **instalado y operativo** en el nodo Snort.

---

### 1.3.1. Preparación e identificación (Caldera + Wazuh)

#### Acceso al Dashboard de MITRE Caldera

Desde un navegador, acceda a:

```
http://IP_CALDERA:8888
```

Autentíquese con las credenciales del laboratorio.

**Observación esperada**

* Acceso correcto al Dashboard.
* Visualización del menú lateral (Agents, Operations, Adversaries, etc.).

#### Verificación del agente en Caldera

En el Dashboard de Caldera:

1. Acceda a **Agents**.
2. Identifique el agente correspondiente al **nodo víctima (Snort)**.

**Observación esperada**

* Agente visible.
* Estado **Alive** (activo).

> Si el agente no está activo, **no continúe** con el ejercicio.

**Evidencie**

* Capture el listado de **Agents** donde se vea el agente del nodo Snort en estado **Alive**.

### 1.3.2. Ejecución (Caldera)

#### Creación de la operación básica

Acceda a **Operations** y seleccione **New Operation**.

Configure la operación con los siguientes parámetros:

* **Name:** `XXxx-ataque-basico`
* **Group:** `red`
* **Adversary:** `Worm`
* **Planner:** `atomic`
* **Run State:** `Run`

Inicie la operación.

**Observación esperada**

* Operación creada correctamente.
* Estado: en ejecución.

**Evidencie**

* Capture la operación creada (pantalla de **Operations** mostrando el nombre y el estado).

#### Ejecución de comandos desde la operación

Ejecute las siguientes acciones desde la operación creada:

1. **Comando básico de ejecución (MITRE T1059):**

```bash
whoami
```

2. **Comando con impacto en logs (simulación de escalada):**

```bash
sudo su
```

**Resultado esperado**

* Ambos comandos se ejecutan con estado `SUCCESS`.
* La salida es visible desde Caldera.

> El segundo comando está diseñado para **generar telemetría clara**.

**Evidencie**

* Capture la vista de **tasks/abilities** donde se vean los comandos ejecutados con estado **SUCCESS** y su salida.

### 1.3.3. Validación end-to-end (Caldera → Wazuh)

#### Búsqueda de eventos en Wazuh (Threat Hunting / Events)

Acceda al **Dashboard de Wazuh**:

```
https://IP_WAZUH_DASHBOARD
```

Vaya a:

* **☰ → Threat Intelligence → Threat Hunting → Events** (según versión)

Filtre los eventos por:

* `agent.name` → nodo Snort (por ejemplo, `snort-server`)
* Rango temporal → últimos **10–15 minutos** (amplíe si hubo pausas)

**Observación esperada**

* Eventos relacionados con:

  * uso de `sudo`
  * ejecución de comandos / elevación de privilegios
  * cambios de usuario / contexto (según telemetría disponible)

**Evidencie**

* Capture la lista de eventos filtrada por el agente Snort y el rango temporal visible.

#### Correlación ataque → detección (validación mínima)

Identifique al menos una alerta/evento y documente:

* **Regla** que ha generado la alerta (`rule.id` y `rule.description`).
* **Nivel de severidad** (`rule.level`).
* **Timestamp** (`timestamp`) del evento/alerta.
* Asociación correcta al host:

  * `agent.name = snort-server` (o el nombre definido)

**Criterio de éxito**

* La actividad ejecutada desde Caldera es visible en Wazuh.
* Los eventos están correctamente asociados al nodo Snort.

**Evidencie**

* Capture el detalle del evento donde se vean `rule.id`, `rule.level`, `timestamp` y `agent.name`.

---

### Validación / Troubleshooting (si no aparece evento en Wazuh)

En el nodo Snort:

```bash
sudo systemctl status wazuh-agent
sudo tail -f /var/ossec/logs/ossec.log
```

Revise también:

* que el agente seleccionado en Wazuh es el correcto (`agent.name`)
* que el rango temporal en el Dashboard incluye el momento del ataque

### Evidencias a entregar

Documente o capture:

* Agente activo en Caldera (Alive).
* Operación creada y en ejecución.
* Comandos ejecutados (tasks en `SUCCESS` con salida visible).
* Eventos correspondientes en Wazuh (misma ventana temporal), mostrando:

  * `rule.id`, `rule.level`, `timestamp`, `agent.name`.

### Conclusión final

Incluya:

* Qué se ejecutó desde Caldera y sobre qué nodo.
* Qué telemetría se generó y cómo se observó en Wazuh.
* Qué regla(s) se activaron (`rule.id`, `rule.level`) y por qué.
* Valor SOC: trazabilidad ataque→evento, base para detecciones y casos de uso.

---

## Ejercicio 1.4 — Simulación Mini SOC: escaneo de reconocimiento con Nmap

### Objetivo

Simular un **ataque de reconocimiento** mediante **Nmap (SYN scan)** ejecutado desde **MITRE Caldera** contra el nodo víctima (Snort) y analizar:

1. La **ausencia de detección** cuando las reglas están desactivadas.
2. La **detección correcta** tras activar reglas en **Snort y Wazuh**.

El ejercicio ilustra el flujo completo de un **Mini-SOC**:

> **reconocimiento (Caldera) → ejecución → logs → correlación → alerta (Wazuh)**

### Prerrequisitos

> Las IPs y credenciales pueden consultarse en: `cat log/level.log`

* Acceso al **nodo atacante** (Caldera).
* Acceso al **Dashboard de Wazuh** (nodo monitor).
* Agente de Wazuh **operativo** en el nodo Snort.
* IP del nodo Snort (objetivo del escaneo).

**¡IMPORTANTE!**
Lance en el nodo Snort siempre:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```
> ⚠️ Recuerde que siempre que quiera capturar tráfico tendrá que arrancar Snort con el comando previo.

---

### 1.4.1. Preparación e identificación (estado inicial)

#### Verificación de Snort en ejecución (Nodo Snort)

Antes de iniciar el ejercicio, asegúrese de que Snort está capturando tráfico:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

**Observación esperada**

* Snort arranca sin errores y queda en ejecución.

> Si Snort no está corriendo, el ejercicio podría dar un “falso negativo” (no detección por falta de captura).

### 1.4.2. Ejecución (reconocimiento SIN detección)

#### Ejecución del escaneo Nmap (desde Caldera)

Desde el terminal del nodo Caldera, ejecute una habilidad de **Command Execution (T1059)** mediante el comando:

```bash
nmap -sS -Pn <IP_NODO_SNORT>
```

### 1.4.3. Análisis en Wazuh (sin reglas activas)

Acceda al **Dashboard de Wazuh**.

1. Vaya a **Threat Intelligence → Threat Hunting → Events**.
2. Filtre por:

   * `agent.name` → nodo Snort
   * Rango temporal → últimos 10 minutos

**Resultado esperado**

* [✖] No aparecen alertas de escaneo
* [✖] No existe correlación de Nmap

El SOC **no detecta el reconocimiento**.

> ⚠️ Asegúrese de que el fallo de la detección no haya sido causado por no tener Snort arrancado.

Si es necesario, vuelva a lanzarlo:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

### 1.4.4. Activación de reglas de detección (Snort + Wazuh)

#### Activar regla en Snort (Nodo Snort)

Primeramente pare Snort si está arrancado monitoreando ya sea, y posteriormente realice los siguientes pasos.

En el nodo Snort:

```bash
sudo nano /etc/snort/rules/local.rules
```

Descomente:

```bash
alert tcp any any -> any any (
    msg:"Posible TCP SYN scan detectado";
    flags:S;
    flow:stateless;
    detection_filter:track by_src, count 5, seconds 20;
    sid:1000011;
    rev:3;
)
```

> Esta regla se descomenta para habilitar explícitamente la detección de escaneos SYN en Snort.

Compruebe su funcionamiento mediante un test:

```bash
# El fichero de configuración de Snort ha cambiado en la versión 3 a snort.lua
sudo snort -T -c /etc/snort/snort.lua
```

Lance de nuevo Snort:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

#### Activar regla en Wazuh (Nodo Wazuh Manager)

En el nodo Wazuh Manager:

```bash
sudo nano /var/ossec/etc/rules/snort_local_rules.xml
```

Descomente el grupo y la regla:

```xml
#<group name="local,snort,network,scan">

  <!-- ICMP Echo Request -->
  <rule id="600001" level="5">
    <match>ICMP Echo Request detectado</match>
    <description>Snort - ICMP Echo Request detected</description>
  </rule>

  #<!-- TCP SYN Scan -->
  #<rule id="600010" level="8">
    #<match>Posible TCP SYN scan detectado</match>
    #<description>Snort - TCP SYN scan activity detected</description>
  #</rule>

  </rule>
#</group>
```

Reinicie Wazuh:

```bash
sudo systemctl restart wazuh-manager
```

### 1.4.5. Reejecución del reconocimiento (CON detección)

Desde Caldera, ejecute **el mismo comando**:

```bash
nmap -sS -Pn <IP_NODO_SNORT>
```

### 1.4.6. Análisis de detección en Wazuh (detección esperada)

En el Dashboard de Wazuh:

* Filtre por el agente Snort.
* Observe eventos relacionados con:

  * **Nmap TCP SYN scan**
  * Severidad elevada (level 8)

**Resultado esperado**

* [✔] Alerta visible
* [✔] Regla aplicada correctamente
* [✔] Reconocimiento detectado

---

### Validación / Troubleshooting (si no aparece detección)

1. Verifique que Snort está corriendo y escribiendo alertas:

```bash
sudo tail -f /var/log/snort/alert_fast.txt
```

2. Verifique que la regla de Snort se cargó correctamente:

```bash
sudo snort -T -c /etc/snort/snort.lua
```

3. Verifique reinicio y estado del manager:

```bash
sudo systemctl status wazuh-manager
```

4. Amplíe el rango temporal en Wazuh (**Last 1 hour**) si hubo pausas.

### Evidencias a entregar

Documente o capture:

* Snort arrancado en el nodo Snort (comando y ejecución).
* Ejecución del primer `nmap -sS -Pn` desde Caldera.
* Vista en Wazuh mostrando **ausencia de detección** (sin reglas activas).
* Fragmento de `/etc/snort/rules/local.rules` con la regla descomentada.
* Ejecución de `sudo snort -T -c /etc/snort/snort.lua` (test correcto).
* Fragmento de `/var/ossec/etc/rules/snort_local_rules.xml` con la regla activada.
* Reinicio de `wazuh-manager`.
* Ejecución del segundo `nmap -sS -Pn` desde Caldera.
* Vista en Wazuh mostrando la **detección** (regla/level asociado).

### Conclusión final

Incluya:

* Qué se ejecutó (reconocimiento con Nmap) y desde dónde.
* Diferencia observada **antes vs después** de activar reglas.
* Qué regla(s) permitieron la detección (Snort + Wazuh) y severidad asociada.
* Valor SOC: importancia de casos de uso/reglas, tuning y validación continua.

---

## Ejercicio 1.5 — Reglas personalizadas en Snort y Wazuh

### Objetivo

Diseñar y probar **reglas personalizadas** en Snort y Wazuh para mejorar la detección de tráfico sospechoso y reducir falsos positivos.

El ejercicio permite comprender el flujo completo de un Mini-SOC:

**tráfico sospechoso controlado (Caldera) → ejecución en víctima (Snort) → telemetría → detección y correlación (Wazuh)**

Se busca que el alumnado:

* Ajuste firmas en Snort (ICMP, TCP SYN, Port Knocking).
* Cree reglas personalizadas en Wazuh para correlación de eventos.
* Evalúe la efectividad de la detección y el impacto en falsos positivos.

### Prerrequisitos

> Las IPs y credenciales pueden consultarse en: `cat log/level.log`

* Acceso al nodo atacante (Caldera / terminal).
* Acceso al Dashboard de Wazuh (nodo monitor).
* Agente de Wazuh operativo en el nodo Snort.
* IP del nodo Snort (objetivo del tráfico).
* Snort corriendo para capturar tráfico:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

---

### 1.5.1. Preparación e identificación (estado inicial)

#### Captura activa en Snort (Nodo Snort)

Asegúrese de que Snort está capturando tráfico antes de ejecutar las pruebas:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

> ⚠️ Si Snort no está corriendo, habrá “falsos negativos” (no detección por falta de captura).

#### Preparación del atacante para Port Knocking (`hping3`)

En el nodo atacante, instale `hping3` si no está disponible:

```bash
sudo apt update
sudo apt install -y hping3
```

> ℹ️ Recomendable: crear un script con los 3 envíos (por ejemplo `h3ping.sh`) y darle permisos `+x`.

### 1.5.2. Ejecución (tráfico CON/SIN detección con reglas actuales)

> En esta fase se busca observar el comportamiento con el set actual de reglas.

#### Prueba ICMP (ping)

```bash
ping -c 4 <IP_NODO_SNORT>
```

#### Prueba TCP SYN (Nmap)

```bash
nmap -sS -Pn <IP_NODO_SNORT>
```

#### Prueba Port Knocking (hping3)

Ejecute de forma consecutiva:

```bash
sudo hping3 -S -p 1001 <IP_NODO_SNORT> -c 1
sudo hping3 -S -p 1002 <IP_NODO_SNORT> -c 1
sudo hping3 -S -p 1003 <IP_NODO_SNORT> -c 1
```

**Observación esperada en Wazuh**

* [✔] Aparecen alertas de ICMP, TCP SYN.
* [✖] No aparecen alertas de Port Knocking.
* [⚠] Asegúrese de que Snort esté corriendo para capturar tráfico.

### 1.5.3. Activación de reglas de detección (Snort + Wazuh)

#### Activar reglas en Snort (Nodo Snort)

En el nodo Snort, edite:

```bash
sudo nano /etc/snort/rules/local.rules
```

Configure (o verifique) las reglas existentes y añada la nueva regla para Port Knocking:

```bash
alert icmp any any -> any any (
    msg:"ICMP Echo Request detectado";
    itype:8;
    detection_filter:track by_src, count 3, seconds 20;
    sid:1000010;
    rev:2;
)

alert tcp any any -> any any (
    msg:"Posible TCP SYN scan detectado";
    flags:S;
    flow:stateless;
    detection_filter:track by_src, count 5, seconds 20;
    sid:1000011;
    rev:3;
)

# Inserte aquí bloque con la nueva regla para Port-Knocking
```

> <details>
> <summary><b>ℹ️ Solución:</b></summary>
> alert tcp any any -> any [1001,1002,1003] ( 
> <br>msg:"Posible port knocking detectado";
> <br>flags:S;
> <br>flow:stateless;
> <br>sid:1000022;
> <br>rev:3;
> <br>)
> </details>

Comprobar configuración:

```bash
sudo snort -T -c /etc/snort/snort.lua
```

Lanzar Snort:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

#### Activar reglas en Wazuh (Nodo Wazuh Manager)

En el nodo Wazuh Manager, edite:

```bash
sudo nano /var/ossec/etc/rules/snort_local_rules.xml
```

Añada la regla nueva de Port Knocking manteniendo las existentes:

```xml
<group name="local,snort,network,scan">

  <rule id="600001" level="5">
    <match>ICMP Echo Request detectado</match>
    <description>Snort - ICMP Echo Request detected</description>
  </rule>

  <rule id="600010" level="8">
    <match>Posible TCP SYN scan detectado</match>
    <description>Snort - TCP SYN scan activity detected</description>
  </rule>

  <!-- Inserte aquí bloque con la nueva regla para Port-Knocking -->

</group>
```

> <details>
> <summary><b>ℹ️ Solución:</b></summary>
>
> ```xml
> <rule id="600020" level="9">
> <br><match>Posible port knocking detectado</match>
> <br><description>Snort - Port knocking attempt detected</description>
> <br></rule>
> ```
>
> </details>

Reiniciar Wazuh:

```bash
sudo systemctl restart wazuh-manager
```

### 1.5.4. Reejecución del tráfico (CON detección)

Desde Caldera/atacante, ejecute de nuevo:

**ICMP**

```bash
ping -c 4 <IP_NODO_SNORT>
```

**TCP SYN (Nmap)**

```bash
nmap -sS -Pn <IP_NODO_SNORT>
```

**Port Knocking**

```bash
sudo hping3 -S -p 1001 <IP_NODO_SNORT> -c 1
sudo hping3 -S -p 1002 <IP_NODO_SNORT> -c 1
sudo hping3 -S -p 1003 <IP_NODO_SNORT> -c 1
```

Visualice los logs de Snort:

```bash
sudo tail -f /var/log/snort/alert_fast.txt
```

### Resultado esperado en Snort

```
[**] [1:1000010:2] "ICMP Echo Request detectado"
[**] [1:1000011:3] "Posible TCP SYN scan detectado"
[**] [1:1000022:3] "Posible port knocking detectado"
```

### 1.5.5. Análisis de detección en Wazuh

En el Dashboard de Wazuh:

* Filtre por **agent.name → nodo Snort**
* Observe eventos relacionados con:

| Evento                    | Severidad Wazuh | Observación                  |
| ------------------------- | --------------- | ---------------------------- |
| ICMP Echo Request         | 5               | Ping detectado               |
| TCP SYN scan              | 8               | Escaneo tipo Nmap detectado  |
| Port Knocking (secuencia) | 9               | Secuencia completa detectada |

**Resultado esperado**

* [✔] Alertas visibles.
* [✔] Reglas aplicadas correctamente.
* [✔] Correlación de port knocking generada correctamente.

#### Interpretación de la severidad en Wazuh (rule.level) + relación con fases tipo INCIBE

En Wazuh, la criticidad que aparece en el Dashboard (campo **`rule.level`**, escala **0–15**) representa una **prioridad operativa** asignada por la regla que coincide con el evento.  
No es una “verdad absoluta”: es una forma de decir **qué mirar primero** en un flujo SOC.

Para que el alumnado no se quede solo con el número, en este LAB se interpreta la severidad junto con una lógica **por fases** (modelo tipo INCIBE): un ataque real rara vez es un único evento; suele ser una **secuencia** (ruta) donde cada fase aumenta el riesgo.

##### 1) Guía por rangos (qué significa en triage)

- **0–2 (Muy bajo / Informativo):**  
  Telemetría útil para contexto. Normalmente no dispara acción, pero sirve para reconstruir líneas temporales.

- **3–4 (Bajo):**  
  Actividad relevante pero frecuente. Suele vigilarse por repetición o por correlación con otros eventos.

- **5–6 (Medio):**  
  Señal potencial de actividad sospechosa. Requiere contexto: origen, frecuencia, ventana temporal y si hay continuidad.

- **7–9 (Alto):**  
  Indicadores claros de actividad anómala asociable a ataque (reconocimiento agresivo, patrones intencionados). Debe investigarse con prioridad.

- **10–12 (Muy alto):**  
  Acciones con impacto o fuerte sospecha de compromiso (persistencia, abuso de credenciales, cambios sensibles). Suele requerir escalado.

- **13–15 (Crítico):**  
  Evidencia fuerte de compromiso/impacto grave. En un entorno real suele activar respuesta inmediata.

> ℹ️ **Importante:** el número guía la prioridad, pero el “peligro real” se determina por **contexto** y por **cadena de eventos**. Un level 5 puede ser grave si encaja en una ruta completa.

##### 2) Cómo se conecta con fases tipo INCIBE (ruta completa del ataque)

En el LAB, el alumnado debe pensar en fases (simplificado):

- **Fase A — Reconocimiento:** el atacante identifica puertos/servicios/superficie.
- **Fase B — Acceso / Credenciales:** intenta conseguir credenciales o acceso inicial.
- **Fase C — Acceso remoto / Entrada:** inicia sesión o establece un punto de apoyo.
- **Fase D — Exploración interna (Discovery/Ejecución):** confirma usuario, permisos, red, sistema.
- **Fase E — Escalada / Acciones posteriores:** intenta elevar permisos o preparar persistencia.

La severidad ayuda a ubicar “dónde estamos”:
- Niveles **medios (5–6)** suelen aparecer en **señales tempranas** (inicio o pruebas).
- Niveles **altos (7–9)** suelen encajar con **fase activa** (recon agresivo, patrones claros).
- Niveles **muy altos/críticos (10+)** suelen acercarse a **compromiso o impacto**.

##### 3) Aplicación al ejercicio (por qué 5, 8 y 9 encajan con fases)

En este ejercicio se observan eventos típicos de fase temprana:

- **ICMP Echo Request (level 5) — Señal temprana / Reconocimiento ligero**  
  Puede ser legítimo (diagnóstico) o parte de reconocimiento.  
  Por eso se queda en un nivel medio: **es señal**, pero no confirma ataque por sí sola.

- **TCP SYN scan (level 8) — Reconocimiento activo (Fase A)**  
  El escaneo SYN es un patrón clásico de enumeración de servicios.  
  Aquí el riesgo sube porque suele ser el paso previo a “elegir objetivo”.

- **Port Knocking (level 9) — Acceso intencionado / Preparación de acceso (Fase B–C según contexto)**  
  Una secuencia de puertos específica es poco frecuente en uso normal.  
  Puede interpretarse como una técnica para habilitar un acceso oculto o preparar entrada, por eso se eleva.

> En este punto del LAB todavía no hay “impacto”, pero ya hay **intencionalidad** clara (sobre todo en SYN scan y knocking).

##### 4) Cómo decidir peligrosidad (mini-guía guiada por fases)

Cuando el alumnado vea una alerta debe completar este guion (rápido):

1. **¿En qué fase encaja este evento?**  
   (reconocimiento / acceso / acceso remoto / discovery / escalada)

2. **¿Qué evidencia lo respalda?**  
   (origen IP, repetición, patrón, secuencia, timestamps)

3. **¿Está aislado o forma parte de una ruta?**  
   - Aislado: puede ser ruido o prueba.
   - Ruta: aumenta criticidad (ej.: ICMP → SYN scan → knocking).

4. **¿Qué haría un atacante después? (hipótesis guiada)**  
   Si estamos en Fase A: buscar credenciales o explotar un servicio.  
   Si estamos en Fase B: intentar login/abuso de credenciales.  
   Si estamos en Fase C: ejecutar comandos de discovery, etc.

##### 5) Regla práctica del LAB (cómo “sube” el riesgo)

- **1 evento medio (5–6)**: vigilar y contextualizar.  
- **2 eventos relacionados en <15 min**: tratar como ruta inicial, investigar con prioridad.  
- **3 eventos encadenados (ICMP + SYN + knocking)**: considerar “ruta coherente de ataque” y documentarla por fases (INCIBE) aunque aún no haya compromiso.

---

### Validación / Troubleshooting

1. Verifique que Snort está corriendo y escribiendo alertas:

```bash
sudo tail -f /var/log/snort/alert_fast.txt
```

2. Verifique que las reglas se cargan correctamente:

```bash
sudo snort -T -c /etc/snort/snort.lua
```

3. Verifique reinicio y estado del manager:

```bash
sudo systemctl status wazuh-manager
```

4. En Wazuh, amplíe el rango temporal (**Last 1 hour**) y revise que filtra por el agente correcto.

### Evidencias a entregar

Documente o capture:

* Snort arrancado en el nodo Snort (comando y ejecución).
* Pruebas iniciales (ICMP, Nmap, hping3) y resultados.
* Fragmento de `/etc/snort/rules/local.rules` con las reglas (incluida Port Knocking).
* Ejecución de `sudo snort -T -c /etc/snort/snort.lua` (test correcto).
* Fragmento de `/var/ossec/etc/rules/snort_local_rules.xml` con la regla añadida.
* Reinicio de `wazuh-manager`.
* `tail -f /var/log/snort/alert_fast.txt` mostrando las alertas esperadas.
* Vista en Wazuh mostrando eventos de ICMP, SYN scan y Port Knocking (con severidad).

### Conclusión final

Incluya:

* Qué tráfico se generó (ICMP, SYN scan, Port Knocking) y desde dónde.
* Diferencia observada antes vs después de activar reglas.
* Qué reglas se añadieron/modificaron (Snort + Wazuh) y qué detectan.
* Valor SOC: tuning de firmas, reducción de ruido, priorización y casos de uso reutilizables.

---

## Ejercicio 1.6 — Ataque de fuerza bruta contra servicio SSH

### Objetivo general

Realizar un ataque de fuerza bruta contra un servicio **SSH** utilizando **Hydra**, con el fin de:

* Comprender el funcionamiento del ataque.
* Identificar evidencias generadas en el sistema.
* Comprobar el nivel de detección inicial del entorno.
* Mapear el ataque con **MITRE ATT&CK**.
* Preparar el escenario para ejercicios defensivos posteriores.

### Contexto

El servicio SSH es uno de los servicios más atacados en entornos reales.
Los ataques de fuerza bruta buscan probar múltiples combinaciones de credenciales hasta encontrar una válida.

Este ejercicio simula este escenario desde el punto de vista ofensivo.

### Prerrequisitos

> Las IPs y credenciales pueden consultarse en: `cat log/level.log`

* Acceso al **nodo atacante (Caldera / terminal)**.
* Acceso SSH o conectividad hacia el **nodo objetivo** con SSH expuesto.
* Conocer el **usuario objetivo** (o el usuario configurado en el laboratorio).
* Disponer de Hydra en el nodo atacante (si aplica, instalarlo).
* Acceso al **Dashboard de Wazuh** (nodo monitor) para observar si hay detección.

---

### 1.6.1. Preparación e identificación (reconocimiento + entorno)

#### Reconocimiento inicial

Antes de lanzar el ataque, el alumnado debe verificar:

* Que el servicio SSH está activo.
* Que el sistema es accesible desde la máquina atacante.
* Qué usuario será el objetivo.

Ejemplos de acciones habituales:

* Comprobación de conectividad.
* Verificación de puertos abiertos.

#### Intro a Hydra

Hydra es una herramienta de fuerza bruta y ataque por diccionario capaz de atacar múltiples protocolos.

Características principales:

* Ataques paralelos.
* Soporte para usuario único o listas.
* Uso de diccionarios personalizados.
* Soporte para SSH, FTP, HTTP, RDP, etc.

#### Diccionarios disponibles en el entorno (nodo Caldera)

En este laboratorio, el alumnado utilizará el **nodo con terminal de CALDERA**, el cual dispone de un conjunto limitado de diccionarios preinstalados como parte del despliegue del entorno.

Visualice los diccionarios disponibles en el nodo Caldera:

```bash
ls -lh wordlists/
```

Características:

* No incluye las librerías completas de Kali Linux.
* Incluye varias wordlists funcionales.
* Una de ellas contiene la contraseña correcta del usuario objetivo.

El alumnado deberá:

* Localizar los diccionarios disponibles.
* Seleccionar cuál utilizar.
* Probar hasta encontrar el que contiene la credencial válida.

Este proceso forma parte del aprendizaje.

### 1.6.2. Ejecución (ataque con Hydra)

#### Sintaxis básica de Hydra

Estructura general:

```bash
hydra -l <usuario> -P <wordlists/DICCIONARIO> ssh://IP_OBJETIVO
```

Parámetros:

* `-l` → Usuario perteneciente a la máquina objetivo del ataque.
* `-P` → Diccionario de contraseñas utilizado.
* `ssh://` → Servicio objetivo.

Hydra probará cada contraseña hasta encontrar una válida.
Cuando la encuentre, la mostrará en pantalla.

#### Observación del comportamiento

Durante el ataque, el alumnado debe observar:

* Número de intentos.
* Velocidad del ataque.
* Mensajes mostrados por Hydra.
* Tiempo hasta encontrar credencial.

### 1.6.3. Validación end-to-end (credencial → acceso → detección)

#### Verificación de acceso

Una vez obtenida la contraseña:

```bash
ssh usuario@IP_OBJETIVO
```

Confirmar acceso exitoso.

#### Análisis del impacto

Redacte una reflexión sobre:

* Facilidad del compromiso.
* Qué controles faltan.
* Qué consecuencias tendría en producción.

#### Detección inicial (estado actual)

Compruebe si el entorno:

* Genera alertas.
* Registra eventos visibles.
* Bloquea el ataque.

Lo esperado es que **no exista detección específica**.

> ℹ️ **Nota:** Este resultado será la base para el Ejercicio 1.7.

### 1.6.4. Mapeo MITRE ATT&CK y creación del *layout* entregable (ruta completa del ataque)

En este ejercicio el alumnado **no debe mapear solo la fuerza bruta**, sino **la ruta completa** de un ataque coherente con lo visto en el LAB (p. ej. reconocimiento con Nmap → ataque a credenciales → acceso SSH → ejecución/descubrimiento/escalada con comandos).
El resultado final **es un layer entregable** en **ATT&CK Navigator**.

#### Qué se entrega 

1. **Layer de ATT&CK Navigator** (exportada en JSON desde el Navigator).
2. **Capturas** del Navigator con las técnicas marcadas y las notas visibles.
3. **Breve justificación por fases** (modelo tipo INCIBE): describe por fases, enlazando *acción observada → técnica ATT&CK*.

#### 1) Acceso a la matriz y apertura en ATT&CK Navigator

1. Abra la **[Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)**
2. Active **show sub-techniques** (para ver subtécnicas).
3. En la parte superior/derecha, pulse **“View on the ATT&CK® Navigator”**.

   * Esto te lleva al **Navigator**, donde construirás la *layer* entregable.

> **ℹ️ Recomendación:** si en la matriz aparece “Version Permalink”, verifique que se está usando la **misma versión**.

#### 2) Crear la layer en el Navigator

Dentro del Navigator:

1. **Create New Layer** (o “New Layer”).
2. Rellene:
   * **Name**: `LAB-SSH-ataque-completo-<equipo/alumnado>`
   * **Description**: Del escenario (Nmap → Hydra → SSH → comandos).

3. Use el buscador del Navigator para ir añadiendo técnicas:
   * Busque por **ID** (ej. `T1110`) o por **nombre** (ej. “Brute Force”).

4. Para cada técnica marcada:
   * Añade una **nota/comentario** con: *qué hizo*, *con qué herramienta*, *qué evidencia lo prueba* (captura/log).

Al terminar:
* Exporte: **Export / Download layer (JSON)**.

##### Tips de navegación (para técnicas/subtécnicas)

* En la matriz, las **tácticas** son columnas (Reconnaissance, Credential Access, Discovery, Privilege Escalation…).
* Las **técnicas** son tarjetas dentro de cada columna.
* Las **subtécnicas** aparecen al activar **show sub-techniques** y suelen llevar formato `Txxxx.xxx`.
* En el Navigator, lo más rápido es buscar por **ID** cuando ya lo tengas identificado.

#### 3) Construir la “ruta del atacante” por fases (modelo tipo INCIBE)

Aquí no hay que “adivinar”; hay que **formular una hipótesis guiada** y mapear **lo que se ha ejecutado/observado** en el LAB.

Puede usar este guion (rellenable) como una plantilla guía. El alumnado debe completar **todas** las fases con lo que corresponda:

**Fase A — Reconocimiento (qué busca y por qué)**

* Qué propósito tiene el atacante (descubrir exposición, puertos/servicios, superficie).
* Qué hizo en el LAB (ej.: Nmap SYN scan).
* Qué evidencia tienes (comando + salida/captura).
* Qué técnica(s) ATT&CK encajan (ID + nombre, y si aplica subtécnica).

**Fase B — Acceso / Credenciales (qué intenta y cómo)**

* Qué propósito tiene (obtener credenciales válidas).
* Qué hizo (Hydra contra SSH con diccionarios del nodo Caldera).
* Evidencia (comando Hydra + “login found” / resultado).
* Técnica(s) ATT&CK (ID + nombre + subtécnica si aplica).

**Fase C — Acceso remoto (cómo obtiene acceso)**

* Qué propósito tiene (sesión remota interactiva).
* Qué hizo (SSH con credencial válida).
* Evidencia (comando `ssh usuario@IP` + prompt/éxito).
* Técnica(s) ATT&CK.

**Fase D — Ejecución / Descubrimiento (qué información consigue)**

* Qué propósito tiene (confirmar usuario, permisos, sistema, red).
* Qué hizo (ej.: `whoami`, `id`, `uname -a`, `ip a`…).
* Evidencia (salidas en terminal o tareas Caldera si aplica).
* Técnica(s) ATT&CK.

**Fase E — Escalada de privilegios (si aplica en tu ruta)**

* Qué propósito tiene (elevar permisos, root/admin).
* Qué hizo (ej.: `sudo su` si se ejecutó).
* Evidencia (salida del comando / evento Wazuh asociado).
* Técnica(s) ATT&CK.

> ℹ️ **Importante**: si una fase no se ejecutó realmente, el alumnado debe marcarla como **hipótesis** (“qué haría después”) y justificarlo como continuación lógica, pero separando claramente **observado** vs **hipotético** en la nota del Navigator.

#### 4) Plantilla mínima para rellenar

El alumnado debe completar una tabla como esta (y esas mismas notas deben ir en el Navigator por técnica):

* **Fase (INCIBE):**
* **Acción en el LAB:**
* **Herramienta / comando:**
* **Evidencia (captura/log):**
* **Táctica ATT&CK (columna):**
* **Técnica/Subtécnica (ID + nombre):**
* **Justificación:**

---

### Validación / Troubleshooting

* Verifique conectividad hacia el objetivo y que SSH responde.
* Revise que el **usuario** y la **IP** sean correctos.
* Confirme que el diccionario seleccionado existe y tiene permisos de lectura:

```bash
ls -lah wordlists/
```

* Si hay errores de servicio o acceso, valide el estado del objetivo y el puerto 22.

### Evidencias a entregar

* Comando ejecutado (Hydra).
* Resultado de Hydra (credencial encontrada / output).
* Acceso SSH exitoso.
* Logs del sistema (si se revisan).
* Estado del SIEM (si hubo eventos/alertas o no).

### Conclusión final

Explique:

* Qué ocurrió.
* Qué debilidades se evidencian.
* Por qué este escenario es realista.

Resultado esperado:

✔ Obtención de credenciales
✔ Acceso al sistema
✔ Ausencia de detección específica
✔ Ataque correctamente mapeado (MITRE ATT&CK)

---

## Ejercicio 1.7 — Diseño e implementación de estrategia defensiva ante ataques a SSH

### Objetivo general

Diseñar e implementar una estrategia defensiva que permita:

* Detectar ataques de fuerza bruta contra SSH.
* Generar alertas en el SIEM.
* Mitigar automáticamente el ataque.
* Endurecer el servicio para reducir superficie de exposición.
* Relacionar las defensas con el marco **MITRE D3FEND**.

El alumnado debe transformar el entorno del ejercicio anterior en un sistema capaz de **detectar, responder y resistir** este tipo de ataques.

### Contexto

En el ejercicio previo se comprobó que un ataque de fuerza bruta puede ejecutarse sin generar alertas específicas.

En este ejercicio se busca **cerrar esa brecha**, aplicando controles defensivos a distintos niveles:

* Monitorización
* Respuesta automática
* Endurecimiento del servicio

### Prerrequisitos

> Las IPs y credenciales pueden consultarse en: `cat log/level.log`

* Haber completado el **Ejercicio 1.6** (ataque con Hydra).
* Acceso al **Dashboard de Wazuh** (nodo monitor).
* Acceso SSH al **nodo objetivo** (donde corre SSH) para aplicar hardening si aplica.
* Acceso al **nodo Wazuh Manager** para modificar reglas / respuesta activa si aplica.
* Capacidad de relanzar el ataque (Hydra) desde el nodo atacante para validar.

---

### 1.7.1. Preparación e identificación (análisis inicial)

#### Análisis inicial del problema

El alumnado debe analizar:

* Qué comportamiento tiene un ataque de fuerza bruta.
* Qué evidencias genera en el sistema.
* Por qué inicialmente no es detectado.

Debe identificar:

* Fuentes de logs relevantes.
* Eventos repetitivos.
* Indicadores de intento de compromiso.

#### Diseño de la estrategia defensiva

Definir una estrategia que combine varios enfoques:

* Detección.
* Mitigación.
* Prevención.

Se espera una breve justificación de por qué se elige cada control.

### 1.7.2. Ejecución (implementación de controles)

#### Métodos defensivos sugeridos (visión general)

> No obligatorios. Son líneas de trabajo posibles.

**A. Reglas personalizadas en Wazuh**
Consiste en crear reglas que identifiquen patrones asociados a:

* Múltiples intentos fallidos.
* Accesos desde una misma IP.
* Mensajes concretos de autenticación fallida.

Objetivo:

* Elevar eventos a nivel de alerta.
* Clasificarlos como intento de ataque.

**B. Mecanismos de bloqueo automático**
Uso de herramientas que:

* Analizan logs.
* Detectan patrones de abuso.
* Bloquean la IP origen temporal o permanentemente.

Ejemplo conceptual:

* Sistemas tipo fail2ban.

Objetivo:

* Cortar el ataque sin intervención manual.

**C. Hardening del servicio SSH**
Endurecimiento del servicio para reducir probabilidad de compromiso:

Algunas líneas habituales:

* Deshabilitar autenticación por contraseña.
* Usar únicamente autenticación por clave.
* Limitar usuarios permitidos.
* Reducir intentos máximos.
* Cambiar puerto por defecto (medida secundaria).

Objetivo:

* Hacer que el ataque sea inefectivo incluso antes de ser bloqueado.

**D. Correlación y visibilidad**
Asegurar que:

* Los eventos relevantes llegan al SIEM.
* Son visibles.
* Están correctamente clasificados.

#### Implementación

El alumnado implementará los controles seleccionados.

Debe quedar claro:

* Qué se ha modificado.
* Por qué.
* En qué sistema.

No se exige un conjunto concreto de herramientas, solo que se cumpla el objetivo.

### 1.7.3. Validación (repetición del ataque)

Se debe repetir el ataque del ejercicio anterior y comprobar:

* Aparición de alertas.
* Bloqueo del origen.
* Reducción de intentos exitosos.
* Diferencia de comportamiento respecto al ejercicio previo.

### 1.7.4. Mapeo MITRE D3FEND (controles defensivos aplicados)

En este ejercicio el alumnado debe **traducir los controles defensivos que ha aplicado** (Wazuh rules/correlación, bloqueos, hardening SSH, etc.) a **técnicas D3FEND**, de forma que quede una **ruta defensiva completa** y justificable.

A diferencia de ATT&CK, en **D3FEND no se entrega una “layer”** como tal. El entregable aquí es un **mapeo documentado** (tabla + evidencias + justificación).

---

#### Qué se entrega

1. **Tabla de mapeo Control → D3FEND** (como mínimo, todos los controles que el alumnado haya aplicado en el Ej. 7).
2. **Capturas** del sitio de D3FEND mostrando las técnicas seleccionadas (o sus fichas) y/o la matriz (Harden / Detect / Isolate).
3. **Evidencia técnica del control aplicado** (snippet de config, captura de Wazuh/SSH/firewall/active response) y justifique el control.

#### 1) Acceso a D3FEND y cómo navegar

1. Abra **[MITRE D3FEND](https://d3fend.mitre.org/)**.

2. Elementos clave de navegación (como en tu captura):

   * **CAD (matriz)** con columnas grandes: **Harden / Detect / Isolate**.
   * Buscador **D3FEND Lookup** (para buscar técnicas por nombre).
   * Buscador **ATT&CK Lookup** (muy útil si quieres partir de técnicas del ataque del Ej. 6).
   * Al hacer clic en una “tarjeta” (técnica), se abre su **ficha** con descripción y relaciones.

**Dos formas válidas de encontrar técnicas:**

* **A) Desde el control defensivo (lo que implementaste):** buscar por palabras clave en **D3FEND Lookup** (ej.: “threshold”, “locking”, “traffic filtering”, “certificate”, “mfa”…).
* **B) Desde el ataque (ATT&CK → D3FEND):** en **ATT&CK Lookup** escribir un ID del ataque (ej.: `T1110`) y usar las contramedidas/relaciones sugeridas para llegar a técnicas D3FEND que lo mitiguen/detecten.

#### 2) Construir el mapeo “defensa por fases” (Harden / Detect / Isolate)

El alumnado debe organizar sus controles en estas **tres fases D3FEND**, explicando qué hace cada una:

* **Harden (Prevención/Reducción de superficie):** endurecer para que el ataque sea más difícil o inútil.
* **Detect (Detección/Visibilidad):** generar señal útil en SIEM (Wazuh), umbrales, correlación, análisis.
* **Isolate (Contención):** cortar el ataque (bloqueo IP, account lock, SG/firewall, active response).

> ℹ️ **Importante**: aquí el alumnado no “elige al azar”. Debe mapear **lo que realmente configuró** en el Ejercicio 1.7 (y si propone algo extra, debe marcarlo como “hipótesis/mejora”, separado de lo implementado).

#### 3) Plantilla guiada por control (lo que deben rellenar)

Para **cada control** aplicado, completar este bloque (y acompañarlo de capturas):

* **Control aplicado (qué hice):**
* **Dónde lo apliqué (Wazuh / SSH / firewall / SG / etc.):**
* **Evidencia técnica:** (snippet config / captura dashboard / log)
* **Ubicación en D3FEND:** (Harden / Detect / Isolate)
* **Técnica D3FEND seleccionada (ID + nombre):**
* **Justificación:** por qué esa técnica representa tu control y cómo frena/detecta el ataque de fuerza bruta.

#### 4) Tabla base (ejemplo orientativo)

> El alumnado debe completar una tabla así con **sus** controles. Esta es la referencia que ya tenías (se mantiene):

| Control aplicado                                                      | Propósito  | Técnica D3FEND                                                                                              |
| --------------------------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------- |
| Umbral/correlación “N fallos SSH en X” en Wazuh                       | Detección  | **D3-ANET — Authentication Event Thresholding**                                                             |
| Detección por intentos fallidos repetidos                             | Detección  | **D3-CAA — Connection Attempt Analysis**                                                                    |
| Bloqueo por IP (firewall/active response/SG)                          | Contención | **D3-ITF — Inbound Traffic Filtering** *(y/o **D3-NAM — Network Access Mediation** si lo haces con SG/NAC)* |
| Bloqueo por cuenta (si aplica)                                        | Contención | **D3-AL — Account Locking**                                                                                 |
| Endurecer credenciales / política contraseñas (si mantienes password) | Prevención | **D3-CH — Credential Hardening** *(y/o **D3-SPP — Strong Password Policy**)*                                |
| Pasar a claves/certificados / MFA (si aplica)                         | Prevención | **D3-CBAN — Certificate-based Authentication** *(y/o **D3-MFA — Multi-factor Authentication**)*             |

#### 5) Cómo justificarlo “como SOC” (enlace con el ataque del Ej. 6)

La justificación debe conectar **ataque → defensa**:

* Qué parte del ataque frenas (p. ej. “Credential Access / Brute Force”).
* Qué señal produces (Wazuh: umbrales, correlación, alertas).
* Qué acción de contención aplicas (bloqueo IP/cuenta, SG, firewall).
* Qué endurecimiento reduce el riesgo residual (MFA/keys/política contraseñas).

Formato recomendado:

* “Este control reduce/detecta **fuerza bruta SSH** porque…”
* “La evidencia es… (captura/log/config)”
* “Se alinea con D3FEND porque describe exactamente… (nombre técnica)”

---

### Validación / Troubleshooting

* Verifique que los logs relevantes llegan a Wazuh (autenticación SSH).
* Revise que las reglas están cargadas y no hay errores en el manager.
* Si hay bloqueo automático, confirme que la IP se bloquea realmente (firewall/active response).
* Si aplicó hardening (p.ej. deshabilitar password), valide que SSH sigue siendo accesible para administración (evitar auto-bloqueo operativo).

### Evidencias a entregar

* Fragmentos de configuración modificados (reglas, hardening, bloqueo).
* Capturas de eventos/alertas en Wazuh.
* Evidencia del bloqueo (si aplica).
* Comparativa antes vs después (resultado del ataque).

### Conclusión final 

Reflexión final:

* Qué controles fueron más efectivos.
* Qué capa aportó mayor valor.
* Cómo se podría mejorar en un entorno real.

---

## Ejercicio 1.8 — Creación de un KPI operativo basado en un ataque real

### Objetivo

Diseñar un **KPI operativo propio** a partir de un ataque observado durante el laboratorio (MITRE Caldera → Snort → Wazuh), de forma que:

* Permita **detectar rápidamente la recurrencia del ataque**.
* Facilite el **triage y la reacción de otro analista SOC**.
* Sirva como **indicador continuo** de riesgo operativo.

Este ejercicio simula una tarea real de un SOC **Level 1 / Level 2**: transformar una detección puntual en un **indicador reutilizable**.

### Contexto del ejercicio

Durante los ejercicios anteriores se ha observado un patrón de ataque realista, por ejemplo:

* Ejecución remota de comandos desde Caldera.
* Uso de `sudo` / cambio de privilegios.
* Actividad anómala detectada por reglas de Wazuh.

Este patrón **no se trata como un evento aislado**, sino como un **caso recurrente** que debe ser monitorizado.

### Prerrequisitos

> Las IPs y credenciales pueden consultarse en: `cat log/level.log`

* Haber completado los ejercicios previos (especialmente aquellos que generen eventos claros en Wazuh).
* Acceso al **Dashboard de Wazuh** (nodo monitor).
* Tener al menos un conjunto de eventos reales generados durante el laboratorio (para usar como base del KPI).

---

### 1.8.1. Preparación e identificación (selección del ataque base)

#### Identificación del ataque observado

Seleccione **un ataque concreto** ejecutado en el laboratorio.

Ejemplos válidos:

* Uso no habitual de `sudo` desde una sesión remota.
* Ejecución de comandos sospechosos (`whoami`, `id`, `uname`).
* Acceso inicial seguido de escalada de privilegios.

Documente brevemente:

* Nodo afectado.
* Técnica MITRE asociada (ej. T1059, T1548).
* Regla(s) de Wazuh que lo detectaron.

> **Este ataque será la base del KPI.**

### 1.8.2. Definición del KPI operativo

#### Diseño del KPI

El KPI debe responder a una pregunta **accionable**, por ejemplo:

> “¿Con qué frecuencia se detectan intentos de escalada de privilegios desde accesos remotos?”

Defina el KPI con la siguiente estructura:

* **Nombre del KPI**
* **Descripción**
* **Evento o patrón que mide**
* **Fuente de datos**
* **Umbral operativo**
* **Acción recomendada**

#### Ejemplo de definición

**KPI:** `Intentos de escalada de privilegios no esperados`

**Descripción:**
Mide el número de eventos donde se detecta uso de `sudo` o cambio de privilegios en nodos que no deberían realizar tareas administrativas.

**Fuente:**
Wazuh – reglas relacionadas con `sudo` (`rule.id` correspondiente).

**Frecuencia de medida:**
Tiempo real / revisión diaria.

### 1.8.3. Implementación del KPI en Wazuh

#### Identificación del patrón en Wazuh

Acceda al Dashboard:

**☰ → Threat Hunting → Events**

Filtre por:

* `agent.name`: nodo Snort
* `rule.description` o `full_log` conteniendo `sudo`
* Rango temporal: últimos ejercicios

Verifique que el patrón es **repetible y reconocible**.

#### Definición de umbrales

Defina un umbral simple y claro:

Ejemplo:

* **0–1 eventos / día:** comportamiento esperado.
* **2–3 eventos / día:** revisión manual.
* **>3 eventos / día:** posible incidente → escalar.

Este umbral es parte del KPI y lo convierte en **operativo**, no solo informativo.

---

## Investigación Opcional — MITRE Caldera (profundización teórico-práctica)

Actividad opcional para explorar **capacidades avanzadas de MITRE Caldera** que normalmente no se dominan en la primera toma de contacto. El objetivo no es “tocar botones”, sino entender **cómo funciona por dentro** (modelo de datos + ejecución) y validarlo con **pruebas cortas, repetibles y bien documentadas**.

> Idea: elegir **3–4 bloques** y documentar cada uno con *concepto → prueba → evidencia → conclusión*.  
> Recomendación: usar siempre una convención de nombres (por ejemplo `INV-<bloque>-<grupo>`) para que luego sea fácil localizar operaciones y resultados.

### Qué se entrega

1. **Documento breve** (2–3 páginas) con apartados por bloque.
2. **Capturas** del Dashboard (antes/durante/después) y, si procede, salida de tasks.
3. **Checklist** final de lo probado (probado / pendiente).

### Bloques de investigación (elige 3–4)

#### 1) Modelo mental de Caldera: ¿qué es cada cosa?

**Teoría (qué entender)**

* **Agent:** el “implant” que vive en la máquina víctima y ejecuta lo que Caldera ordena.
* **Ability:** una acción/técnica concreta (equivale a “una pieza” del comportamiento del atacante).
* **Adversary:** un conjunto de abilities ordenadas que representan una ruta o estilo de ataque.
* **Planner:** la lógica que decide cómo se ejecuta esa ruta (orden, selección, reintentos).
* **Operation:** la ejecución real: “esta ruta” sobre “estos agentes” en “este momento”.

**Práctica (qué probar)**

* Identificar en la UI: 1 agent, 3 abilities, 1 adversary y 1 planner.
* Explicar en 3–5 líneas cómo viaja una orden:
  *Operation → Planner → Abilities → Agent → Output*.
* Ejecutar una operación mínima (2–3 abilities) para ver el flujo completo.

**Evidencia**

* Captura del agent + captura de la operación mostrando tasks y output (al menos 2 tasks).

---

#### 2) Agents: estabilidad, permisos y “supervivencia”

**Teoría (qué entender)**

* Un agente no solo “está vivo”: importa **si ejecuta con permisos suficientes**, si mantiene conexión estable y cómo se recupera ante fallos.
* Muchos “fallos de Caldera” en realidad son:
  * permisos insuficientes,
  * binarios/comandos no disponibles,
  * o pérdida de conectividad.

**Práctica (qué probar)**

* Diseñar una mini-prueba de estabilidad:
  * ejecutar 3 tasks seguidas,
  * forzar un fallo controlado (p. ej. cortar conexión/reiniciar host si se permite),
  * observar si vuelve y qué tareas fallan o quedan pendientes.
* Ejecutar 1 ability “simple” y 1 ability que normalmente requiera más privilegios, para ver la diferencia.

**Evidencia**

* Captura de Agents (Alive/Last seen) + captura de tasks con éxito/fallo y su mensaje de error.

---

#### 3) Abilities: qué hacen “de verdad” y qué requieren

**Teoría (qué entender)**

* Una ability no es solo un comando: tiene **plataforma**, **ejecutor**, **condiciones** y devuelve un **output**.
* Dos abilities con “misma intención” pueden generar evidencias muy distintas según:
  * el host,
  * permisos,
  * o el método de ejecución.

**Práctica (qué probar)**

* Seleccionar 5 abilities de categorías distintas (p. ej. discovery / execution / privilege).
* Para cada una, completar:
  * qué intenta conseguir,
  * qué ejecuta exactamente (comando/acción),
  * qué devuelve (output),
  * qué requisito tiene (permisos, binarios, sistema).
* Marcar cuáles son “ruidosas” (generan mucha evidencia) y cuáles más “discretas”.

**Evidencia**

* Captura de cada task con output (o error) + 1 línea de nota por ability.

---

#### 4) Adversaries: construir una ruta coherente

**Teoría (qué entender)**

* Un adversary es el “guion” del atacante: lo importante es la **coherencia** (qué tiene sentido ejecutar y en qué orden).
* La calidad se mide por:
  * secuencia lógica por fases,
  * dependencias claras,
  * y reproducibilidad (que sea repetible con resultados similares).

**Práctica (qué probar)**

* Crear un adversary propio con 4–6 abilities ordenadas por fases:
  * Recon → Discovery → Credential/Access → Post-access.
* Ejecutarlo y comprobar:
  * si se cumple la secuencia,
  * dónde falla,
  * qué dependencia faltaba (permiso, comando, contexto).
* Ajustar 1 vez el adversary para mejorar la tasa de éxito (cambio de orden o sustitución de 1 ability).

**Evidencia**

* Captura del adversary (lista de abilities) + captura de la operación ejecutada (tasks y resultados).

---

#### 5) Planners: misma ruta, resultados distintos

**Teoría (qué entender)**

* El planner define el “cómo”: puede ejecutar de forma simple o más adaptativa (según versión/plugins).
* Cambiar de planner puede afectar:
  * orden real de ejecución,
  * reintentos,
  * y tasa final de éxito.

**Práctica (qué probar)**

* Ejecutar **el mismo adversary** con planners distintos (si el entorno los ofrece) y comparar:
  * orden de tasks,
  * tasa de éxito,
  * tiempos,
  * comportamiento ante fallos.

**Evidencia**

* Tabla comparativa (2 ejecuciones) + capturas de ambas operaciones.

---

#### 6) Facts y encadenamiento: cuando Caldera “usa lo aprendido”

**Teoría (qué entender)**

* Los **facts** permiten automatizar: Caldera guarda datos descubiertos y los reutiliza.
* Esto convierte una operación de “comandos sueltos” en una ruta más realista.

**Práctica (qué probar)**

* Ejecutar una ability que descubra un dato (usuario/host/IP/ruta).
* Ver si aparece como fact.
* Usar ese fact como input en otra ability (encadenamiento simple).
* Si no aparecen facts automáticamente, documentar por qué (parser ausente, output no estructurado, etc.).

**Evidencia**

* Captura del fact + captura de la segunda task usando ese dato.

---

#### 7) Parsers: evitar que todo sea “texto”

**Teoría (qué entender)**

* Sin parsing, el output queda “plano” y no se puede reutilizar.
* Con parsers, el output se convierte en facts (datos) y permite encadenar operaciones.

**Práctica (qué probar)**

* Elegir una ability con output rico (varios campos).
* Identificar 1 dato que debería extraerse siempre (usuario, IP, hostname, ruta…).
* Proponer cómo se extraería (regex conceptual) y dónde encajaría (parser asociado a esa ability).

**Evidencia**

* Captura del output + párrafo proponiendo el dato a extraer, regex conceptual y utilidad.

---

#### 8) Plugins: ampliar capacidades (sin entrar en instalación)

**Teoría (qué entender)**

* Caldera es modular: los plugins pueden añadir planners, abilities, pantallas o funcionalidades.
* Entender plugins sirve para saber qué capacidades “no se ven” si no están instaladas.

**Práctica (qué probar)**

* Listar plugins visibles en el entorno.
* Elegir 1 plugin y explicar:
  * qué añade,
  * qué casos de uso habilita,
  * qué complejidad introduce (operación, mantenimiento, aprendizaje).

**Evidencia**

* Captura del listado + mini ficha del plugin.

### Plantilla de ejemplo

Para cada bloque seleccionado, redactar:

* **Concepto:** qué es y por qué importa en Caldera.
* **Prueba realizada:** qué tocaste / ejecutaste.
* **Resultado observado:** qué pasó (éxito/fallo) y por qué crees que ocurrió.
* **Evidencias:** capturas y/o output.
* **Conclusión:** qué aprendiste y qué mejorarías en una siguiente iteración.

---

## Ejercicio 2.0 — MISP: creación de un usuario y organización con mínimo privilegio

### Objetivo

Aplicar el principio de **mínimo privilegio**, ya exigido en las [Normas generales del laboratorio](#normas-generales-del-laboratorio) (*"usar cuentas/roles justos para cada tarea, y documentar cuándo/por qué se eleva"*), creando una organización y un usuario propios del laboratorio en vez de operar con la cuenta de administrador para las tareas del día a día.

### Prerrequisitos

* MISP desplegado (`MISP/install-misp.sh`) y accesible por navegador (`https://IP_MISP`).
* Credenciales de **administrador** de MISP (se usan únicamente en este ejercicio, para la configuración inicial):

```bash
cat ~/misp-logs/misp-settings.txt
```

---

### 2.0.1. Preparación e identificación (acceso como administrador)

Acceda a `https://IP_MISP` (acepte el aviso del certificado autofirmado) e inicie sesión con el usuario y contraseña de administrador (`- Admin Username` / `- Admin Password` en `misp-settings.txt`).

> Este es el **único** ejercicio del nivel (junto con partes del 2.2) donde se usa la cuenta de administrador, y es precisamente para dejar de necesitarla en el resto.

**Evidencie**

* Captura del login como administrador.

### 2.0.2. Ejecución (organización + usuario de laboratorio)

#### Crear la organización

1. **Administration → List Organisations → Add Organisation**.
2. Rellene un nombre identificable, por ejemplo `SOC-LAB`.
3. Guarde.

**Evidencie**

* Captura de la organización creada.

#### Crear el usuario

1. **Administration → List Users → Add User**.
2. Rellene:

   * **Email:** el que use el alumnado (por ejemplo, `analista@soc-lab.local`).
   * **Org:** `SOC-LAB` (la creada arriba).
   * **Role:** el rol **más bajo** que permita crear y publicar eventos propios: `Publisher`
   * Marque la casilla **Set Password** y escriba la contraseña ahí mismo.
3. Guarde. Anote la contraseña que fijó en el paso anterior.

**Evidencie**

* Captura del usuario creado, con su rol visible.

#### Verificar el acceso

1. Cierre la sesión de administrador.
2. Inicie sesión con el nuevo usuario y la contraseña fijada con **Set Password**.
3. Confirme que el Dashboard funciona con normalidad, pero que el menú **Administration** no está disponible.

**Evidencie**

* Captura del login con el usuario de laboratorio.
* Captura mostrando que el acceso a Administration ya no aparece.

### Validación / Troubleshooting

* Si el usuario no puede publicar eventos (lo comprobará en el ejercicio 2.1), vuelva como administrador a **Administration → List Users → Edit User**, y cambie el **Role** a `Publisher` (en **List Roles** puede comprobar antes que ese rol incluye "Manage and Publish Organisation Events"). **Documente ese cambio y su motivo**: es exactamente el "documentar cuándo/por qué se eleva" de la norma de mínimo privilegio.
* ⚠️ **Importante:** al guardar el cambio de rol, MISP pide **confirmar la contraseña del propio administrador** antes de aplicarlo. Si se omite ese paso, el formulario puede parecer guardado pero el rol **no cambia realmente**: vuelva a **List Users** y confirme que la columna de rol ya dice `Publisher` antes de continuar.
* Tras confirmar el cambio, cierre sesión del usuario de laboratorio y vuelva a iniciarla (o use una ventana de incógnito) para que la sesión recoja el nuevo rol.
* Si se pierde u olvida la contraseña, un administrador puede restablecerla desde **List Users → Edit User → Set Password**.

### Evidencias a entregar

* Organización creada.
* Usuario creado (con su rol).
* Login exitoso con el usuario de laboratorio.
* Comprobación de que el acceso a Administration está restringido.

### Conclusión final

Incluya:

* Qué rol se asignó y por qué (y si tuvo que elevarse, el motivo documentado).
* Qué puede y qué **no** puede hacer este usuario frente al administrador.
* Por qué operar con una cuenta de privilegio reducido es más realista que usar siempre la cuenta de admin, y cómo conecta con el principio de mínimo privilegio ya exigido en el resto del laboratorio.

---

## Ejercicio 2.1 — MISP: creación manual de un evento e IOCs

### Objetivo

Familiarizarse con el modelo de datos de MISP (**Event → Attribute → flag IDS → Tag**) creando manualmente inteligencia propia sobre la actividad que ya se genera en el Level-01: la IP del nodo `caldera-server`.

### Prerrequisitos

* MISP desplegado (`MISP/install-misp.sh`) y accesible por navegador (`https://IP_MISP`).
* **Ejercicio 2.0 completado**: usuario y organización de laboratorio creados. En este ejercicio **no se usa** la cuenta de administrador.
* IP del nodo `caldera-server`.

---

### 2.1.1. Preparación e identificación (acceso a MISP)

#### Acceso al Dashboard de MISP

Desde un navegador, acceda a:

```
https://IP_MISP
```

El certificado es autofirmado (lo genera `install-misp.sh`): acepte el aviso de seguridad del navegador, es esperado en este laboratorio.

Inicie sesión con el **usuario de laboratorio** creado en el ejercicio 2.0 (no con la cuenta de administrador, aplicando el principio de mínimo privilegio).

**Evidencie**

* Captura de la pantalla principal de MISP tras iniciar sesión.

### 2.1.2. Ejecución (creación del evento)

#### Crear el evento

1. En el menú superior: **Event Actions → Add Event**.
2. Rellene los metadatos mínimos:

   * **Date:** fecha actual.
   * **Distribution:** `Your organisation only` (suficiente para este ejercicio de laboratorio).
   * **Threat Level:** `Medium` (u otro, justifíquelo).
   * **Analysis:** `Initial`.
   * **Event info:** por ejemplo, `LAB - Actividad de caldera-server detectada por Snort`.
3. Pulse **Submit**.

**Evidencie**

* Captura del evento recién creado (metadata visible).

#### Añadir atributos (IOCs)

1. Dentro del evento, **Add Attribute**.
2. Cree un primer atributo:

   * **Category:** `Network activity`
   * **Type:** `ip-src`
   * **Value:** IP de `caldera-server`
   * **Distribution:** `Inherit event` (así el atributo mantiene el mismo alcance, `Your organisation only`, que fijamos para el evento, en vez de quedar potencialmente más expuesto que él).
   * Marque la casilla **IDS** (`For Intrusion Detection System`): es lo que convierte el atributo en un IOC exportable.
3. Añada un `Contextual Comment` describiendo el contexto (por ejemplo, "IP usada en el Level-01 para simular ataques con Caldera").
4. Guarde los cambios.

**Evidencie**

* Captura de los atributos del evento, mostrando el flag **IDS** activo en el atributo `ip-src`.

#### Publicar el evento

1. En la vista del evento, pulse **Publish Event** y confirme.
2. MISP pedirá confirmación porque la publicación notificaría a otras organizaciones en un despliegue real; en este laboratorio solo sirve para dejar el evento activo y consultable.

**Evidencie**

* Captura del evento en estado **Published**.

#### (Opcional) Enriquecer con Taxonomía TLP y Galaxy ATT&CK

Hasta aquí el evento tiene un IOC, pero le falta contexto estructurado. MISP ofrece dos mecanismos para eso:

* **Activar la taxonomía TLP (paso previo):** MISP trae muchas taxonomías precargadas, pero la mayoría vienen **desactivadas** por defecto (incluida `tlp`), así que no aparecerán en el buscador de tags hasta activarlas. Vaya a **Event Actions** (barra superior) → **List Taxonomies** (visible con `Publisher`), busque `tlp` y ábrala. A partir de aquí, **Enable** y **Update Taxonomies** solo están disponibles para el rol administrador, así que este paso concreto debe hacerse como admin: pulse **Enable** y después **Update Taxonomies** para que el cambio surta efecto. Documente esa elevación puntual, como en ejercicios anteriores. Enable/Update dejan la taxonomía disponible en el sistema, pero para que sus etiquetas aparezcan realmente en el buscador de **Add Tag** aún falta activar las tags concretas: dentro de la taxonomía `tlp` ya abierta, en el listado de tags (columna **Active Tags**), marque como activas las que vaya a usar (por ejemplo `tlp:amber`).
* **Taxonomía TLP:** en la vista del evento, **Add a tag** → busque `tlp:` y elija el nivel adecuado (por ejemplo `tlp:amber`, "compartible dentro de la organización, no fuera"). No confunda esto con `Distribution`: `Distribution` controla técnicamente **quién puede ver** el evento en MISP; el tag **TLP** es la instrucción de **cómo debe tratar la información** quien la reciba, aunque ambos apunten en la misma dirección.
* **Galaxy MITRE ATT&CK:** en la vista del evento, **Add new cluster** → busque `Attack Pattern` (galaxy de MITRE ATT&CK) y seleccione la técnica que corresponda a la actividad observada (por ejemplo, `T1595 - Active Scanning`, si el evento documenta el reconocimiento con Nmap del Ejercicio 1.4 del Level-01). Esto conecta directamente con el mapeo a ATT&CK Navigator que ya hicisteis "aparte" en los Ejercicios 1.6-1.7: aquí veis que MISP puede hacer ese mismo mapeo dentro de la propia plataforma de CTI. A diferencia de las taxonomías, las Galaxies suelen venir **activadas** por defecto; si no encuentra `Attack Pattern` en el buscador, revise igualmente en **Administration → List Galaxies** que esté habilitada.

**Evidencie (si se realiza)**

* Captura de la taxonomía `tlp` activada en **Taxonomies**.
* Captura del tag TLP añadido al evento.
* Captura del Galaxy/técnica ATT&CK añadida al evento.

### Validación / Troubleshooting

* Si no aparece el botón **Publish**, compruebe que el evento tiene al menos un atributo.
* Si el atributo no queda marcado como IDS, edítelo y marque la casilla explícitamente (no todas las categorías la activan por defecto).

### Evidencias a entregar

* Captura del login en MISP.
* Captura del evento creado (metadata).
* Captura de los atributos, con el flag IDS visible en el `ip-src`.
* Captura del evento publicado.
* (Si se realiza) captura del tag TLP y de la técnica ATT&CK asociados al evento.

### Conclusión final

Incluya:

* Qué es un **Event** y qué es un **Attribute** en MISP, y cómo se relacionan.
* Para qué sirve el flag **IDS**
* Qué es la **distribución** y por qué importa en un contexto real (compartir o no compartir con otras organizaciones).
* (Si se realiza) diferencia entre `Distribution`  y el tag **TLP** , y qué aporta enlazar el evento a una técnica **MITRE ATT&CK** vía Galaxy frente a mapearlo solo en el Navigator externo.
* Cómo este evento servirá de base para los ejercicios 2.3 (consulta por API) y 2.4 (integración automática con Wazuh).

---

## Ejercicio 2.2 — MISP: consumo de un feed público de threat intelligence

### Objetivo

Dar de alta manualmente, activar y sincronizar un **feed externo** de indicadores de amenaza, activar además uno de los feeds nativos que MISP ya trae preconfigurados para comparar formatos, y diferenciar la inteligencia propia (ejercicio 2.1) de la inteligencia procedente de fuentes de terceros.

### Prerrequisitos

* Acceso de **administrador** a MISP.

  > ℹ️ **Nota de mínimo privilegio:** junto con el Ejercicio 2.0, este es el único ejercicio que requiere la cuenta de admin. La gestión de feeds afecta a toda la instancia de MISP (no solo a una organización), y MISP la restringe a administración de servidor: es una elevación de privilegio justificada y documentada, no un atajo.
* Conectividad a Internet desde `misp-server`.
* Recomendable: Ejercicio 2.1 completado.

---

### 2.2.1. Preparación e identificación (elección de la fuente)

> ⚠️ **Importante:** no pulse "Load default feed metadata": ese botón carga un catálogo mucho más amplio (decenas de feeds públicos, algunos con cientos de miles de indicadores) que puede llenar el disco de `misp-server` (50 GB) o tardar horas en sincronizar.

En el Dashboard de MISP:

* **Sync Actions → List Feeds**. Verá 2 feeds predefinidos, deshabilitados: **CIRCL OSINT Feed** y **The Botvrij.eu Data**. Son fuentes que MISP ya conoce, en formato nativo "MISP Feed" (eventos ya estructurados vía `manifest.json`). En este ejercicio vamos a trabajar con dos fuentes distintas para comparar:
  1. Una fuente que **MISP no trae por defecto**, dada de alta manualmente desde cero, tal como se haría con un proveedor de threat intel nuevo.
  2. Uno de los dos feeds nativos ya preconfigurados, simplemente activándolo, para ver cómo importa MISP un feed en su propio formato estructurado.
* Fuente nueva que usaremos: **blocklist.de**, IPs reportadas por ataques SSH por fuerza bruta, con estos parámetros (verificados: URL accesible, ~4.445 IPs, ~63 KB de texto plano, pequeño y directamente relacionado con el Ejercicio 1.6 del Level-01, el ataque SSH con Hydra):

  * **Name:** `blocklist.de - SSH attackers`
  * **Provider:** `blocklist.de`
  * **URL:** `https://lists.blocklist.de/lists/ssh.txt`
  * **Input source:** `Network`
  * **Source format:** `Freetext` (a diferencia de CIRCL/Botvrij, formato nativo "MISP Feed" con eventos ya estructurados, esta fuente es una lista plana de IPs sin estructura MISP; el formato `Freetext` hace que MISP reconozca automáticamente el patrón de IOC, aquí IPs, en cada línea).
* Feed nativo que activaremos: **The Botvrij.eu Data**, ya preconfigurado (formato `MISP Feed`, no necesita rellenar formulario). Se ha comprobado su tamaño real (~435 eventos, ~10 MB en total): sincroniza en segundos y permite ver el resultado completo de inmediato, algo idóneo para un ejercicio de laboratorio acotado en el tiempo. El otro feed predefinido, **CIRCL OSINT Feed**, se deja deliberadamente sin activar: ronda 1.670 eventos y, por el tamaño de varios de sus informes individuales, puede suponer del orden de 1-2 GB de datos en bruto. No es un problema de espacio en disco (el 50 GB de `misp-server` lo asume sin problema), sino de alcance: tardaría bastante más en sincronizar y añadiría un volumen de eventos poco manejable para explorar en el propio ejercicio.

**Evidencie**

* Captura del listado de feeds antes de añadir el nuevo (mostrando los 2 predefinidos, deshabilitados).

### 2.2.2. Ejecución (alta, activación y sincronización)

#### Dar de alta el feed

1. **Sync Actions → List Feeds → Add Feed**.
2. Rellene el formulario con los parámetros de arriba (Name, Provider, URL, Input source, Source format).
3. **Distribution:** puede dejar `All communities`, ya que es contenido público de un feed OSINT y no afecta al alcance de vuestros propios datos del ejercicio 2.1.
4. Marque **Enabled**.
5. Guarde.

**Evidencie**

* Captura del formulario **Add Feed** relleno antes de guardar.
* Captura del feed ya creado en la lista, en estado **Enabled**.

#### Activar el feed nativo Botvrij.eu Data

1. En **List Feeds**, localice **The Botvrij.eu Data** (ya existente, deshabilitado) y márquelo como **Enabled** (editar el feed → casilla **Enabled** → guardar).
2. Deje **CIRCL OSINT Feed** tal como está, deshabilitado: no forma parte de este ejercicio, por el volumen de datos comentado arriba.

**Evidencie**

* Captura de **The Botvrij.eu Data** en estado **Enabled**, con **CIRCL OSINT Feed** aún deshabilitado.

#### Sincronizar

1. En **List Feeds**, seleccione el feed `blocklist.de - SSH attackers` recién creado y ejecute **Fetch all events** (botón de sincronización individual del feed).
2. Repita la misma acción **Fetch all events** sobre **The Botvrij.eu Data**.
3. Espere a que finalicen ambas importaciones.

**Evidencie**

* Captura del resultado/progreso de la sincronización de cada uno de los dos feeds.

#### Explorar lo importado

1. Vaya a **Event Actions → List Events** y localice los eventos importados por ambos feeds.
   * `blocklist.de` (formato `Freetext`): es normal que el resultado sea **un único evento** con miles de atributos de tipo `ip-src`/`ip-dst`.
   * `Botvrij.eu Data` (formato nativo `MISP Feed`): al contrario, veréis **varios eventos pequeños y ya estructurados**, uno por cada indicador/informe original de la fuente. Esta es la diferencia práctica entre un feed en formato nativo de MISP y uno en texto plano interpretado con `Freetext`.
2. Use **Search Attributes** filtrando por tipo `ip-src` para localizar IPs concretas, y abra el evento de origen.

**Evidencie**

* Captura del evento importado por `blocklist.de`, con varios de sus atributos IP visibles.
* Captura de uno o varios eventos importados por `Botvrij.eu Data`, mostrando su estructura (más eventos, cada uno más pequeño que el de `blocklist.de`).

### Validación / Troubleshooting

* Si al guardar el feed da error de validación, confirme que **Source format** esté en `Freetext` (no `MISP Feed`, que espera un `manifest.json` que esta URL no tiene).
* Si la sincronización falla o no avanza, compruebe la conectividad a Internet desde `misp-server`:

```bash
curl -I https://lists.blocklist.de/lists/ssh.txt
```

* Si el disco empieza a llenarse, deshabilite el feed y elimine los datos importados (el propio feed en MISP permite purgar sus eventos) antes de continuar.

### Evidencias a entregar

* Listado de feeds antes de añadir el nuevo.
* Formulario **Add Feed** relleno.
* Feed creado y habilitado.
* Resultado de la sincronización.
* Un evento/atributo importado por el feed.
* Nota breve: cuántos eventos/atributos trajo el feed.

### Conclusión final

Incluya:

* Qué parámetros definen un feed en MISP (URL, formato de origen: `MISP Feed` vs `Freetext`/`CSV`, distribución) y qué papel juega cada uno.
* Diferencia entre un IOC propio (ejercicio 2.1) y uno de fuente externa (este ejercicio).
* Cómo esto se traduce a un caso real: dar de alta un feed nuevo es lo que haría un analista al incorporar un proveedor de threat intelligence (comercial o comunitario) que no viene precargado en la plataforma. Y por qué muchas fuentes reales (como listas de bloqueo) no vienen en formato nativo MISP.
* Cómo conecta con el Ejercicio 1.6 del Level-01: la IP atacante de vuestro ataque Hydra es una IP **privada** del propio laboratorio, así que nunca aparecería en un feed OSINT público como `blocklist.de` (que solo recoge IPs de Internet reportadas por terceros); ninguna cantidad de feeds públicos habría detectado ese ataque por reputación. ¿Qué aporta entonces este tipo de feed, y qué límite real tiene frente a una amenaza interna o de un origen aún no reportado por nadie?

---

## Ejercicio 2.3 — MISP: consultas a la API REST con curl

### Objetivo

Entender cómo se consulta MISP de forma programática: es exactamente lo que hace, de forma automática, la integración del ejercicio 2.4.

### Prerrequisitos

* Ejercicios 2.0 y 2.1 completados (usuario de laboratorio creado; evento con la IP de `caldera-server`, publicado).
* Acceso a una máquina con conectividad HTTPS hacia MISP (puede ser el propio `misp-server` u otra VM del laboratorio).
* Una **API key propia del usuario de laboratorio**, no la del administrador; se genera en el paso siguiente.

---

### 2.3.1. Preparación e identificación (generar la propia API key)

Inicie sesión en MISP con el **usuario de laboratorio** del ejercicio 2.0. Cada usuario puede generarse su propia Auth Key sin necesitar privilegios de administrador:

1. Menú de usuario (arriba a la derecha) → **Auth Keys**.
2. **Add authentication key**.
3. Copie la clave generada: MISP solo la muestra **una vez**.

> Usar la clave del usuario de laboratorio en vez de la del administrador es, de nuevo, mínimo privilegio: si esta clave se filtra, no compromete la administración completa de MISP.

**Evidencie**

* Captura de la Auth Key recién creada (sin mostrar la clave completa si se documenta fuera del entorno controlado).

### 2.3.2. Ejecución (consultas)

#### Consulta con coincidencia

Busque la IP creada en el ejercicio 2.1:

```bash
curl -k -s \
  -H "Authorization: TU_API_KEY" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  -d '{"value": "IP_DE_CALDERA", "type": ["ip-src"]}' \
  https://IP_MISP/attributes/restSearch
```

> `-k` desactiva la verificación del certificado autofirmado (esperado en este laboratorio). Si tiene `jq` instalado, añada `| jq .` al final para formatear la salida.

Identifique en la respuesta el campo `response.Attribute`: debe contener el atributo creado en 2.1, con su `Event.uuid` y `value`.

**Evidencie**

* Captura/salida del comando con el JSON de respuesta (coincidencia encontrada).

#### Consulta sin coincidencia

Repita la misma consulta con una IP que **no** exista en MISP (por ejemplo, `198.51.100.1`, rango reservado para documentación):

```bash
curl -k -s \
  -H "Authorization: TU_API_KEY" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  -d '{"value": "198.51.100.1", "type": ["ip-src"]}' \
  https://IP_MISP/attributes/restSearch
```

Compruebe que `response.Attribute` viene vacío (`[]`).

**Evidencie**

* Captura/salida del comando mostrando la respuesta vacía.

#### (Opcional) Comprobación de versión del servidor

```bash
curl -k -s -H "Authorization: TU_API_KEY" -H "Accept: application/json" \
  https://IP_MISP/servers/getVersion
```

### Validación / Troubleshooting

* **HTTP 403 / "Check MISP credentials":** revise que la API key se copió sin espacios ni saltos de línea.
* **`curl: (60) SSL certificate problem`:** falta el flag `-k` (certificado autofirmado, esperado aquí).

### Evidencias a entregar

* JSON de la consulta con coincidencia.
* JSON de la consulta sin coincidencia.
* Comando exacto utilizado en cada caso.

### Conclusión final

Incluya:

* Por qué la API es la pieza que permite **automatizar** consultas de threat intelligence (enlace directo con el ejercicio 2.4).
* Qué campos de la respuesta son relevantes para decidir si un indicador es una amenaza conocida (`Attribute`, `Event.uuid`, `to_ids`).

---

## Ejercicio 2.4 — MISP: integración automática con Wazuh

### Objetivo

Desplegar y validar la integración automática (`automation/wazuh-misp.sh`) que consulta MISP cada vez que Wazuh recibe una alerta derivada de Snort (ICMP / SYN scan), cerrando el ciclo **detección → enriquecimiento**.

### Prerrequisitos

* Ejercicios 2.1 y 2.3 completados (evento publicado en MISP con la IP de `caldera-server`; API key **del usuario de laboratorio** generada).
* Level-01 desplegado e integrado (`automation/wazuh-snort.sh` ya ejecutado).
* Clave SSH generada (`automation/key-generate.sh`) y acceso desde el anfitrión a las VMs del laboratorio.

> ℹ️ **Nota de mínimo privilegio:** use la API key del usuario de laboratorio (ejercicio 2.3), **no la del administrador**. Esa clave queda guardada en `ossec.conf` del Wazuh Manager; si fuera la de admin, cualquiera con acceso a esa VM tendría de facto privilegios de administrador sobre MISP.

---

### Cómo funciona la integración (antes de desplegar)

`wazuh-misp.sh` no es una caja negra: antes de lanzarlo, conviene entender qué instala y por qué.

1. **Se apoya en el módulo Integrator de Wazuh** (`wazuh-integratord`), el mecanismo nativo con el que Wazuh invoca un script externo cada vez que se dispara una alerta que cumple ciertas condiciones, el mismo patrón que usan las integraciones oficiales (VirusTotal, Slack, etc.). Se activa declarando un bloque `<integration>` en `ossec.conf`.
2. **El script instala tres piezas en el Wazuh Manager, por SSH:**
   * `/var/ossec/integrations/custom-misp_ip.py`: el script Python que hace la consulta a MISP.
   * `/var/ossec/etc/rules/misp_ip_rules.xml`: reglas locales `600200`-`600203` que interpretan la respuesta de ese script.
   * Un bloque `<integration>` en `/var/ossec/etc/ossec.conf` que conecta las reglas `600001`/`600010` (las de Snort del Level-01) con el script.
3. **Flujo completo, alerta a alerta:**
   1. Snort detecta tráfico → el Wazuh Agent en `snort-server` reenvía el log → el Wazuh Manager evalúa las reglas y dispara `600001` o `600010`.
   2. Por el bloque `<integration>`, `wazuh-integratord` invoca automáticamente `custom-misp_ip.py`, pasándole el JSON completo de esa alerta más la API key y la URL de MISP.
   3. El script extrae la IP origen de la alerta y consulta `/attributes/restSearch` en MISP: "¿hay algún atributo con este valor?".
   4. Cuando el script termina la consulta, no "contesta" a nadie: simplemente escribe una línea de texto con el resultado, por ejemplo `{"integration": "misp_ip", "misp_ip": {"found": 1, ...}}`, y la deja caer en un buzón especial de Wazuh (el socket `queue/sockets/queue`). Ese buzón es la misma puerta de entrada por la que llega cualquier log (los de Snort, los de sudo, etc.), así que a partir de este punto Wazuh trata esa línea exactamente igual que si fuera un log más que acaba de llegar, sin saber ni importarle que en realidad venga de un script y no de un fichero.
   5. Como es un log más, Wazuh lo compara contra todas sus reglas, y ahí es donde entran `600200`-`600203`: son las únicas reglas que "reconocen" ese log concreto (buscan el campo `"integration":"misp_ip"`) y deciden qué hacer con él: `600202` (nivel 12) si `found` es `1` (coincidencia), `600201` (nivel 0, silenciosa) si `found` es `0`, `600203` si hubo un error de conexión o credenciales.
4. **Por qué así:** separa claramente "detectar" (Snort + reglas de Snort del Level-01) de "enriquecer con contexto" (este script). Wazuh sigue funcionando igual sin MISP, y MISP solo añade una capa de contexto encima de alertas que ya existían.

**Cómo verlo con vuestros propios ojos:**

* El código que se va a desplegar es legible **antes** de ejecutar nada, directamente en `automation/wazuh-misp.sh`: el bloque entre `cat > "$TMP_INTEGRATION" <<'PYEOF'` y `PYEOF` es el script Python completo; el bloque con `<group name="local,misp,threat_intel,">` son las reglas.
* **Después** de desplegarlo, en el propio Wazuh Manager:

  ```bash
  cat /var/ossec/integrations/custom-misp_ip.py
  cat /var/ossec/etc/rules/misp_ip_rules.xml
  sudo grep -A8 "custom-misp_ip.py" /var/ossec/etc/ossec.conf
  ```

---

### 2.4.1. Preparación e identificación (estado previo)

Confirme que el evento del ejercicio 2.1 sigue **publicado** en MISP, con la IP de `caldera-server` marcada como IDS.

**Evidencie**

* Captura del evento en MISP (recordatorio del estado de partida).

### 2.4.2. Ejecución (despliegue de la integración)

Desde el anfitrión:

```bash
cd nics-cyberlab-edu-lite/automation
sudo bash wazuh-misp.sh
```

Responda a las preguntas:

* Datos SSH del **Wazuh Manager**.
* **URL de MISP** y **API key** (la del usuario de laboratorio del ejercicio 2.3, no la de admin).
* IDs de regla que disparan la consulta: deje el valor por defecto (`600001,600010`).

Confirme el resumen (`y`) y espere a que el script termine (instala el script de integración, las reglas, y reinicia `wazuh-manager`).

**Evidencie**

* Salida completa del script, o al menos el resumen final.

### 2.4.3. Validación end-to-end (Snort → Wazuh → MISP)

#### Generar tráfico detectable

Desde `caldera-server`:

```bash
ping -c 4 <IP_SNORT>
```

(o el escaneo `nmap -sS -Pn` del Ejercicio 1.4 del Level-01).

#### Comprobar el enriquecimiento en Wazuh Manager (línea de comandos)

```bash
sudo grep '"integration":"misp_ip"' /var/ossec/logs/alerts/alerts.json | tail -5
```

> `integrations.log` solo se rellena con `debug: true` (ver Troubleshooting); no es el sitio para comprobar esto por defecto.

**Resultado esperado**

* Alerta con `rule.id = 600202` (nivel 12), incluyendo la IP de `caldera-server` y un `permalink` hacia el evento de MISP del ejercicio 2.1.

#### Comprobar el enriquecimiento en el Dashboard de Wazuh

La misma alerta 600202 aparece también en la interfaz gráfica, igual que los eventos de Snort del apartado 1.2.5 del Level-01 (Ejercicio 1.2, Visualización en Wazuh):

1. **☰ → Threat Intelligence → Threat Hunting** (o **→ Events**, según versión).
2. Seleccione el agente `snort-server` y ajuste el rango temporal para cubrir el momento en que generó el tráfico.
3. Filtre por `rule.id: 600202` (o busque por la palabra clave `misp`).
4. Abra el evento: en el campo `data.misp_ip.permalink` está el enlace directo al evento de MISP.

**Evidencie**

* Captura/log de la alerta 600202 con el `permalink` (línea de comandos o Dashboard).
* Captura del evento en MISP confirmando que el `permalink` apunta al mismo evento.

#### (Opcional) Contraste con una IP desconocida

Si es posible generar tráfico detectado por Snort desde un origen que **no** esté registrado en MISP, repita la prueba y compruebe que solo aparece `rule.id = 600201` (`found: 0`), sin alerta de nivel 12, para evidenciar la diferencia entre "IP desconocida" e "IP con antecedentes".

**Evidencie**

* Captura/log de la alerta 600201 (sin coincidencia).

### Validación / Troubleshooting

* `integrations.log` solo se rellena si `debug` está a `true` en las `<options>` del bloque `<integration>` de `ossec.conf` (por defecto está en `false`). Si lo ve vacío, no es necesariamente un fallo: busque errores directamente en el log general de Wazuh:

  ```bash
  sudo tail -n 100 /var/ossec/logs/ossec.log | grep -i integrat
  ```

  Si aparecen líneas `wazuh-integratord: ERROR: While running custom-misp_ip.py ... Exit status was: 1`, la integración se está invocando pero el script falla: siga con el resto de puntos.
* Confirme primero que las reglas base 600001/600010 (ejercicio de Snort del Level-01) se están disparando, antes de sospechar de la parte MISP:

  ```bash
  sudo grep -c '"rule":{"level":7,"description":"Snort ICMP detection"' /var/ossec/logs/alerts/alerts.json
  ```

  (el `rule.id` va anidado bajo `"rule":{"id":"600001",...}`, no en el `"id"` de nivel superior del alert, que es el identificador único del evento).
* Si `wazuh-integratord` da `Exit status was: 1` y en el log aparece `Output: Exception`, pruebe el script a mano para ver el traceback completo:

  ```bash
  sudo grep '"rule":{"id":"600001"' /var/ossec/logs/alerts/alerts.json | tail -1 | sudo tee /tmp/test_alert.json
  sudo /var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-misp_ip.py \
    /tmp/test_alert.json "<API_KEY>" "https://<IP_MISP>" debug
  ```
* Si `misp_ip.error` aparece con código `403`, revise la API key configurada en `ossec.conf` (`<api_key>`).
* Recuerde que Snort debe estar en ejecución (`sudo snort -i ens33 ...`) para que exista tráfico que detectar.

### Evidencias a entregar

* Log de ejecución de `wazuh-misp.sh`.
* Alerta 600202 con el `permalink` a MISP.
* Evento en MISP correspondiente.
* (Si se realiza) alerta 600201 de contraste.

### Conclusión final

Incluya:

* Qué aporta esta integración frente a Snort + Wazuh solos (Level-01): pasar de "hay tráfico sospechoso" a "hay tráfico de un origen con antecedentes conocidos en threat intelligence".
* Cómo esto refuerza el ciclo **detección → investigación → mejora → reporte** con una capa adicional de contexto.
* Valor SOC: priorización del triage.

---

## Ejercicio 2.5 — MISP: exportación de reglas Snort (NIDS)

### Objetivo

Usar la exportación nativa de MISP a formato Snort/Suricata (NIDS) para convertir atributos de red marcados como IDS (`to_ids=true`) en reglas Snort reales, cerrando el flujo de threat intelligence en la dirección opuesta al ejercicio 2.4: aquí es **MISP quien alimenta a Snort** (detección proactiva en el propio IDS), en vez de que Snort dispare una consulta reactiva a MISP.

### Prerrequisitos

* Ejercicio 2.1 completado (evento publicado en MISP, con el atributo `ip-src` de `caldera-server` marcado como IDS).
* Acceso SSH al nodo `snort-server`.
* Rol de usuario de laboratorio (`Publisher`), confirmado que no requiere privilegios de administrador.

---

### 2.5.1. Preparación e identificación

Confirme que el evento del ejercicio 2.1 sigue publicado, con el atributo `ip-src` marcado como **IDS** (columna/icono "IDS" activo en la vista del evento): solo los atributos con ese flag se incluyen en la exportación NIDS.

**Evidencie**

* Captura del evento en MISP mostrando el atributo `ip-src` marcado como IDS.

### 2.5.2. Ejecución (exportación y despliegue en Snort)

#### Exportar las reglas desde MISP

1. En la vista del evento, use el botón **Download as...** y seleccione el formato **Snort rules** (o equivalente NIDS/Snort en el listado de formatos).
2. Descargue el fichero `.rules` generado.

**Evidencie**

* Captura de la opción de exportación usada en MISP.
* Contenido del fichero `.rules` descargado (debe incluir la IP de `caldera-server`).

#### Desplegar la regla en snort-server

1. Transfiera el fichero a `snort-server` (p. ej. `scp`).
2. Relance Snort incluyendo el fichero de reglas de MISP además de la configuración habitual:

```bash
sudo snort -i ens33 -c /etc/snort/snort.lua -R <ruta_al_fichero_misp>.rules -A alert_fast -k none -l /var/log/snort
```

**Evidencie**

* Captura/log de Snort arrancando con la regla de MISP cargada, sin errores de parseo.

### 2.5.3. Validación (detección proactiva)

1. Desde `caldera-server` (la IP ya registrada en el evento de MISP), genere tráfico hacia `snort-server`.
2. Compruebe en `alert_fast.txt` que Snort detecta el tráfico **con la regla generada por MISP**, distinta de las reglas ICMP/SYN-scan del Level-01:

```bash
sudo tail -f /var/log/snort/alert_fast.txt
```

**Resultado esperado**

* Una alerta cuyo SID/mensaje corresponde a la regla exportada de MISP (no a las reglas `wazuh-snort.sh` del Level-01), referenciando el evento/atributo de origen.

**Evidencie**

* Captura de `alert_fast.txt` con la alerta generada por la regla de MISP.

### Validación / Troubleshooting

* Si la exportación no incluye la IP esperada, confirme que el atributo tiene el flag **IDS** activo: MISP excluye del export NIDS cualquier atributo sin ese flag.
* Si Snort da error al cargar el `.rules` por colisión de SID, tenga en cuenta que las reglas locales del Level-01 ya usan SIDs propios (visibles en `alert_fast.txt` como `[1:1001001:1]` y `[1:1000010:1]`); verifique en la práctica el rango de SIDs que asigna vuestra instalación de MISP y ajuste si colisiona.
* Si no aparece ninguna alerta nueva, confirme que relanzó Snort **incluyendo** el nuevo fichero de reglas (`-R`), no solo con `snort.lua`.

### Evidencias a entregar

* Fichero `.rules` exportado desde MISP.
* Log de Snort arrancando con la regla cargada.
* Alerta de `alert_fast.txt` generada por la regla de MISP.

### Conclusión final

Incluya:

* Diferencia entre este ejercicio (MISP → Snort, proactivo) y el ejercicio 2.4 (Snort → Wazuh → MISP, reactivo): quién actúa primero y en qué capa ocurre la detección.
* Qué mantenimiento exige este modelo (refrescar la exportación cuando cambien los IOCs en MISP) frente al modelo reactivo, que consulta MISP en vivo en cada alerta.
* Cuándo tiene sentido cada patrón en un SOC real: detección proactiva de IOCs conocidos en el perímetro frente a enriquecimiento contextual de alertas ya generadas.

---

## Investigación Opcional — MISP → Snort: automatización de IoCs e IDPS

Actividad opcional para llevar el ejercicio 2.5 (exportación manual, puntual) un paso más allá: **automatizar** la exportación de IoCs de MISP a Snort, y explorar qué implicaría pasar de un IDS puramente pasivo (alerta) a un **IDPS** capaz de cortar tráfico de forma activa (`drop`/`reject`). El objetivo consiste en entender **qué cambia técnica y operativamente** al automatizar ese paso, y documentar los riesgos con el mismo rigor que el resto del laboratorio.

> Idea: elegir **2-3 bloques** y documentar cada uno con *concepto → prueba (o diseño, si no es viable en el VM actual) → evidencia → conclusión*.

### Qué se entrega

1. **Documento breve** (2-3 páginas) con un apartado por bloque elegido.
2. **Script(s)** desarrollados (si el bloque lo incluye) y su código comentado.
3. **Capturas/logs** de las pruebas realizadas.
4. **Checklist** final de lo probado (probado / diseñado pero no ejecutado / pendiente), justificando por qué en cada caso.

### Bloques de investigación (elige 2-3)

#### 1) Automatizar la exportación MISP → Snort

**Teoría (qué entender)**

* El ejercicio 2.5 usa **Download as...** manualmente, una vez. En producción, los IoCs de MISP cambian constantemente: hace falta un proceso que repita esa exportación de forma periódica sin intervención humana.
* MISP expone la misma exportación NIDS por API (autenticada con API key), lo que permite guionizarla con `curl`/`PyMISP`.
* Recargar Snort con reglas nuevas no es gratis: hay que decidir entre reiniciar el proceso (corta la captura unos instantes) o usar un mecanismo de recarga en caliente si la versión de Snort lo soporta, y validar la sintaxis del `.rules` **antes** de aplicarlo (una regla mal formada no debería tumbar todo el IDS).

**Práctica (qué probar)**

* Escribir un script propio (bash o Python) que:
  * autentique contra la API de MISP con una API key (reutilizando el usuario del ejercicio 2.0/2.3, con el privilegio mínimo necesario),
  * descargue la exportación NIDS de uno o varios eventos (o de un feed concreto),
  * sustituya el fichero de reglas en `snort-server` de forma idempotente (sin duplicar reglas en ejecuciones repetidas),
  * valide la sintaxis antes de aplicar el cambio,
  * recargue o relance Snort.
* Programar la ejecución periódica (`cron` o `systemd timer`) y dejarlo correr varios ciclos.
* Añadir un IoC nuevo en MISP entre dos ejecuciones y comprobar que aparece automáticamente en Snort sin intervención manual.

**Evidencia**

* Código del script + log de al menos 2 ejecuciones automáticas.
* Captura de un IoC añadido en MISP y, en la siguiente ejecución programada, detectado por Snort sin haber tocado nada a mano.

---

#### 2) De IDS a IDPS: qué exige realmente el modo `drop`

**Teoría (qué entender)**

* Snort en modo **IDS** (el que usa el laboratorio) es pasivo: recibe una copia del tráfico y solo alerta, nunca corta nada, así que una regla `drop` en ese modo **no bloquea de verdad**.
* Para bloquear tráfico de forma real (**IDPS/IPS**), Snort necesita estar **en línea** con el tráfico, no en una copia (span/mirror): recibiendo el paquete, decidiendo, y reenviándolo o descartándolo antes de que llegue a su destino. Esto exige un modo de captura distinto (p. ej. AF_PACKET en modo inline con dos interfaces formando un puente, o NFQUEUE vía `iptables`), no un simple cambio de `alert` a `drop` en la regla.
* Investigar primero si el `snort-server` actual del laboratorio está desplegado en una posición de red que permitiría modo inline (¿tiene una única interfaz en modo promiscuo, o dos interfaces en el camino real del tráfico?). Es muy probable que la topología actual (pensada para IDS) no lo permita sin cambios de red; documentar por qué es un resultado válido de esta investigación.

**Práctica (qué probar)**

* Documentar la topología de red actual de `snort-server` y razonar si permite modo inline tal cual, o qué cambiaría falta (interfaces, bridge, `iptables`/NFQUEUE).
* Si el entorno lo permite (aunque sea en una VM de prueba aparte, **no** sobre el `snort-server` compartido del laboratorio, para no romper la detección del resto de ejercicios): montar una prueba mínima de Snort inline y comprobar que una regla `drop` corta de verdad una conexión de prueba.
* Si no es viable en el VM actual, diseñar (sin ejecutar) los pasos concretos que harían falta, como si fuera una propuesta de mejora de arquitectura para el laboratorio.

**Evidencia**

* Si se ejecuta: captura de una conexión bloqueada por `drop` en modo inline (y de la misma regla en modo IDS, sin bloquear, como contraste).
* Si no se ejecuta: documento de diseño con los cambios de red necesarios y por qué no se aplicaron sobre el `snort-server` compartido.

---

#### 3) Confianza y falsos positivos al automatizar el bloqueo

**Teoría (qué entender)**

* Automatizar IoCs de MISP hacia reglas `drop` sin filtrar es peligroso: un feed público puede incluir IPs obsoletas, mal atribuidas, o compartidas (NAT/CDN), y un `drop` automático convierte un error de threat intel en una interrupción de servicio real.
* Un enfoque más realista es **escalonado**: todo IoC nuevo entra en modo `alert` (como en el ejercicio 2.5); solo pasa a `drop` automáticamente si cumple un criterio de confianza explícito (por ejemplo, un tag concreto en MISP tipo `confirmed` o un nivel de TLP determinado, o si ha sido validado manualmente por un analista).

**Práctica (qué probar)**

* Proponer y documentar una política de confianza concreta para este laboratorio (qué tag/criterio en MISP habilitaría el paso a `drop`).
* Adaptar el script del bloque 1 para que filtre la exportación por ese criterio (p. ej. consultando solo atributos con un tag concreto vía la API) y genere **dos** ficheros de reglas separados: uno en `alert` (todo) y otro en `drop` (solo los de confianza alta).
* Razonar qué pasaría si un IoC de confianza alta resulta ser un falso positivo: cómo se detectaría y cómo se revertiría el bloqueo.

**Evidencia**

* Documento con la política de confianza propuesta.
* Los dos ficheros de reglas generados (`alert` vs `drop`) a partir del mismo evento/feed de MISP, con el filtro aplicado.

### Plantilla de ejemplo

Para cada bloque seleccionado, redactar:

* **Concepto:** qué es y por qué importa.
* **Prueba realizada (o diseño propuesto):** qué se ejecutó, o qué se habría ejecutado y por qué no fue posible en el VM actual.
* **Resultado observado:** qué pasó (éxito/fallo) y por qué crees que ocurrió.
* **Evidencias:** capturas, logs y/o código.
* **Conclusión:** qué aprendiste, qué riesgos identificaste, y qué mejorarías en una siguiente iteración.

---

###### © NICS LAB — NICS | CyberLab

_Proyecto experimental para entornos de laboratorio y formación en ciberseguridad._
