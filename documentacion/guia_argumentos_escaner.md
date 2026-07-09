# Guía de Argumentos y Configuración de Escaneo - SecScan

Este documento contiene la explicación técnica y empresarial de todos los parámetros, argumentos de línea de comandos (Nmap, SNMP, sockets) y configuraciones de red implementados en el motor de escaneo **SecScan** (`backend/core/scanner.py`).

Está estructurado para explicar **qué hace cada argumento, por qué se eligió y en qué casos prácticos sirve** para optimizar la visibilidad en entornos PYME y redes complejas.

---

## 📌 Índice de Contenidos
1. [Fase 1: Traceroute e Identificación de Topología](#1-fase-1-traceroute-e-identificación-de-topología)
2. [Fase 2: Descubrimiento de Dispositivos en Cascada](#2-fase-2-descubrimiento-de-dispositivos-en-cascada)
3. [Fase 3: Escaneo Profundo y Port Scan](#3-fase-3-escaneo-profundo-y-port-scan)
4. [Resumen y Guía Rápida de Casos de Uso (Cuadro de Escenarios)](#4-resumen-y-guía-rápida-de-casos-de-uso-cuadro-de-escenarios)

---

## 1. Fase 1: Traceroute e Identificación de Topología

En esta fase se dibuja la columna vertebral de la red enviando paquetes de prueba hacia un destino público externo (`8.8.8.8`) para mapear saltos intermedios.

### Comando Principal
```bash
nmap --traceroute -sn -T2 8.8.8.8
```

### Argumentos Explicados

| Argumento | Nombre Técnico | ¿Qué hace? | ¿En qué caso sirve? (Caso de Uso PYME) |
| :--- | :--- | :--- | :--- |
| `--traceroute` | Traceroute por Sondas | Envía sondas activas optimizadas de Nmap a cada salto para calcular el camino hacia el objetivo. | **Descubrimiento de extensores e infraestructura:** Permite identificar switches de capa 3, routers intermedios y subredes aisladas antes de salir a Internet. |
| `-sn` | Ping Scan (No Port Scan) | Desactiva por completo el escaneo de puertos en el destino intermedio y final. | **Acelerar la topología:** Sin `-sn`, Nmap intentaría escanear los 1,000 puertos por defecto de `8.8.8.8`, tardando minutos en completar una fase que solo requiere trazar la ruta en segundos. |
| `-T2` | Plantilla de Tiempo: *Polite* | Reduce la velocidad de envío de paquetes (añade retardos entre sondas) y aumenta el timeout. | **Evitar bloqueos de Firewall/IDS:** En redes PYME administradas o corporativas, los sistemas de seguridad bloquean instantáneamente barridos de red rápidos. `-T2` simula tráfico legítimo y persistente. |

### Fallback Automático
Si el comando Nmap falla debido a políticas de seguridad estrictas (bloqueo total de ICMP o sockets raw sin privilegios de Administrador), el motor ejecuta un fallback a `ipconfig` para extraer el `Default Gateway` (Puerta de Enlace Predeterminada) y continuar el escaneo sin interrumpir la experiencia de usuario.

---

## 2. Fase 2: Descubrimiento de Dispositivos en Cascada

Esta fase es el corazón de la velocidad del escáner. Utiliza una estrategia jerárquica para obtener dispositivos en menos de 5 minutos, bypassando firewalls e identificando IoT silenciosos.

---

### 🚀 Intento 1: SNMP Nativo (Protocolo de Gestión de Red)
Consulta de forma directa la tabla ARP (`ipNetToMediaPhysAddress`) a través del protocolo SNMP en el router principal.

#### Parámetros Técnicos (Código Python con `pysnmp`)
* **OID consultado:** `1.3.6.1.2.1.4.22.1.2`
* **Timeout:** `3.0s` (Límite estricto de espera de socket)
* **Reintentos (Retries):** `1`
* **Comunidades probadas:** `["public", "private"]`

#### ¿Para qué sirve y en qué caso se usa?
* **Dispositivos ocultos / Evasión de Firewalls:** Si un dispositivo (como una PC de trabajo) tiene su firewall activo y bloquea pings/puertos, el Router Principal de igual manera *debe* comunicarse con él para entregarle tráfico de red, por lo que su IP y dirección MAC **sí están guardadas en la tabla ARP del Router**. 
* **Caso de Uso:** SNMP nos permite "preguntarle" al router quién está conectado. Obtenemos el 100% de los dispositivos activos de manera instantánea (en menos de 3 segundos) sin enviar un solo paquete a los dispositivos finales. Esto es óptimo para **PYMEs con políticas de firewalls estrictas**.

---

### 🚀 Intento 2: Búsqueda de Servidor DHCP Activo
Si el router no tiene SNMP habilitado, el escáner busca un servidor DHCP alternativo en la subred que pueda tener la lista de concesiones de IPs de red.

#### Comando de Descubrimiento DHCP
```bash
nmap -sU -p 67 -T2 <network_range>
```

#### Argumentos Explicados

| Argumento | Nombre Técnico | ¿Qué hace? | ¿En qué caso sirve? (Caso de Uso PYME) |
| :--- | :--- | :--- | :--- |
| `-sU` | UDP Port Scan | Realiza un escaneo de puertos sobre el protocolo UDP en lugar del tradicional TCP. | **Mapear Servicios UDP:** DHCP opera en el puerto UDP 67. Los escaneos normales de TCP no detectarán servidores DHCP o de DNS locales. |
| `-p 67` | Selección de Puerto Único | Restringe el escaneo estrictamente al puerto 67. | **Foco y Velocidad:** Escanear puertos UDP es extremadamente lento por diseño de red. Filtrar solo el puerto 67 permite barrer una red de 256 IPs en menos de 10 segundos buscando servidores de red. |
| `-T2` | Plantilla de Tiempo: *Polite* | Mantiene el ritmo de envío moderado para sockets UDP de Windows. | **Estabilidad del Driver de Red (Npcap):** Windows es muy inestable al manejar ráfagas masivas de paquetes UDP crudos. `-T2` asegura que no se pierdan respuestas. |

---

### 🚀 Intento 3: Descubrimiento Híbrido TCP/UDP/ICMP (Último Recurso)
Si los métodos de consulta centralizados fallan, el escáner realiza un barrido de red altamente inteligente utilizando una combinación de sondas de descubrimiento.

#### Comando de Descubrimiento Híbrido
```bash
nmap -sn -PE -PS21,22,23,80,139,443,445,9100,8080 -PA21,22,23,80,139,443,445,9100,8080 -PU53,137,161 -T3 <network_range>
```

#### Argumentos Explicados

| Argumento | Nombre Técnico | ¿Qué hace? | ¿En qué caso sirve? (Caso de Uso PYME) |
| :--- | :--- | :--- | :--- |
| `-sn` | Ping Sweep (No Port Scan) | Realiza únicamente el descubrimiento de hosts encendidos, sin escanear puertos. | **Velocidad de Barrido:** Barrer una red de clase C (/24) buscando hosts activos toma menos de 40 segundos si se desactiva el mapeo de puertos individuales. |
| `-PE` | ICMP Echo Request | Envía un ping convencional a cada IP de la red. | **Mapear Dispositivos Estándar:** Detecta rápidamente laptops Mac/Linux, routers y servidores empresariales que tienen el protocolo ICMP habilitado. |
| `-PS21,22,...` | TCP SYN Ping | Envía paquetes de inicio de conexión TCP a los puertos más populares (HTTP, SSH, SMB, Impresoras). | **Dispositivos sin respuesta ICMP (Ping bloqueado):** Si una PC tiene el ping bloqueado pero tiene una carpeta compartida (`445`), una impresora (`9100`) o un panel de administración (`8080`), responderá confirmando que está encendida. |
| `-PA21,22,...` | TCP ACK Ping | Envía paquetes de confirmación TCP vacíos. | **Evasión de Firewalls de Estado (Stateful):** Los Firewalls de Windows bloquean ICMP y paquetes SYN entrantes (descartándolos en silencio). Sin embargo, al recibir un paquete ACK falso, la pila TCP de Windows cree que es un error de una sesión existente y **responde de inmediato con un paquete RST (Reset)**. Nmap captura este RST y marca la PC como encendida. Es el arma secreta para descubrir PCs de escritorio Windows 10/11 "invisibles". |
| `-PU53,137,161` | UDP Ping | Envía paquetes UDP vacíos a puertos de infraestructura (DNS, NetBIOS, SNMP). | **Mapeo de IoT UDP-Only:** Muchos sensores, cámaras IP, impresoras antiguas o teléfonos VoIP no tienen servicios TCP activos. Responderán con un error ICMP "Port Unreachable" al recibir paquetes en estos puertos, revelando su existencia. |
| `-T3` | Plantilla de Tiempo: *Normal* | Utiliza la velocidad de escaneo estándar optimizada para redes locales LAN de alto rendimiento. | **Velocidad sin saturación:** En este punto secundario del algoritmo, optimiza la velocidad para terminar el barrido en un máximo de 30-40 segundos sin saturar los recursos de Windows. |

---

## 3. Fase 3: Escaneo Profundo y Port Scan

Una vez descubiertos los hosts activos, se ejecuta un análisis profundo de vulnerabilidades y servicios de forma paralela.

### Comando Principal
```bash
nmap -sV -T3 --top-ports 100 --max-retries 1 <ip_target>
```

### Argumentos Explicados

| Argumento | Nombre Técnico | ¿Qué hace? | ¿En qué caso sirve? (Caso de Uso PYME) |
| :--- | :--- | :--- | :--- |
| `-sV` | Detección de Versiones | Envía firmas de protocolo específicas a los puertos abiertos para analizar la cabecera y determinar la versión exacta de la aplicación. | **Auditoría de Vulnerabilidades (CVE):** Permite detectar servicios desactualizados (ej. *Apache 2.4.41* en lugar de solo *HTTP*) para indicar si el dispositivo es vulnerable a exploits conocidos. |
| `-T3` | Plantilla de Tiempo: *Normal* | Mantiene una velocidad de escaneo rápida y estable. | **Precisión de Huellas:** El escaneo de versiones requiere enviar y recibir textos (banners). `-T3` proporciona el tiempo de espera exacto para que el servidor responda sin causar timeouts falsos. |
| `--top-ports 100` | Escaneo Limitado a Top 100 | Escanea únicamente los 100 puertos más atacados y comunes de la base de datos de Nmap (en lugar de los 1,000 por defecto). | **Cumplimiento estricto del SLA (< 5 min):** Escanear 1,000 puertos en 20 hosts secuencialmente puede tomar 10 minutos. Reducir a los 100 puertos críticos proporciona el 95% de la superficie de ataque relevante en una fracción del tiempo (menos de 3 segundos por host). |
| `--max-retries 1` | Límite de Reintentos de Puerto | Si una sonda se pierde en la red, Nmap solo intentará enviarla una vez más en lugar de reintentarla continuamente. | **Optimización para redes Wi-Fi saturadas:** En PYMEs con redes inalámbricas inestables, esto evita que el escáner se cuelgue infinitamente reintentando puertos lentos, finalizando el escaneo rápidamente. |

### Resoluciones Secundarias en Código
Para garantizar el nombre exacto de los dispositivos (`hostname`) sin depender únicamente de Nmap, el motor realiza las siguientes consultas directas desde Python:
1. **DNS Inverso nativo (`socket.gethostbyaddr`):** Intenta traducir la IP al nombre registrado en el servidor DNS local (muy útil para servidores y controladores de dominio).
2. **NetBIOS (`nbtstat -A`):** Para equipos Windows en la misma LAN, consulta el puerto `137` para extraer el nombre de equipo de red de Windows (Workgroup/Domain).

---

## 4. Resumen y Guía Rápida de Casos de Uso (Cuadro de Escenarios)

A continuación se muestra qué argumentos y técnicas salvan el escaneo en diferentes escenarios empresariales reales:

| Escenario PYME | Problema de Red | Técnica / Argumento Aplicado | Resultado de SecScan |
| :--- | :--- | :--- | :--- |
| **PC Windows con Firewall Activo** | Bloquea pings tradicionales e ignora peticiones de puertos. Es "invisible". | **ACK Ping (`-PA`)** y **Consulta SNMP ARP (`1.3.6.1.2.1.4.22.1.2`)**. | El escáner la detecta como encendida y recupera su IP y MAC sin alertar al sistema operativo. |
| **Dispositivos IoT (Cámaras/Sensores)** | No tienen puertos HTTP, SSH o SMB abiertos. Solo hablan UDP. | **UDP Ping (`-PU53,137,161`)**. | El dispositivo responde con un error ICMP revelando que está encendido y listo para auditoría. |
| **Switches y Routers Intermedios** | Bloquean barridos de red rápidos por políticas de seguridad (Flood Protection). | **Traceroute Moderado (`-T2`)**. | Se traza el esqueleto de la red sin que la IP del escáner sea bloqueada por los switches administrados. |
| **Doble NAT / Subred Remota Oculta** | El tráfico hacia la subred remota es descartado o traducido, lo que causa demoras de 15 minutos en el escáner. | **Aborto Temprano de "Frontera Opaca"**. | Si la red está detrás de un salto NAT y SNMP no responde en el gateway, el escáner se auto-limita y aborta en 3 segundos en esa rama para no colgar la cola. |
| **Redes de Alta Inestabilidad (Wi-Fi)** | Se pierden paquetes de red, causando retardos masivos por reintentos de puertos. | **Limitación de Reintentos (`--max-retries 1`)**. | El escaneo mantiene su velocidad óptima sin retrasos falsos en canales inalámbricos saturados. |
