# Controles de la revisión

| Control | Severidad | Qué detecta | Por qué importa |
|---|---|---|---|
| **OT-01** | crítica | Tráfico de internet que termina en L0-L3 | Exposición directa de equipos de control. Muchos incidentes OT conocidos empezaron con una HMI o un acceso VNC publicado. |
| **OT-02** | crítica (L0-L2) / alta (L3) | IT (L4) que llega a OT sin pasar por la DMZ | Es el camino por el que el ransomware de IT llega a la planta. |
| **OT-03** | alta / media | Equipos de OT que inician conexiones hacia IT o internet | Exfiltración, comando y control, dependencias no documentadas (telemetría del fabricante). |
| **OT-04** | crítica → baja | Protocolo industrial sin autenticación que cruza zonas | Quien llega al puerto puede leer o escribir en el equipo. Desde la DMZ o IT es crítico; desde L3 o saltando niveles es alto; entre supervisión y su celda (L2→L1) es el riesgo residual normal: se acota con inspección del protocolo. |
| **OT-05** | crítica / alta | Acceso al SIS desde fuera de su zona | El SIS es la última barrera antes de un daño físico. |
| **OT-06** | alta / media | Acceso remoto (RDP, SSH, VNC, TeamViewer) a OT que no viene del jump host | Accesos de proveedores sin control, sin MFA y sin registro. |
| **OT-06b** | alta | Telnet o VNC hacia OT | Credenciales y sesión en texto claro. |
| **OT-07** | crítica / alta | Reglas con `any` en origen, destino o servicio que tocan OT | Anulan la segmentación. |
| **OT-08** | media | Administración en texto claro (FTP, TFTP, HTTP, SNMP v1/v2c) hacia control desde otra zona | Robo de credenciales y alteración de configuraciones. |
| **OT-09** | media | SMB, RPC o NetBIOS hacia control desde otra zona | Vía típica de propagación lateral del ransomware. |
| **OT-10** | media | Orígenes o destinos que no están en el inventario | No se puede proteger lo que no se conoce. |
| **OT-11** | media | Comunicación que saltea niveles Purdue (con protocolos que no son industriales inseguros) | Conductos no previstos en el diseño. |
| **OT-12** | media | Conjunto de reglas sin "deny any any" al final | Sin lista blanca explícita ni registro de lo bloqueado. |
| **OT-13** | baja | Activo sin nivel ni tipo reconocido | No se puede evaluar. |

## Tipos de activo y nivel por defecto
- **L0:** sensor, actuator, drive, field-device, instrument
- **L1:** plc, rtu, ied, controller, dcs-controller, pac, sis, safety-controller (los dos últimos van a la zona SIS)
- **L2:** hmi, scada, scada-server, eng-workstation, ews, opc-server, alarm-server, local-historian, operator-station
- **L3:** historian, mes, ops-workstation, ot-ad, ot-server, patch-server, backup-server, antivirus-server, ot-monitoring
- **L3.5:** jump-host, dmz-server, historian-mirror, remote-access-gateway, file-transfer, dmz-proxy, patch-dmz
- **L4:** it-server, workstation, erp, it-ad, email, it, laptop
- **L5:** internet, cloud, vendor, remote-vendor
- **Infraestructura (no se evalúa como origen ni destino):** firewall, switch, router, data-diode

## Protocolos reconocidos por puerto
Modbus/TCP 502 · S7comm / IEC 61850 MMS 102 · DNP3 20000 · EtherNet/IP 44818 y 2222/udp · IEC 60870-5-104 2404 · BACnet/IP 47808/udp · PROFINET 34962-34964 · OMRON FINS 9600 · HART-IP 5094 · GE-SRTP 18245 · MELSEC 5007 · Niagara Fox 1911 · PC Worx 1962 · ProConOS 20547 · OPC UA 4840/4843 · MQTT 1883 (8883 con TLS) · RDP 3389 · VNC 5900-5903 · SSH 22 · Telnet 23 · TeamViewer 5938 · FTP 21 · TFTP 69 · HTTP 80 · SNMP 161 · SMB 445 · RPC 135 · NetBIOS 137-139.

Si un protocolo industrial corre en un puerto no estándar, indicalo en la columna `protocol` (por ejemplo, `modbus`): el nombre tiene prioridad sobre el puerto.
