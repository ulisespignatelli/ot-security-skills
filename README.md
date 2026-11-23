# ot-security-skills

**Skills de ciberseguridad para redes industriales (OT/ICS/SCADA).** Funcionan en Claude.ai, en la app de escritorio y en Claude Code.
*Claude skills for industrial (OT/ICS) cybersecurity, aligned with IEC 62443 and the Purdue model.*

[![CI](https://github.com/ulisespignatelli/ot-security-skills/actions/workflows/ci.yml/badge.svg)](https://github.com/ulisespignatelli/ot-security-skills/actions/workflows/ci.yml)

| Skill | Qué hace |
|---|---|
| [`ot-segmentation-review`](plugins/ot-segmentation/skills/ot-segmentation-review/SKILL.md) | Revisa la segmentación de una planta según **IEC 62443** y el **modelo Purdue** a partir del inventario y las reglas de firewall. Arma el mapa de zonas y conductos y prioriza los caminos peligrosos: de IT a la planta, desde internet, protocolos industriales sin autenticación, acceso al SIS, accesos remotos sin jump host. |

## ot-segmentation-review

En OT, el incidente más caro casi nunca entra directo a un PLC. Entra por IT (un correo, una VPN, una carpeta compartida) y salta a la planta porque una regla de firewall de hace años lo permite. Esta skill encuentra esos caminos **sin tocar la red**: trabaja solo con documentación, porque en OT un escaneo activo puede detener equipos.

**Entradas:** dos CSV, que Claude puede armar a partir de una exportación de firewall (FortiGate, Palo Alto, Cisco ASA, pfSense, iptables), de una planilla de activos o de una descripción en palabras.
- **Activos:** `name, ip, type [, level, zone, criticality]`. El nivel Purdue y la zona se deducen del tipo si faltan.
- **Reglas o flujos:** `src, dst [, protocol, port, action, rule_id]`. Pueden ser reglas de firewall o tráfico observado por una herramienta de monitoreo pasivo.

**Salidas:** informe con diagrama de zonas y conductos (Mermaid, se ve directo en GitHub), CSV y JSON de hallazgos.

**13 controles**, cada uno con severidad, explicación, corrección y referencia a los requisitos fundamentales de IEC 62443 (FR1 a FR7):

| | Control |
|---|---|
| OT-01 | Internet que llega directo a OT |
| OT-02 | IT que llega a OT sin pasar por la DMZ industrial |
| OT-03 | Equipos de OT que salen a IT o a internet |
| OT-04 | Protocolos industriales sin autenticación (Modbus, S7, DNP3, EtherNet/IP…) entre zonas, con severidad según de dónde vienen |
| OT-05 | Acceso al sistema instrumentado de seguridad (SIS) desde fuera de su zona |
| OT-06 | Acceso remoto que no pasa por un jump host; Telnet o VNC |
| OT-07 | Reglas con `any` que tocan OT |
| OT-08 / 09 | Administración en texto claro y protocolos de Windows (vía del ransomware) hacia control |
| OT-10 | Equipos que aparecen en reglas pero no en el inventario |
| OT-11 | Comunicaciones que saltean niveles Purdue |
| OT-12 / 13 | Sin denegación por defecto; activos sin nivel |

### Ejemplo

Con una planta potabilizadora **ficticia** ([activos](examples/activos.csv), [reglas](examples/reglas.csv)), la skill detecta, entre otros, VNC publicado a internet en la HMI, PCs de oficina leyendo Modbus de un PLC, SMB desde el ERP al SCADA, una regla `any` de ingeniería que alcanza al SIS y un PLC que manda telemetría a la nube sin TLS. También reconoce como válidas las reglas bien hechas: el acceso por jump host, la réplica del historiador en la DMZ y la VPN. [Ver el informe completo →](examples/informe-planta-ficticia.md)

En el chat se le pide algo así:

> Te paso el export de reglas del FortiGate entre IT y planta y la planilla de activos. El PLC-07 es el SIS de la caldera. ¿Qué tan bien segmentada está?

El script también se usa solo, sin Claude:

```bash
python3 plugins/ot-segmentation/skills/ot-segmentation-review/scripts/ot_review.py \
  --assets activos.csv --flows reglas.csv --out-dir ot-review-out
```

## Instalación

### Claude Code

```bash
claude plugin marketplace add ulisespignatelli/ot-security-skills
claude plugin install ot-segmentation@ulises-ot-security
```

### Claude.ai y app de escritorio

1. Descargá `ot-segmentation-review.zip` de la última [release](https://github.com/ulisespignatelli/ot-security-skills/releases).
2. Activá la ejecución de código en **Settings → Capabilities**.
3. Andá a **Customize → Skills**, tocá **+** → **Create skill** → **Upload a skill** y elegí el ZIP.

## Principios

- **Nada activo.** No escanea ni sugiere escanear redes en producción.
- **Primero la seguridad física y la continuidad.** Cada cambio se propone para una ventana de mantenimiento, con plan de vuelta atrás.
- **Explicable.** Cada hallazgo dice qué regla es, qué riesgo implica para el proceso y cómo se corrige.
- **Honesta.** Es una revisión documental: no reemplaza una evaluación de riesgos IEC 62443-3-2 ni la validación en sitio, y lo dice en cada informe.
- **Sin dependencias.** Solo biblioteca estándar de Python. 17 tests sobre una planta ficticia con errores plantados a propósito.

```bash
python3 -m unittest discover -s tests -v
claude plugin validate .
```

## Hoja de ruta

- [ ] Priorización de vulnerabilidades OT (avisos ICS de CISA, firmware, mitigación hasta la próxima parada)
- [ ] Inventario pasivo desde capturas de tráfico (PCAP)
- [ ] Guía de respuesta a incidentes en OT

## Licencia

MIT
