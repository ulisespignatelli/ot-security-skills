#!/usr/bin/env python3
"""Revision de segmentacion de una red OT segun IEC 62443 y el modelo Purdue.

Trabaja SOLO con documentacion: inventario de activos y reglas de firewall (o flujos observados).
Nunca toca la red: en OT un escaneo activo puede detener equipos.

Entradas (CSV):
  activos:  name, ip, type [, level, zone, criticality, notes]
            ip puede ser una IP o una red CIDR (para grupos de equipos).
  flujos:   src, dst [, protocol, port, transport, action, rule_id, comment]
            src/dst: nombre de activo, IP, CIDR, "any" o "internet".
            Con columna action se interpretan como REGLAS de firewall; sin ella, como TRAFICO observado.

Salidas: informe Markdown (con diagrama Mermaid de zonas y conductos), JSON y CSV de hallazgos.

Uso:
  ot_review.py --assets activos.csv --flows reglas.csv [--out-dir DIR] [--format md|json|csv|all]
"""
from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import date

# ----------------------------------------------------------------------------- conocimiento

# Nivel Purdue por tipo de activo. 3.5 = DMZ industrial (entre IT y OT).
TYPE_LEVEL = {
    "sensor": 0, "actuator": 0, "drive": 0, "field-device": 0, "instrument": 0,
    "plc": 1, "rtu": 1, "ied": 1, "controller": 1, "dcs-controller": 1, "sis": 1, "safety-controller": 1, "pac": 1,
    "hmi": 2, "scada": 2, "scada-server": 2, "eng-workstation": 2, "ews": 2, "opc-server": 2, "alarm-server": 2,
    "local-historian": 2, "operator-station": 2,
    "historian": 3, "mes": 3, "ops-workstation": 3, "ot-ad": 3, "ot-server": 3, "patch-server": 3, "backup-server": 3,
    "antivirus-server": 3, "ot-monitoring": 3,
    "jump-host": 3.5, "dmz-server": 3.5, "historian-mirror": 3.5, "remote-access-gateway": 3.5, "file-transfer": 3.5,
    "dmz-proxy": 3.5, "patch-dmz": 3.5,
    "it-server": 4, "workstation": 4, "erp": 4, "it-ad": 4, "email": 4, "it": 4, "laptop": 4,
    "internet": 5, "cloud": 5, "vendor": 5, "remote-vendor": 5,
}
SAFETY_TYPES = {"sis", "safety-controller"}
INFRA_TYPES = {"firewall", "switch", "router", "data-diode"}
LEVEL_NAME = {0: "L0 Proceso", 1: "L1 Control", 2: "L2 Supervisión", 3: "L3 Operaciones", 3.5: "L3.5 DMZ industrial",
              4: "L4 Empresa (IT)", 5: "L5 Internet"}

# Protocolos: (nombre, transporte, puertos). "insecure" = sin autenticacion ni cifrado nativos en su uso habitual.
PROTOCOLS = {
    "modbus":      {"ports": {("tcp", 502)}, "kind": "industrial", "insecure": True, "label": "Modbus/TCP"},
    "s7":          {"ports": {("tcp", 102)}, "kind": "industrial", "insecure": True, "label": "S7comm / MMS"},
    "dnp3":        {"ports": {("tcp", 20000), ("udp", 20000)}, "kind": "industrial", "insecure": True, "label": "DNP3"},
    "enip":        {"ports": {("tcp", 44818), ("udp", 44818), ("udp", 2222)}, "kind": "industrial", "insecure": True, "label": "EtherNet/IP (CIP)"},
    "iec104":      {"ports": {("tcp", 2404)}, "kind": "industrial", "insecure": True, "label": "IEC 60870-5-104"},
    "bacnet":      {"ports": {("udp", 47808)}, "kind": "industrial", "insecure": True, "label": "BACnet/IP"},
    "profinet":    {"ports": {(t, p) for t in ("tcp", "udp") for p in (34962, 34963, 34964)}, "kind": "industrial", "insecure": True, "label": "PROFINET"},
    "fins":        {"ports": {("udp", 9600), ("tcp", 9600)}, "kind": "industrial", "insecure": True, "label": "OMRON FINS"},
    "hart-ip":     {"ports": {("tcp", 5094), ("udp", 5094)}, "kind": "industrial", "insecure": True, "label": "HART-IP"},
    "ge-srtp":     {"ports": {("tcp", 18245)}, "kind": "industrial", "insecure": True, "label": "GE-SRTP"},
    "melsec":      {"ports": {("tcp", 5007)}, "kind": "industrial", "insecure": True, "label": "MELSEC"},
    "fox":         {"ports": {("tcp", 1911)}, "kind": "industrial", "insecure": True, "label": "Niagara Fox"},
    "pcworx":      {"ports": {("tcp", 1962)}, "kind": "industrial", "insecure": True, "label": "PC Worx"},
    "proconos":    {"ports": {("tcp", 20547)}, "kind": "industrial", "insecure": True, "label": "ProConOS"},
    "opc-ua":      {"ports": {("tcp", 4840), ("tcp", 4843)}, "kind": "industrial", "insecure": False, "label": "OPC UA"},
    "opc-classic": {"ports": set(), "kind": "industrial", "insecure": True, "label": "OPC DA/AE (DCOM)"},
    "mqtt":        {"ports": {("tcp", 1883)}, "kind": "industrial", "insecure": True, "label": "MQTT sin TLS"},
    "mqtts":       {"ports": {("tcp", 8883)}, "kind": "industrial", "insecure": False, "label": "MQTT con TLS"},
    "rdp":         {"ports": {("tcp", 3389)}, "kind": "remote", "insecure": False, "label": "RDP"},
    "vnc":         {"ports": {("tcp", p) for p in range(5900, 5904)}, "kind": "remote", "insecure": True, "label": "VNC"},
    "ssh":         {"ports": {("tcp", 22)}, "kind": "remote", "insecure": False, "label": "SSH"},
    "telnet":      {"ports": {("tcp", 23)}, "kind": "remote", "insecure": True, "label": "Telnet"},
    "teamviewer":  {"ports": {("tcp", 5938)}, "kind": "remote", "insecure": False, "label": "TeamViewer"},
    "ftp":         {"ports": {("tcp", 21)}, "kind": "cleartext", "insecure": True, "label": "FTP"},
    "tftp":        {"ports": {("udp", 69)}, "kind": "cleartext", "insecure": True, "label": "TFTP"},
    "http":        {"ports": {("tcp", 80)}, "kind": "cleartext", "insecure": True, "label": "HTTP"},
    "snmp":        {"ports": {("udp", 161)}, "kind": "cleartext", "insecure": True, "label": "SNMP v1/v2c"},
    "smb":         {"ports": {("tcp", 445)}, "kind": "windows", "insecure": False, "label": "SMB"},
    "msrpc":       {"ports": {("tcp", 135)}, "kind": "windows", "insecure": False, "label": "MS-RPC / DCOM"},
    "netbios":     {"ports": {("udp", 137), ("udp", 138), ("tcp", 139)}, "kind": "windows", "insecure": True, "label": "NetBIOS"},
    "https":       {"ports": {("tcp", 443)}, "kind": "web", "insecure": False, "label": "HTTPS"},
}
ALIASES = {"modbus-tcp": "modbus", "modbustcp": "modbus", "s7comm": "s7", "s7comm-plus": "s7", "iso-tsap": "s7", "mms": "s7",
           "iec61850": "s7", "iec-61850": "s7", "ethernet/ip": "enip", "ethernetip": "enip", "cip": "enip",
           "iec-104": "iec104", "iec60870-5-104": "iec104", "omron-fins": "fins", "hartip": "hart-ip", "srtp": "ge-srtp",
           "slmp": "melsec", "niagara-fox": "fox", "opcua": "opc-ua", "opc-da": "opc-classic", "dcom": "msrpc",
           "rpc": "msrpc", "cifs": "smb", "remote-desktop": "rdp", "anydesk": "teamviewer"}

# Redes que no son internet: RFC 1918, CGNAT, loopback, link-local y sus equivalentes IPv6.
INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                    "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")]

ANY_SRC, ANY_DST = "Cualquier origen", "Cualquier destino"

SEV_ORDER = {"critica": 0, "alta": 1, "media": 2, "baja": 3}


# ----------------------------------------------------------------------------- modelo

@dataclass
class Asset:
    name: str
    net: ipaddress._BaseNetwork | None
    type: str
    level: float | None
    zone: str
    criticality: str = "media"
    safety: bool = False
    infra: bool = False

    @property
    def ot(self) -> bool:
        return self.level is not None and self.level <= 3


@dataclass
class Flow:
    src: str
    dst: str
    protocol: str            # clave de PROTOCOLS, "any" o "unknown"
    port: str
    transport: str
    action: str
    rule_id: str
    row: int


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    detail: str
    recommendation: str
    iec62443: str
    src: str
    dst: str
    protocol: str
    rule_id: str = ""
    rows: list[int] = field(default_factory=list)


# ----------------------------------------------------------------------------- lectura

def read_csv(path: str) -> list[dict[str, str]]:
    with open(path, encoding="utf-8-sig") as fh:
        text = fh.read()
    sample = text[:2048]
    dialect = csv.Sniffer().sniff(sample, delimiters=",;\t") if sample.strip() else csv.excel
    rows = list(csv.DictReader(io.StringIO(text), dialect=dialect))
    return [{(k or "").strip().lower(): (v or "").strip() for k, v in r.items()} for r in rows]


def parse_net(s: str):
    s = s.strip()
    if not s:
        return None
    try:
        return ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None


def load_assets(path: str) -> list[Asset]:
    assets = []
    for i, r in enumerate(read_csv(path), start=2):
        name = r.get("name") or r.get("nombre") or r.get("hostname")
        if not name:
            raise ValueError(f"{path}:{i}: falta la columna name")
        typ = (r.get("type") or r.get("tipo") or "").lower().replace(" ", "-").replace("_", "-")
        lvl_raw = (r.get("level") or r.get("nivel") or "").upper().lstrip("L")
        level = None
        if lvl_raw:
            try:
                level = float(lvl_raw)
            except ValueError:
                raise ValueError(f"{path}:{i}: nivel inválido {lvl_raw!r} (usar 0, 1, 2, 3, 3.5, 4 o 5)") from None
        elif typ in TYPE_LEVEL:
            level = TYPE_LEVEL[typ]
        infra = typ in INFRA_TYPES
        safety = typ in SAFETY_TYPES or (r.get("safety") or "").lower() in ("1", "true", "si", "sí", "yes")
        zone = r.get("zone") or r.get("zona") or ""
        if not zone:
            zone = "SIS" if safety else (LEVEL_NAME.get(level, "Sin nivel") if level is not None else "Sin nivel")
        crit = {"high": "alta", "medium": "media", "low": "baja"}.get((r.get("criticality") or "").lower(),
                                                                          (r.get("criticality") or r.get("criticidad") or "media").lower())
        assets.append(Asset(name=name, net=parse_net(r.get("ip") or ""), type=typ or "desconocido", level=level,
                            zone=zone, criticality=crit, safety=safety, infra=infra))
    return assets


def proto_from(name: str, port: str, transport: str) -> str:
    n = (name or "").strip().lower()
    n = ALIASES.get(n, n)
    if n in PROTOCOLS:
        return n
    if n in ("any", "*", "all", "cualquiera"):
        return "any"
    p = (port or "").strip().lower()
    if p in ("", "any", "*", "all"):
        return "any" if not n else "unknown"
    t = (transport or "").lower()
    ports = expand_ports(p)
    for key, spec in PROTOCOLS.items():
        for (tr, num) in spec["ports"]:
            if num in ports and (not t or t == tr):
                return key
    return "unknown"


def expand_ports(p: str) -> set[int]:
    out: set[int] = set()
    for part in re.split(r"[,\s]+", p):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            if a.isdigit() and b.isdigit() and int(b) - int(a) < 70000:
                out.update(range(int(a), int(b) + 1))
        elif part.isdigit():
            out.add(int(part))
    return out


def load_flows(path: str) -> tuple[list[Flow], bool]:
    rows = read_csv(path)
    is_rules = bool(rows) and any("action" in r or "accion" in r or "acción" in r for r in rows)
    flows = []
    for i, r in enumerate(rows, start=2):
        src, dst = r.get("src") or r.get("source") or r.get("origen"), r.get("dst") or r.get("destination") or r.get("destino")
        if not src or not dst:
            raise ValueError(f"{path}:{i}: faltan src o dst")
        port = r.get("port") or r.get("dport") or r.get("puerto") or ""
        transport = r.get("transport") or r.get("proto") or ""
        name = r.get("protocol") or r.get("service") or r.get("servicio") or ""
        action = (r.get("action") or r.get("accion") or r.get("acción") or "allow").lower()
        action = "deny" if action in ("deny", "drop", "reject", "block", "denegar") else "allow"
        flows.append(Flow(src=src, dst=dst, protocol=proto_from(name, port, transport), port=port or "any",
                          transport=transport.lower(), action=action, rule_id=r.get("rule_id") or r.get("rule") or r.get("id") or "", row=i))
    return flows, is_rules


# ----------------------------------------------------------------------------- resolucion

class Resolver:
    """Traduce src/dst (nombre, IP, CIDR, any, internet) a activos del inventario."""

    def __init__(self, assets: list[Asset]):
        self.assets = assets
        self.by_name = {a.name.lower(): a for a in assets}
        self.internet = Asset(name="Internet", net=None, type="internet", level=5, zone=LEVEL_NAME[5])

    def resolve(self, ref: str) -> tuple[list[Asset], bool]:
        """Devuelve (activos, conocido). 'conocido' es False si la referencia no coincide con el inventario."""
        r = ref.strip()
        low = r.lower()
        if low in ("any", "*", "all", "cualquiera"):
            return [*self.assets, self.internet], True
        if low in ("internet", "external", "externo", "0.0.0.0/0"):
            return [self.internet], True
        if low in self.by_name:
            return [self.by_name[low]], True
        net = parse_net(r)
        if net is None:
            return [], False
        hits = [a for a in self.assets if a.net is not None and a.net.version == net.version and (a.net.subnet_of(net) or net.subnet_of(a.net))]
        if hits:
            return hits, True
        if not any(net.version == p.version and net.subnet_of(p) for p in INTERNAL_NETS):
            return [self.internet], True
        return [], False


# ----------------------------------------------------------------------------- reglas

def lv(a: Asset) -> float:
    return a.level if a.level is not None else -1


def check_flow(f: Flow, s: Asset, d: Asset, raw_any: tuple[bool, bool, bool], add) -> None:
    """Evalua un par origen-destino de un flujo permitido."""
    if s is d or s.infra or d.infra or s.level is None or d.level is None:
        return
    spec = PROTOCOLS.get(f.protocol)
    label = spec["label"] if spec else ("cualquier servicio" if f.protocol == "any" else f"puerto {f.port}")
    kind = spec["kind"] if spec else f.protocol
    cross = s.zone != d.zone
    src_any, dst_any, port_any = raw_any

    # OT-01: Internet directo a OT
    if s.level == 5 and d.level <= 3:
        add("OT-01", "critica", "Acceso directo desde internet a la red OT",
            f"{s.name} → {d.name} ({LEVEL_NAME[d.level]}) por {label}.",
            "Ningún flujo desde internet debe terminar en OT. El acceso remoto entra por un gateway en la DMZ industrial "
            "(L3.5) con MFA, y desde ahí a un jump host.", "FR5 Flujo de datos restringido; zona y conducto con internet", s, d, f)
        return
    # OT-02: IT directo a L0-L3 (sin DMZ)
    if s.level == 4 and d.level <= 3:
        sev = "critica" if d.level <= 2 else "alta"
        add("OT-02", sev, "La red corporativa (IT) llega a OT sin pasar por la DMZ",
            f"{s.name} ({LEVEL_NAME[4]}) → {d.name} ({LEVEL_NAME[d.level]}) por {label}.",
            "Todo intercambio IT↔OT debe terminar en la DMZ industrial: réplica del historiador, servidor de archivos o jump host. "
            "Ninguna regla debería permitir conexiones directas de L4 a L3 o niveles inferiores.",
            "FR5 Flujo de datos restringido; modelo de zonas y conductos (IEC 62443-3-2)", s, d, f)
        return
    # OT-03: OT inicia hacia IT o internet
    if s.level <= 3 and d.level >= 4:
        sev = "alta" if s.level <= 2 or d.level == 5 else "media"
        add("OT-03", sev, "Un equipo de OT inicia conexiones hacia IT o internet",
            f"{s.name} ({LEVEL_NAME[s.level]}) → {d.name} ({LEVEL_NAME[d.level]}) por {label}.",
            "Los equipos de control no deberían salir a IT ni a internet. Los datos hacia IT se publican en la DMZ "
            "(réplica del historiador) y las actualizaciones bajan desde un servidor de parches en la DMZ.",
            "FR5 Flujo de datos restringido", s, d, f)
    # OT-05: SIS
    if d.safety and s.zone != d.zone:
        sev = "critica" if s.level >= 3 else "alta"
        add("OT-05", sev, "Acceso al sistema instrumentado de seguridad (SIS) desde fuera de su zona",
            f"{s.name} ({s.zone}) → {d.name} (SIS) por {label}.",
            "El SIS protege vidas y equipos: debe estar en una zona propia. Solo la estación de ingeniería de seguridad accede, "
            "en ventanas controladas, con la llave de modo de programación en RUN o con un mecanismo equivalente. "
            "Para monitoreo, usar lectura de una sola vía.", "FR5 y FR3 Integridad del sistema; zona dedicada para funciones de seguridad", s, d, f)
    # OT-07: any/any
    if port_any and (s.ot or d.ot):
        add("OT-07", "critica" if d.safety or s.level >= 4 and d.level <= 3 else "alta", "Regla demasiado amplia (any) que toca OT",
            f"Regla {f.rule_id or 'fila ' + str(f.row)}: {s.name} → {d.name} por cualquier servicio.",
            "Reemplazar por reglas explícitas origen → destino → puerto, una por cada comunicación necesaria y documentada.",
            "FR5 Flujo de datos restringido (lista blanca de comunicaciones)", s, d, f, dedupe_pair=False)
    # OT-04: protocolo industrial inseguro que cruza zonas
    if spec and kind == "industrial" and spec["insecure"] and cross and not d.safety and 5 not in (s.level, d.level):
        # Supervision → control de una celda (L2 → L1) es el conducto normal de toda planta: riesgo residual.
        # Lo grave es que el protocolo llegue desde mas lejos (L3, DMZ, IT) o salte niveles.
        if s.level >= 3.5:
            sev = "critica"
        elif s.level >= 3 or abs(s.level - d.level) >= 2:
            sev = "alta"
        elif s.level == 2 and d.level <= 1:
            sev = "baja"
        else:
            sev = "media"
        add("OT-04", sev, f"Protocolo sin autenticación entre zonas: {spec['label']}",
            f"{s.name} ({s.zone}) → {d.name} ({d.zone}).",
            f"{spec['label']} no autentica a quien envía comandos: cualquiera que llegue a ese puerto puede leer o escribir en el equipo. "
            "Limitar el conducto a los orígenes estrictamente necesarios. Si el firewall lo permite, inspeccionar el protocolo "
            "y bloquear las funciones de escritura y programación desde fuera de la zona. A mediano plazo, migrar a variantes "
            "seguras (OPC UA con seguridad, DNP3-SA, CIP Security).",
            "FR1 Identificación y autenticación; FR5 Flujo de datos restringido", s, d, f)
    # OT-06: acceso remoto
    if spec and kind == "remote" and d.level <= 3 and cross and s.level != 3.5:
        sev = "alta" if spec["insecure"] or s.level >= 4 else "media"
        add("OT-06", sev, f"Acceso remoto ({spec['label']}) a OT sin pasar por un jump host en la DMZ",
            f"{s.name} ({LEVEL_NAME.get(s.level, s.zone)}) → {d.name} ({LEVEL_NAME[d.level]}).",
            "El acceso interactivo a OT (soporte, proveedores, ingeniería remota) debe pasar por un jump host en la DMZ "
            "industrial, con MFA, sesiones grabadas y habilitación por tiempo limitado.",
            "FR1 Identificación y autenticación; FR2 Control de uso", s, d, f)
    if spec and f.protocol in ("telnet", "vnc") and d.level <= 3:
        add("OT-06b", "alta", f"{spec['label']} hacia OT: credenciales y sesión en texto claro",
            f"{s.name} → {d.name}.", "Reemplazar por SSH o por RDP con NLA a través del jump host. Si el equipo solo soporta "
            f"{spec['label']}, encapsularlo en un túnel cifrado desde el jump host.", "FR4 Confidencialidad de los datos", s, d, f)
    # OT-08: administracion en claro hacia control
    if spec and kind == "cleartext" and d.level <= 2 and cross:
        add("OT-08", "media", f"Administración en texto claro ({spec['label']}) hacia equipos de control",
            f"{s.name} → {d.name}.", "Usar variantes cifradas (SFTP, HTTPS, SNMPv3) o limitar el origen a la estación de "
            "ingeniería de la misma zona.", "FR4 Confidencialidad de los datos", s, d, f)
    # OT-09: protocolos de Windows hacia control (camino tipico de ransomware)
    if spec and kind == "windows" and d.level <= 2 and cross:
        add("OT-09", "media", f"{spec['label']} hacia la red de control desde otra zona",
            f"{s.name} ({s.zone}) → {d.name} ({d.zone}).",
            "SMB y RPC son el camino típico por el que el ransomware salta de IT a las estaciones de OT. Transferir archivos "
            "por un servidor de la DMZ con antivirus, no con carpetas compartidas que cruzan zonas.",
            "FR5 Flujo de datos restringido; FR3 Integridad del sistema", s, d, f)
    # OT-11: salto de niveles dentro de OT
    if 0 <= d.level <= 3 and 0 <= s.level <= 3 and abs(s.level - d.level) >= 2 and not (spec and kind == "industrial" and spec["insecure"]):
        add("OT-11", "media", "Comunicación que saltea niveles del modelo Purdue",
            f"{s.name} ({LEVEL_NAME[s.level]}) → {d.name} ({LEVEL_NAME[d.level]}) por {label}.",
            "Los niveles se comunican con el adyacente. Si L3 necesita datos de L1, conviene leerlos desde un servidor "
            "de L2 (SCADA u OPC) en vez de abrir un conducto directo.", "Modelo Purdue; FR5 Flujo de datos restringido", s, d, f)


def review(assets: list[Asset], flows: list[Flow], is_rules: bool) -> tuple[list[Finding], dict]:
    res = Resolver(assets)
    findings: dict[tuple, Finding] = {}
    conduits: dict[tuple[str, str], set[str]] = {}
    unknown: dict[str, list[int]] = {}

    def add(check, sev, title, detail, rec, iec, s, d, f, dedupe_pair=True):
        key = (check, s.name, d.name, f.protocol) if dedupe_pair else (check, f.rule_id or f.row)
        if key in findings:
            if f.row not in findings[key].rows:
                findings[key].rows.append(f.row)
            return
        findings[key] = Finding(check, sev, title, detail, rec, iec, s.name, d.name,
                                PROTOCOLS[f.protocol]["label"] if f.protocol in PROTOCOLS else f.protocol, f.rule_id, [f.row])

    for f in flows:
        srcs, sk = res.resolve(f.src)
        dsts, dk = res.resolve(f.dst)
        if not sk:
            unknown.setdefault(f.src, []).append(f.row)
        if not dk:
            unknown.setdefault(f.dst, []).append(f.row)
        if f.action != "allow":
            continue
        raw_any = (f.src.lower() in ("any", "*", "all"), f.dst.lower() in ("any", "*", "all"), f.protocol == "any")
        if raw_any[0] or raw_any[1]:
            # Una regla con origen o destino "any" es un solo problema: se informa una vez, con su alcance.
            # Importa si la regla deja LLEGAR a OT, o si deja a un equipo de OT salir a cualquier lado.
            reach_ot = any(d.ot for d in dsts) or (raw_any[1] and any(s.ot for s in srcs))
            if reach_ot:
                sis = sorted({d.name for d in dsts if d.safety})
                inet = any(s.level == 5 for s in srcs) and any(d.ot for d in dsts)
                n = sum(raw_any)
                sev = "critica" if n >= 2 or sis or inet else "alta"
                scope = []
                if inet:
                    scope.append("permite tráfico desde internet hacia OT")
                if sis:
                    scope.append(f"alcanza al SIS ({', '.join(sis)})")
                ot_dsts = [d.name for d in dsts if d.ot]
                s0 = srcs[0] if len(srcs) == 1 else Asset("any", None, "any", None, "any")
                d0 = dsts[0] if len(dsts) == 1 else Asset("any", None, "any", None, "any")
                add("OT-07", sev, "Regla demasiado amplia (any) que toca OT",
                    f"Regla {f.rule_id or 'fila ' + str(f.row)}: {f.src} → {f.dst} por "
                    f"{'cualquier servicio' if raw_any[2] else (PROTOCOLS[f.protocol]['label'] if f.protocol in PROTOCOLS else 'puerto ' + f.port)}. "
                    f"Llega a {len(ot_dsts)} activos de OT" + (f"; {'; '.join(scope)}" if scope else "") + ".",
                    "Reemplazar por reglas explícitas origen → destino → puerto, una por cada comunicación necesaria y documentada.",
                    "FR5 Flujo de datos restringido (lista blanca de comunicaciones)", s0, d0, f, dedupe_pair=False)
            proto = "any" if raw_any[2] else (PROTOCOLS[f.protocol]["label"] if f.protocol in PROTOCOLS else f"puerto {f.port}")
            src_zones = {ANY_SRC} if raw_any[0] else {x.zone for x in srcs if not x.infra}
            dst_zones = {ANY_DST} if raw_any[1] else {x.zone for x in dsts if not x.infra}
            for zs in src_zones:
                for zd in dst_zones:
                    if zs != zd:
                        conduits.setdefault((zs, zd), set()).add(proto)
            continue
        for s in srcs:
            for d in dsts:
                if s is d:
                    continue
                if s.zone != d.zone and not s.infra and not d.infra:
                    conduits.setdefault((s.zone, d.zone), set()).add(
                        PROTOCOLS[f.protocol]["label"] if f.protocol in PROTOCOLS else ("any" if f.protocol == "any" else f"puerto {f.port}"))
                check_flow(f, s, d, raw_any, add)

    # OT-10: referencias que no estan en el inventario
    for ref, rows in unknown.items():
        findings[("OT-10", ref)] = Finding("OT-10", "media", "Origen o destino que no está en el inventario",
                                           f"«{ref}» aparece en {len(rows)} regla(s) o flujo(s) pero no coincide con ningún activo.",
                                           "Completar el inventario: no se puede proteger lo que no se conoce. Si es un equipo "
                                           "retirado, eliminar la regla.", "FR7 Disponibilidad; inventario de activos (IEC 62443-2-1)",
                                           ref, "", "", "", rows)
    # OT-12: sin denegacion por defecto
    if is_rules:
        last_deny = any(f.action == "deny" and f.src.lower() in ("any", "*", "all") and f.dst.lower() in ("any", "*", "all")
                        and f.protocol == "any" for f in flows)
        if not last_deny:
            findings[("OT-12",)] = Finding("OT-12", "media", "No hay una regla explícita de denegación por defecto",
                                           "Ninguna regla deniega any → any al final del conjunto.",
                                           "Terminar cada conducto con una regla deny any any con registro: deja claro que solo pasa "
                                           "lo permitido y genera eventos para detectar intentos.",
                                           "FR5 Flujo de datos restringido; FR6 Respuesta oportuna a eventos", "any", "any", "any")
    # Activos sin nivel
    for a in assets:
        if a.level is None and not a.infra:
            findings[("OT-13", a.name)] = Finding("OT-13", "baja", "Activo sin nivel Purdue",
                                                  f"{a.name} (tipo «{a.type}») no tiene nivel y su tipo no es conocido.",
                                                  "Indicar el nivel en la columna level (0, 1, 2, 3, 3.5, 4 o 5) para poder evaluarlo.",
                                                  "Modelo de zonas (IEC 62443-3-2)", a.name, "", "")

    items = sorted(findings.values(), key=lambda x: (SEV_ORDER[x.severity], x.check, x.src, x.dst))
    zones: dict[str, dict] = {}
    for a in assets:
        if a.infra:
            continue
        z = zones.setdefault(a.zone, {"zone": a.zone, "levels": set(), "assets": [], "safety": False})
        if a.level is not None:
            z["levels"].add(a.level)
        z["assets"].append(a.name)
        z["safety"] |= a.safety
    model = {
        "zones": [{**z, "levels": sorted(z["levels"])} for z in sorted(zones.values(), key=lambda z: (-(max(z["levels"]) if z["levels"] else -1), z["safety"], z["zone"]))],
        "conduits": [{"from": a, "to": b, "protocols": sorted(p)} for (a, b), p in sorted(conduits.items())],
        "mode": "reglas de firewall" if is_rules else "tráfico observado",
    }
    return items, model


# ----------------------------------------------------------------------------- informe

def mermaid(model: dict, findings: list[Finding], assets: list[Asset]) -> str:
    zid = {z["zone"]: f"Z{i}" for i, z in enumerate(model["zones"])}
    worst: dict[tuple[str, str], str] = {}
    zone_of = {a.name: a.zone for a in assets}
    zone_of["Internet"] = LEVEL_NAME[5]
    zone_of["any"] = ANY_SRC
    for f in findings:
        k = (zone_of.get(f.src, ""), zone_of.get(f.dst, "") if f.dst != "any" else ANY_DST)
        if k[0] and k[1] and (k not in worst or SEV_ORDER[f.severity] < SEV_ORDER[worst[k]]):
            worst[k] = f.severity
    lines = ["flowchart TB"]
    for special, node in ((ANY_SRC, "ZA"), (LEVEL_NAME[5], "ZI"), (ANY_DST, "ZB")):
        if special not in zid and any(special in (c["from"], c["to"]) for c in model["conduits"]):
            zid[special] = node
            lines.append(f'  {node}(["{special}"])')
    for z in model["zones"]:
        label = z["zone"].replace('"', "'") + ("<br/>⚠ seguridad (SIS)" if z["safety"] else "") + f"<br/>{len(z['assets'])} {'activo' if len(z['assets']) == 1 else 'activos'}"
        lines.append(f'  {zid[z["zone"]]}["{label}"]')
    styles = []
    for i, c in enumerate(model["conduits"]):
        if c["from"] not in zid or c["to"] not in zid:
            continue
        protos = ", ".join(c["protocols"][:3]) + ("…" if len(c["protocols"]) > 3 else "")
        lines.append(f'  {zid[c["from"]]} -->|"{protos}"| {zid[c["to"]]}')
        sev = worst.get((c["from"], c["to"]))
        if sev in ("critica", "alta"):
            styles.append(f"  linkStyle {sum(1 for x in lines if '-->' in x) - 1} stroke:{'#e5484d' if sev == 'critica' else '#f76b15'},stroke-width:2px")
    return "\n".join(lines + styles)


def render_md(findings: list[Finding], model: dict, assets: list[Asset], inputs: list[str]) -> str:
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV_ORDER}
    out = [f"# Revisión de segmentación OT — {date.today().isoformat()}", "",
           f"{len(assets)} activos · {len(model['zones'])} zonas · {len(model['conduits'])} conductos con tráfico permitido · "
           f"entradas: {', '.join(os.path.basename(i) for i in inputs)} (interpretadas como {model['mode']})", "",
           "| Severidad | Hallazgos |", "|---|---:|", *[f"| {s.capitalize()} | {n} |" for s, n in counts.items()], "",
           "## Zonas y conductos", "", "```mermaid", mermaid(model, findings, assets), "```", "",
           "| Zona | Niveles | Activos |", "|---|---|---|"]
    for z in model["zones"]:
        lv_ = ", ".join(("L" + (str(int(l)) if l == int(l) else str(l))) for l in z["levels"]) or "—"
        names = ", ".join(z["assets"][:8]) + (f" y {len(z['assets']) - 8} más" if len(z["assets"]) > 8 else "")
        out.append(f"| {z['zone']}{' ⚠ SIS' if z['safety'] else ''} | {lv_} | {names} |")
    out += ["", "| Desde | Hacia | Protocolos permitidos |", "|---|---|---|"]
    out += [f"| {c['from']} | {c['to']} | {', '.join(c['protocols'])} |" for c in model["conduits"]]
    out += ["", "## Hallazgos", ""]
    for f in findings:
        where = f" · regla {f.rule_id}" if f.rule_id else (f" · filas {', '.join(map(str, f.rows[:6]))}" if f.rows else "")
        out += [f"### [{f.severity.upper()}] {f.check} — {f.title}", "", f"{f.detail}{where}", "",
                f"**Qué hacer:** {f.recommendation}", "", f"*Referencia: {f.iec62443}*", ""]
    if not findings:
        out.append("No se encontraron problemas con las reglas incluidas en la revisión.")
    out += ["---", "Revisión documental: se basa solo en el inventario y las reglas o flujos provistos. No reemplaza una evaluación "
            "de riesgos IEC 62443-3-2 ni la validación en sitio, y nunca debe complementarse con escaneos activos sobre equipos en producción."]
    return "\n".join(out) + "\n"


def write_outputs(findings, model, assets, inputs, out_dir, fmt) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    written = []
    if fmt in ("md", "all"):
        p = os.path.join(out_dir, "ot-review.md")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(render_md(findings, model, assets, inputs))
        written.append(p)
    if fmt in ("json", "all"):
        p = os.path.join(out_dir, "ot-review.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump({"generated": date.today().isoformat(), "model": model, "findings": [asdict(f) for f in findings]},
                      fh, ensure_ascii=False, indent=2)
        written.append(p)
    if fmt in ("csv", "all"):
        p = os.path.join(out_dir, "ot-review.csv")
        with open(p, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["severity", "check", "title", "src", "dst", "protocol", "rule_id", "rows", "detail", "recommendation", "iec62443"])
            for f in findings:
                w.writerow([f.severity, f.check, f.title, f.src, f.dst, f.protocol, f.rule_id, " ".join(map(str, f.rows)),
                            f.detail, f.recommendation, f.iec62443])
        written.append(p)
    return written


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Revisión de segmentación OT (IEC 62443 / Purdue) a partir de documentación.")
    ap.add_argument("--assets", required=True, help="CSV de activos")
    ap.add_argument("--flows", required=True, help="CSV de reglas de firewall o flujos observados")
    ap.add_argument("--out-dir", default="ot-review-out")
    ap.add_argument("--format", default="all", choices=["md", "json", "csv", "all"])
    a = ap.parse_args(argv)
    try:
        assets = load_assets(a.assets)
        flows, is_rules = load_flows(a.flows)
    except (OSError, ValueError, csv.Error) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    findings, model = review(assets, flows, is_rules)
    files = write_outputs(findings, model, assets, [a.assets, a.flows], a.out_dir, a.format)
    counts = " · ".join(f"{s} {sum(1 for f in findings if f.severity == s)}" for s in SEV_ORDER)
    print(f"{len(assets)} activos · {len(model['zones'])} zonas · {len(flows)} {model['mode']} · hallazgos: {counts}")
    for p in files:
        print("escrito:", p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
