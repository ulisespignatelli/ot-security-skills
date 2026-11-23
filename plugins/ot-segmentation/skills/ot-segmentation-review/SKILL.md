---
name: ot-segmentation-review
description: Revisa la segmentación de una red industrial (OT/ICS/SCADA) según IEC 62443 y el modelo Purdue, a partir del inventario y las reglas de firewall. Propone zonas y conductos y prioriza los riesgos.
---

# Revisión de segmentación OT (IEC 62443 / Purdue)

En una red industrial, el ataque que más daño hace casi siempre entra por IT: un correo, una VPN o una carpeta compartida, y de ahí salta a la planta porque nadie cerró el camino. Esta skill revisa ese camino a partir de documentación: el **inventario de activos** y las **reglas de firewall** (o los flujos observados por una herramienta de monitoreo pasivo). Con eso arma el modelo de **zonas y conductos** de IEC 62443 y marca qué hay que corregir primero.

Antes de justificar un hallazgo o proponer una arquitectura, leé `references/iec62443.md` (conceptos y niveles) y `references/checks.md` (cada control, por qué importa y cómo se corrige).

## Regla de oro: nada activo

**Nunca** propongas ni ejecutes escaneos (nmap, escáneres de vulnerabilidades, descubrimiento activo) sobre una red OT en producción, aunque el usuario lo pida para "completar el inventario". En OT un escaneo puede detener PLC viejos y frenar un proceso físico. Para completar el inventario, sugerí:
- la documentación de ingeniería: proyectos del PLC, listas de E/S, planos de red;
- las tablas ARP y CAM de los switches, exportadas por quien los administra;
- una herramienta de monitoreo pasivo (puerto espejo o TAP), coordinada con operaciones.

## Flujo

1. **Conseguir dos insumos** y llevarlos a CSV:
   - **Activos:** `name, ip, type [, level, zone, criticality]`. `ip` acepta una IP o una red CIDR para un grupo. Tipos reconocidos: `plc, rtu, ied, sis, hmi, scada-server, eng-workstation, opc-server, historian, ot-ad, jump-host, historian-mirror, remote-access-gateway, it-server, workstation, erp, firewall, switch`, entre otros (la lista completa está en `references/checks.md`). Si falta `level`, se deduce del tipo. Si falta `zone`, se usa el nivel; los SIS van a una zona propia.
   - **Reglas o flujos:** `src, dst [, protocol, port, transport, action, rule_id, comment]`. `src` y `dst` pueden ser un nombre del inventario, una IP, una red CIDR, `any` o `internet`. **Con** columna `action`, el archivo se toma como reglas de firewall (también evalúa la denegación por defecto). **Sin** ella, se toma como tráfico observado.

   Si el usuario pega una exportación de firewall (FortiGate, Palo Alto, Cisco ASA, pfSense, iptables) o describe la red en palabras, convertila vos al CSV: resolvé los objetos de dirección y servicio a IP y puertos, y mostrá el resultado para que lo confirme. Si algo es ambiguo (un objeto sin definir, un grupo de servicios), preguntá en vez de adivinar.

2. **Preguntar el contexto mínimo**, en un solo mensaje y solo si no está claro: qué equipos son de seguridad funcional (SIS) y cuáles son críticos para el proceso. Si hay accesos de proveedores, preguntá por dónde entran.

3. **Correr el script** (Python 3.10+, solo biblioteca estándar; la ruta es relativa a la carpeta de esta skill):
   ```bash
   python3 scripts/ot_review.py --assets activos.csv --flows reglas.csv --out-dir ot-review-out
   ```
   Genera `ot-review.md` (informe con diagrama Mermaid de zonas y conductos), `ot-review.csv` y `ot-review.json`.

4. **Presentar el resultado.** Empezá por lo crítico y explicalo en términos de la planta, no del firewall. Por ejemplo: "cualquier PC de oficina puede escribir registros en el PLC de bombeo por Modbus; un ransomware en IT podría detener el bombeo".
   - Hallazgos críticos y altos: qué regla es, qué riesgo implica y qué cambiar.
   - El diagrama de zonas y conductos del informe.
   - Una **arquitectura objetivo** breve: qué zonas y conductos debería haber, qué termina en la DMZ industrial y qué reglas se eliminan o reemplazan.
   - Las suposiciones que hiciste (niveles deducidos, tipos dudosos, objetos que interpretaste).
   - Entregá los archivos generados; no pegues el CSV completo.

5. **Ofrecer el paso siguiente:** redactar las reglas nuevas para los conductos, un plan de corrección por etapas compatible con las paradas de planta, o la lista de comunicaciones permitidas (allowlist) para cada conducto.

## Reglas

- **Primero la seguridad física y la continuidad.** Cada cambio que propongas sobre reglas en producción se planifica con operaciones, se prueba en una ventana de mantenimiento y tiene un plan de vuelta atrás. Nunca sugieras "bloquear ya" una comunicación de control sin confirmar que no la usa el proceso.
- **Es una revisión documental.** No reemplaza una evaluación de riesgos IEC 62443-3-2 ni la verificación en sitio. Decilo en el informe.
- **No inventes equipos ni reglas.** Si el inventario o las reglas están incompletos, informalo (el control OT-10 lo detecta) y pedí lo que falta.
- **Citá la norma con precisión.** Mencioná los requisitos fundamentales (FR1 a FR7), las zonas y conductos y los niveles de seguridad (SL) en términos generales. No inventes numeraciones de requisitos detallados de IEC 62443-3-3 que no estén en `references/`.
- **Solo uso defensivo.** No expliques cómo explotar los protocolos ni cómo enviar comandos a los equipos.
