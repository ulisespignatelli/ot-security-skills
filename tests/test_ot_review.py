"""Tests de ot_review.py. La planta de las fixtures es ficticia."""
import csv
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "plugins", "ot-segmentation", "skills", "ot-segmentation-review", "scripts")
sys.path.insert(0, SCRIPT)
import ot_review as ot  # noqa: E402

FX = lambda n: os.path.join(HERE, "fixtures", n)  # noqa: E731


def write(tmp, name, text):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)
    return p


class Plant(unittest.TestCase):
    """Planta potabilizadora ficticia con errores plantados a propósito."""

    @classmethod
    def setUpClass(cls):
        cls.assets = ot.load_assets(FX("activos.csv"))
        flows, cls.is_rules = ot.load_flows(FX("reglas.csv"))
        cls.findings, cls.model = ot.review(cls.assets, flows, cls.is_rules)

    def find(self, check, rule=None):
        return [f for f in self.findings if f.check == check and (rule is None or f.rule_id == rule)]

    def test_levels_and_zones_from_type(self):
        by = {a.name: a for a in self.assets}
        self.assertEqual(by["PLC-Bombas"].level, 1)
        self.assertEqual(by["Jump-DMZ"].level, 3.5)
        self.assertEqual(by["SIS-Cloro"].zone, "SIS")
        self.assertTrue(by["SIS-Cloro"].safety)
        self.assertEqual(by["ERP"].zone, "L4 Empresa (IT)")
        self.assertTrue(by["FW-OT"].infra)
        self.assertNotIn("Sin nivel", [z["zone"] for z in self.model["zones"]])

    def test_internet_to_hmi_is_critical(self):
        f = self.find("OT-01", "R12")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "critica")

    def test_it_to_plc_and_scada_without_dmz(self):
        self.assertEqual({(f.rule_id, f.severity) for f in self.find("OT-02")}, {("R08", "critica"), ("R10", "critica")})

    def test_plc_to_cloud_is_detected_once(self):
        self.assertEqual([(f.rule_id, f.severity) for f in self.find("OT-03")], [("R14", "alta")])
        self.assertFalse(self.find("OT-04", "R14"), "OT-03 ya cubre la salida a internet")

    def test_insecure_protocol_severity_by_distance(self):
        sev = {f.rule_id: f.severity for f in self.find("OT-04")}
        self.assertEqual(sev["R09"], "alta")  # historiador (L3) leyendo S7 directo del PLC
        self.assertEqual(sev["R01"], "baja")  # HMI → PLC de su celda: riesgo residual
        self.assertNotIn("R13", sev)          # el SIS lo cubre OT-05

    def test_sis_access(self):
        f = self.find("OT-05")
        self.assertEqual([(x.rule_id, x.severity) for x in f], [("R13", "alta")])
        self.assertFalse([x for x in self.findings if x.rule_id == "R16"], "la ingeniería del SIS desde su propia zona es válida")

    def test_any_rules(self):
        f = self.find("OT-07")
        self.assertEqual([(x.rule_id, x.severity) for x in f], [("R15", "critica")])
        self.assertIn("SIS-Cloro", f[0].detail)
        self.assertFalse([x for x in self.findings if x.rule_id == "R11"], "any → gateway VPN en la DMZ es legítimo")

    def test_good_rules_produce_nothing(self):
        for rule in ("R04", "R05", "R06", "R07"):
            self.assertFalse([x for x in self.findings if x.rule_id == rule], rule)

    def test_unknown_and_default_deny(self):
        self.assertEqual([f.src for f in self.find("OT-10")], ["10.10.7.44"])
        self.assertEqual(len(self.find("OT-12")), 1)

    def test_conduits_use_any_nodes(self):
        pairs = {(c["from"], c["to"]) for c in self.model["conduits"]}
        self.assertIn((ot.ANY_SRC, "DMZ"), pairs)
        self.assertIn(("Supervisión", ot.ANY_DST), pairs)
        self.assertNotIn(("Celda Bombeo", "DMZ"), pairs, "una regla any no debe inventar conductos")

    def test_sorted_by_severity(self):
        order = [ot.SEV_ORDER[f.severity] for f in self.findings]
        self.assertEqual(order, sorted(order))


class Parsing(unittest.TestCase):
    def test_protocol_by_name_wins_over_port(self):
        self.assertEqual(ot.proto_from("modbus", "5020", "tcp"), "modbus")
        self.assertEqual(ot.proto_from("", "502", "tcp"), "modbus")
        self.assertEqual(ot.proto_from("", "47808", "udp"), "bacnet")
        self.assertEqual(ot.proto_from("", "34962-34964", ""), "profinet")
        self.assertEqual(ot.proto_from("", "any", ""), "any")
        self.assertEqual(ot.proto_from("", "1502", "tcp"), "unknown")
        self.assertEqual(ot.proto_from("EtherNet/IP", "", ""), "enip")

    def test_semicolon_csv_and_spanish_headers(self):
        with tempfile.TemporaryDirectory() as d:
            a = write(d, "a.csv", "nombre;ip;tipo\nPLC1;10.0.0.5;plc\nPC;192.168.1.0/24;workstation\n")
            r = write(d, "r.csv", "origen;destino;puerto;acción\nPC;PLC1;502;permitir\nany;any;any;deny\n")
            assets = ot.load_assets(a)
            flows, is_rules = ot.load_flows(r)
            self.assertTrue(is_rules)
            findings, _ = ot.review(assets, flows, is_rules)
            checks = {f.check for f in findings}
            self.assertIn("OT-02", checks)
            self.assertNotIn("OT-12", checks, "hay deny any any al final")

    def test_traffic_mode_skips_default_deny(self):
        with tempfile.TemporaryDirectory() as d:
            a = write(d, "a.csv", "name,ip,type\nH,10.0.2.1,hmi\nP,10.0.1.1,plc\n")
            r = write(d, "f.csv", "src,dst,port\n10.0.2.1,10.0.1.1,502\n")
            findings, model = ot.review(ot.load_assets(a), *ot.load_flows(r))
            self.assertEqual(model["mode"], "tráfico observado")
            self.assertNotIn("OT-12", {f.check for f in findings})

    def test_bad_level(self):
        with tempfile.TemporaryDirectory() as d:
            a = write(d, "a.csv", "name,ip,type,level\nX,10.0.0.1,plc,nueve\n")
            with self.assertRaises(ValueError):
                ot.load_assets(a)


class CLI(unittest.TestCase):
    def test_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            p = subprocess.run([sys.executable, os.path.join(SCRIPT, "ot_review.py"), "--assets", FX("activos.csv"),
                                "--flows", FX("reglas.csv"), "--out-dir", d], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(os.path.join(d, "ot-review.md"), encoding="utf-8") as fh:
                md = fh.read()
            self.assertIn("```mermaid", md)
            self.assertIn("Revisión documental", md)
            with open(os.path.join(d, "ot-review.csv"), encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(rows[0]["severity"], "critica")
            with open(os.path.join(d, "ot-review.json"), encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(len(data["findings"]), len(rows))

    def test_missing_file(self):
        p = subprocess.run([sys.executable, os.path.join(SCRIPT, "ot_review.py"), "--assets", "no.csv", "--flows", "no.csv"],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)


if __name__ == "__main__":
    unittest.main()
