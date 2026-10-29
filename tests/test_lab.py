from lootlib import engagement, ingest, rawstore
from tests import SAMPLES
from tests.helpers import EngagementCase

LAB = SAMPLES / "lab"
DESIGN = {
    "host:10.99.56.10": {("tcp", 21), ("tcp", 22), ("tcp", 23), ("tcp", 25), ("tcp", 80), ("tcp", 443), ("tcp", 8080)},
    "host:10.99.56.11": {("tcp", 53), ("tcp", 139), ("tcp", 445), ("udp", 53), ("udp", 123), ("udp", 161)},
    "host:10.99.56.12": {("tcp", 80), ("tcp", 443), ("tcp", 6379), ("tcp", 8080), ("tcp", 11211), ("udp", 11211)},
}
MASSCAN_SAW = {host: ports - {("udp", 123)} for host, ports in DESIGN.items()}
PARSERS = {"masscan.xml": "nmap", "masscan.gnmap": "nmap-text", "masscan.txt": "masscan", "masscan.json": "masscan",
           "masscan.ndjson": "masscan", "masscan-screen.txt": "masscan", "naabu.json": "naabu",
           "naabu-names.json": "naabu", "naabu-sv.json": "naabu", "naabu.xml": "nmap", "naabu.gnmap": "nmap-text"}


class Lab(EngagementCase):
    """Real masscan, naabu and nmap runs against the Docker lab in tests/lab, read against its design."""

    def _open(self):
        found: dict[str, set] = {}
        for svc in self.all("service"):
            if svc.get("state", "open") == "open":
                found.setdefault(svc["host_id"], set()).add((svc["protocol"], svc["port"]))
        return found

    def test_every_capture_is_read_by_its_parser(self):
        for name, parser in PARSERS.items():
            with self.subTest(name):
                self.assertEqual(ingest.import_path(self.eng, LAB / name)[0]["parser"], parser)

    def test_all_captures_together_give_the_lab_open_ports_and_one_record_per_host(self):
        ingest.import_path(self.eng, LAB)
        self.assertEqual(self._open(), DESIGN)
        self.assertEqual(sorted(h["ip"] for h in self.all("host")), ["10.99.56.10", "10.99.56.11", "10.99.56.12"])
        self.assert_citations_hold()

    def test_only_the_banners_masscan_grepable_cannot_tie_to_one_protocol_go_to_the_agent(self):
        ingest.import_path(self.eng, LAB)
        queued = [line for e in rawstore.manifest(self.eng) if e.get("ai") == "pending"
                  for line in rawstore.read(self.eng, e["blob"]).decode().splitlines()]
        self.assertTrue(queued)
        self.assertEqual({line.split("\t")[1] for line in queued}, {"Port: 53", "Port: 11211"})

    def test_each_masscan_format_finds_the_same_open_ports(self):
        # masscan's NTP probe got no reply in this run; nmap -sU found 123/udp.
        for number, name in enumerate(("masscan.xml", "masscan.gnmap", "masscan.txt", "masscan.json", "masscan.ndjson")):
            with self.subTest(name):
                self.eng = engagement.create(f"format{number}", self.tmp)
                ingest.import_path(self.eng, LAB / name)
                self.assertEqual(self._open(), MASSCAN_SAW)

    def test_naabu_by_name_keeps_the_name_and_service_discovery_names_the_service(self):
        ingest.import_path(self.eng, LAB / "naabu-names.json")
        ingest.import_path(self.eng, LAB / "naabu-sv.json")
        names = {h["ip"]: h["hostnames"] for h in self.all("host")}
        self.assertEqual(names["10.99.56.10"], ["lab-web.lab.test"])
        ssh = {s["id"]: s for s in self.all("service")}["service:10.99.56.10-tcp-22"]
        self.assertEqual(ssh["name"], "ssh")
