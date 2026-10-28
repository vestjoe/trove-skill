from lootlib import ingest, rawstore
from tests.helpers import EngagementCase


class NaabuJson(EngagementCase):
    """Counts and values on the naabu ``-json`` fixtures."""

    def _services(self):
        return {s["id"]: s for s in self.all("service")}

    def test_each_line_is_an_open_port_on_its_address_and_the_target_name_is_a_hostname(self):
        report = self.import_fixture("naabu/naabu-sunspear.json")
        self.assertEqual((report["parser"], report["counts"], report["notes"]),
                         ("naabu", {"host": 3, "service": 7}, []))
        hosts = {h["ip"]: h for h in self.all("host")}
        self.assertEqual(hosts["192.168.56.43"]["hostnames"], ["sunspear.essos.local"])
        self.assertEqual(hosts["2001:db8:5eed::43"]["hostnames"], ["sunspear.essos.local"])
        self.assertNotIn("hostnames", hosts["192.168.56.44"])
        svcs = self._services()
        self.assertEqual(svcs["service:192.168.56.43-udp-53"]["protocol"], "udp")
        self.assertEqual(svcs["service:192.168.56.43-tcp-636"]["ext"]["tls"], True)
        self.assertNotIn("state", svcs["service:192.168.56.43-tcp-445"])
        self.assertIn("service:2001:db8:5eed::43-tcp-445", svcs)
        self.assert_citations_hold()

    def test_service_discovery_fields_are_cited_and_the_rest_kept_as_ext(self):
        self.import_fixture("naabu/naabu-pyke-sv.json")
        svcs = self._services()
        ssh = svcs["service:192.168.56.45-tcp-22"]
        self.assertEqual((ssh["name"], ssh["product"], ssh["version"]), ("ssh", "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.10"))
        self.assertEqual(ssh["prov"]["port"]["quote"], "22")
        self.assertEqual(ssh["ext"]["cpes"], ["cpe:/a:openbsd:openssh:8.9p1", "cpe:/o:linux:linux_kernel"])
        self.assertEqual(svcs["service:192.168.56.45-tcp-8443"]["ext"]["tunnel"], "ssl")
        host = self.all("host")[0]
        self.assertEqual((host["ext"]["mac"], host["ext"]["mac_vendor"]), ("08:00:27:5e:ed:45", "PCS Systemtechnik GmbH"))
        self.assert_citations_hold()

    def test_a_port_naabu_and_nmap_both_found_is_one_service(self):
        self.import_fixture("nmap/naabu-basic.xml")
        line = ('{"host":"oldtown.sevenkingdoms.local","ip":"192.168.56.40",'
                '"timestamp":"2026-10-28T10:30:00.1Z","port":445,"protocol":"tcp","tls":false}\n')
        reports = ingest.import_data(self.eng, line.encode(), "naabu.json")
        self.assertEqual((reports[0]["parser"], reports[0]["new"]), ("naabu", 0))
        self.assertEqual(len(self.all("host")), 2)
        self.assertEqual(len([s for s in self.all("service") if s["host_id"] == "host:192.168.56.40"]), 3)
        self.assert_citations_hold()

    def test_lines_that_are_not_results_go_to_the_agent(self):
        data = (b'{"ip":"192.168.56.44","port":3389,"protocol":"tcp","tls":false}\n'
                b"192.168.56.44:5985\n"
                b'{"ip":"192.168.56.44","port":445}\n')
        report = ingest.import_data(self.eng, data, "mixed.json")[0]
        self.assertEqual((report["parser"], report["counts"]), ("naabu", {"host": 1, "service": 1}))
        queued = [e for e in rawstore.manifest(self.eng) if e.get("ai") == "pending"]
        self.assertEqual(rawstore.read(self.eng, queued[0]["blob"]).decode().splitlines(),
                         ["192.168.56.44:5985", '{"ip":"192.168.56.44","port":445}'])

    def test_plain_host_port_text_is_not_claimed(self):
        report = ingest.import_data(self.eng, b"192.168.56.44:3389\nadmin:1234\n", "naabu.txt")[0]
        self.assertEqual(report["status"], "pending AI extraction")

    def test_the_tool_can_be_forced(self):
        report = self.import_fixture("naabu/naabu-sunspear.json", tool="naabu")
        self.assertEqual(report["parser"], "naabu")
