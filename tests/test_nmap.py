from lootlib import rawstore
from tests.helpers import EngagementCase


class NmapXml(EngagementCase):
    """Counts and values on the nmap XML fixtures."""

    def test_every_host_and_port_in_the_scan_becomes_a_record(self):
        report = self.import_fixture("nmap/nmap-basic.xml")
        self.assertEqual(report["counts"], {"host": 2, "service": 6})
        self.assertEqual({h["ip"] for h in self.all("host")}, {"10.10.10.5", "10.10.10.6"})
        self.assert_citations_hold()

    def test_a_host_carries_what_nmap_said_and_nothing_it_did_not(self):
        self.import_fixture("nmap/nmap-basic.xml")
        hosts = {h["ip"]: h for h in self.all("host")}
        web = hosts["10.10.10.5"]
        self.assertEqual((web["hostnames"], web["os"], web["state"]), (["web01.lab.local"], "Linux 5.15", "up"))
        self.assertEqual((web["ext"]["os_accuracy"], web["ext"]["mac_vendor"]), ("97", "VMware"))
        self.assertNotIn("os", hosts["10.10.10.6"])

    def test_udp_ipv6_down_hosts_and_filtered_states_survive_verbatim(self):
        self.import_fixture("nmap/nmap-udp-ipv6.xml")
        hosts = {h["ip"]: h for h in self.all("host")}
        self.assertEqual(set(hosts), {"2001:db8:acme::5", "2001:db8:acme::9"})
        self.assertEqual(hosts["2001:db8:acme::9"]["state"], "down")
        svcs = {s["id"]: s for s in self.all("service")}
        self.assertEqual(svcs["service:2001:db8:acme::5-udp-53"]["protocol"], "udp")
        self.assertEqual(svcs["service:2001:db8:acme::5-udp-161"]["state"], "open|filtered")
        self.assertEqual(svcs["service:2001:db8:acme::5-udp-123"]["state"], "filtered")
        self.assertFalse([s for s in svcs.values() if s["host_id"] == "host:2001:db8:acme::9"])
        self.assert_citations_hold()

    def test_masscan_is_read_by_the_nmap_parser_and_one_host_stays_one_record(self):
        report = self.import_fixture("nmap/masscan-basic.xml")
        self.assertEqual(report["parser"], "nmap")
        self.assertEqual(len(self.all("host")), 2)
        self.assertEqual({(s["port"], s["protocol"], s["name"]) for s in self.all("service")},
                         {(22, "tcp", "ssh"), (443, "tcp", "https"), (445, "tcp", "microsoft-ds")})

    def test_a_truncated_scan_is_refused_whole_and_its_bytes_kept(self):
        report = self.import_fixture("nmap/nmap-truncated.xml")
        self.assertIn("not readable nmap XML", report["status"])
        self.assertEqual(self.all(), [])
        self.assertEqual(rawstore.manifest(self.eng)[0]["ai"], "refused")

    def test_naabu_xml_is_read_by_the_nmap_parser(self):
        report = self.import_fixture("nmap/naabu-basic.xml")
        self.assertEqual((report["parser"], report["counts"]), ("nmap", {"host": 2, "service": 5}))
        hosts = {h["ip"]: h for h in self.all("host")}
        self.assertEqual(hosts["192.168.56.40"]["hostnames"], ["oldtown.sevenkingdoms.local"])
        self.assertNotIn("hostnames", hosts["192.168.56.41"])
        svcs = {s["id"]: s for s in self.all("service")}
        self.assertEqual(svcs["service:192.168.56.40-udp-53"]["product"], "Simple DNS Plus")
        self.assertEqual(svcs["service:192.168.56.41-tcp-22"]["version"], "8.9p1 Ubuntu 3ubuntu0.10")
        self.assert_citations_hold()
