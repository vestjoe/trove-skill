from tests.helpers import EngagementCase


class NmapText(EngagementCase):
    """Counts and values on the nmap text fixtures."""

    def _services(self):
        return {(s["host_id"], s["port"], s["protocol"]): s for s in self.all("service")}

    def test_a_scan_report_gives_its_hosts_and_every_port_row(self):
        report = self.import_fixture("nmap/nmap-normal.nmap")
        self.assertEqual((report["parser"], report["counts"]), ("nmap-text", {"host": 2, "service": 5}))
        hosts = {h["ip"]: h for h in self.all("host")}
        self.assertEqual((hosts["198.51.100.7"]["hostnames"], hosts["198.51.100.7"]["state"]),
                         (["mail.example.test"], "up"))
        self.assertEqual(hosts["198.51.100.8"]["state"], "down")
        self.assertNotIn("hostnames", hosts["198.51.100.8"])
        self.assertEqual(sorted(p for _, p, _ in self._services()), [25, 80, 443, 2222, 5060])
        self.assert_citations_hold()

    def test_the_version_column_is_a_banner_and_a_tunnel_is_split_off_the_name(self):
        self.import_fixture("nmap/nmap-normal.nmap")
        svcs = self._services()
        http = svcs[("host:198.51.100.7", 80, "tcp")]
        self.assertEqual(http["banner"], "nginx 1.18.0 (Ubuntu)")
        self.assertNotIn("product", http)
        https = svcs[("host:198.51.100.7", 443, "tcp")]
        self.assertEqual((https["name"], https["ext"]["tunnel"]), ("http", "ssl"))
        ssh = svcs[("host:198.51.100.7", 2222, "tcp")]
        self.assertEqual((ssh["name"], ssh["prov"]["name"]["quote"]), ("ssh", "ssh"))
        self.assertEqual(svcs[("host:198.51.100.7", 5060, "udp")]["name"], "sip")

    def test_a_grepable_host_stated_twice_lands_once(self):
        report = self.import_fixture("nmap/nmap-grepable.gnmap")
        self.assertEqual((report["parser"], report["counts"]), ("nmap-text", {"host": 2, "service": 7}))
        hosts = {h["ip"]: h for h in self.all("host")}
        self.assertEqual(hosts["198.51.100.7"]["hostnames"], ["mail.example.test"])
        self.assertEqual((hosts["198.51.100.7"]["state"], hosts["198.51.100.7"]["prov"]["state"]["quote"]),
                         ("up", "Up"))
        self.assertNotIn("hostnames", hosts["198.51.100.9"])
        self.assert_citations_hold()

    def test_a_comma_inside_a_grepable_version_does_not_end_the_entry(self):
        self.import_fixture("nmap/nmap-grepable.gnmap")
        svcs = self._services()
        ldaps = svcs[("host:198.51.100.9", 636, "tcp")]
        self.assertEqual(ldaps["banner"], "Microsoft Windows Active Directory LDAP "
                                          "(Domain: example.test, Site: Default-First-Site-Name)")
        self.assertEqual((ldaps["name"], ldaps["ext"]["tunnel"]), ("ldap", "ssl"))
        self.assertEqual(sorted(p for h, p, _ in svcs if h == "host:198.51.100.9"), [389, 636])

    def test_a_multibyte_character_does_not_shift_the_citations(self):
        report = self.import_fixture("nmap/nmap-utf8.nmap")
        self.assertEqual(report["counts"], {"host": 1, "service": 1})
        self.assertEqual(self.all("host")[0]["hostnames"], ["büro-dateiserver.büro.example"])
        self.assertEqual(self.all("service")[0]["banner"], "nginx 1.18.0 (Ubuntu — Bürgerportal)")
        self.assert_citations_hold()

    def test_the_xml_still_goes_to_the_xml_parser(self):
        self.assertEqual(self.import_fixture("nmap/nmap-basic.xml")["parser"], "nmap")

    def test_naabu_grepable_output_is_read_whole_and_an_address_is_not_a_hostname(self):
        report = self.import_fixture("nmap/naabu-basic.gnmap")
        self.assertEqual((report["parser"], report["counts"], report["notes"]),
                         ("nmap-text", {"host": 3, "service": 5}, []))
        hosts = {h["ip"]: h for h in self.all("host")}
        self.assertEqual(hosts["192.168.56.40"]["hostnames"], ["oldtown.sevenkingdoms.local"])
        self.assertNotIn("hostnames", hosts["192.168.56.41"])
        self.assertEqual(hosts["192.168.56.42"]["state"], "up")
        svcs = self._services()
        self.assertEqual(svcs[("host:192.168.56.41", 22, "tcp")]["banner"], "OpenSSH 8.9p1 Ubuntu 3ubuntu0.10")
        self.assertEqual(svcs[("host:192.168.56.40", 53, "udp")]["name"], "domain")
        self.assert_citations_hold()
