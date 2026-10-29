from lootlib import engagement, ingest, rawstore
from tests import SAMPLES
from tests.helpers import EngagementCase

FORMATS = ("masscan/masscan-list.txt", "masscan/masscan.json", "masscan/masscan.ndjson", "masscan/masscan-screen.txt")
PORTS = {("host:192.168.56.50", 22, "tcp"), ("host:192.168.56.50", 80, "tcp"), ("host:192.168.56.51", 3389, "tcp"),
         ("host:192.168.56.51", 161, "udp"), ("host:2001:db8:5eed::52", 443, "tcp")}


class Masscan(EngagementCase):
    """The same masscan scan saved four ways reads the same, every field cited."""

    def _services(self):
        return {(s["host_id"], s["port"], s["protocol"]): s for s in self.all("service")}

    def test_each_format_gives_the_same_open_ports_with_nothing_left_over(self):
        for number, rel in enumerate(FORMATS):
            with self.subTest(rel):
                self.eng = engagement.create(f"format{number}", self.tmp)
                report = self.import_fixture(rel)
                self.assertEqual((report["parser"], report["notes"]), ("masscan", []))
                self.assertEqual(set(self._services()), PORTS)
                self.assertEqual({s["state"] for s in self.all("service")}, {"open"})
                self.assert_citations_hold()

    def test_the_first_banner_is_the_banner_and_every_banner_is_kept(self):
        for number, rel in enumerate(FORMATS):
            with self.subTest(rel):
                self.eng = engagement.create(f"format{number}", self.tmp)
                self.import_fixture(rel)
                web = self._services()[("host:192.168.56.50", 80, "tcp")]
                self.assertEqual(web["banner"], "nginx/1.18.0 (Ubuntu)")
                self.assertEqual([b.split(":")[0] for b in web["ext"]["banners"]], ["http.server", "title"])
                self.assertNotIn("name", web)

    def test_an_arp_reply_is_a_host_that_is_up_and_no_service(self):
        self.import_fixture("masscan/masscan-screen.txt")
        host = {h["ip"]: h for h in self.all("host")}["192.168.56.53"]
        self.assertEqual((host["state"], host["ext"]["mac"]), ("up", "08:00:27:5e:ed:53"))
        self.assertFalse([s for s in self.all("service") if s["host_id"] == "host:192.168.56.53"])

    def test_a_port_masscan_and_nmap_both_found_keeps_the_nmap_name(self):
        self.import_fixture("nmap/nmap-basic.xml")
        line = "#masscan\nopen tcp 22 10.10.10.5 1793181601\nbanner tcp 22 10.10.10.5 1793181604 ssh SSH-2.0-x\n# end\n"
        ingest.import_data(self.eng, line.encode(), "masscan.txt")
        ssh = {s["id"]: s for s in self.all("service")}["service:10.10.10.5-tcp-22"]
        self.assertEqual((ssh["name"], ssh["banner"]), ("ssh", "SSH-2.0-x"))
        self.assert_citations_hold()

    def test_lines_that_are_not_masscan_go_to_the_agent(self):
        data = b"#masscan\nopen tcp 445 192.168.56.53 1793181601\nmasscan -p445 192.168.56.0/24 -oL out.txt\n# end\n"
        report = ingest.import_data(self.eng, data, "masscan.txt")[0]
        self.assertEqual((report["parser"], report["counts"]), ("masscan", {"host": 1, "service": 1}))
        queued = [e for e in rawstore.manifest(self.eng) if e.get("ai") == "pending"]
        self.assertEqual(rawstore.read(self.eng, queued[0]["blob"]).decode().splitlines(),
                         ["masscan -p445 192.168.56.0/24 -oL out.txt"])

    def test_nmap_verbose_output_is_not_masscan(self):
        report = self.import_fixture("nmap/nmap-verbose-os.nmap")
        self.assertEqual(report["parser"], "nmap-text")

    def test_the_tool_can_be_forced(self):
        report = ingest.import_data(self.eng, b"open tcp 445 192.168.56.53 1793181601\n", "list.txt", tool="masscan")[0]
        self.assertEqual((report["parser"], report["counts"]), ("masscan", {"host": 1, "service": 1}))

    def test_masscan_run_lines_are_its_own_and_not_sent_to_the_agent(self):
        data = ("Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2025-03-15 11:49:37 GMT\n"
                "Initiating SYN Stealth Scan\nScanning 1 hosts [65535 ports/host]\n"
                " -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth\n"
                "Discovered open port 445/tcp on 192.168.56.53                                  \n")
        report = ingest.import_data(self.eng, data.encode(), "screen.txt")[0]
        self.assertEqual((report["parser"], report["counts"], report["notes"]),
                         ("masscan", {"host": 1, "service": 1}, []))

    def test_a_real_lab_scan_with_banners_reads_whole(self):
        report = ingest.import_path(self.eng, SAMPLES / "masscan/rzlab-masscan.xml")[0]
        self.assertEqual((report["parser"], report["notes"]), ("nmap", []))
        self.assertEqual((len(self.all("host")), len(self.all("service"))), (117, 389))
        svcs = self.all("service")
        self.assertFalse([s for s in svcs if "name" in s])
        self.assertEqual(sum("banner" in s for s in svcs), 56)
        self.assertFalse(rawstore.manifest(self.eng)[0].get("ai") == "pending")
        self.assert_citations_hold()

    def test_progress_lines_are_masscan_and_a_repeated_banner_is_kept_once(self):
        data = ("Discovered open port 11211/tcp on 192.168.56.53                                \n"
                "rate:  0.00-kpps, 100.00% done, waiting 4-secs, found=1       \r"
                "Banner on port 11211/tcp on 192.168.56.53: [memcached] uptime=85 version=1.6.27\n"
                "rate:  0.00-kpps, 100.00% done, waiting 3-secs, found=1       \r"
                "Banner on port 11211/tcp on 192.168.56.53: [memcached] uptime=85 version=1.6.27\n")
        report = ingest.import_data(self.eng, data.encode(), "screen.txt")[0]
        self.assertEqual((report["parser"], report["notes"]), ("masscan", []))
        self.assertEqual(self.all("service")[0]["ext"]["banners"], ["memcached: uptime=85 version=1.6.27"])
