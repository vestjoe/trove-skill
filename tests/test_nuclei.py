import json

from lootlib import ingest, rawstore
from lootlib.encoding import WINDOW
from tests.helpers import EngagementCase

SSL = "self-signed-ssl at 192.168.56.70:443"
LINE = ('{"template-id":"self-signed-ssl","info":{"name":"Self Signed SSL Certificate","severity":"low"},'
        '"type":"ssl","host":"192.168.56.70","port":"443","matched-at":"192.168.56.70:443",'
        '"ip":"192.168.56.70","timestamp":"2026-10-29T11:02:00Z","matcher-status":true}')


class NucleiResults(EngagementCase):
    """Counts and values on the nuclei fixtures built from nuclei v3.11.1's output code."""

    def _findings(self):
        return {f["title"]: f for f in self.all("finding")}

    def test_each_result_is_a_confirmed_finding_on_its_host_and_port_with_nucleis_severity(self):
        report = self.import_fixture("nuclei/nuclei-highgarden.jsonl")
        self.assertEqual((report["parser"], report["counts"]), ("nuclei", {"host": 3, "service": 3, "finding": 6}))
        self.assertEqual(report["notes"], ["nuclei-highgarden.jsonl: 1 result(s) nuclei reported as failed (-ms) make no "
                                           "finding."])
        found = self._findings()
        ssl = found[SSL]
        self.assertEqual((ssl["host_id"], ssl["service_id"], ssl["status"], ssl["description"]),
                         ("host:192.168.56.70", "service:192.168.56.70-tcp-443", "confirmed", "Self Signed SSL Certificate"))
        self.assertEqual((ssl["ext"]["severity"], ssl["ext"]["cwe-id"]), ("low", ["cwe-295"]))
        self.assertEqual(ssl["prov"]["title"]["quote"], "self-signed-ssl")
        self.assertEqual(ssl["prov"]["status"]["quote"], "true")
        self.assertNotIn("exposed-redis at 192.168.56.70:6379", found)
        self.assertNotIn("request", found["tech-detect:microsoft-iis at https://highgarden.sevenkingdoms.local/"]["ext"])
        self.assert_citations_hold()

    def test_the_target_name_is_a_hostname_and_the_service_states_only_port_and_protocol(self):
        self.import_fixture("nuclei/nuclei-highgarden.jsonl")
        hosts = {h["ip"]: h for h in self.all("host")}
        self.assertEqual(hosts["192.168.56.70"]["hostnames"], ["highgarden.sevenkingdoms.local"])
        svc = {s["id"]: s for s in self.all("service")}["service:192.168.56.70-tcp-443"]
        self.assertEqual({k for k in svc if k not in ("id", "type", "prov", "ext")}, {"host_id", "port", "protocol"})
        self.assertEqual(svc["prov"]["protocol"]["quote"], "http")
        self.assertIn("service:2001:db8:5eed::70-tcp-22", {s["id"] for s in self.all("service")})

    def test_a_javascript_result_makes_no_service_and_a_dns_result_has_no_host(self):
        self.import_fixture("nuclei/nuclei-highgarden.jsonl")
        found = self._findings()
        smb = found["smb-default-login at 192.168.56.70:445"]
        self.assertNotIn("service_id", smb)
        self.assertEqual(smb["ext"]["meta"], [{"passwords": "Summer2026!", "usernames": "margaery.tyrell"}])
        self.assertNotIn("service:192.168.56.70-tcp-445", {s["id"] for s in self.all("service")})
        self.assertNotIn("host_id", found["caa-fingerprint at sevenkingdoms.local"])
        self.assertFalse(self.all("credential"))

    def test_a_result_before_v3_1_names_its_host_in_a_url(self):
        self.import_fixture("nuclei/nuclei-highgarden.jsonl")
        git = self._findings()["git-config at http://192.168.56.71:8080/.git/config"]
        self.assertEqual((git["host_id"], git["service_id"]), ("host:192.168.56.71", "service:192.168.56.71-tcp-8080"))
        self.assertEqual((git["ext"]["tags"], git["ext"]["extracted-results"]), ("config,git,exposure", ["[core]"]))
        self.assertNotIn("hostnames", {h["ip"]: h for h in self.all("host")}["192.168.56.71"])

    def test_the_array_export_and_the_text_output_give_the_same_findings_as_the_jsonl(self):
        self.import_fixture("nuclei/nuclei-highgarden.jsonl")
        before = {f["id"] for f in self.all("finding")}
        array = self.import_fixture("nuclei/nuclei-highgarden.json")
        self.assertEqual((array["parser"], array["new"]), ("nuclei", 0))
        text = self.import_fixture("nuclei/nuclei-highgarden.txt")
        self.assertEqual(text["parser"], "nuclei")
        self.assertEqual({f["id"] for f in self.all("finding")} - before, set())
        ssh = self._findings()["openssh-detect at [2001:db8:5eed::70]:22"]
        self.assertEqual(ssh["ext"]["shown"], ['["SSH-2.0-OpenSSH_for_Windows_9.5"]'])
        self.assert_citations_hold()

    def test_a_text_result_naming_only_a_host_name_waits_for_a_scan_that_names_it(self):
        report = self.import_fixture("nuclei/nuclei-highgarden.txt")
        self.assertIn("nuclei-highgarden.txt: the results on braavos.essos.local, "
                      "highgarden.sevenkingdoms.local wait for a scan that names that host; each lands on it once "
                      "Trove holds it.", report["notes"])
        self.assertEqual(len(self.all("finding")), 3)
        scan = (b"Nmap scan report for braavos.essos.local (192.168.56.72)\nHost is up (0.0010s latency).\n"
                b"PORT     STATE SERVICE\n1433/tcp open  ms-sql-s\n")
        ingest.import_data(self.eng, scan, "braavos.nmap")
        mssql = self._findings()["mssql-detect at braavos.essos.local:1433"]
        self.assertEqual((mssql["host_id"], mssql["service_id"]), ("host:192.168.56.72", "service:192.168.56.72-tcp-1433"))
        self.assertTrue(rawstore.manifest(self.eng)[0]["waiting"])
        self.assert_citations_hold()

    def test_nucleis_banner_and_log_lines_are_its_own_and_other_lines_go_to_the_agent(self):
        report = self.import_fixture("nuclei/nuclei-highgarden-screen.log")
        self.assertEqual((report["parser"], report["counts"]), ("nuclei", {"host": 1, "service": 1, "finding": 1}))
        queued = [e for e in rawstore.manifest(self.eng) if e.get("ai") == "pending"]
        self.assertEqual(rawstore.read(self.eng, queued[0]["blob"]).decode().splitlines(), [
            "$ nuclei -u https://highgarden.sevenkingdoms.local -nc",
            "the anonymous ftp share has a backup of web.config with sa:Highgarden1! in it"])

    def test_a_first_line_past_the_sniff_window_is_still_nucleis(self):
        line = json.loads(LINE)
        line["response"] = "HTTP/1.1 200 OK\r\n\r\n" + "A" * (WINDOW + 10)
        jsonl = (json.dumps(line, separators=(",", ":")) + "\n").encode()
        array = ("[" + json.dumps(line, separators=(",", ":")) + "]").encode()
        for name, data in (("big.jsonl", jsonl), ("big.json", array)):
            with self.subTest(name):
                report = ingest.import_data(self.eng, data, name)[0]
                self.assertEqual((report["parser"], report["counts"]), ("nuclei", {"host": 1, "service": 1, "finding": 1}))
        self.assert_citations_hold()

    def test_a_port_nuclei_and_nmap_both_found_keeps_nmaps_name_and_state(self):
        scan = (b"Nmap scan report for 192.168.56.70\nHost is up (0.0010s latency).\n"
                b"PORT    STATE SERVICE\n443/tcp open  https\n")
        ingest.import_data(self.eng, scan, "highgarden.nmap")
        self.import_fixture("nuclei/nuclei-highgarden.jsonl")
        svc = {s["id"]: s for s in self.all("service")}["service:192.168.56.70-tcp-443"]
        self.assertEqual((svc["name"], svc["state"]), ("https", "open"))

    def test_tool_nuclei_forces_the_parser(self):
        report = self.import_fixture("nuclei/nuclei-highgarden.txt", tool="nuclei")
        self.assertEqual(report["parser"], "nuclei")
