from lootlib import ingest, parsers, rawstore
from lootlib.errors import LootError
from tests.helpers import FIXTURES, EngagementCase

HEADER = (b"# Hydra v9.8dev run at 2026-11-15 11:00:00 on 192.168.56.83 ssh "
          b"(hydra -l podrick.payne -p Sq41re! -o out.txt ssh://192.168.56.83)\n")
FOUND = b"[22][ssh] host: 192.168.56.83   login: podrick.payne   password: Sq41re!\n"
NAMED = b"[22][ssh] host: stormsend.stormlands.local   login: davos.seaworth   password: Onion.Kn1ght\n"
SCAN = (b'{"host":"stormsend.stormlands.local","ip":"192.168.56.80","timestamp":"2026-11-15T09:58:00Z",'
        b'"port":22,"protocol":"tcp","tls":false}\n')


def json_file(results: str) -> bytes:
    return ('{ "generator": {\n\t"software": "Hydra", "version": "v9.8dev", "built": "2026-11-15 11:00:00",\n'
            '\t"server": "192.168.56.83", "service": "ftp", "jsonoutputversion": "1.00",\n'
            '\t"commandline": "hydra -l gendry -p Bl4cksmith! -b json -o out.json ftp://192.168.56.83"\n\t},\n'
            f'"results": [{results}\n\t],\n"success": true,\n"errormessages": [  ],\n"quantityfound": 1   }}\n'
            ).encode()


class Hydra(EngagementCase):
    """Hydra's -o file, its JSON and a console capture."""

    def _creds(self):
        return {c["principal"]: c for c in self.all("credential")}

    def _import(self, data, name="hydra.txt", **kw):
        return ingest.import_data(self.eng, data, name, **kw)[0]

    def test_a_found_line_is_a_confirmed_login_on_its_host_and_service(self):
        report = self.import_fixture("hydra/hydra-stormsend.txt")
        self.assertEqual((report["parser"], report["counts"]), ("hydra", {"host": 1, "service": 1, "credential": 2}))
        davos = self._creds()["davos.seaworth"]
        self.assertEqual((davos["secret"], davos["state"], davos["hosts"]),
                         ("Onion.Kn1ght", "confirmed", ["host:192.168.56.80"]))
        self.assertTrue(davos["prov"]["state"]["quote"].startswith("[22][ssh] host: 192.168.56.80"))
        self.assertNotIn("realm", davos)
        svc = self.all("service")[0]
        self.assertEqual((svc["host_id"], svc["port"], svc["protocol"], svc["name"]),
                         ("host:192.168.56.80", 22, "tcp", "ssh"))
        self.assert_citations_hold()

    def test_the_header_command_line_is_held_back_when_a_login_was_found(self):
        report = self.import_fixture("hydra/hydra-stormsend.txt")
        self.assertEqual(report["status"], "parsed")
        self.assertNotIn("_queued", report)
        self.assertFalse([m for m in rawstore.manifest(self.eng) if m["ai"] == "pending"])
        self.assertTrue(any("command line" in n for n in report["notes"]))

    def test_the_header_command_line_is_queued_when_nothing_was_found(self):
        report = self._import(HEADER)
        self.assertEqual(report["parser"], "hydra")
        self.assertEqual(report["status"], "pending AI extraction")

    def test_several_passwords_for_one_login_on_one_port_make_no_credential(self):
        report = self.import_fixture("hydra/hydra-dragonstone-console.txt")
        self.assertEqual((report["parser"], report["counts"]), ("hydra", {"host": 1, "service": 1}))
        self.assertEqual(self.all("credential"), [])
        note = next(n for n in report["notes"] if "podrick.payne" in n)
        self.assertIn("192.168.56.81:80", note)
        self.assertIn("4 passwords", note)
        self.assertEqual(self.all("service")[0]["name"], "http-post-form")
        self.assert_citations_hold()

    def test_hydras_own_lines_never_go_to_extraction(self):
        report = self.import_fixture("hydra/hydra-dragonstone-console.txt")
        self.assertEqual(report["status"], "parsed")
        self.assertFalse([m for m in rawstore.manifest(self.eng) if m["ai"] == "pending"])

    def test_a_console_capture_with_no_found_line_is_still_hydras(self):
        text = (FIXTURES / "hydra/hydra-dragonstone-console.txt").read_text()
        kept = "".join(line for line in text.splitlines(keepends=True) if "] host: " not in line)
        report = self._import(kept.encode())
        self.assertEqual((report["parser"], report["status"]), ("hydra", "parsed"))
        self.assertEqual(self.all(), [])

    def test_one_password_on_one_port_is_confirmed_beside_a_false_positive_elsewhere(self):
        many = b"".join(b"[21][ftp] host: 192.168.56.84   login: podrick.payne   password: " + p + b"\n"
                        for p in (b"a", b"b", b"c"))
        self._import(FOUND + many + FOUND)
        cred = self._creds()["podrick.payne"]
        self.assertEqual((cred["secret"], cred["hosts"]), ("Sq41re!", ["host:192.168.56.83"]))
        self.assertEqual(len(self.all("credential")), 1)

    def test_the_json_file_gives_the_same_records(self):
        report = self.import_fixture("hydra/hydra-ftp.json")
        self.assertEqual((report["parser"], report["counts"]), ("hydra", {"host": 1, "service": 1, "credential": 1}))
        self.assertEqual(report["status"], "parsed")
        brienne = self._creds()["brienne.tarth"]
        self.assertEqual((brienne["secret"], brienne["state"], brienne["hosts"]),
                         ("Oathk33per", "confirmed", ["host:192.168.56.82"]))
        self.assertEqual(self.all("service")[0]["port"], 21)
        self.assert_citations_hold()

    def test_json_with_no_results_queues_its_command_line(self):
        report = self._import(json_file(""), "out.json")
        self.assertEqual(report["parser"], "hydra")
        pending = [m for m in rawstore.manifest(self.eng) if m["ai"] == "pending"]
        self.assertEqual(len(pending), 1)
        self.assertIn("commandline", rawstore.read(self.eng, pending[0]["blob"]).decode())

    def test_json_with_a_raw_backslash_is_still_read(self):
        row = ('\n\t{"port": 21, "service": "ftp", "host": "192.168.56.83", '
               '"login": "STORMLANDS\\gendry", "password": "Bl4ck\\"smith"}')
        self._import(json_file(row), "out.json")
        gendry = self._creds()["gendry"]
        self.assertEqual((gendry["realm"], gendry["secret"], gendry["hosts"]),
                         ("STORMLANDS", 'Bl4ck"smith', ["host:192.168.56.83"]))
        self.assert_citations_hold()

    def test_colour_codes_from_a_terminal_capture_are_read_through(self):
        line = (b"[\x1b[1;32m22\x1b[0m][\x1b[1;32mssh\x1b[0m] host: \x1b[1;32m192.168.56.83\x1b[0m   "
                b"login: \x1b[1;32mpodrick.payne\x1b[0m   password: \x1b[1;32mSq41re!\x1b[0m\n")
        self._import(line)
        self.assertEqual(self._creds()["podrick.payne"]["secret"], "Sq41re!")
        self.assert_citations_hold()

    def test_a_line_with_no_login_or_no_password_is_only_reported(self):
        report = self._import(b"[5900][vnc] host: 192.168.56.83   password: Sq41re!\n"
                              b"[22][ssh] host: 192.168.56.83   login: podrick.payne\n")
        self.assertEqual(report["counts"], {"host": 1, "service": 2})
        self.assertEqual(self.all("credential"), [])
        self.assertTrue(any("2 found line(s)" in n for n in report["notes"]))
        self.assertEqual(report["status"], "parsed")

    def test_a_named_target_joins_the_host_that_carries_the_name(self):
        ingest.import_data(self.eng, SCAN, "naabu.json")
        self._import(NAMED)
        davos = self._creds()["davos.seaworth"]
        self.assertEqual(davos["hosts"], ["host:192.168.56.80"])
        self.assertIn("service:192.168.56.80-tcp-22", {s["id"] for s in self.all("service")})
        self.assert_citations_hold()

    def test_a_named_target_waits_for_a_scan_that_names_it(self):
        report = self._import(NAMED)
        davos = self._creds()["davos.seaworth"]
        self.assertEqual(davos["state"], "confirmed")
        self.assertNotIn("hosts", davos)
        self.assertTrue(any("stormsend.stormlands.local" in n for n in report["notes"]))
        ingest.import_data(self.eng, SCAN, "naabu.json")
        self.assertEqual(self._creds()["davos.seaworth"]["hosts"], ["host:192.168.56.80"])
        self.assert_citations_hold()

    def test_realm_names_the_domain_of_hydras_logins(self):
        data = FOUND + b"[22][ssh] host: 192.168.56.83   login: NORTH\\gendry   password: Bl4cksmith!\n"
        self._import(data, tool="hydra", realm="stormlands.local")
        creds = self._creds()
        self.assertEqual(creds["podrick.payne"]["realm"], "stormlands.local")
        self.assertEqual(creds["podrick.payne"]["prov"]["realm"]["origin"], "you")
        self.assertEqual(creds["gendry"]["realm"], "NORTH")

    def test_realm_is_still_refused_with_other_parsers(self):
        with self.assertRaisesRegex(LootError, "--realm"):
            self._import(FOUND, tool="netexec", realm="stormlands.local")

    def test_hydra_is_a_parser_name(self):
        self.assertEqual(parsers.by_name("hydra").NAME, "hydra")
