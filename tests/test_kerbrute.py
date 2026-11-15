from lootlib import ingest, parsers, rawstore
from tests.helpers import FIXTURES, EngagementCase

DOM = b"vale.sevenkingdoms.local"
LOGIN = b"2026/11/15 10:40:00 >  [+] VALID LOGIN:\t mya.stone@" + DOM + b":Eyrie.Moon3\n"
ASREP = next(line.removesuffix("\x1b[0m") for line in (FIXTURES / "kerbrute/kerbrute-userenum-vale.txt").read_text()
             .split("\n") if line.startswith("$krb5asrep$"))


class Kerbrute(EngagementCase):
    """kerbrute's console captures and its -o file."""

    def _by(self, type_name):
        return {r["principal"]: r for r in self.all(type_name)}

    def _import(self, data, name="kerbrute.txt", **kw):
        return ingest.import_data(self.eng, data, name, **kw)[0]

    def _pending(self):
        return [m for m in rawstore.manifest(self.eng) if m["ai"] == "pending"]

    def test_a_valid_login_is_a_confirmed_credential_in_its_realm(self):
        report = self.import_fixture("kerbrute/kerbrute-spray-vale.txt")
        self.assertEqual((report["parser"], report["counts"]), ("kerbrute", {"credential": 2}))
        robin = self._by("credential")["robin.arryn"]
        self.assertEqual((robin["realm"], robin["secret"], robin["state"]),
                         ("vale.sevenkingdoms.local", "Falcon.Gate1", "confirmed"))
        self.assertEqual(robin["id"], "credential:vale.sevenkingdoms.local\\robin.arryn+" + robin["id"].rsplit("+")[1])
        self.assertNotIn("hosts", robin)
        self.assertIn("[+] VALID LOGIN:\t robin.arryn@", robin["prov"]["state"]["quote"])
        self.assert_citations_hold()

    def test_a_login_with_an_error_is_confirmed_and_reported(self):
        report = self.import_fixture("kerbrute/kerbrute-spray-vale.txt")
        harrold = self._by("credential")["harrold.hardyng"]
        self.assertEqual((harrold["realm"], harrold["secret"], harrold["state"]),
                         ("vale.sevenkingdoms.local", "Falcon.Gate1", "confirmed"))
        note = next(n for n in report["notes"] if "harrold.hardyng" in n)
        self.assertIn("User's password has expired", note)

    def test_a_valid_username_is_a_principal_in_its_realm(self):
        report = self.import_fixture("kerbrute/kerbrute-userenum-vale.txt")
        self.assertEqual((report["parser"], report["counts"]), ("kerbrute", {"principal": 4, "credential": 1}))
        found = self._by("principal")
        self.assertEqual(set(found), {"robin.arryn", "mya.stone", "yohn.royce", "lothor.brune"})
        self.assertEqual({p["realm"] for p in found.values()}, {"vale.sevenkingdoms.local"})
        self.assertEqual(self.all("host"), [])
        self.assert_citations_hold()

    def test_an_asrep_hash_is_the_credential_the_creds_parser_makes(self):
        self.import_fixture("kerbrute/kerbrute-userenum-vale.txt")
        [mya] = self.all("credential")
        self.assertEqual((mya["principal"], mya["hash_type"]), ("mya.stone", "krb5asrep"))
        self.assertEqual(mya["secret_hash"], ASREP)
        report = self._import(ASREP.encode() + b"\n", "asrep.txt")
        self.assertEqual((report["parser"], report["counts"]["credential"]), ("creds", 1))
        self.assertEqual(len(self.all("credential")), 1)

    def test_a_password_keeps_everything_after_the_realm(self):
        report = self.import_fixture("kerbrute/kerbrute-o-vale.txt")
        self.assertEqual((report["parser"], report["counts"]), ("kerbrute", {"credential": 1}))
        yohn = self._by("credential")["yohn.royce"]
        self.assertEqual((yohn["realm"], yohn["secret"], yohn["state"]),
                         ("vale.sevenkingdoms.local", "Bronze:Runes4", "confirmed"))
        self.assert_citations_hold()

    def test_kerbrutes_own_lines_never_go_to_extraction(self):
        for rel in ("kerbrute-spray-vale.txt", "kerbrute-userenum-vale.txt", "kerbrute-o-vale.txt"):
            self.assertEqual(self.import_fixture(f"kerbrute/{rel}")["status"], "parsed", rel)
        self.assertEqual(self._pending(), [])

    def test_a_run_with_no_hit_is_still_kerbrutes(self):
        text = (FIXTURES / "kerbrute/kerbrute-spray-vale.txt").read_text()
        kept = "".join(line for line in text.splitlines(keepends=True) if "VALID" not in line)
        report = self._import(kept.encode())
        self.assertEqual((report["parser"], report["status"]), ("kerbrute", "parsed"))
        self.assertEqual(self.all(), [])

    def test_prose_around_the_output_goes_to_extraction(self):
        report = self._import(b"sprayed the vale with the seasonal list\n" + LOGIN)
        self.assertEqual(report["parser"], "kerbrute")
        self.assertEqual(len(self.all("credential")), 1)
        self.assertEqual(len(self._pending()), 1)

    def test_one_login_printed_twice_is_one_credential(self):
        self._import(LOGIN + LOGIN)
        self.assertEqual(len(self.all("credential")), 1)

    def test_it_is_reachable_by_name(self):
        self.assertEqual(parsers.by_name("kerbrute").NAME, "kerbrute")
        report = ingest.import_data(self.eng, LOGIN, "spray.txt", tool="kerbrute")[0]
        self.assertEqual((report["parser"], report["counts"]), ("kerbrute", {"credential": 1}))
