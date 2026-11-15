from lootlib import ingest, rawstore
from tests.helpers import FIXTURES, EngagementCase

LM = "aad3b435b51404eeaad3b435b51404ee"
WEST = "westerlands.sevenkingdoms.local"
NTDS = (FIXTURES / "creds/westerlands.ntds").read_text().splitlines()
KEVAN_NT = next(line for line in NTDS if "kevan.lannister" in line).split(":")[3]
ADMIN_NT = next(line for line in NTDS if "Administrator" in line).split(":")[3]
TYREK = "tyrek.lannister@WESTERLANDS.SEVENKINGDOMS.LOCAL"
OTHER_ASREP = ("$krb5asrep$23$tyrek.lannister@CROWNLANDS.SEVENKINGDOMS.LOCAL:" + "4f" * 16 + "$" + "a7" * 120)
SECOND_ASREP = ("$krb5asrep$23$" + TYREK + ":" + "5e" * 16 + "$" + "b8" * 120)


class JohnShow(EngagementCase):
    """John's --show lines joined to the credentials they cracked."""

    def _by(self):
        return {(r.get("realm"), r["principal"]): r for r in self.all("credential")}

    def _import(self, text, name="show.txt"):
        return ingest.import_data(self.eng, text.encode(), name)[0]

    def _pending(self):
        return [m["source"] for m in rawstore.manifest(self.eng) if m["ai"] == "pending"]

    def test_an_ntds_line_fills_the_password_of_the_account_with_that_nt_hash(self):
        self.import_fixture("creds/westerlands.ntds")
        report = self.import_fixture("creds/john-show-ntds.txt")
        self.assertEqual((report["parser"], report["new"]), ("creds", 0))
        kevan = self._by()[(WEST, "kevan.lannister")]
        self.assertEqual((kevan["secret"], kevan["state"]), ("Casterly:Rock7", "cracked"))
        self.assertEqual(kevan["prov"]["secret"]["quote"], "Casterly:Rock7")
        self.assertEqual(self._by()[(WEST, "addam.marbrand")]["secret"], "Ashemark2!")
        self.assertEqual(len(self.all("credential")), 5)
        self.assert_citations_hold()

    def test_a_show_file_imported_first_waits_for_its_hashes(self):
        report = self.import_fixture("creds/john-show-ntds.txt")
        self.assertEqual((report["parser"], self.all("credential")), ("creds", []))
        self.assertTrue(any("match no credential" in n for n in report["notes"]))
        self.import_fixture("creds/westerlands.ntds")
        self.assertEqual(self._by()[(WEST, "kevan.lannister")]["secret"], "Casterly:Rock7")

    def test_a_netntlmv2_line_joins_the_captured_hash_it_rebuilds(self):
        self.import_fixture("creds/westerlands-hashes.txt")
        self.import_fixture("creds/john-show-netntlmv2.txt")
        jeyne = self._by()[("WESTERLANDS", "jeyne.westerling")]
        self.assertEqual((jeyne["secret"], jeyne["state"]), ("Oxcross1", "cracked"))
        self.assertEqual(len(self.all("credential")), 2)
        self.assert_citations_hold()

    def test_an_asrep_line_joins_the_one_asrep_hash_of_that_account_and_realm(self):
        self.import_fixture("creds/westerlands-hashes.txt")
        self._import(OTHER_ASREP + "\n", "crownlands.txt")
        self.import_fixture("creds/john-show-asrep.txt")
        by = self._by()
        self.assertEqual(by[("WESTERLANDS.SEVENKINGDOMS.LOCAL", "tyrek.lannister")]["secret"], "Lannisport9")
        self.assertNotIn("secret", by[("CROWNLANDS.SEVENKINGDOMS.LOCAL", "tyrek.lannister")])
        self.assertEqual(len(self.all("credential")), 3)
        self.assert_citations_hold()

    def test_two_asrep_hashes_of_the_account_are_one_credential_that_takes_the_password(self):
        self.import_fixture("creds/westerlands-hashes.txt")
        self._import(SECOND_ASREP + "\n", "again.txt")
        self.assertEqual(len(self.all("credential")), 2)
        self.import_fixture("creds/john-show-asrep.txt")
        self.assertEqual(self._by()[("WESTERLANDS.SEVENKINGDOMS.LOCAL", "tyrek.lannister")]["secret"], "Lannisport9")
        self.assertEqual(len(self.all("credential")), 2)

    def test_a_local_account_of_the_same_name_keeps_its_own_hash(self):
        self.import_fixture("creds/westerlands.ntds")
        self._import("[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)\n"
                     f"Administrator:500:{LM}:{'3c' * 16}:::\n", "sam.txt")
        self._import(f"Administrator:Lion.Gold5:500:{LM}:{ADMIN_NT}:::\n")
        admins = [r for r in self.all("credential") if r["principal"] == "Administrator"]
        self.assertEqual(sorted((r.get("realm") or "", r.get("secret") or "") for r in admins),
                         [("", ""), (WEST, "Lion.Gold5")])

    def test_a_password_beside_an_lm_hash_is_not_read(self):
        self.import_fixture("creds/westerlands.ntds")
        report = self._import(f"{WEST}\\kevan.lannister:CASTERLY:1104:{'e5' * 16}:{KEVAN_NT}:::\n")
        self.assertTrue(any("LM" in n for n in report["notes"]))
        self.assertNotIn("secret", self._by()[(WEST, "kevan.lannister")])

    def test_an_empty_password_beside_a_set_nt_hash_is_not_read(self):
        self.import_fixture("creds/westerlands.ntds")
        report = self._import(f"{WEST}\\kevan.lannister::1104:{LM}:{KEVAN_NT}:::\n")
        self.assertTrue(any("empty" in n for n in report["notes"]))
        self.assertNotIn("secret", self._by()[(WEST, "kevan.lannister")])

    def test_johns_summary_never_goes_to_extraction(self):
        for rel in ("john-show-ntds.txt", "john-show-netntlmv2.txt", "john-show-asrep.txt"):
            self.assertEqual(self.import_fixture(f"creds/{rel}")["status"], "parsed", rel)
        self.assertEqual(self._pending(), [])

    def test_a_name_and_password_alone_are_not_joined(self):
        self.import_fixture("creds/westerlands.ntds")
        self._import("kevan.lannister:Casterly:Rock7\n?:Lion.Gold5\n\n2 password hashes cracked, 0 left\n")
        self.assertFalse(any(r.get("secret") for r in self.all("credential")))
