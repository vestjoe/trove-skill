from lootlib import ingest, rawstore
from tests import SAMPLES
from tests.helpers import EngagementCase

LAB = SAMPLES / "lab-creds"
REALM = "arbor.lab.test"


class LabCreds(EngagementCase):
    """Real Hydra, kerbrute, GetNPUsers, NetNTLMv2 and John runs against lab-web and lab-dc in tests/lab."""

    def _import(self, *names):
        return [ingest.import_path(self.eng, LAB / name)[0] for name in names]

    def _by(self, type_name="credential"):
        return {(r.get("realm"), r["principal"]): r for r in self.all(type_name)}

    def _pending(self):
        return [m["source"] for m in rawstore.manifest(self.eng) if m["ai"] == "pending"]

    def test_each_hydra_output_is_the_one_confirmed_login_on_lab_web(self):
        reports = self._import("hydra-ssh.txt", "hydra-ftp.json", "hydra-ftp-console.txt")
        self.assertEqual({r["parser"] for r in reports}, {"hydra"})
        [quill] = self.all("credential")
        self.assertEqual((quill["principal"], quill["secret"], quill["state"], quill["hosts"]),
                         ("quill", "Ink-Well-4", "confirmed", ["host:10.99.56.10"]))
        self.assertEqual({(s["port"], s["name"]) for s in self.all("service")}, {(21, "ftp"), (22, "ssh")})
        self.assertEqual(self._pending(), [])
        self.assert_citations_hold()

    def test_kerbrute_userenum_gives_the_accounts_and_the_asrep_hash(self):
        [report] = self._import("kerbrute-userenum.txt")
        self.assertEqual(report["parser"], "kerbrute")
        self.assertEqual({p for (realm, p) in self._by("principal") if realm == REALM},
                         {"rowan.ash", "elm.stone", "willow.reed", "hazel.birch", "alder.fern"})
        self.assertTrue(any("alder.fern" in n and "expired" in n for n in report["notes"]))
        [hazel] = self.all("credential")
        self.assertEqual((hazel["principal"], hazel["hash_type"]), ("hazel.birch", "krb5asrep"))
        self.assertTrue(hazel["secret_hash"].startswith("$krb5asrep$18$hazel.birch@ARBOR.LAB.TEST:"))
        self.assert_citations_hold()

    def test_kerbrute_spray_confirms_both_logins_and_reports_the_expired_one(self):
        [report] = self._import("kerbrute-spray.txt")
        by = self._by()
        for user in ("rowan.ash", "alder.fern"):
            self.assertEqual((by[(REALM, user)]["secret"], by[(REALM, user)]["state"]), ("Spring-Lab-26", "confirmed"))
        self.assertTrue(any("alder.fern" in n and "expired" in n for n in report["notes"]))
        self.assertEqual(self._pending(), [])

    def test_kerbrute_1_0_3_o_file_confirms_both_logins(self):
        [report] = self._import("kerbrute-o.txt")
        self.assertEqual(report["parser"], "kerbrute")
        self.assertEqual({p: c["state"] for (realm, p), c in self._by().items() if realm == REALM},
                         {"rowan.ash": "confirmed", "alder.fern": "confirmed"})

    def test_john_cracks_the_getnpusers_asrep_hash(self):
        self._import("getnpusers.txt", "john-show-krb5asrep.txt")
        [hazel] = self.all("credential")
        self.assertEqual((hazel["principal"], hazel["realm"], hazel["secret"], hazel["state"]),
                         ("hazel.birch", "ARBOR.LAB.TEST", "Birch:Bark9", "cracked"))
        self.assert_citations_hold()

    def test_only_the_getnpusers_error_that_names_no_account_goes_to_the_agent(self):
        self._import("getnpusers.txt")
        [entry] = [m for m in rawstore.manifest(self.eng) if m["ai"] == "pending"]
        self.assertEqual(rawstore.read(self.eng, entry["blob"]).decode().strip(),
                         "[-] Kerberos SessionError: KDC_ERR_KEY_EXPIRED(Password has expired; change password to reset)")

    def test_john_cracks_the_dc_accounts_by_nt_hash(self):
        reports = self._import("arbor.ntds", "john-show-nt.txt")
        self.assertEqual([r["parser"] for r in reports], ["creds", "creds"])
        cracked = {p: c["secret"] for (realm, p), c in self._by().items() if c.get("state") == "cracked"}
        self.assertEqual(cracked, {"Administrator": "Arbor-Admin-26", "rowan.ash": "Spring-Lab-26",
                                   "alder.fern": "Spring-Lab-26", "hazel.birch": "Birch:Bark9"})
        self.assertEqual(self._by()[(REALM, "rowan.ash")]["prov"]["secret"]["source"], "john-show-nt.txt")
        self.assertEqual(self._pending(), [])
        self.assert_citations_hold()

    def test_john_cracks_the_captured_netntlmv2_hash(self):
        self._import("netntlmv2.txt", "john-show-netntlmv2.txt")
        [rowan] = self.all("credential")
        self.assertEqual((rowan["principal"], rowan["realm"], rowan["secret"], rowan["state"]),
                         ("rowan.ash", "ARBOR", "Spring-Lab-26", "cracked"))
        self.assertEqual(self._pending(), [])

    def test_show_left_adds_no_password(self):
        self._import("arbor.ntds", "john-show-left.txt")
        self.assertFalse([c for c in self.all("credential") if c.get("secret")])

    def test_everything_together_is_one_credential_per_account(self):
        ingest.import_path(self.eng, LAB)
        accounts = [(c.get("realm"), c["principal"]) for c in self.all("credential")]
        self.assertEqual(len(accounts), len(set(accounts)))
        by = self._by()
        self.assertEqual({p: (c["state"], c.get("secret")) for (realm, p), c in by.items() if realm == REALM}, {
            "rowan.ash": ("cracked", "Spring-Lab-26"), "alder.fern": ("cracked", "Spring-Lab-26"),
            "hazel.birch": ("cracked", "Birch:Bark9"), "willow.reed": ("found", None), "elm.stone": ("found", None)})
        self.assertEqual(by[(None, "quill")]["state"], "confirmed")
        self.assert_citations_hold()
