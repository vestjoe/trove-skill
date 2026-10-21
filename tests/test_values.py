import contextlib
import io
import json
import os

from lootlib import aiingest, cli, notes
from tests.helpers import FIXTURES, EngagementCase

ODD = "p\"a\\ss:w'o rd%é."
ADMIN_NT = "3f2a91d7c05b48e6a17c4d9082ef5613"


def field(value, evidence):
    return {"value": value, "evidence": evidence}


class Values(EngagementCase):
    """Passwords and hashes come back exactly as the source wrote them, asked through ``find``."""

    def cli(self, *argv):
        out = io.StringIO()
        cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = cli.main(list(argv))
        finally:
            os.chdir(cwd)
        self.assertEqual(code, 0, argv)
        return out.getvalue()

    def secrets(self, *where):
        argv = ["find", "--type", "credential", "--json", "--limit", "1000"]
        for w in where:
            argv += ["--where", w]
        return {r["principal"]: r.get("secret") for r in json.loads(self.cli(*argv))["records"]}

    def propose(self, text, *recs):
        blob = notes.add(self.eng, text.encode())["blob"]
        return aiingest.check(self.eng, blob, json.dumps({"records": list(recs)}))

    def load(self, name, text):
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return self.cli("import", str(path), "--no-ai")

    def test_q2_an_ai_password_cut_short_of_its_evidence_is_refused(self):
        result = self.propose("svc_backup:Summer2024! from the share\n", {"type": "credential", "fields": {
            "principal": field("svc_backup", "svc_backup:Summer2024!"),
            "secret": field("Summer2024", "svc_backup:Summer2024!")}})
        self.assertIsNone(self.secrets().get("svc_backup"))
        self.assertTrue(any("secret" in d and "whole" in d for d in result["dropped"]))

    def test_q2_a_password_ending_a_sentence_keeps_its_last_character(self):
        self.propose("backup login is svc_backup, pass: Summer2024!.\n", {"type": "credential", "fields": {
            "principal": field("svc_backup", "svc_backup"),
            "secret": field("Summer2024!", "pass: Summer2024!.")}})
        self.assertEqual(self.secrets()["svc_backup"], "Summer2024!")

    def test_q2_an_ai_password_spaced_unlike_its_evidence_is_refused(self):
        self.propose("kiosk pw: Blue  Sky9\n", {"type": "credential", "fields": {
            "principal": field("kiosk", "kiosk pw"),
            "secret": field("Blue Sky9", "kiosk pw: Blue  Sky9")}})
        self.assertIsNone(self.secrets().get("kiosk"))

    def test_q2_any_password_a_tool_dumped_comes_back_byte_for_byte(self):
        dump = (FIXTURES / "creds/secretsdump-cleartext.txt").read_text()
        self.load("odd-ntds.txt", dump.replace("lab-01.local\\dave:CLEARTEXT:Autumn2025!", f"LAB\\odd:CLEARTEXT:{ODD}"))
        self.assertEqual(self.secrets("principal=odd")["odd"], ODD)
        self.assertIn(ODD, self.cli("find", "--type", "credential", "--where", "principal=odd"))

    def test_q2_any_password_the_ai_quoted_whole_comes_back_byte_for_byte(self):
        self.propose(f"odd account password is {ODD}\n", {"type": "credential", "fields": {
            "principal": field("odd", "odd account"),
            "secret": field(ODD, f"password is {ODD}")}})
        self.assertEqual(self.secrets()["odd"], ODD)

    def test_q3_an_nt_hash_in_another_case_is_the_same_hash(self):
        self.cli("import", str(FIXTURES / "creds/secretsdump-ntds.txt"), "--no-ai")
        upper = ADMIN_NT.upper()
        result = self.propose(f"ACME Administrator hash {upper} works\n", {"type": "credential", "fields": {
            "principal": field("Administrator", "ACME Administrator"),
            "realm": field("ACME", "ACME Administrator"),
            "secret_hash": field(ADMIN_NT, upper),
            "hash_type": field("ntlm", upper)}})
        self.assertEqual(result["dropped"], [])
        admins = [r for r in json.loads(self.cli("find", "--type", "credential", "--json", "--where",
                                                 "principal=Administrator", "--where", "realm=ACME"))["records"]]
        self.assertEqual([a["secret_hash"] for a in admins], [ADMIN_NT])

    def test_q2_a_stored_nt_hash_is_lowercase_whatever_case_the_tool_printed(self):
        self.load("upper-sam.txt", "[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)\n"
                                   f"Administrator:500:aad3b435b51404eeaad3b435b51404ee:{ADMIN_NT.upper()}:::\n")
        self.assertIn(f"secret_hash {ADMIN_NT}", " ".join(self.cli("find", "--type", "credential").split()))

    def test_q3_a_dumped_password_with_no_account_is_listed_untried(self):
        self.cli("import", str(FIXTURES / "creds/secretsdump-autologon-offline.txt"), "--no-ai")
        self.assertEqual(self.secrets("secret?", "hosts!").get("(Unknown User)"), "AutoLogon2026!")

    def test_two_passwords_with_no_account_stay_two_credentials(self):
        self.cli("import", str(FIXTURES / "creds/secretsdump-autologon-offline.txt"), "--no-ai")
        dump = (FIXTURES / "creds/secretsdump-autologon-offline.txt").read_text()
        self.load("second-box.txt", dump.replace("AutoLogon2026!", "Kiosk2027!").replace("LABWS3", "LABWS4"))
        held = [r["secret"] for r in json.loads(self.cli("find", "--type", "credential", "--json", "--where",
                                                         "principal=(Unknown User)"))["records"]]
        self.assertEqual(sorted(held), ["AutoLogon2026!", "Kiosk2027!"])

    def test_q2_a_whole_password_in_common_cheat_sheet_forms_is_kept(self):
        lines = ["svc_backup,Summer2024!,DC01", "smbclient -U svc_backup%Summer2024! //dc01/c$",
                 "svc_backup:Summer2024!:DC01", "http://dc01/login?user=svc_backup&pass=Summer2024!&go=1",
                 "svc_backup password “Summer2024!”", "svc_backup password: **Summer2024!**",
                 "psexec lab.local/svc_backup:Summer2024!@10.10.20.10", "svc_backup <password>Summer2024!</password>",
                 "svc_backup/Summer2024!", "svc_backup {Summer2024!}", "is the svc_backup pw Summer2024!?"]
        for line in lines:
            with self.subTest(line=line):
                result = self.propose(line + "\n", {"type": "credential", "fields": {
                    "principal": field("svc_backup", line), "secret": field("Summer2024!", line)}})
                self.assertEqual(result["dropped"], [])

    def test_q2_a_password_with_a_space_at_either_end_is_refused(self):
        for value in (" Summer2024!", "Summer2024! "):
            with self.subTest(value=value):
                self.propose("svc_backup pass:  Summer2024!  ok\n", {"type": "credential", "fields": {
                    "principal": field("svc_backup", "svc_backup"),
                    "secret": field(value, "pass:  Summer2024!  ok")}})
                self.assertIsNone(self.secrets().get("svc_backup"))

    def test_a_hash_login_refused_elsewhere_is_found_whatever_case_netexec_printed(self):
        pth = "".join((FIXTURES / "netexec/nxc-pth.txt").read_text().splitlines(keepends=True)[:2])
        self.load("pth-upper.txt", pth.replace("c5d73fd255b69aad0b8be3420b2b03c8", "C5D73FD255B69AAD0B8BE3420B2B03C8"))
        refused = (FIXTURES / "netexec/nxc-pth-refused.txt").read_text()
        self.load("refused-upper.txt", refused.replace("backup.ops:da7a868ae3207455a709066b8fdab1f6",
                                                       "Administrator:C5D73FD255B69AAD0B8BE3420B2B03C8"))
        self.assertIn("SMB refused lab-01.local\\Administrator", self.cli("find", "--type", "finding"))

    def test_a_password_with_no_account_is_not_counted_as_a_local_account(self):
        report = self.cli("import", str(FIXTURES / "creds/secretsdump-autologon-offline.txt"), "--no-ai")
        self.assertEqual(report.count("belong to LABWS3"), 1)
        self.assertIn("2 local account(s) belong to LABWS3", report)

    def test_a_password_written_with_no_account_is_kept_under_unknown_user_and_untried(self):
        result = self.propose("lab seed passwords:\nHeartsbane\nWinter2022\n", *[
            {"type": "credential", "fields": {"principal": field("(Unknown User)", pw), "secret": field(pw, pw)}}
            for pw in ("Heartsbane", "Winter2022")])
        self.assertEqual(result["dropped"], [])
        out = self.cli("find", "--type", "credential", "--where", "secret?", "--where", "hosts!")
        self.assertIn("principal   (Unknown User)", out)
        self.assertIn("Heartsbane", out)
        self.assertIn("Winter2022", out)

    def test_unknown_user_needs_a_secret_and_is_never_an_account_the_text_names(self):
        result = self.propose("svc_backup has a password somewhere\n", {"type": "credential", "fields": {
            "principal": field("(Unknown User)", "svc_backup has a password")}})
        self.assertIsNone(self.secrets().get("(Unknown User)"))
        self.assertTrue(any("(Unknown User)" in d for d in result["dropped"]))

    def seed(self, *passwords):
        return self.propose("seed:\n" + "\n".join(passwords) + "\n", *[
            {"type": "credential", "fields": {"principal": field("(Unknown User)", pw), "secret": field(pw, pw)}}
            for pw in passwords])

    def test_an_unknown_user_password_held_under_a_named_account_is_not_listed_again(self):
        for order in ("seed first", "seed last"):
            with self.subTest(order=order):
                self.setUp()
                if order == "seed first":
                    self.seed("Winter2022", "Kiosk2027!")
                self.cli("import", str(FIXTURES / "netexec/nxc-cred-check.txt"), "--no-ai")
                if order == "seed last":
                    self.seed("Winter2022", "Kiosk2027!")
                out = self.cli("find", "--type", "credential", "--where", "secret?", "--where", "hosts!")
                self.assertIn("Kiosk2027!", out)
                self.assertNotIn("Winter2022", out)
                self.assertIn("1 (Unknown User) password(s) not shown", out)

    def test_a_search_the_repeat_would_not_match_does_not_count_it(self):
        self.cli("import", str(FIXTURES / "netexec/nxc-cred-check.txt"), "--no-ai")
        self.seed("Winter2022")
        self.assertNotIn("not shown", self.cli("find", "--type", "credential", "--where", "state=cracked"))
