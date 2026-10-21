import contextlib
import io
import json
import os

from lootlib import cli
from tests.helpers import FIXTURES, EngagementCase

ADMIN_NT = "c5d73fd255b69aad0b8be3420b2b03c8"


class Dumps(EngagementCase):
    """NetExec dumps, pass-the-hash logins and secretsdump cleartext, asked as the operator asks."""

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

    def load(self, *rels):
        return "".join(self.cli("import", str(FIXTURES / rel), "--no-ai") for rel in rels)

    def blocks(self, *where):
        """Each record the text ``find`` prints, keyed by id, as {field: value}."""
        argv = ["find", "--type", "credential", "--limit", "1000"]
        for w in where:
            argv += ["--where", w]
        out = {}
        for chunk in self.cli(*argv).split("\n\n")[1:]:
            lines = chunk.strip().splitlines()
            out[lines[0]] = {line.split()[0]: line.split()[1] for line in lines[1:]}
        return out

    def by_principal(self, blocks):
        return {(b.get("realm"), b["principal"]): b for b in blocks.values()}

    def test_q3_lists_every_sam_hash_nxc_dumped_taken_from_that_host(self):
        self.load("netexec/nxc-sam.txt")
        held = self.by_principal(self.blocks("secret_hash?"))
        self.assertEqual(set(held), {("LABWS1", "Administrator"), ("LABWS1", "Guest"), ("LABWS1", "DefaultAccount")})
        admin = held[("LABWS1", "Administrator")]
        self.assertEqual((admin["secret_hash"], admin["host_id"], admin["state"]),
                         ("8846f7eaee8fb117ad06bdd830b7586c", "host:10.10.20.21", "found"))
        self.assertEqual(set(self.by_principal(self.blocks("host=10.10.20.21"))),
                         set(held) | {("lab-01.local", "backup.ops")})
        self.assert_citations_hold()

    def test_an_nxc_ntds_dump_names_the_domain_and_joins_the_login_it_came_with(self):
        self.load("netexec/nxc-ntds.txt")
        held = self.by_principal(self.blocks("host=10.10.20.10"))
        self.assertEqual(set(held), {("lab-01.local", p) for p in
                                     ("Administrator", "Guest", "krbtgt", "backup.ops", "LABDC$")})
        backup = held[("lab-01.local", "backup.ops")]
        self.assertEqual((backup["secret"], backup["secret_hash"], backup["hosts"], backup["admin_hosts"]),
                         ("Backup2026!", "da7a868ae3207455a709066b8fdab1f6", "host:10.10.20.10", "host:10.10.20.10"))
        self.assertEqual(held[("lab-01.local", "Administrator")]["host_id"], "host:10.10.20.10")
        self.assert_citations_hold()

    def test_q2_a_pass_the_hash_login_is_the_accounts_hash_not_its_password(self):
        self.load("netexec/nxc-pth.txt")
        worked = self.by_principal(self.blocks("hosts?"))
        self.assertEqual(set(worked), {("lab-01.local", "Administrator")})
        admin = worked[("lab-01.local", "Administrator")]
        self.assertNotIn("secret", admin)
        self.assertEqual((admin["secret_hash"], admin["hash_type"], admin["admin_hosts"]),
                         (ADMIN_NT, "ntlm", "host:10.10.20.10"))
        self.assertIn("host:10.10.20.22", self.cli("find", "--type", "credential", "--where", "hosts=10.10.20.22"))
        self.assert_citations_hold()

    def test_a_pass_the_hash_login_joins_the_dumped_hash_it_used(self):
        self.load("netexec/nxc-ntds.txt", "netexec/nxc-pth.txt")
        admins = [b for b in self.blocks("principal=Administrator").values() if b.get("realm") == "lab-01.local"]
        self.assertEqual(len(admins), 1)
        self.assertEqual((admins[0]["secret_hash"], admins[0]["host_id"], admins[0]["hosts"]),
                         (ADMIN_NT, "host:10.10.20.10", "host:10.10.20.10"))

    def test_a_masked_login_stores_no_password_and_says_so(self):
        report = self.load("netexec/nxc-pth.txt")
        self.assertNotIn("********", self.cli("find", "--type", "credential"))
        self.assertIn("masked", report)
        self.assertNotIn(("lab-01.local", "backup.ops"), self.by_principal(self.blocks()))

    def write(self, name, text):
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return self.cli("import", str(path), "--no-ai")

    def test_a_mask_after_revealed_characters_stores_no_password(self):
        banner = (FIXTURES / "netexec/nxc-pth.txt").read_text().splitlines(keepends=True)[2]
        report = self.write("nxc-reveal.txt", banner + banner[:banner.index("[*]")]
                            + "[+] lab-01.local\\backup.ops:Wi******** (Pwn3d!)\n")
        self.assertIn("masked", report)
        self.assertNotIn(("lab-01.local", "backup.ops"), self.by_principal(self.blocks()))

    def test_an_autologon_for_an_account_with_no_domain_is_kept_under_that_account(self):
        sam = (FIXTURES / "creds/secretsdump-cleartext.txt").read_text().splitlines(keepends=True)[5:8]
        self.write("autologon.txt", "".join(sam) + "[*] Dumping LSA Secrets\n[*] DefaultPassword \nkiosk:Kiosk2026!\n")
        kiosk = self.by_principal(self.blocks("secret?"))[(None, "kiosk")]
        self.assertEqual((kiosk["secret"], kiosk["source"]), ("Kiosk2026!", "DefaultPassword"))

    def test_q3_secretsdump_cleartext_and_a_named_autologon_are_plaintexts(self):
        self.load("creds/secretsdump-cleartext.txt")
        held = self.by_principal(self.blocks("secret?"))
        self.assertEqual(set(held), {("lab-01.local", "dave"), ("LAB-01", "kiosk")})
        dave = held[("lab-01.local", "dave")]
        self.assertEqual((dave["secret"], dave["secret_hash"]), ("Autumn2025!", "980dfdd798a72d28b645c02273a081fe"))
        self.assertEqual((held[("LAB-01", "kiosk")]["secret"], held[("LAB-01", "kiosk")]["source"]),
                         ("Kiosk2026!", "DefaultPassword"))
        self.assert_citations_hold()

    def test_an_autologon_password_with_no_account_is_kept_owned_by_no_account(self):
        report = self.load("creds/secretsdump-autologon-offline.txt")
        held = json.loads(self.cli("find", "--type", "credential", "--json", "--where", "principal=(Unknown User)"))
        self.assertEqual([(r.get("realm"), r["secret"], r["source"]) for r in held["records"]],
                         [(None, "AutoLogon2026!", "DefaultPassword")])
        self.assertIn("1 password(s) were dumped with no account", report)
        self.assert_citations_hold()

    def test_a_pass_the_hash_login_then_its_ntds_dump_is_one_credential_with_both_facts(self):
        self.load("netexec/nxc-pth-ntds.txt")
        admins = self.blocks("principal=Administrator")
        self.assertEqual(len(admins), 1)
        admin = next(iter(admins.values()))
        self.assertEqual((admin["host_id"], admin["hosts"], admin["admin_hosts"], admin["state"]),
                         ("host:10.10.20.10", "host:10.10.20.10", "host:10.10.20.10", "confirmed"))
        self.assert_citations_hold()

    def test_a_dump_after_a_share_table_is_still_a_dump(self):
        report = self.load("netexec/nxc-shares-then-sam.txt")
        self.assertNotIn("share row does not fit", report)
        admin = self.by_principal(self.blocks("host=10.10.20.21"))[("LABWS1", "Administrator")]
        self.assertEqual(admin["secret_hash"], "8846f7eaee8fb117ad06bdd830b7586c")

    def test_a_hash_login_refused_elsewhere_is_a_refusal_once_the_hash_worked(self):
        self.load("netexec/nxc-ntds.txt")
        report = self.load("netexec/nxc-pth-refused.txt")
        self.assertNotIn("failed and produced no credential", report)
        self.assertIn("SMB refused lab-01.local\\backup.ops", self.cli("find", "--type", "finding"))
