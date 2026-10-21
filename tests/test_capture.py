import contextlib
import io
import json
import os

from lootlib import cli, rawstore
from tests.helpers import FIXTURES, EngagementCase


class Capture(EngagementCase):
    """Each tool's output saved the way the capture guide says, read as the operator asks."""

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

    def load(self, rel):
        return self.cli("import", str(FIXTURES / rel), "--no-ai")

    def write(self, name, text):
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return self.cli("import", str(path), "--no-ai")

    def records(self, *where, kind="credential"):
        argv = ["find", "--type", kind, "--json", "--limit", "1000"]
        for w in where:
            argv += ["--where", w]
        return json.loads(self.cli(*argv))["records"]

    def queued(self):
        return [line for e in rawstore.manifest(self.eng) if e.get("ai") == "pending"
                for line in rawstore.read(self.eng, e["blob"]).decode().splitlines() if line.strip()]

    def test_a_netexec_log_file_is_read_like_its_screen_output(self):
        self.load("netexec/nxc-log-riverrun.log")
        jojen = self.records("principal=jojen.reed")
        self.assertEqual([(r["secret"], r["hosts"], r["admin_hosts"]) for r in jojen],
                         [("Gr33nS1ght!", ["host:192.168.56.24"], ["host:192.168.56.24"])])
        admin = self.records("principal=Administrator")
        self.assertEqual([r.get("host_id") for r in admin], [["host:192.168.56.24"]])
        self.assertIn("service:192.168.56.24-tcp-445", self.cli("find", "--where", "host=192.168.56.24"))
        self.assertEqual(len(self.queued()), 1)
        self.assertTrue(self.queued()[0].startswith("[2026-10-17 09:12:01]> nxc smb 192.168.56.24"))
        self.assert_citations_hold()

    def test_secretsdump_cached_logons_are_dcc2_hashes_of_their_domain_accounts(self):
        self.load("creds/secretsdump-cached-riverrun.txt")
        cached = {r["principal"]: r for r in self.records("hash_type=dcc2")}
        self.assertEqual(set(cached), {"meera.reed", "osha"})
        meera = cached["meera.reed"]
        self.assertEqual(meera["realm"].lower(), "north.sevenkingdoms.local")
        self.assertTrue(meera["secret_hash"].startswith("$DCC2$10240#meera.reed#"))
        self.assertNotIn(":", meera["secret_hash"])
        self.assertEqual(self.queued(), [])
        self.assert_citations_hold()

    def test_a_responder_session_log_ties_the_hash_to_the_client(self):
        self.load("creds/Responder-Session.log")
        meera = self.records("principal=meera.reed")
        self.assertEqual([(r["hash_type"], r.get("host_id")) for r in meera],
                         [("netntlmv2", ["host:192.168.56.25"])])
        self.assertEqual(self.queued(), [])
        self.assert_citations_hold()

    def test_a_bloodhound_collection_without_object_properties_says_why_users_are_missing(self):
        users = {"data": [{"ObjectIdentifier": "S-1-5-21-1111-2222-3333-1601",
                           "Properties": {"name": "MEERA.REED@NORTH.SEVENKINGDOMS.LOCAL",
                                          "domain": "NORTH.SEVENKINGDOMS.LOCAL"}}],
                 "meta": {"methods": 0, "type": "users", "count": 1, "version": 6}}
        report = self.write("20261017091500_users.json", json.dumps(users))
        self.assertIn("-c All", report)

    def test_a_hashcat_outfile_with_hex_and_position_columns_stores_only_the_password(self):
        nt = "6f1d4b8e2a9c03f75e8d1b4a2c6f9e30"
        self.write("dump.txt", f"osha:1105:aad3b435b51404eeaad3b435b51404ee:{nt}:::\n")
        self.write("cracked.out", f"{nt}:Wildl1ng!:57696c646c316e6721:48213\n")
        self.assertEqual([r["secret"] for r in self.records("principal=osha")], ["Wildl1ng!"])

    def dumped_admins(self):
        return sorted((r["id"], r.get("host_id")) for r in self.records("principal=Administrator"))

    LOG, SAM = "netexec/nxc-log-riverrun.log", "creds/RIVERRUN_192.168.56.24_2026-10-17_091204.sam"

    def assert_one_riverrun_administrator(self):
        self.assertEqual(self.dumped_admins(),
                         [("credential:riverrun\\administrator-cb1eff26", ["host:192.168.56.24"])])
        self.assertEqual(sorted((r["id"], r.get("host_id")) for r in self.records("principal=Guest")),
                         [("credential:guest-5db21f1a", None),
                          ("credential:riverrun\\guest-5db21f1a", ["host:192.168.56.24"])])
        self.assert_citations_hold()

    def test_a_netexec_sam_file_joins_the_account_its_log_names(self):
        self.load(self.LOG)
        self.load(self.SAM)
        self.assert_one_riverrun_administrator()

    def test_a_netexec_sam_file_imported_first_joins_the_account_its_log_names(self):
        self.load(self.SAM)
        self.load(self.LOG)
        self.assert_one_riverrun_administrator()

    def test_a_sam_file_whose_hash_two_hosts_hold_joins_neither(self):
        line = "SMB         192.168.56.{ip}   445    {name}         {text}\n"
        for ip, name in (("24", "RIVERRUN"), ("26", "HARRENHAL")):
            self.write(f"{name}.txt", line.format(ip=ip, name=name, text=f"[*] Windows Server 2019 (name:{name})")
                       + line.format(ip=ip, name=name, text="[*] Dumping SAM hashes")
                       + line.format(ip=ip, name=name, text="Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
                                     "a141817c48ef7530b8976f9e0b2afea2:::"))
        self.load("creds/RIVERRUN_192.168.56.24_2026-10-17_091204.sam")
        self.assertEqual([i for i, _ in self.dumped_admins()],
                         ["credential:administrator-cb1eff26", "credential:harrenhal\\administrator-cb1eff26",
                          "credential:riverrun\\administrator-cb1eff26"])

    def test_a_dump_file_that_names_no_host_says_where_the_host_is(self):
        report = self.load(self.SAM)
        self.assertIn("2 dumped line(s) name no domain and no host", report)
        self.assertIn("NetExec log", report)
        self.assertIn("empty password", report)

    def test_a_dump_file_whose_lines_all_joined_says_nothing_about_hosts(self):
        self.load(self.LOG)
        report = self.load(self.SAM)
        self.assertIn("1 dumped line(s) name no domain and no host", report)

    def test_a_dump_line_with_an_lm_hash_counts_once(self):
        report = self.write("bob.sam", "bob:1001:e52cac67419a9a224a3b108f3fa6cb6d:"
                                       "d1f8b340aa1c6a4b6c2f3e8d9a0b7c51:::\n")
        self.assertIn("1 dumped line(s) name no domain and no host", report)

    def test_a_dump_line_with_another_rid_joins_nothing(self):
        self.load(self.LOG)
        self.write("other.sam", "Administrator:1001:aad3b435b51404eeaad3b435b51404ee:"
                                "a141817c48ef7530b8976f9e0b2afea2:::\n")
        self.assertEqual([i for i, _ in self.dumped_admins()],
                         ["credential:administrator-cb1eff26", "credential:riverrun\\administrator-cb1eff26"])
