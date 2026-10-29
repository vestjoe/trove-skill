import contextlib
import io
import json
import os

from lootlib import aiingest, cli, rawstore
from tests import CORPUS
from tests.helpers import FIXTURES, EngagementCase

BOX_NOTES = """# Box notes

Found creds in the share: svc-backup / Backup2026! works on WS01 over winrm.
Domain admin is da-joe, password reused from the web app: Adm1n!2026

Scan excerpt:
Nmap scan report for 10.10.10.5
445/tcp open  microsoft-ds
"""
PROSE = ("Found creds in the share: svc-backup / Backup2026! works on WS01 over winrm.",
         "Domain admin is da-joe, password reused from the web app: Adm1n!2026")


class MixedFiles(EngagementCase):
    """A file a parser claims keeps what the parser read; the lines it did not go to extraction alone."""

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

    def load(self, name, text):
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return self.cli("import", str(path), "--no-ai")

    def pending(self):
        return [e for e in rawstore.manifest(self.eng) if e.get("ai") == "pending"]

    def test_h1_a_note_with_a_scan_excerpt_keeps_the_scan_and_queues_only_the_prose(self):
        report = self.load("box-notes.md", BOX_NOTES)
        self.assertIn("service:10.10.10.5-tcp-445", self.cli("find", "--where", "host=10.10.10.5"))
        waiting = self.pending()
        self.assertEqual(len(waiting), 1)
        text = rawstore.read(self.eng, waiting[0]["blob"]).decode()
        for line in PROSE:
            self.assertIn(line, text)
        self.assertNotIn("Nmap scan report", text)
        self.assertIn("not read by nmap-text", report)
        self.assertIn(waiting[0]["blob"][:23], self.cli("pending"))

    def test_h1_prose_that_starts_like_a_scan_line_is_still_prose(self):
        prose = ["# Box notes", "Note: the admin password is Summer2024!", "Nmap found 445 open, try svc_sql",
                 "Running the web app as svc_web / Web2026!", "Host has a second NIC on 10.20.0.0/24"]
        self.load("scan-notes.md", "\n".join(prose) + "\nNmap scan report for 10.10.10.5\n445/tcp open  microsoft-ds\n")
        self.assertEqual(rawstore.read(self.eng, self.pending()[0]["blob"]).decode().splitlines(), prose)

    def queued(self):
        return [line for e in self.pending() if "not read by" in e["source"]
                for line in rawstore.read(self.eng, e["blob"]).decode().splitlines()]

    def test_h1_prose_shaped_like_netexec_output_is_still_prose(self):
        prose = ["[+] got DA: acme.local\\da-joe : Adm1n!2026 (from the GPP file)",
                 "[*] note: svc_web password is Web2026! on WEB01",
                 "[-] did not work: alice / Alice2026! on SQL01, try on WEB01",
                 "nxc says carol:Carol2026! works on WS01 over winrm",
                 "cme also showed dave:Dave2026! as admin on WS02",
                 "SMB 10.10.10.7 445 is open and eve:Eve2026! logs in"]
        real = "SMB         10.10.10.6      445    DC01             [+] acme.local\\svc_backup:Winter2024!"
        self.load("nxc-notes.txt", "\n".join([real] + prose) + "\n")
        self.assertEqual(self.queued(), prose)

    def test_h1_prose_shaped_like_nmap_output_is_still_prose(self):
        prose = ["# Box notes", "| user | password |", "|------|----------|", "| svc_sql | Sql2026! |",
                 "Host is running IIS; admin portal login admin / Adm1nPortal!",
                 "Scanning the web root found config.php with db_pass=Db2026!",
                 "Completed the box; local admin is Administrator / L0cal2026!",
                 "Service Info: creds for the jenkins box are jenkins:J3nkins!"]
        after = ["Host is running IIS too, creds alice / Alice2026!", "| alice | Alice2026! |"]
        scan = ["Nmap scan report for 10.10.10.5", "Host is up (0.031s latency).", "445/tcp open  microsoft-ds"]
        self.load("nmap-notes.md", "\n".join(prose + scan + after) + "\n")
        self.assertEqual(self.queued(), prose + after)
        self.assertNotIn("running", self.cli("find", "--where", "host=10.10.10.5"))

    def test_h1_prose_shaped_like_a_dump_or_a_prompt_is_still_prose(self):
        prose = ["[NOTE] alice / Alice2026! works on SQL01", "[DC01] local admin is Administrator / L0cal2026!",
                 "[-] bob / Bob2026! did not work on DC01, try WEB01",
                 "> john said the backup admin password is Backup2026!", "# hashcat cracked carol's hash: Carol2026!",
                 "Note: dave reused Dave2026! everywhere"]
        self.load("creds-notes.txt", "\n".join(["8c2e4a91d7b05f63c18a4d90e2f57614:Summer2024!"] + prose[:5]
                                               + ["[*] _SC_Spooler"] + prose[5:]) + "\n")
        self.assertEqual(self.queued(), prose)
        self.assertNotIn("principal   Note", self.cli("find", "--type", "credential"))

    def test_h1_a_file_with_nothing_of_its_tool_is_left_pending_whole(self):
        path = self.tmp / "prose.txt"
        path.write_text("Found creds on the share\nsvc_backup / Backup2026! works on WS01\n")
        report = self.cli("import", str(path), "--tool", "creds", "--no-ai")
        self.assertEqual([e["source"] for e in self.pending()], ["prose.txt"])
        self.assertIn("prose.txt", self.cli("pending"))

    def test_h1_a_netexec_paste_with_a_line_of_prose_queues_the_prose(self):
        nxc = (FIXTURES / "netexec/nxc-cred-check.txt").read_text()
        self.load("nxc-and-notes.txt", nxc + "the share \\\\DC01\\backup has svc_backup's password in it\n")
        waiting = self.pending()
        self.assertEqual(len(waiting), 1)
        self.assertEqual(rawstore.read(self.eng, waiting[0]["blob"]).decode(),
                         "the share \\\\DC01\\backup has svc_backup's password in it\n")

    def test_h1_the_queued_lines_are_extracted_and_cited_like_any_file(self):
        self.load("box-notes.md", BOX_NOTES)
        blob = self.pending()[0]["blob"]
        quote = "da-joe, password reused from the web app: Adm1n!2026"
        result = aiingest.check(self.eng, blob, json.dumps({"records": [{"type": "credential", "fields": {
            "principal": {"value": "da-joe", "evidence": quote},
            "secret": {"value": "Adm1n!2026", "evidence": quote}}}]}))
        self.assertEqual(result["dropped"], [])
        self.assertIn("Adm1n!2026", self.cli("find", "--type", "credential", "--where", "principal=da-joe"))
        self.assert_citations_hold()

    def test_h1_importing_the_goad_folder_queues_only_lines_no_parser_reads(self):
        self.cli("import", str(CORPUS), "--no-ai")
        self.assertEqual(sorted(e["source"] for e in self.pending() if "not read by" in e["source"]), [
            "goad/nxc/dump-members-goadmin.txt (lines not read by netexec)",
            "goad/nxc/loggedon.txt (lines not read by netexec)",
            "goad/nxc/nxc-logs/lsa/castelblack_192.168.56.22_2026-10-19_141913.secrets (lines not read by creds)",
            "goad/nxc/users-north.txt (lines not read by netexec)",
            "goad/responder/logs/Responder-Session.log (lines not read by creds)"])

    def test_h1_a_parser_s_own_output_queues_only_the_command_that_ran_it(self):
        self.cli("import", str(FIXTURES), "--no-ai")
        queued = [e["source"] for e in self.pending() if "not read by" in e["source"]]
        self.assertEqual(queued, ["fixtures/freeform/tool-scratch.log (lines not read by netexec)",
                                  "fixtures/netexec/nxc-kali-proxychains.txt (lines not read by netexec)",
                                  "fixtures/netexec/nxc-log-riverrun.log (lines not read by netexec)",
                                  "fixtures/netexec/nxc-sam-goad.log (lines not read by netexec)",
                                  "fixtures/nuclei/nuclei-highgarden-screen.log (lines not read by nuclei)"])

    def test_a_password_only_on_the_command_line_is_kept_and_untried(self):
        banner = (FIXTURES / "netexec/nxc-cred-check.txt").read_text().splitlines(keepends=True)[0]
        command = "$ nxc smb 10.10.10.7 -u svc_backup -p 'Winter2024!'"
        self.load("nxc-masked.txt", command + "\n" + banner)
        self.assertEqual(self.queued(), [command])
        blob = [e["blob"] for e in self.pending() if "not read by" in e["source"]][0]
        quote = "-u svc_backup -p 'Winter2024!'"
        result = aiingest.check(self.eng, blob, json.dumps({"records": [{"type": "credential", "fields": {
            "principal": {"value": "svc_backup", "evidence": quote},
            "secret": {"value": "Winter2024!", "evidence": quote}}}]}))
        self.assertEqual(result["dropped"], [])
        self.assertIn("Winter2024!", self.cli("find", "--type", "credential", "--where", "secret?", "--where", "hosts!"))

    def test_a_verbose_nmap_scan_with_os_detection_queues_nothing(self):
        self.load("scan.nmap", (FIXTURES / "nmap/nmap-verbose-os.nmap").read_text())
        self.assertEqual(self.queued(), [])
        self.assertIn("service:10.10.20.10-tcp-445", self.cli("find", "--where", "host=10.10.20.10"))

    def test_an_online_lsa_dump_queues_nothing_and_keeps_the_machine_password(self):
        self.load("lsa.txt", (FIXTURES / "creds/secretsdump-lsa-online.txt").read_text())
        self.assertEqual(self.queued(), [])
        found = self.cli("find", "--type", "credential", "--where", "hash_type=plain_password_hex")
        self.assertIn("2f0061004b003b0051002e00", found)
        self.assertIn("LABWS2$", found)

    def test_a_hashcat_session_queues_nothing_and_keeps_the_crack(self):
        self.load("crack.txt", (FIXTURES / "creds/hashcat-session.txt").read_text())
        self.assertEqual(self.queued(), [])

    def test_a_getnpusers_table_is_read_not_queued(self):
        self.load("asrep.txt", (FIXTURES / "creds/getnpusers-request.txt").read_text())
        self.assertEqual(self.queued(), [])
        self.assertIn("Backup Operators", self.cli("find", "--type", "group"))
        self.assertIn("member_of", self.cli("find", "--type", "relationship"))

    def test_a_prompt_proxychains_and_a_traceback_queue_only_the_command_and_the_error(self):
        self.load("nxc-proxied.txt", (FIXTURES / "netexec/nxc-kali-proxychains.txt").read_text())
        self.assertEqual([line.strip() for line in self.queued()], [
            "└─$ proxychains4 nxc smb 10.10.20.10 10.10.20.11 -u svc_backup -p 'Winter2024!'",
            "[16:01:02] ERROR    Exception while calling proto_flow() on target 10.10.20.11: [Errno 113] No route to "
            "host   connection.py:158",
            "OSError: [Errno 113] No route to host"])
        self.assertIn("service:10.10.20.10-tcp-445", self.cli("find", "--where", "host=10.10.20.10"))

    def test_an_impacket_command_line_is_queued_beside_the_dump(self):
        dump = (FIXTURES / "creds/secretsdump-ntds.txt").read_text()
        command = "$ impacket-secretsdump 'lab.local/svc_backup:Winter2024!@10.10.20.10'"
        self.load("dump-with-command.txt", command + "\n" + dump)
        self.assertEqual(self.queued(), [command])
        self.assertIn("3f2a91d7c05b48e6a17c4d9082ef5613", self.cli("find", "--type", "credential"))
