import contextlib
import io
import json
import os

from lootlib import aiingest, cli, notes
from tests.helpers import FIXTURES, EngagementCase

NOTE = "MSSQL on castelblack accepts sql_svc? try xp_cmdshell later\n"


def field(value, evidence):
    return {"value": value, "evidence": evidence}


class FindingStatus(EngagementCase):
    """A finding's status is a fixed set; the AI suggests one and the operator decides, asked through ``find``."""

    def cli(self, *argv, code=0):
        out = io.StringIO()
        cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                got = cli.main(list(argv))
        finally:
            os.chdir(cwd)
        self.assertEqual(got, code, argv)
        return out.getvalue()

    def findings(self, *where):
        argv = ["find", "--type", "finding", "--json", "--limit", "1000"]
        for w in where:
            argv += ["--where", w]
        return {r["title"]: r for r in json.loads(self.cli(*argv))["records"]}

    def propose(self, *fields):
        blob = notes.add(self.eng, NOTE.encode())["blob"]
        rec = {"type": "finding", "fields": {"title": field("MSSQL xp_cmdshell on castelblack", "MSSQL on castelblack"),
                                             **dict(fields)}}
        return aiingest.check(self.eng, blob, json.dumps({"records": [rec]}))

    def test_h5d_a_speculative_note_is_an_open_finding_with_a_suggestion(self):
        self.propose(("status", field("confirmed", "accepts sql_svc?")),
                     ("suggested_status", field("confirmed", "accepts sql_svc?")))
        got = self.findings()["MSSQL xp_cmdshell on castelblack"]
        self.assertEqual((got["status"], got["suggested_status"]), ("open", "confirmed"))
        self.assertEqual(got["prov"]["suggested_status"]["quote"], "accepts sql_svc?")

    def test_h5d_an_ai_finding_with_no_status_is_open(self):
        self.propose()
        self.assertEqual(self.findings()["MSSQL xp_cmdshell on castelblack"]["status"], "open")

    def test_a_status_outside_the_set_is_refused(self):
        result = self.propose(("suggested_status", field("pwned", "accepts")))
        self.assertNotIn("suggested_status", self.findings()["MSSQL xp_cmdshell on castelblack"])
        self.assertTrue(any("suggested_status" in d and "false_positive" in d for d in result["dropped"]))

    def test_which_findings_need_my_decision(self):
        self.propose(("suggested_status", field("confirmed", "accepts sql_svc?")))
        self.cli("import", str(FIXTURES / "netexec/nxc-null-session.txt"), "--no-ai")
        self.assertEqual(set(self.findings("suggested_status?")), {"MSSQL xp_cmdshell on castelblack"})

    def test_the_operator_sets_a_status_and_no_import_overrides_it(self):
        self.propose(("suggested_status", field("confirmed", "accepts sql_svc?")))
        fid = self.findings()["MSSQL xp_cmdshell on castelblack"]["id"]
        self.cli("set", fid, "status=false_positive")
        self.propose(("status", field("open", "accepts sql_svc?")))
        got = self.findings()[("MSSQL xp_cmdshell on castelblack")]
        self.assertEqual((got["status"], got["prov"]["status"]["origin"]), ("false_positive", "you"))
        self.assertIn("status      false_positive   [you", self.cli("find", "--type", "finding"))

    def test_set_refuses_a_value_outside_the_set_and_other_fields(self):
        self.propose()
        fid = self.findings()["MSSQL xp_cmdshell on castelblack"]["id"]
        self.cli("set", fid, "status=pwned", code=1)
        self.cli("set", fid, "title=other", code=1)
        self.cli("set", "finding:nothing-00000000", "status=open", code=1)
        self.assertEqual(self.findings()["MSSQL xp_cmdshell on castelblack"]["status"], "open")

    def test_find_shows_the_suggestion_apart_from_its_label(self):
        self.propose(("suggested_status", field("confirmed", "accepts sql_svc?")))
        self.assertIn("suggested_status confirmed   [ai", self.cli("find", "--type", "finding"))

    def test_a_tool_finding_with_no_status_takes_none_from_a_proposal(self):
        self.cli("import", str(FIXTURES / "netexec/nxc-password-policy.txt"), "--no-ai")
        title, tool = next((t, f) for t, f in self.findings().items() if t.startswith("Password policy"))
        ip = tool["host_id"].removeprefix("host:")
        blob = notes.add(self.eng, f"{title} on {ip} looks weak\n".encode())["blob"]
        aiingest.check(self.eng, blob, json.dumps({"records": [{"type": "finding", "fields": {
            "title": field(title, title), "host": field(ip, ip), "suggested_status": field("confirmed", "looks weak")}}]}))
        held = self.findings()[title]
        self.assertEqual(held["id"], tool["id"])
        self.assertNotIn("status", held)
        self.assertEqual(held["suggested_status"], "confirmed")

    def test_a_tool_status_outranks_an_ai_open_in_either_order(self):
        for first_tool in (True, False):
            with self.subTest(first_tool=first_tool):
                self.tearDown()
                self.setUp()
                tool = lambda: self.cli("import", str(FIXTURES / "netexec/nxc-null-session.txt"), "--no-ai")
                title = "SMB null session accepted"
                ai = lambda: aiingest.check(self.eng, notes.add(self.eng, b"SMB null session accepted on KINGSLANDING\n")["blob"],
                                            json.dumps({"records": [{"type": "finding", "fields": {
                                                "title": field(title, "SMB null session accepted"),
                                                "host": field("10.10.10.5", "KINGSLANDING")}}]}))
                (tool(), ai()) if first_tool else (ai(), tool())
                got = [f for f in json.loads(self.cli("find", "--type", "finding", "--json"))["records"]
                       if f["title"] == title and f.get("host_id") == "host:10.10.10.5"]
                self.assertEqual([(f["status"], f["prov"]["status"]["origin"]) for f in got], [("confirmed", "tool")])
                self.assert_citations_hold()
