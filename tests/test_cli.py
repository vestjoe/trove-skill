import contextlib
import io
import json
import os
from unittest import mock

from lootlib import cli, records
from tests.helpers import FIXTURES, EngagementCase


class Cli(EngagementCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = cli.main(list(argv))
        finally:
            os.chdir(cwd)
        return code, out.getvalue()

    def test_import_then_find_as_json(self):
        self.assertEqual(self.run_cli("import", str(FIXTURES / "nmap/nmap-basic.xml"))[0], 0)
        code, out = self.run_cli("find", "--type", "host", "--json")
        self.assertEqual((code, json.loads(out)["total"]), (0, 2))

    def test_each_value_of_a_merged_list_cites_its_own_source(self):
        rec = records.new("host")
        tool = {"blob": "sha256:00", "span": [0, 1], "quote": "a", "origin": "tool", "source": "scan.xml"}
        ai = {"blob": "sha256:01", "span": [0, 1], "quote": "b", "origin": "ai", "source": "note.md"}
        records.set_field(rec, "ip", "10.0.0.9", tool)
        records.set_field(rec, "hostnames", ["a", "b"], [tool, ai])
        records.put_all(self.eng, [rec])
        out = self.run_cli("find", "10.0.0.9")[1]
        self.assertIn("hostnames   a   [tool, scan.xml]", out)
        self.assertIn("            b   [ai, note.md]", out)

    def test_an_extraction_reply_says_what_the_engagement_now_holds(self):
        self.run_cli("import", str(FIXTURES / "nmap/nmap-basic.xml"))
        blob = self.import_fixture("freeform/engagement-note.md")["blob"]
        proposal = json.dumps({"records": [{"type": "finding", "fields": {
            "title": {"value": "No lockout", "evidence": "no lockout"}}}]})
        with mock.patch("sys.stdin", io.StringIO(proposal)):
            code, out = self.run_cli("ingest-ai", blob, "--json")
        self.assertEqual((code, json.loads(out)["holds"]["finding"]), (0, 1))

    def test_a_refusal_exits_one(self):
        self.assertEqual(self.run_cli("find", "--where", "nonsense")[0], 1)


class TerminalSafety(EngagementCase):
    run_cli = Cli.run_cli

    def test_a_hostile_value_cannot_put_escape_sequences_on_the_terminal(self):
        rec = records.new("host")
        ref = {"blob": "sha256:00", "span": [0, 1], "quote": "x", "origin": "tool"}
        records.set_field(rec, "ip", "10.0.0.9", ref)
        records.set_field(rec, "hostnames", ["web01\x1b]0;pwned\x07"], [ref])
        records.put_all(self.eng, [rec])
        for argv in (("find", "web01"), ("find", "web01", "--json")):
            out = self.run_cli(*argv)[1]
            self.assertNotIn("\x1b", out)
            self.assertNotIn("\x07", out)
        self.assertIn("\\x1b]0;pwned", self.run_cli("find", "web01")[1])

    def test_the_engagement_may_be_named_before_or_after_the_verb(self):
        self.run_cli("import", str(FIXTURES / "nmap/nmap-basic.xml"))
        after = self.run_cli("find", "--type", "host", "-e", str(self.eng.root))
        before = self.run_cli("-e", str(self.eng.root), "find", "--type", "host")
        self.assertEqual(before, after)
        self.assertEqual(after[0], 0)

    def test_two_different_engagements_on_one_line_are_refused(self):
        code, _ = self.run_cli("-e", str(self.eng.root), "find", "-e", "other")
        self.assertEqual(code, 1)
