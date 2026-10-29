import codecs
import io
import json
import shutil
import sys
import time

from lootlib import ingest, rawstore, records
from tests.helpers import FIXTURES, EngagementCase
from tests.test_cli import Cli

ALL_FIXTURES = {"credential": 68, "finding": 36, "group": 153, "host": 36, "principal": 41,
                "relationship": 83, "service": 73, "share": 6}


class Directory(EngagementCase):
    def copy(self, rel, name):
        dest = self.tmp / "in" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(FIXTURES / rel, dest)

    def test_files_are_read_in_name_order_skipping_engagements_and_os_metadata(self):
        self.copy("nmap/nmap-normal.nmap", "b/scan.nmap")
        self.copy("creds/secretsdump-ntlm.txt", "a.txt")
        self.copy("nmap/nmap-basic.xml", "old.loot/raw.xml")
        self.copy("nmap/nmap-basic.xml", ".DS_Store")
        reports = ingest.import_path(self.eng, self.tmp / "in")
        self.assertEqual([r["source"] for r in reports], ["in/a.txt", "in/b/scan.nmap"])

    def test_a_computer_read_before_the_scan_still_reaches_its_host(self):
        self.copy("bloodhound/example_computers.json", "a_computers.json")
        self.copy("nmap/nmap-normal.nmap", "b_scan.nmap")
        reports = ingest.import_path(self.eng, self.tmp / "in")
        [host] = [h for h in self.all("host") if "mail.example.test" in h.get("hostnames", [])]
        self.assertEqual(host["os"], "Windows Server 2019 Datacenter")
        self.assertFalse(any("match no single host" in n for r in reports for n in r["notes"]))
        self.assert_citations_hold()


class Stdin(EngagementCase):
    run_cli = Cli.run_cli

    def test_utf16_on_stdin_is_converted_and_parsed(self):
        text = (FIXTURES / "nmap/nmap-normal.nmap").read_text("utf-8")
        stdin = io.TextIOWrapper(io.BytesIO(codecs.BOM_UTF16_LE + text.encode("utf-16-le")))
        sys.stdin, saved = stdin, sys.stdin
        try:
            code, out = self.run_cli("import", "-", "--json")
        finally:
            sys.stdin = saved
        [report] = json.loads(out)["inputs"]
        self.assertEqual((code, report["source"], report["parser"]), (0, "stdin", "nmap-text"))
        self.assertIn("converted from utf-16-le", report["notes"][0])
        self.assertEqual(len(self.all("host")), 2)


class EndToEnd(EngagementCase):
    """Every fixture in one import. Expected counts and their sources are in the phase notes."""

    run_cli = Cli.run_cli

    def test_all_fixtures_give_the_summed_counts(self):
        code, out = self.run_cli("import", str(FIXTURES), "--json")
        report = json.loads(out)
        counts: dict[str, int] = {}
        for rec in self.all():
            counts[rec["type"]] = counts.get(rec["type"], 0) + 1
        self.assertEqual((code, counts), (0, ALL_FIXTURES))
        self.assertEqual(sorted(r["source"] for r in report["refused"]), [
            "fixtures/archive/mixed.zip/locked.txt", "fixtures/archive/nested.zip/scans.zip",
            "fixtures/nmap/nmap-truncated.xml"])
        self.assertEqual(len(report["pending"]), 12)
        self.assertEqual(len(report["pending"]), sum(m["ai"] == "pending" for m in rawstore.manifest(self.eng)))
        host = records.load_all(self.eng)["host:198.51.100.7"]
        self.assertEqual(host["os"], "Windows Server 2019 Datacenter")
        self.assertEqual(host["prov"]["os"]["source"], "fixtures/bloodhound/example_computers.json")
        self.assert_citations_hold()

    def test_find_over_all_fixtures_is_fast(self):
        self.run_cli("import", str(FIXTURES))
        start = time.perf_counter()
        self.run_cli("find", "smb")
        self.assertLess(time.perf_counter() - start, 2.0)

    def test_the_human_report_names_refusals_and_pending(self):
        out = self.run_cli("import", str(FIXTURES))[1]
        self.assertIn("Refused (3):", out)
        self.assertIn("Pending AI extraction (12):", out)
        self.assertNotIn("Records read", out)
        holds = {t: n for t, n in (pair.split(" ")[::-1] for pair in
                 out.split("now holds: ")[1].splitlines()[0].split(", "))}
        self.assertEqual({t: int(n) for t, n in holds.items()}, ALL_FIXTURES)


class Links(EngagementCase):
    def test_a_symlink_in_a_directory_is_refused_and_its_target_not_read(self):
        (self.tmp / "in").mkdir()
        (self.tmp / "in" / "scan.xml").symlink_to(FIXTURES / "nmap/nmap-basic.xml")
        [report] = ingest.import_path(self.eng, self.tmp / "in")
        self.assertIn("symbolic link", report["status"])
        self.assertEqual((rawstore.manifest(self.eng), self.all()), ([], []))
