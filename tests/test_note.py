import contextlib
import io
import json
import os
import sys

from lootlib import notes, rawstore
from lootlib.errors import LootError
from tests.helpers import EngagementCase
from tests.test_cli import Cli


class Note(EngagementCase):
    run_cli = Cli.run_cli

    def test_a_note_is_a_blob_a_file_and_a_record_from_you(self):
        code, out = self.run_cli("note", "svc_backup creds work over SMB on 10.10.10.5", "--json")
        result = json.loads(out)
        self.assertEqual(code, 0)
        rec = self.all("note")[0]
        self.assertEqual((rec["id"], rec["text"]), (result["id"], "svc_backup creds work over SMB on 10.10.10.5"))
        self.assertEqual(rec["prov"]["text"]["origin"], "you")
        self.assertEqual((self.eng.root / result["file"]).read_text(), rec["text"])
        self.assertTrue(result["file"].startswith("notes/") and result["file"].endswith(".md"))
        entry = rawstore.entry(self.eng, result["blob"])
        self.assertEqual((entry["ai"], entry["source"]), ("pending", result["file"]))
        self.assert_citations_hold_for("text")

    def assert_citations_hold_for(self, field):
        for rec in self.all("note"):
            ref = rec["prov"][field]
            start, end = ref["span"]
            self.assertEqual(rawstore.read(self.eng, ref["blob"])[start:end].decode(), ref["quote"])

    def test_host_given_as_an_ip_links_to_the_host_id(self):
        self.run_cli("note", "kerberoastable account here", "--host", "10.10.10.5", "--tag", "ad", "--tag", "todo")
        rec = self.all("note")[0]
        self.assertEqual((rec["host_id"], rec["tags"]), ("host:10.10.10.5", ["ad", "todo"]))
        self.assertEqual(rec["prov"]["host_id"]["quote"], "10.10.10.5")
        self.assertEqual({r["origin"] for r in rec["prov"]["tags"]}, {"you"})

    def test_host_given_as_a_host_id_is_kept(self):
        self.run_cli("note", "web root is writable", "--host", "host:10.10.10.7")
        self.assertEqual(self.all("note")[0]["host_id"], "host:10.10.10.7")

    def test_a_host_that_is_not_an_ip_is_refused_and_nothing_is_stored(self):
        self.assertEqual(self.run_cli("note", "anything", "--host", "dc01")[0], 1)
        self.assertEqual((self.all(), rawstore.manifest(self.eng)), ([], []))

    def test_text_from_stdin(self):
        stdin, sys.stdin = sys.stdin, io.TextIOWrapper(io.BytesIO(b"found /backup share on dc01\n"))
        try:
            code, out = self.run_cli("note", "-")
        finally:
            sys.stdin = stdin
        self.assertEqual(code, 0)
        self.assertIn("Pending AI extraction", out)
        self.assertEqual(self.all("note")[0]["text"], "found /backup share on dc01")
        self.assert_citations_hold_for("text")

    def test_the_same_note_twice_is_one_record_and_tags_union(self):
        notes.add(self.eng, b"same text", tags=["a"])
        again = notes.add(self.eng, b"same text", tags=["b"])
        self.assertFalse(again["new"])
        self.assertEqual([r["tags"] for r in self.all("note")], [["a", "b"]])
        self.assertEqual(len(list(self.eng.notes.iterdir())), 1)

    def test_an_extracted_note_is_not_marked_pending_again(self):
        first = notes.add(self.eng, b"same text")
        rawstore.update(self.eng, first["blob"], ai="done")
        self.assertFalse(notes.add(self.eng, b"same text")["pending"])

    def test_an_empty_note_is_refused(self):
        with self.assertRaises(LootError):
            notes.add(self.eng, b"  \n")


class NoteByName(EngagementCase):
    run_cli = Cli.run_cli

    def setUp(self):
        super().setUp()
        from lootlib import ingest
        ingest.import_data(self.eng, b"SMB   10.0.0.5   445   DC01   [*] Windows (name:DC01) (domain:lab)\n"
                                     b"SMB   10.0.0.6   445   DC01   [*] Windows (name:DC01) (domain:dev)\n"
                                     b"SMB   10.0.0.7   445   WS01   [*] Windows (name:WS01) (domain:lab)\n", "nxc.txt")

    def test_a_host_named_once_is_found_by_name(self):
        self.assertEqual(self.run_cli("note", "check the share", "--host", "ws01")[0], 0)
        self.assertEqual(self.all("note")[0]["host_id"], "host:10.0.0.7")

    def test_a_name_on_two_hosts_is_refused_not_guessed(self):
        self.assertEqual(self.run_cli("note", "check the share", "--host", "dc01")[0], 1)
        self.assertEqual(self.all("note"), [])
