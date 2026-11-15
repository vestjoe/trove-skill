import codecs

from lootlib import ingest, rawstore
from tests.helpers import FIXTURES, EngagementCase

USERS = b"edmure.tully\nbrynden.tully\n"


class ReadAgain(EngagementCase):
    """A file already stored is parsed again when the operator names a parser, or when it waits for AI."""

    def test_a_pending_user_list_is_read_by_the_users_parser_on_a_second_import(self):
        first = ingest.import_data(self.eng, USERS, "users.txt")[0]
        self.assertEqual(first["status"], "pending AI extraction")
        again = ingest.import_data(self.eng, USERS, "users.txt", tool="users")[0]
        self.assertEqual((again["status"], again["counts"]), ("parsed", {"principal": 2}))
        self.assertIn("stored earlier; read again by users", again["notes"])
        self.assertEqual(rawstore.entry(self.eng, again["blob"])["ai"], "n/a")
        self.assertEqual(sorted(p["principal"] for p in self.all("principal")), ["brynden.tully", "edmure.tully"])

    def test_a_converted_file_is_judged_by_its_utf8_copy(self):
        data = codecs.BOM_UTF16_LE + USERS.decode().encode("utf-16-le")
        first = ingest.import_data(self.eng, data, "users.txt")[0]
        self.assertEqual(rawstore.entry(self.eng, first["blob"])["ai"], "pending")
        again = ingest.import_data(self.eng, data, "users.txt", tool="users")[0]
        self.assertEqual(again["blob"], first["blob"])
        self.assertIn("stored earlier; read again by users", again["notes"])
        self.assertEqual(rawstore.entry(self.eng, first["blob"])["ai"], "n/a")
        self.assertEqual(len(self.all("principal")), 2)

    def test_a_parsed_file_read_again_by_name_updates_and_never_duplicates(self):
        path = FIXTURES / "nmap/nmap-basic.xml"
        ingest.import_path(self.eng, path)
        held = sorted(r["id"] for r in self.all())
        again = ingest.import_path(self.eng, path, "nmap")[0]
        self.assertEqual((again["status"], again["new"]), ("parsed", 0))
        self.assertEqual(sorted(r["id"] for r in self.all()), held)

    def test_without_a_parser_named_a_stored_file_is_already_imported(self):
        path = FIXTURES / "nmap/nmap-basic.xml"
        ingest.import_path(self.eng, path)
        self.assertEqual(ingest.import_path(self.eng, path)[0]["status"], "already imported")
        ingest.import_data(self.eng, USERS, "users.txt")
        self.assertEqual(ingest.import_data(self.eng, USERS, "users.txt")[0]["status"], "already imported")

    def test_a_wrong_parser_on_a_pending_file_leaves_it_pending(self):
        blob = ingest.import_data(self.eng, USERS, "users.txt")[0]["blob"]
        ingest.import_data(self.eng, USERS, "users.txt", tool="nmap")
        self.assertEqual(rawstore.entry(self.eng, blob)["ai"], "pending")
