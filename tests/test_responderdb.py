import sqlite3

from lootlib import engagement, find, ingest, rawstore, records
from tests import ROOT
from tests.helpers import FIXTURES, EngagementCase

DATABASES = ROOT / "tests" / "databases"


class ResponderDatabase(EngagementCase):
    """Responder.db answers Q1-Q3 like the session log of the same run."""

    def database(self):
        path = self.tmp / "logs" / "Responder.db"
        if not path.exists():
            path.parent.mkdir(exist_ok=True)
            con = sqlite3.connect(path)
            con.executescript((DATABASES / "responder.sql").read_text())
            con.close()
        return path

    def cred(self, principal):
        return next(c for c in self.all("credential") if c["principal"] == principal)

    def test_q1_each_client_a_capture_came_from_is_a_host(self):
        report = ingest.import_path(self.eng, self.database())[0]
        self.assertEqual(report["parser"], "responder-db")
        self.assertEqual(sorted(h["ip"] for h in self.all("host")),
                         ["192.168.56.25", "192.168.56.26", "192.168.56.27"])
        self.assert_citations_hold()

    def test_q3_a_netntlm_hash_is_found_on_the_client_it_came_from(self):
        ingest.import_path(self.eng, self.database())
        jojen = self.cred("jojen.reed")
        self.assertEqual((jojen["realm"], jojen["hash_type"], jojen["state"], jojen["host_id"]),
                         ("NORTH", "netntlmv2", "found", ["host:192.168.56.26"]))
        self.assertTrue(jojen["secret_hash"].startswith("jojen.reed::NORTH:7d3e91a0c4b2f856:"))
        self.assertEqual(jojen["prov"]["host_id"][0]["quote"], "192.168.56.26")
        self.assert_citations_hold()

    def test_q3_a_cleartext_capture_is_untried_and_from_its_client(self):
        ingest.import_path(self.eng, self.database())
        hodor = self.cred("hodor")
        self.assertEqual((hodor["secret"], hodor["state"], hodor["host_id"]),
                         ("HoldTheDoor!", "found", ["host:192.168.56.27"]))
        untried = find.search(records.load_all(self.eng), types=["credential"], where=["secret?", "hosts!"])[1]
        self.assertEqual([c["principal"] for c in untried], ["hodor"])
        self.assert_citations_hold()

    def test_the_report_counts_poisoned_answers_and_hashes_it_cannot_read(self):
        notes = " ".join(ingest.import_path(self.eng, self.database())[0]["notes"])
        self.assertIn("Poisoned (2)", notes)
        self.assertNotIn("DHCP", notes)
        self.assertIn("1 capture(s)", notes)
        self.assertFalse([c for c in self.all("credential") if c["principal"] == "gilly"])

    def test_the_rows_are_cited_in_a_text_copy_derived_from_the_stored_database(self):
        report = ingest.import_path(self.eng, self.database())[0]
        copy = rawstore.entry(self.eng, report["blob"])
        self.assertEqual(rawstore.entry(self.eng, copy["derived_from"])["source"], "Responder.db")
        self.assertEqual(self.cred("hodor")["prov"]["secret"]["quote"], "HoldTheDoor!")

    def test_importing_the_same_database_again_changes_nothing(self):
        ingest.import_path(self.eng, self.database())
        before = records.load_all(self.eng)
        self.assertEqual(ingest.import_path(self.eng, self.database())[0]["status"], "already imported")
        self.assertEqual(records.load_all(self.eng), before)

    def test_the_database_and_the_session_log_of_one_run_agree_in_either_order(self):
        database, log = self.database(), FIXTURES / "creds/Responder-Session.log"
        answers = []
        for n, order in enumerate(((database, log), (log, database))):
            eng = engagement.create(f"order{n}", self.tmp)
            for path in order:
                ingest.import_path(eng, path)
            meera = [c for c in records.load_all(eng).values()
                     if c["type"] == "credential" and c["principal"] == "meera.reed"]
            self.assertEqual(len(meera), 1)
            answers.append((meera[0]["realm"], meera[0]["host_id"], meera[0]["state"]))
        self.assertEqual(answers, [("NORTH", ["host:192.168.56.25"], "found")] * 2)
