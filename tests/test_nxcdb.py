import sqlite3

from lootlib import engagement, find, ingest, rawstore, records
from tests import ROOT
from tests.helpers import FIXTURES, EngagementCase

DATABASES = ROOT / "tests" / "databases"


class NetExecDatabase(EngagementCase):
    """A NetExec workspace database answers Q1-Q3 like the runs that filled it."""

    def database(self, name):
        path = self.tmp / "workspace" / f"{name}.db"
        if not path.exists():
            path.parent.mkdir(exist_ok=True)
            con = sqlite3.connect(path)
            con.executescript((DATABASES / f"nxc-{name}.sql").read_text())
            con.close()
        return path

    def import_db(self, name):
        return ingest.import_path(self.eng, self.database(name))

    def cred(self, principal):
        return next(c for c in self.all("credential") if c["principal"] == principal)

    def test_each_host_row_is_a_host_with_its_name_os_and_signing_findings(self):
        report = self.import_db("smb")[0]
        self.assertEqual(report["parser"], "netexec-db")
        hosts = {h["ip"]: h for h in self.all("host")}
        self.assertEqual(sorted(hosts), ["10.10.10.23", "10.10.10.24", "192.168.56.31"])
        self.assertEqual((hosts["10.10.10.23"]["hostnames"], hosts["10.10.10.23"]["os"]),
                         (["DREADFORT"], "Windows Server 2019 Standard 17763 x64"))
        self.assertEqual(sorted((f["host_id"], f["title"]) for f in self.all("finding")),
                         [("host:10.10.10.23", "SMB signing not required"), ("host:10.10.10.24", "SMBv1 enabled")])
        self.assertTrue(all(f["status"] == "confirmed" for f in self.all("finding")))
        self.assert_citations_hold()

    def test_q2_logins_and_admin_rights_come_from_the_relation_tables(self):
        self.import_db("smb")
        everything = records.load_all(self.eng)
        worked = {r["principal"]: r for r in find.search(everything, types=["credential"], where=["hosts?"])[1]}
        self.assertEqual(sorted(worked), ["ramsay.snow", "rickon.stark", "roose.bolton"])
        self.assertEqual(worked["roose.bolton"]["hosts"], ["host:10.10.10.23", "host:10.10.10.24"])
        roose = worked["roose.bolton"]
        self.assertEqual((roose["secret"], roose["state"]), ("Flayed!2024", "confirmed"))
        admins = find.search(everything, types=["credential"], where=["admin_hosts?"])[1]
        self.assertEqual([(c["principal"], c["admin_hosts"]) for c in admins], [("ramsay.snow", ["host:10.10.10.24"])])
        ramsay = worked["ramsay.snow"]
        self.assertEqual((ramsay["secret_hash"], ramsay["hash_type"]), ("b4b9b02e6f09a9bd760f388b67351e2b", "ntlm"))
        self.assertIn("loggedin_relations", ramsay["prov"]["hosts"][0]["quote"])
        self.assertIn("admin_relations", ramsay["prov"]["admin_hosts"][0]["quote"])
        self.assert_citations_hold()

    def test_q3_a_password_no_login_used_is_untried_and_a_sam_hash_is_its_hosts(self):
        self.import_db("smb")
        everything = records.load_all(self.eng)
        untried = find.search(everything, types=["credential"], where=["secret?", "hosts!"])[1]
        untried = {r["principal"] for r in untried}
        self.assertEqual(untried, {"svc_gpp"})
        self.assertEqual(self.cred("svc_gpp")["state"], "found")
        admin = self.cred("Administrator")
        self.assertEqual((admin["realm"], admin["secret_hash"], admin["hash_type"], admin["host_id"], admin["state"]),
                         ("DREADFORT", "2b576acbe6bcfda7294d6bd18041b8fe", "ntlm", ["host:10.10.10.23"], "found"))
        self.assertNotIn("hosts", admin)
        self.assertEqual(len([c for c in self.all("credential") if c["principal"] == "Administrator"]), 1)
        self.assert_citations_hold()

    def test_q1_shares_belong_to_the_host_they_name(self):
        self.import_db("smb")
        shares = {s["name"]: s for s in self.all("share")}
        self.assertEqual(sorted(shares), ["ADMIN$", "IPC$", "flaying"])
        self.assertEqual((shares["flaying"]["host_id"], shares["flaying"]["permissions"], shares["flaying"]["remark"]),
                         ("host:10.10.10.23", "READ,WRITE", "Bolton drop box"))
        self.assertEqual(shares["IPC$"]["permissions"], "READ")
        self.assertNotIn("permissions", shares["ADMIN$"])
        on_host = {r["id"] for r in find.search(records.load_all(self.eng), where=["host=10.10.10.23"])[1]}
        self.assertTrue({"host:10.10.10.23", "share:10.10.10.23-flaying"} <= on_host)

    def test_the_rows_are_cited_in_a_text_copy_derived_from_the_stored_database(self):
        report = self.import_db("smb")[0]
        copy = rawstore.entry(self.eng, report["blob"])
        original = rawstore.entry(self.eng, copy["derived_from"])
        self.assertEqual((copy["parser"], copy["ai"]), ("netexec-db", "n/a"))
        self.assertEqual(original["source"], "smb.db")
        self.assertTrue(rawstore.read(self.eng, original["blob"]).startswith(b"SQLite format 3\x00"))
        roose = self.cred("roose.bolton")
        self.assertEqual(roose["prov"]["secret"]["quote"], "Flayed!2024")
        self.assertEqual(roose["prov"]["secret"]["blob"], report["blob"])

    def test_the_report_counts_hosts_by_range_and_names_tables_it_does_not_read(self):
        notes = " ".join(self.import_db("smb")[0]["notes"])
        self.assertIn("3 host(s)", notes)
        self.assertIn("10.10.10.0/24 (2)", notes)
        self.assertIn("192.168.56.0/24 (1)", notes)
        self.assertIn("groups (1)", notes)
        self.assertIn("dpapi_secrets (1)", notes)

    def test_importing_the_same_database_again_changes_nothing(self):
        self.import_db("smb")
        before = records.load_all(self.eng)
        self.assertEqual(self.import_db("smb")[0]["status"], "already imported")
        self.assertEqual(records.load_all(self.eng), before)

    def test_a_winrm_database_gives_its_logins_and_admin_rights(self):
        self.import_db("winrm")
        roose = self.cred("roose.bolton")
        self.assertEqual((roose["hosts"], roose["admin_hosts"]), (["host:10.10.10.24"], ["host:10.10.10.24"]))
        self.assertEqual(self.all("finding"), [])
        self.assert_citations_hold()

    def test_a_database_loot_has_no_reader_for_is_stored_and_its_tables_named(self):
        report = self.import_db("ldap")[0]
        self.assertIn("hosts, users", report["status"])
        self.assertEqual(rawstore.entry(self.eng, report["blob"])["ai"], "binary")
        self.assertEqual(self.all(), [])

    def test_the_database_and_the_screen_output_of_one_run_agree_in_either_order(self):
        database, screen = self.database("smb"), FIXTURES / "netexec/nxc-cred-check.txt"
        answers = []
        for n, order in enumerate(((database, screen), (screen, database))):
            eng = engagement.create(f"order{n}", self.tmp)
            for path in order:
                ingest.import_path(eng, path)
            rickon = [c for c in records.load_all(eng).values() if c["type"] == "credential"
                      and c["principal"] == "rickon.stark" and c.get("realm") == "north.acme.local"]
            self.assertEqual(len(rickon), 1)
            answers.append(sorted(rickon[0]["hosts"]))
        self.assertEqual(answers, [["host:10.10.10.23", "host:10.10.10.6", "host:10.10.10.8"]] * 2)

    def test_a_row_holding_a_tab_is_left_out_and_counted(self):
        con = sqlite3.connect(self.database("smb"))
        con.execute("INSERT INTO users VALUES (6, 'north.acme.local', 'walda.frey', 'Fat\tWalda', 'plaintext', NULL)")
        con.commit()
        con.close()
        report = self.import_db("smb")[0]
        self.assertIn("1 row(s) hold a tab", " ".join(report["notes"]))
        self.assertFalse([c for c in self.all("credential") if c["principal"] == "walda.frey"])

    def test_a_database_in_wal_mode_is_read_from_its_own_file(self):
        path = self.tmp / "wal" / "smb.db"
        path.parent.mkdir()
        con = sqlite3.connect(path)
        con.execute("PRAGMA journal_mode = WAL")
        con.executescript((DATABASES / "nxc-smb.sql").read_text())
        con.close()
        ingest.import_path(self.eng, path)
        self.assertEqual(self.cred("roose.bolton")["secret"], "Flayed!2024")

    def test_bytes_that_only_start_like_a_database_are_stored_unread(self):
        path = self.tmp / "broken.db"
        path.write_bytes(b"SQLite format 3\x00" + b"\x00" * 84)
        report = ingest.import_path(self.eng, path)[0]
        self.assertIn("not a readable SQLite database", report["status"])
        self.assertEqual(self.all(), [])

    def test_a_value_holding_any_line_break_is_left_out_and_the_rest_read(self):
        con = sqlite3.connect(self.database("smb"))
        con.execute("UPDATE hosts SET hostname = ? WHERE id = 3", ("OLD" + chr(0x2028) + "BOX",))
        con.commit()
        con.close()
        report = self.import_db("smb")[0]
        self.assertEqual(report["status"], "parsed")
        self.assertIn("1 row(s) hold a tab", " ".join(report["notes"]))
        self.assertEqual(sorted(h["ip"] for h in self.all("host")), ["10.10.10.23", "10.10.10.24"])
