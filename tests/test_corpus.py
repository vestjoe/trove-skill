import contextlib
import io
import json
import os
import re
import shlex
import tempfile
import unittest
from pathlib import Path

from lootlib import cli, engagement, ingest, rawstore, records
from tests import CORPUS, FIXTURES, ROOT
from tests.helpers import EngagementCase

BRAAVOS, KINGSLANDING, CASTELBLACK = "192.168.56.23", "192.168.56.10", "192.168.56.22"
WINTERFELL, JUMPBOX = "192.168.56.11", "192.168.56.100"
ON_CASTELBLACK = {
    f"host:{CASTELBLACK}",
    *(f"credential:castelblack\\{who}" for who in (
        "administrator-ed9ea4da", "ansible-ed9ea4da", "goadmin-ed9ea4da", "defaultaccount-5db21f1a",
        "guest-5db21f1a", "wdagutilityaccount-9a96c985")),
    *(f"credential:north.sevenkingdoms.local\\{who}" for who in (
        "rickon.stark-c4cdb77f", "brandon.stark-964b41a5", "goadmin-ed9ea4da", "castelblack$-3cc097cb",
        "sql_svc-bc5dcbb4")),
    "finding:error-enumerating-logged-on-users-4fb17530", "finding:smb-signing-not-required-ae0523bf",
    "finding:winrm-refused-north.sevenkingdoms.local--6040d833", "finding:smb-login-with-an-empty-password-accepte-b809ed7a",
    *(f"service:{CASTELBLACK}-tcp-{port}" for port in (
        80, 135, 139, 445, 1433, 3389, 5985, 5986, 47001, 49664, 49665, 49667, 49668, 49669, 49677, 49710, 49711,
        49719, 49720, 49741, 49744, 49791, 49792)),
    *(f"share:{CASTELBLACK}-{name}" for name in ("ADMIN$", "C$", "IPC$", "all", "public")),
}
NORTH, ESSOS = "north.sevenkingdoms.local", "essos.local"
_ROW = re.compile(r"^\| (?P<q>Q\d|--) \| (?P<question>[^|]+) \| `loot find (?P<args>[^`]+)` \|$", re.M)


def recipe(question: str, nth: int = 0, asking: str = "") -> list[str]:
    """The search references/chat.md gives the model for an operator question (or, with ``--``,
    for the unnumbered question containing ``asking``), as argv."""
    rows = [m for m in _ROW.finditer((ROOT / "loot/references/chat.md").read_text())
            if m["q"] == question and asking in m["question"]]
    return shlex.split(rows[nth]["args"])


class GoadEngagement(EngagementCase):
    """The operator questions over the GOAD corpus, asked through the CLI as the model asks them."""

    order = "folder"

    def setUp(self):
        super().setUp()
        if self.order == "folder":
            self.cli("import", str(CORPUS), "--no-ai")
        else:
            files = sorted(p for p in CORPUS.rglob("*") if p.is_file())
            for path in reversed(files):
                self.cli("import", str(path), "--no-ai")

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

    def found(self, *argv):
        return json.loads(self.cli("find", *argv, "--limit", "1000", "--json"))["records"]

    @staticmethod
    def account(rec):
        return ((rec.get("realm") or "").lower(), rec["principal"].lower())

    def test_q1_what_do_i_have_on_a_host_by_ip_or_name(self):
        by_ip = self.found(*[a.replace("host=dc01", f"host={BRAAVOS}") for a in recipe("Q1")])
        self.assertIn("braavos", [n.lower() for r in by_ip if r["type"] == "host" for n in r["hostnames"]])
        worked = {self.account(r) for r in by_ip if r["type"] == "credential"}
        self.assertLessEqual({(ESSOS, "missandei"), (ESSOS, "sql_svc"), ("braavos", "vagrant"),
                              ("braavos", "administrator")}, worked)
        by_name = self.found(*[a.replace("host=dc01", "host=braavos") for a in recipe("Q1")])
        self.assertEqual({r["id"] for r in by_name}, {r["id"] for r in by_ip})

    def test_q1_is_exactly_what_loot_holds_on_one_host_each_cited(self):
        self.assertEqual({r["id"] for r in self.found(*[a.replace("host=dc01", "host=castelblack")
                                                         for a in recipe("Q1")])}, ON_CASTELBLACK)
        text = self.cli("find", "--where", "host=castelblack", "--limit", "1000")
        self.assertRegex(text, rf'(?i)host:192\.168\.56\.11 \(winterfell[^)]*\) +\[tool, [^]]+, quote "[^"]*\[\+\] '
                               rf'north\.sevenkingdoms\.local\\rickon\.stark:Winter2022"\]')
        self.assertRegex(text, rf'(?i)host:{re.escape(CASTELBLACK)} \(castelblack[^)]*\) +\[tool, [^]]+, quote "{re.escape(CASTELBLACK)} '
                               rf'[^"]*\[\+\] north\.sevenkingdoms\.local\\rickon\.stark:Winter2022"\]')

    def test_q1_a_null_session_is_on_its_host(self):
        on_dc01 = self.found("--where", f"host={KINGSLANDING}")
        nulls = sorted((r["title"], r["host_id"], r["status"]) for r in on_dc01
                       if r["type"] == "finding" and "null" in r["title"].lower())
        self.assertEqual(nulls, [("SMB null auth allowed", f"host:{KINGSLANDING}", "confirmed"),
                                 ("SMB null session accepted", f"host:{KINGSLANDING}", "confirmed")])

    def test_hosts_that_do_not_require_smb_signing(self):
        unsigned = self.found(*recipe("--", 0, "SMB signing"))
        self.assertEqual(sorted(r["host_id"] for r in unsigned), [f"host:{JUMPBOX}", "host:192.168.56.22", f"host:{BRAAVOS}"])
        text = self.cli("find", *recipe("--", 0, "SMB signing"))
        self.assertRegex(text, r"(?i)host:192\.168\.56\.22 \(castelblack[^)]*\)")
        self.assertRegex(text, rf"(?i)host:{re.escape(BRAAVOS)} \(braavos[^)]*\)")

    def test_a_protocol_word_finds_its_services_by_scan_name_and_port(self):
        smb = {r["id"] for r in self.found("smb", "--type", "service")}
        self.assertEqual(smb, {f"service:192.168.56.{h}-tcp-{p}" for h in (10, 11, 12, 22, 23) for p in (139, 445)}
                         | {f"service:{JUMPBOX}-tcp-445"})
        self.assertIn(f"service:{BRAAVOS}-tcp-3389", {r["id"] for r in self.found("rdp")})

    def test_the_import_summary_is_what_the_engagement_holds(self):
        out = self.cli("import", str(CORPUS / "scans"), "--no-ai")
        self.assertIn("now holds: ", out)
        self.assertRegex(out, r"now holds: (?:.*, )?8 host(?:,|\n)")
        self.assertNotIn("Records read", out)

    def test_q2_which_credentials_work_where_and_as_admin(self):
        worked = self.found(*recipe("Q2"))
        hosts = {self.account(r): set(r["hosts"]) for r in worked}
        self.assertEqual(len(worked), len(hosts), "one record per account")
        self.assertEqual(hosts, {
            (NORTH, "rickon.stark"): {f"host:{WINTERFELL}", f"host:{CASTELBLACK}"},
            (NORTH, "brandon.stark"): {f"host:{WINTERFELL}", f"host:{CASTELBLACK}"},
            (NORTH, "sql_svc"): {f"host:{WINTERFELL}", f"host:{CASTELBLACK}"},
            (NORTH, "goadmin"): {f"host:192.168.56.{h}" for h in (10, 11, 12, 22, 23)},
            ("castelblack", "goadmin"): {f"host:{CASTELBLACK}"},
            (ESSOS, "missandei"): {"host:192.168.56.12", f"host:{BRAAVOS}"},
            (ESSOS, "sql_svc"): {"host:192.168.56.12", f"host:{BRAAVOS}"},
        })
        admin = {self.account(r): set(r["admin_hosts"]) for r in self.found("--type", "credential", "--where", "admin_hosts?")}
        self.assertEqual(admin, {(ESSOS, "sql_svc"): {f"host:{BRAAVOS}"}, (NORTH, "sql_svc"): {f"host:{CASTELBLACK}"},
                                 (NORTH, "goadmin"): {f"host:{WINTERFELL}", f"host:{CASTELBLACK}"},
                                 ("castelblack", "goadmin"): {f"host:{CASTELBLACK}"}})

    def test_q2_every_host_a_login_worked_on_is_cited_in_text(self):
        text = self.cli("find", *recipe("Q2"), "--limit", "1000")
        for ip in ("192.168.56.11", "192.168.56.22", "192.168.56.12", BRAAVOS):
            self.assertRegex(text, re.compile(rf'quote "[^"]*{re.escape(ip)}[^"]*\[\+\]'), ip)
        self.assertIn("(Pwn3d!)", text)

    def test_q3_what_is_cracked_including_what_already_worked(self):
        cracked = self.found(*recipe("Q3"))
        self.assertEqual(sorted(self.account(r) for r in cracked), [
            ("braavos", "vagrant"), (ESSOS, "missandei"), (ESSOS, "sql_svc"), (NORTH, "brandon.stark"),
            (NORTH, "jon.snow"), (NORTH, "sansa.stark"), (NORTH, "sql_svc")])
        untried = self.found(*recipe("Q3", 1))
        self.assertEqual(sorted(self.account(r) for r in untried), [
            ("braavos", "vagrant"), (NORTH, "jon.snow"), (NORTH, "samwell.tarly"), (NORTH, "sansa.stark")])
        self.assertEqual({r["state"] for r in untried}, {"cracked", "found"})

    def test_q4_who_is_in_domain_admins(self):
        members = {(r["src_id"], r["dst_id"]) for r in self.found(*recipe("Q4"))}
        self.assertEqual(members, {
            (f"principal:{ESSOS}\\{who}", f"group:{ESSOS}\\domain admins")
            for who in ("administrator", "daenerys.targaryen", "goadmin")
        } | {(f"group:{ESSOS}\\queenprotector", f"group:{ESSOS}\\domain admins")} | {
            (f"principal:{NORTH}\\{who}", f"group:{NORTH}\\domain admins")
            for who in ("administrator", "eddard.stark", "goadmin")
        })

    def test_q1_what_do_i_have_on_castelblack_by_name(self):
        on = self.found(*[a.replace("host=dc01", "host=castelblack") for a in recipe("Q1")])
        self.assertIn("castelblack", [n for r in on if r["type"] == "host" for n in r["hostnames"]])
        self.assertIn(f"share:{CASTELBLACK}-all", {r["id"] for r in on})

    def test_q1_braavos_holds_the_adcs_weaknesses_certipy_found(self):
        on = self.found(*[a.replace("host=dc01", "host=braavos") for a in recipe("Q1")])
        self.assertEqual(sorted(r["title"] for r in on if r["type"] == "finding" and r["title"].startswith("ESC")),
                         sorted(CorpusCertipy.ESSOS))

    def test_guest_with_an_empty_password_works_on_braavos_and_castelblack_only(self):
        empty = {(r["host_id"], r["title"]) for r in self.found("--type", "finding", "--where", "title~empty password")}
        self.assertEqual(empty, {
            (f"host:{BRAAVOS}", "SMB login with an empty password accepted (essos.local\\guest)"),
            (f"host:{CASTELBLACK}", f"SMB login with an empty password accepted ({NORTH}\\guest)")})

    def test_q5_what_i_noted_to_come_back_to(self):
        self.cli("note", "sql_svc is admin here; check the MSSQL linked servers", "--host", "braavos", "--tag", "todo")
        noted = self.found(*recipe("Q5"))
        self.assertEqual([r["host_id"] for r in noted], [f"host:{BRAAVOS}"])


class GoadEngagementReversed(GoadEngagement):
    """The same answers when every file arrives in the opposite order, one import at a time."""

    order = "reversed"


class CorpusCertipy(EngagementCase):
    """Each way certipy find was saved gives one finding per weakness it flags, on the CA's host."""

    ESSOS = ["ESC6: ESSOS-CA", "ESC8: ESSOS-CA", "ESC11: ESSOS-CA", "ESC1: template ESC1 on ESSOS-CA",
             "ESC2: template ESC2 on ESSOS-CA", "ESC3: template ESC2 on ESSOS-CA",
             "ESC3: template ESC3-CRA on ESSOS-CA", "ESC9: template ESC9 on ESSOS-CA"]
    HOSTS = "nxc/check-brandon.stark.txt"

    def load(self, *rels):
        for rel in rels:
            ingest.import_path(self.eng, CORPUS / rel)

    def findings(self):
        return {r["title"]: (r.get("host_id"), r.get("status")) for r in self.all("finding")
                if r["title"].startswith("ESC")}

    def queued(self):
        return [e["source"] for e in rawstore.manifest(self.eng) if e.get("ai") == "pending"]

    def assert_essos_from(self, rel):
        self.load(self.HOSTS, rel)
        self.assertEqual(self.findings(), {t: (f"host:{BRAAVOS}", "confirmed") for t in self.ESSOS})
        self.assertEqual(self.queued(), [])
        self.assert_citations_hold()

    def test_json_gives_the_essos_weaknesses(self):
        self.assert_essos_from("adcs/certipy-essos_Certipy.json")

    def test_tee_d_vulnerable_screen_gives_the_same_weaknesses(self):
        self.assert_essos_from("adcs/certipy-essos-vulnerable.txt")

    def test_a_weakness_says_why_in_certipys_words(self):
        self.load(self.HOSTS, "adcs/certipy-essos-vulnerable.txt")
        esc1 = next(r for r in self.all("finding") if r["title"].startswith("ESC1:"))
        self.assertEqual(esc1["description"], "'ESSOS.LOCAL\\\\Domain Users' can enroll, enrollee supplies subject "
                                              "and template allows client authentication")

    def test_text_and_json_of_one_run_are_the_same_records(self):
        self.load(self.HOSTS, "adcs/certipy-north_Certipy.txt")
        text = {r["id"]: (r["title"], r.get("host_id")) for r in self.all("finding")}
        self.load("adcs/certipy-north_Certipy.json")
        self.assertEqual({r["id"]: (r["title"], r.get("host_id")) for r in self.all("finding")}, text)
        self.assertEqual(self.findings(), {"ESC8: SEVENKINGDOMS-CA": (f"host:{KINGSLANDING}", "confirmed")})

    def test_a_ca_name_two_held_hosts_carry_is_said_and_not_waited_on(self):
        scan = self.tmp / "two-braavos.gnmap"
        scan.write_text("Host: 10.20.0.23 (braavos)\tStatus: Up\nHost: 10.20.1.23 (braavos)\tStatus: Up\n")
        ingest.import_path(self.eng, scan)
        notes = ingest.import_path(self.eng, CORPUS / "adcs/certipy-essos_Certipy.json")[0]["notes"]
        self.assertEqual(self.findings(), {})
        self.assertTrue(any("braavos.essos.local matches 2 held hosts" in n for n in notes), notes)
        self.assertFalse(any(e.get("waiting") for e in rawstore.manifest(self.eng)))

    def test_weaknesses_wait_for_the_scan_that_names_the_ca_host(self):
        self.load("adcs/certipy-essos_Certipy.json")
        self.assertEqual(self.findings(), {})
        self.load(self.HOSTS)
        self.assertEqual(self.findings(), {t: (f"host:{BRAAVOS}", "confirmed") for t in self.ESSOS})


class CorpusBloodHound(unittest.TestCase):
    """A collection run without -c All names the same groups as one run with it."""

    ALL = CORPUS / "bloodhound/20261019141655_bloodhound.zip"
    DEFAULT = FIXTURES / "bloodhound/north_default_20261019142903_bloodhound.zip"

    def held(self, *rels):
        with tempfile.TemporaryDirectory() as tmp:
            eng = engagement.create("lab", Path(tmp))
            for rel in rels:
                ingest.import_path(eng, rel)
            return {k: r["type"] for k, r in records.load_all(eng).items() if r["type"] in ("group", "relationship")}

    def test_both_collections_give_one_group_per_group_in_either_order(self):
        alone = self.held(self.ALL)
        self.assertEqual(self.held(self.ALL, self.DEFAULT), alone)
        self.assertEqual(self.held(self.DEFAULT, self.ALL), alone)


class CorpusRows(EngagementCase):
    """NetExec rows Trove does not read reach the AI; status lines do not."""

    def load(self, rel):
        ingest.import_path(self.eng, CORPUS / rel)

    def queued(self):
        return [line for e in rawstore.manifest(self.eng) if e.get("ai") == "pending"
                for line in rawstore.read(self.eng, e["blob"]).decode().splitlines() if line.strip()]

    def cached(self):
        return [(r["realm"].upper(), r["principal"], r.get("host_id")) for r in self.all("credential")
                if r.get("hash_type") == "dcc2"]

    def test_a_cached_logon_names_its_domain_without_the_nul_impacket_writes(self):
        self.load("dumps/secretsdump-castelblack.txt")
        self.assertEqual(self.cached(), [("NORTH.SEVENKINGDOMS.LOCAL", "sql_svc", None)])
        self.assert_citations_hold()

    def test_netexec_lsa_screen_gives_the_cached_logon_of_its_host(self):
        self.load("nxc/dump-members-goadmin.txt")
        self.assertEqual(self.cached(), [("NORTH.SEVENKINGDOMS.LOCAL", "sql_svc", [f"host:{CASTELBLACK}"])])
        self.assertNotIn("Added 6 SAM hashes to the database", "\n".join(self.queued()))
        self.assert_citations_hold()

    def test_nmap_verbose_grepable_header_is_nmaps_own(self):
        ingest.import_path(self.eng, FIXTURES / "nmap/nmap-os-verbose.gnmap")
        self.assertEqual(self.queued(), [])

    def test_getnpusers_refusals_are_impackets_own(self):
        self.load("roast/asrep-north-screen.txt")
        self.assertEqual(self.queued(), [])
        self.assertEqual([r["principal"] for r in self.all("credential")], ["brandon.stark"])

    def test_getuserspns_table_without_hashes_names_who_is_in_each_group(self):
        self.load("roast/spns-north-screen.txt")
        self.assertEqual(self.queued(), [])
        self.assertEqual(sorted((r["src_id"], r["dst_id"]) for r in self.all("relationship")),
                         [("principal:north.sevenkingdoms.local\\jon.snow", "group:north.sevenkingdoms.local\\night watch"),
                          ("principal:north.sevenkingdoms.local\\sansa.stark", "group:north.sevenkingdoms.local\\stark")])
        self.assert_citations_hold()

    def test_netexec_user_table_rows_go_to_the_ai(self):
        self.load("nxc/users-north.txt")
        self.assertTrue(any("Samwell Tarly (Password : Heartsbane)" in line for line in self.queued()))

    def test_netexec_logged_on_user_rows_go_to_the_ai(self):
        self.load("nxc/loggedon.txt")
        self.assertTrue(any("NORTH\\robb.stark" in line for line in self.queued()))


class CorpusDumps(unittest.TestCase):
    """Each way the north DC's NTDS was saved, imported alone, names the same accounts."""

    def accounts(self, rel):
        with tempfile.TemporaryDirectory() as tmp:
            eng = engagement.create("lab", Path(tmp))
            ingest.import_path(eng, CORPUS / rel)
            return sorted(r["principal"] for r in records.load_all(eng).values()
                          if r["type"] == "credential" and r.get("hash_type") == "ntlm")

    def test_secretsdump_file_netexec_screen_and_netexec_file_name_the_same_twenty_accounts(self):
        named = [self.accounts(rel) for rel in (
            "dumps/sd-winterfell.ntds", "nxc/ntds-north.txt",
            "nxc/nxc-logs/ntds/winterfell_192.168.56.11_2026-10-19_141813.ntds")]
        self.assertEqual(len(named[0]), 20)
        self.assertEqual(named[1:], [named[0], named[0]])


class CorpusCachedLogons(unittest.TestCase):
    """A cached logon of a password Trove holds is that password, in either order."""

    DUMPS = ("nxc/ntds-north.txt", "nxc/dump-members-goadmin.txt")
    CAPTURES = ("roast/kerb-north.txt", "responder/logs/Responder-Session.log")

    def sql_svc(self, *rels):
        with tempfile.TemporaryDirectory() as tmp:
            eng = engagement.create("lab", Path(tmp))
            for rel in rels:
                ingest.import_path(eng, CORPUS / rel)
            return [r for r in records.load_all(eng).values() if r["type"] == "credential"
                    and r["principal"] == "sql_svc" and (r.get("realm") or "").lower() == NORTH]

    def test_a_dcc2_hash_joins_the_nt_hash_of_its_password(self):
        for rels in (self.DUMPS, self.DUMPS[::-1]):
            with self.subTest(order=rels):
                [cred] = self.sql_svc(*rels)
                self.assertEqual((cred["hash_type"], cred["secret_hash"]), ("ntlm", "84a5092f53390ea48d660be52b93b804"))
                self.assertIn(f"host:{CASTELBLACK}", cred["host_id"])

    def test_captures_join_the_one_password_whatever_arrives_first(self):
        for rels in (self.DUMPS + self.CAPTURES, self.CAPTURES + self.DUMPS):
            with self.subTest(order=rels):
                [cred] = self.sql_svc(*rels)
                self.assertEqual(cred["hash_type"], "ntlm")

    def test_a_cached_logon_with_an_absurd_work_factor_or_a_bad_nt_hash_joins_nothing(self):
        nt = {"hash_type": "ntlm", "secret_hash": "84a5092f53390ea48d660be52b93b804"}
        slow = {"secret_hash": "$DCC2$9999999#sql_svc#89e701ebbd305e4f5380c5150494584a"}
        self.assertFalse(records._cached_logon_of(slow, nt))
        good = {"secret_hash": "$DCC2$10240#sql_svc#89e701ebbd305e4f5380c5150494584a"}
        self.assertFalse(records._cached_logon_of(good, {"hash_type": "ntlm", "secret_hash": "not-a-hash"}))
        self.assertTrue(records._cached_logon_of(good, nt))
