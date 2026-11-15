from lootlib import ingest
from lootlib.errors import LootError
from tests.helpers import FIXTURES, EngagementCase

USERS = b"hodor\nnorth\\samwell.tarly\njeor.mormont@sevenkingdoms.local\n"


class Users(EngagementCase):
    """Counts and values on the users fixture."""

    def test_a_user_list_is_never_sniffed(self):
        self.assertEqual(self.import_fixture("users/user-list.txt")["status"], "pending AI extraction")

    def test_named_by_the_operator_every_name_becomes_a_principal(self):
        report = self.import_fixture("users/user-list.txt", tool="users")
        self.assertEqual(report["counts"], {"principal": 5})
        self.assertEqual(self.all("credential"), [])
        names = self.all("principal")
        self.assertEqual(sorted((p["principal"], p.get("realm")) for p in names),
                         sorted([("asmith", None), ("jdoe", None), ("mwilson", None), ("svc_backup", "ACME"),
                                 ("rjones", None)]))
        self.assertTrue(any("repeated name" in n for n in report["notes"]))
        self.assert_citations_hold()


class Realm(EngagementCase):
    """``--realm`` names the domain of a user list's bare names, as the operator's word."""

    def test_bare_names_take_the_realm_from_you(self):
        report = ingest.import_data(self.eng, USERS, "users.txt", tool="users", realm="north.sevenkingdoms.local")[0]
        held = {p["principal"]: p for p in self.all("principal")}
        self.assertEqual(held["hodor"]["realm"], "north.sevenkingdoms.local")
        self.assertEqual(held["hodor"]["prov"]["realm"],
                         {"blob": report["blob"], "origin": "you", "source": "--realm",
                          "quote": "north.sevenkingdoms.local"})

    def test_a_name_with_its_own_domain_keeps_it(self):
        ingest.import_data(self.eng, USERS, "users.txt", tool="users", realm="north.sevenkingdoms.local")
        held = {p["principal"]: p for p in self.all("principal")}
        self.assertEqual(held["samwell.tarly"]["realm"], "north")
        self.assertEqual(held["jeor.mormont"]["realm"], "sevenkingdoms.local")
        self.assertEqual(held["jeor.mormont"]["prov"]["realm"]["origin"], "tool")

    def test_a_realm_is_refused_without_the_users_parser(self):
        for tool in (None, "creds", "netexec"):
            with self.subTest(tool=tool), self.assertRaisesRegex(LootError, "--realm"):
                ingest.import_data(self.eng, USERS, "users.txt", tool=tool, realm="north.sevenkingdoms.local")
        self.assertEqual(self.all(), [])

    def test_a_sam_dump_without_a_machine_account_never_gets_a_realm(self):
        sam = FIXTURES / "creds/secretsdump-ntlm.txt"
        with self.assertRaisesRegex(LootError, "--realm"):
            ingest.import_path(self.eng, sam, realm="north.sevenkingdoms.local")
        ingest.import_path(self.eng, sam)
        self.assertTrue(self.all("credential"))
        self.assertTrue(all(not c.get("realm") for c in self.all("credential")))
