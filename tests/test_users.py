from tests.helpers import EngagementCase


class Users(EngagementCase):
    """Counts and values on the users fixture."""

    def test_a_user_list_is_never_sniffed(self):
        self.assertEqual(self.import_fixture("users/user-list.txt")["status"], "pending AI extraction")

    def test_named_by_the_operator_every_name_becomes_a_principal_only_credential(self):
        report = self.import_fixture("users/user-list.txt", tool="users")
        self.assertEqual(report["counts"], {"credential": 5})
        creds = self.all("credential")
        self.assertEqual(sorted(c["principal"] for c in creds),
                         sorted(["asmith", "jdoe", "mwilson", "ACME\\svc_backup", "rjones"]))
        self.assertTrue(all(set(c["prov"]) == {"principal"} for c in creds))
        self.assertTrue(any("repeated name" in n for n in report["notes"]))
        self.assert_citations_hold()
